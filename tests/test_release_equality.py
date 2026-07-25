"""Release equality: a released aggregate is a function of the gateway-
FINALIZED table alone (roadmap item 2; FORMAL_METHODS_ANALYSIS §C.2).

The query path's analogue of the model path's P21 reproducibility meta-test.
There (`refit_from_artifact`, test_glm_properties) a released fit is
reproduced bit-for-bit from the released cell table; here a released frame is
reproduced bit-for-bit from the frame the gateway approved. Both discharge the
same statement in the two halves of the pipeline: the release carries no
information beyond what the gateway vetted.

Hardening #26 is what makes the statement true of the code — released-value
shaping (`postprocess`: rounding, corr's derived `p_value`) was moved out of
the engine and now runs on the finalized frame, so `release = postprocess ∘
finalize ∘ vet` holds on both the plain and the model path. These tests pin
that factoring against regression, from two directions:

1. `test_release_reproduces_from_the_finalized_frame` — a verifier holding the
   vetted table and the spec recomputes the service's released frame exactly.
   Move `postprocess` back before finalization (the #26 bug) and this fails:
   corr's `p_value` would again be a function of the exact `n` rather than the
   released one.

2. `test_release_is_insensitive_to_what_finalization_erases` — perturbing the
   raw frame in ways finalization erases (exact row counts moved inside their
   rounding bucket; the internal donor count and the dominance/influence
   witnesses moved inside the region where their verdict is unchanged; tied
   rows reordered) leaves the released frame byte-identical. The
   noninterference form of the same claim: of each internal control, only its
   *verdict* reaches the output, never its value. This is the direction that
   found hardening #27 and #28 — the sacrificed complementary-suppression cell
   and the released row order were both ranked on exact counts.

Both run over the enumerated no-filter skeleton — a spread sample by default,
the whole space under `-m slow`, matching test_glm_properties.
"""

from __future__ import annotations

import json
from collections import Counter

import pandas as pd
import pytest
from test_formal_enumeration import _all_specs_no_filter

from safetre import synth
from safetre.disclosure import DisclosurePolicy, SessionAuditor, _count_cols
from safetre.engine import QueryEngine
from safetre.procedures import get_procedure
from safetre.service import QueryService

# every Nth skeleton point in the default run: a spread across datasets,
# measures and group-by widths (the space is ordered by all three)
SAMPLE_STEP = 17


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=17)


@pytest.fixture(scope="module")
def engine(tables):
    return QueryEngine(tables)


class _CapturingEngine:
    """Engine proxy that keeps the raw frame the service was handed.

    The recomputation below must start from *the frame the gateway vetted*,
    not from a second engine run: `ORDER BY n DESC` leaves ties in an
    unspecified order, so two runs of the same query are equal as tables but
    need not be equal row-for-row.
    """

    def __init__(self, engine: QueryEngine):
        self._engine = engine
        self.raw: pd.DataFrame | None = None

    def run(self, spec):
        self.raw = self._engine.run(spec)
        return self.raw.copy()

    def marginal_donor_counts(self):
        return self._engine.marginal_donor_counts()


def _skeleton(step: int | None):
    specs = list(_all_specs_no_filter())
    return specs if step is None else specs[::step]


def _recompute(policy: DisclosurePolicy, raw: pd.DataFrame, spec):
    """The verifier's job: from the vetted table and the spec alone, the
    released frame. Deliberately written out here rather than called through
    the service, so the two agree only if the service really does factor as
    `postprocess ∘ finalize ∘ vet`."""
    finalized, action, _ = policy.apply(raw)
    if finalized is None:
        return None, action
    return get_procedure(spec.measure.fn).postprocess(finalized.copy(), spec), action


def _run_reproducibility(tables, specs) -> Counter:
    seen: Counter = Counter()
    service = QueryService(tables)
    capture = _CapturingEngine(service.engine)
    service.engine = capture                      # type: ignore[assignment]
    policy = DisclosurePolicy()
    for spec in specs:
        capture.raw = None
        result = service.handle(json.dumps(spec.model_dump()), planner=None,
                                auditor=SessionAuditor())
        ctx = (spec.dataset, spec.measure.model_dump(), spec.group_by)
        seen[result.status] += 1
        if result.status not in ("released", "redacted"):
            assert result.output is None, ctx
            continue
        expected, action = _recompute(policy, capture.raw, spec)
        assert action == ("release" if result.status == "released" else "redacted"), ctx
        assert expected is not None, ctx
        # bit-equality: same columns, same dtypes, same values, same order
        assert list(result.output.columns) == list(expected.columns), ctx
        assert result.output.equals(expected), (
            ctx, result.output.to_dict("list"), expected.to_dict("list"))
    return seen


def test_release_reproduces_from_the_finalized_frame(tables):
    seen = _run_reproducibility(tables, _skeleton(SAMPLE_STEP))
    # both gateway outcomes must occur, or the equality proves nothing: the
    # interesting one is `redacted`, where the finalized table is a strict
    # subset of the cells the engine computed
    assert seen["released"] > 10, seen
    assert seen["redacted"] > 10, seen


@pytest.mark.slow
def test_release_reproduces_from_the_finalized_frame_full_skeleton(tables):
    seen = _run_reproducibility(tables, _skeleton(None))
    assert seen["released"] > 10 and seen["redacted"] > 10, seen


# --- what finalization erases must not reach the output ------------------------

def _round_counts(values: pd.Series, base: int) -> pd.Series:
    """`DisclosurePolicy._finalize`'s count rounding, applied to a candidate
    set — so 'same rounding bucket' means what the gateway means by it."""
    return (values / base).round().astype(int) * base


def _jitter(raw: pd.DataFrame, policy: DisclosurePolicy) -> pd.DataFrame:
    """A raw frame the gateway finalizes to exactly the same table.

    Every quantity moved here is one finalization erases:

    - exact row counts (`n`), moved to another value in the same base-5
      bucket and on the same side of the frequency threshold, so the cell's
      released count and its suppression verdict both stay put;
    - the internal distinct-donor count (`n_donors`), dropped before release,
      moved the same way;
    - the dominance/influence witnesses, dropped before release, replaced by
      *some other value with the same verdict* — a fixed safe value where the
      cell passes, `+inf` where it does not;
    - the row order, re-derived from the jittered counts. `ORDER BY n DESC`
      leaves tied cells in an unspecified order, so this is a frame the engine
      could equally have returned.

    Cells whose count has no room to move inside its bucket keep it: the point
    is a frame that finalizes identically, not a maximal perturbation.
    """
    out = raw.copy()
    for column in _count_cols(out):
        original = out[column].astype(int)
        target = _round_counts(original, policy.round_base)
        moved = []
        for value, bucket in zip(original, target, strict=True):
            releasable = value >= policy.threshold
            candidates = [c for c in range(value - 2, value + 3)
                          if c != value
                          and (c >= policy.threshold) == releasable
                          and int(_round_counts(pd.Series([c]), policy.round_base)[0])
                          == int(bucket)]
            moved.append(candidates[-1] if candidates else value)
        out[column] = pd.Series(moved, index=out.index, dtype=original.dtype)
    for column, limit in (("dominance", policy.dom_threshold),
                          ("influence", policy.influence_threshold)):
        if column in out.columns:
            witness = pd.to_numeric(out[column], errors="coerce")
            passes = witness.notna() & (witness <= limit)
            out[column] = pd.Series(
                [limit / 2 if ok else float("inf") for ok in passes],
                index=out.index, dtype=float)
    if "n" in out.columns:
        # the engine's ORDER BY, re-applied to the jittered counts, with ties
        # falling the other way
        out = out.iloc[::-1].sort_values("n", ascending=False, kind="stable")
    return out


def _run_insensitivity(engine, specs) -> tuple[int, int]:
    policy = DisclosurePolicy()
    compared = perturbed = 0
    for spec in specs:
        raw = engine.run(spec)
        jittered = _jitter(raw, policy)
        ctx = (spec.dataset, spec.measure.model_dump(), spec.group_by)
        baseline, action = _recompute(policy, raw, spec)
        shifted, jittered_action = _recompute(policy, jittered, spec)
        assert action == jittered_action, ctx
        if baseline is None:
            assert shifted is None, ctx
            continue
        compared += 1
        if not raw.equals(jittered):
            perturbed += 1
        assert shifted is not None, ctx
        assert shifted.equals(baseline), (
            ctx, baseline.to_dict("list"), shifted.to_dict("list"))
    return compared, perturbed


def test_release_is_insensitive_to_what_finalization_erases(engine):
    compared, perturbed = _run_insensitivity(engine, _skeleton(SAMPLE_STEP))
    # the jitter must actually bite somewhere, or this proves nothing
    assert compared > 10, compared
    assert perturbed > 10, perturbed


@pytest.mark.slow
def test_release_is_insensitive_to_what_finalization_erases_full_skeleton(engine):
    compared, perturbed = _run_insensitivity(engine, _skeleton(None))
    assert compared > 10 and perturbed > 10
