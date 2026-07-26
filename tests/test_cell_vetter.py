"""The cell-vetting seam (roadmap item 1, `docs/acro-integration.md`).

`CellVetter` is where ACRO's checks will enter: it *decides* which cells may
be released and nothing else, so complementary suppression, finalization and
released-value shaping stay the policy's own whatever rules run. These tests
pin the two properties that make that seam safe to extend:

- the extracted `StandinVetter` decides exactly what the policy decided before
  it existed — checked against an independent restatement of the old
  filtering, not against the implementation;
- composition is a **union** and therefore monotone: adding a vetter can
  suppress more, never less, so bringing ACRO in cannot regress protection
  even if its rules are wrong.

The whole-pipeline regression lives in the existing suites: if this refactor
changed any decision, `test_disclosure`, `test_release_equality`,
`test_procedure_conformance` and the red-team corpus would say so.
"""

from __future__ import annotations

import pandas as pd
import pytest

from safetre.disclosure import (
    CellVetter, CompositeVetter, DisclosurePolicy, Finding, StandinVetter,
    Verdicts, VettingParameters, _count_cols,
)

PARAMS = VettingParameters(threshold=10, max_rows=100, dom_threshold=0.5,
                           influence_threshold=0.5)


def _frames():
    """Cell tables spanning the decisions a vetter has to make."""
    return {
        "all safe": pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0],
                                  "n": [50, 60], "n_donors": [40, 55]}),
        "small cell": pd.DataFrame({"region": ["A", "B", "C"], "value": [1.0, 2.0, 3.0],
                                    "n": [3, 12, 30], "n_donors": [3, 12, 30]}),
        "few donors, many rows": pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0],
                                               "n": [40, 50], "n_donors": [3, 50]}),
        "dominated": pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0],
                                   "n": [40, 50], "dominance": [0.9, 0.1]}),
        "influential": pd.DataFrame({"region": ["A", "B"], "value": [0.3, 0.2],
                                     "n": [40, 50], "influence": [0.9, 0.05]}),
        "unresolved witness": pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0],
                                            "n": [40, 50],
                                            "dominance": [float("inf"), 0.1]}),
        "missing count": pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0],
                                       "n": [40, float("nan")]}),
        "empty": pd.DataFrame({"region": [], "value": [], "n": []}),
        "no cells to judge": pd.DataFrame({"region": ["A"], "value": [1.0]}),
    }


def _surviving_the_old_way(df: pd.DataFrame, params: VettingParameters) -> pd.Index:
    """The pre-seam filtering, restated: `DisclosurePolicy.apply` trimmed the
    frame with these three predicates in this order."""
    kept = df.copy()
    for column in _count_cols(kept):
        kept = kept[kept[column] >= params.threshold]
    if "dominance" in kept.columns:
        kept = kept[kept["dominance"] <= params.dom_threshold]
    if "influence" in kept.columns:
        kept = kept[kept["influence"] <= params.influence_threshold]
    return kept.index


@pytest.mark.parametrize("label", sorted(_frames()))
def test_standin_vetter_suppresses_exactly_what_the_old_filtering_dropped(label):
    df = _frames()[label]
    verdicts = StandinVetter().vet(df, PARAMS)
    survivors = df.index[~verdicts.suppress]
    assert list(survivors) == list(_surviving_the_old_way(df, PARAMS)), label


@pytest.mark.parametrize("label", sorted(_frames()))
def test_suppression_and_findings_agree(label):
    # a suppressable finding and a suppressed cell are two views of one
    # decision: neither may appear without the other
    df = _frames()[label]
    verdicts = StandinVetter().vet(df, PARAMS)
    suppressable = {"small_cell", "dominance", "influence"}
    complained = any(f.rule in suppressable for f in verdicts.findings)
    assert complained == bool(verdicts.suppress.any()), label


def test_the_default_policy_vets_with_the_standin_rules():
    assert isinstance(DisclosurePolicy().vetter, StandinVetter)


def test_a_policy_decides_with_its_configured_thresholds_not_stale_ones():
    # parameters are read at call time, so a policy built from config.yaml
    # cannot end up vetting on the defaults
    df = pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0], "n": [4, 40]})
    strict, lenient = DisclosurePolicy(), DisclosurePolicy(threshold=3)
    assert strict.vetter.vet(df, strict.parameters()).suppress.tolist() == [True, False]
    assert lenient.vetter.vet(df, lenient.parameters()).suppress.tolist() == [False, False]


# --- composition ---------------------------------------------------------------

class _Fixed(CellVetter):
    """A vetter with a fixed opinion, for testing composition."""

    def __init__(self, name, suppress_regions=(), deny=False):
        self.name = name
        self.suppress_regions = set(suppress_regions)
        self.deny = deny

    def vet(self, df, params, context=None):
        mask = df["region"].isin(self.suppress_regions) if len(df) else \
            pd.Series(False, index=df.index)
        findings = [Finding("high", f"{self.name}_rule", "fixed opinion")] \
            if mask.any() or self.deny else []
        return Verdicts(suppress=mask, findings=findings, deny=self.deny)


def test_composition_is_the_union_of_its_vetters():
    df = pd.DataFrame({"region": ["A", "B", "C"], "value": [1.0, 2.0, 3.0],
                       "n": [40, 50, 60]})
    left, right = _Fixed("left", ["A"]), _Fixed("right", ["B"])
    both = CompositeVetter(left, right)
    assert both.vet(df, PARAMS).suppress.tolist() == [True, True, False]
    assert both.name == "left+right"


def test_composition_is_monotone():
    # adding a vetter never releases a cell that was suppressed without it —
    # the property that makes bringing ACRO in safe even if its rules are wrong
    df = _frames()["small cell"]
    alone = StandinVetter().vet(df, PARAMS).suppress
    for extra in (_Fixed("quiet"), _Fixed("noisy", ["B", "C"])):
        composed = CompositeVetter(StandinVetter(), extra).vet(df, PARAMS).suppress
        assert (composed | alone).equals(composed), extra.name


def test_a_vetter_with_nothing_to_say_changes_no_decision():
    df = _frames()["small cell"]
    policy = DisclosurePolicy()
    quiet = DisclosurePolicy(vetter=CompositeVetter(StandinVetter(), _Fixed("quiet")))
    released, action, _ = policy.apply(df)
    also, same_action, _ = quiet.apply(df)
    assert action == same_action
    assert released.equals(also)


def test_any_vetter_may_deny_the_whole_table():
    df = pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0], "n": [40, 50]})
    policy = DisclosurePolicy(
        vetter=CompositeVetter(StandinVetter(), _Fixed("refuser", deny=True)))
    released, action, findings = policy.apply(df)
    assert action == "deny"
    assert released is None
    assert any(f.rule == "refuser_rule" for f in findings)


def test_a_second_vetter_can_only_take_cells_away():
    # the end-to-end shape of the union: the composed release is a subset of
    # what the stand-in alone would have released
    df = pd.DataFrame({"region": ["A", "B", "C", "D"], "value": [1.0, 2.0, 3.0, 4.0],
                       "n": [40, 50, 60, 70]})
    alone, action, _ = DisclosurePolicy().apply(df)
    assert action == "release"
    composed, composed_action, _ = DisclosurePolicy(
        vetter=CompositeVetter(StandinVetter(), _Fixed("strict", ["A"]))).apply(df)
    assert composed_action == "redacted"
    assert set(composed["region"]) < set(alone["region"])


def test_a_composite_needs_a_vetter():
    with pytest.raises(ValueError, match="at least one"):
        CompositeVetter()
