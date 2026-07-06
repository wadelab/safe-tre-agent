"""Property-based and exhaustive machine checks over the GLM release path.

Three layers on top of the compile-only enumeration:

1. Hypothesis fuzz end-to-end (spec space including filters): whatever the
   spec, a denial carries no output and no artifacts, and a release carries
   only contract-declared columns with rounded, above-threshold counts and no
   forbidden columns anywhere.
2. THE REPRODUCIBILITY META-TEST (P21, machine-checked): for every released
   model, refitting from the released cell table alone — `refit_from_artifact`,
   the function an analyst outside the safepod would run — reproduces the
   released coefficients exactly (`==`, not approx: the fitter is
   deterministic pure Python). Exhaustive over the 1-2 term skeleton;
   Hypothesis samples 3-term specs; the full skeleton runs under -m slow.
3. A structural sentinel check: a column smuggled into the finalized frame is
   caught by the output contract and denies — released frames cannot carry
   undeclared columns, and the fitter demonstrably consumes exactly the
   gateway-finalized frame.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from safetre import synth
from safetre.disclosure import ROUND_BASE, DisclosurePolicy, SessionAuditor
from safetre.glm import GLMProcedure, refit_from_artifact
from safetre.query import CATALOGUE, GLMSpec
from safetre.schema import identifier_columns, sensitive_columns
from safetre.service import QueryService

_DIM_PHRASE = {
    "age_band": "age band", "sex": "sex", "region": "region",
    "income_band": "income band", "device_os": "device os", "genre": "genre",
    "contains_lootboxes": "lootbox", "price_tier": "price tier",
    "event_type": "event type", "age_rating": "age rating", "wave": "wave",
}
_RESPONSE_PHRASE = {
    "amount_gbp": "spend", "ingame_currency": "in-game currency",
    "contains_lootboxes": "lootbox availability",
    "total_spend_gbp": "total spend", "purchase_events": "purchase events",
    "lootbox_events": "lootbox events",
    "wemwbs_score": "wellbeing", "pgsi_score": "pgsi",
    "igds_score": "igds", "monthly_spend_selfreport": "self-reported spend",
}

PROC = GLMProcedure()
_TABLES = synth.generate(seed=7)


@pytest.fixture(scope="module")
def service():
    return QueryService(_TABLES)


def _request_for(spec_dict: dict) -> str:
    """A request the term/response coherence gate accepts for this spec."""
    terms = " and ".join(_DIM_PHRASE[t] for t in spec_dict["terms"])
    return f"regress {_RESPONSE_PHRASE[spec_dict['response']]} on {terms}"


class _FixedModelPlanner:
    def __init__(self, spec: dict):
        self.spec = spec

    def plan(self, request: str) -> dict:
        return self.spec


@st.composite
def valid_glmspec_dicts(draw) -> dict:
    dataset = draw(st.sampled_from(sorted(CATALOGUE)))
    cat = CATALOGUE[dataset]
    response = draw(st.sampled_from(sorted(cat["glm_responses"])))
    family = draw(st.sampled_from(sorted(cat["glm_responses"][response])))
    candidates = sorted(set(cat["dims"]) - {response})
    terms = draw(st.lists(st.sampled_from(candidates), min_size=1, max_size=3,
                          unique=True))
    filters = []
    if draw(st.booleans()):
        filters.append({"column": "age_years",
                        "op": draw(st.sampled_from([">", ">=", "<", "<="])),
                        "value": draw(st.integers(min_value=10, max_value=90))})
    return {"tool": "glm", "dataset": dataset, "family": family,
            "response": response, "terms": terms, "filters": filters}


def _assert_release_invariants(result) -> None:
    spec = GLMSpec(**{k: v for k, v in result.spec.items() if k != "aggregates"})
    contract = PROC.output_contract(spec)
    frames = {"output": result.output, **result.artifacts}
    forbidden = identifier_columns() | (sensitive_columns() - identifier_columns()) \
        | {"free_text", "age_years", "dominance", "influence", "n_donors"}
    for name, frame in frames.items():
        cols = set(frame.columns)
        assert cols <= set(contract[name]), (name, cols)
        assert not (cols & forbidden), (name, cols)
        for col in frame.columns:
            if contract[name][col] == "count" and name != "model":
                assert (frame[col] % ROUND_BASE == 0).all(), (name, col)
    cells = result.artifacts["cells"]
    assert (cells["n"] >= DisclosurePolicy.threshold).all()
    # P21: an analyst refits from the released artifacts and gets the release
    refit, artifacts = refit_from_artifact(cells, spec)
    assert refit.equals(result.output)
    assert artifacts["cells"].equals(cells)
    assert artifacts["model"].equals(result.artifacts["model"])


@given(valid_glmspec_dicts())
@settings(max_examples=60, deadline=None)
def test_any_valid_glmspec_denies_cleanly_or_releases_the_contract(raw):
    service = QueryService(_TABLES)
    result = service.handle(_request_for(raw), _FixedModelPlanner(raw),
                            auditor=SessionAuditor())
    if result.status != "released":
        assert result.status in ("denied", "review")
        assert result.output is None and result.artifacts is None
    else:
        _assert_release_invariants(result)


def _skeleton(max_terms: int | None = None):
    for point in PROC.skeleton(CATALOGUE):
        if max_terms is None or len(point["terms"]) <= max_terms:
            yield point


def _run_reproducibility(service, points) -> tuple[int, int]:
    released = denied = 0
    for point in points:
        result = service.handle(_request_for(point), _FixedModelPlanner(point),
                                auditor=SessionAuditor())
        if result.status == "released":
            released += 1
            _assert_release_invariants(result)
        else:
            denied += 1
            assert result.output is None and result.artifacts is None
    return released, denied


def test_reproducibility_exhaustive_over_1_and_2_term_skeleton(service):
    # every 1-2 term model over the whole catalogue: released ⇒ reproducible
    released, denied = _run_reproducibility(service, _skeleton(max_terms=2))
    # the synthetic data must exercise both branches, or this proves nothing
    assert released > 10, (released, denied)
    assert denied > 10, (released, denied)


@pytest.mark.slow
def test_reproducibility_exhaustive_over_full_skeleton(service):
    released, denied = _run_reproducibility(service, _skeleton())
    assert released > 10 and denied > 10


def test_smuggled_column_in_finalized_frame_is_denied_by_contract(service, monkeypatch):
    # structural P21/R14 check: the fitter consumes exactly the frame the
    # gateway returned — so a column smuggled in there surfaces in the
    # released frames, violates the declared contract, and denies.
    real_apply = DisclosurePolicy.apply

    def poisoned_apply(self, df):
        released, action, findings = real_apply(self, df)
        if released is not None:
            released = released.assign(sentinel=1.0)
        return released, action, findings

    monkeypatch.setattr(DisclosurePolicy, "apply", poisoned_apply)
    raw = {"tool": "glm", "dataset": "donor_spend", "family": "gaussian",
           "response": "total_spend_gbp", "terms": ["age_band"]}
    result = QueryService(_TABLES).handle(
        "regress total spend on age band", _FixedModelPlanner(raw),
        auditor=SessionAuditor())
    assert result.status == "denied"
    assert any(f.rule == "contract_violation" for f in result.findings)
    assert result.output is None and result.artifacts is None
