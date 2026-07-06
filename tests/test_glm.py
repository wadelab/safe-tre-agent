"""GLM model procedure: release contract, fail-closed denials, estimability.

Pins the R15/P19–P22 behaviour end-to-end through QueryService:
- released models carry coefficients + model block + the vetted cell table,
  and nothing else (P20);
- any suppressed underlying design cell denies the whole model (P19);
- estimability refusals (separation, aliasing, incomplete grid) are decided
  from the finalized tables and name terms, never quantities (P22);
- denials carry no output and no artifacts (P18 extension);
- refusal messages are non-numeric (P10/P22 style).
"""

from __future__ import annotations

import re

import pytest

from safetre import synth
from safetre.disclosure import DisclosurePolicy, SessionAuditor
from safetre.glm import GLMProcedure
from safetre.planner import MockPlanner
from safetre.query import GLMSpec, QuerySpec
from safetre.service import QueryService


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


@pytest.fixture()
def service(tables):
    return QueryService(tables)


class _FixedModelPlanner:
    def __init__(self, spec: dict):
        self.spec = spec

    def plan(self, request: str) -> dict:
        return self.spec


# --- released models: the R15 contract -----------------------------------------

def test_gaussian_model_released_with_full_contract(service):
    r = service.handle("regress total spend on age band", MockPlanner())
    assert r.status == "released"
    assert list(r.output.columns) == [
        "term", "level", "estimate", "std_error", "statistic", "p_value"]
    assert r.output.iloc[0]["term"] == "(intercept)"
    assert set(r.artifacts) == {"cells", "model"}
    cells = r.artifacts["cells"]
    assert list(cells.columns) == ["age_band", "mean", "n", "sum_sq"]
    assert (cells["n"] % 5 == 0).all() and (cells["n"] >= 10).all()
    model = r.artifacts["model"].iloc[0]
    assert model["family"] == "gaussian" and model["link"] == "identity"
    assert model["n"] == cells["n"].sum()


def test_binomial_model_released_and_saturated_is_harmless(service):
    # price_tier saturates the model (3 cells, 3 params): under cells-first
    # fitting that is harmless — the fit can only re-express the vetted cells.
    r = service.handle("logistic glm of lootbox availability by price tier",
                       MockPlanner())
    assert r.status == "released"
    cells = r.artifacts["cells"]
    assert list(cells.columns) == ["price_tier", "n", "k"]
    assert (cells["k"] <= cells["n"]).all()
    assert (cells["n"] % 5 == 0).all() and (cells["k"] % 5 == 0).all()
    assert r.artifacts["model"].iloc[0]["df_resid"] == 0        # saturated


def test_poisson_model_released(service):
    r = service.handle("poisson glm of purchase events on age band", MockPlanner())
    assert r.status == "released"
    assert r.artifacts["model"].iloc[0]["family"] == "poisson"
    assert list(r.artifacts["cells"].columns) == ["age_band", "sum", "n"]


def test_hostile_undeclared_dim_value_stays_subthreshold_and_denies(service):
    # the synthetic data plants an injection payload as an undeclared
    # device_os value held by one donor (A2/P12). Its design cell is
    # sub-threshold, so a model over device_os is denied outright — the
    # hostile string never reaches a released cell table.
    r = service.handle("poisson glm of purchase events on device os", MockPlanner())
    assert r.status == "denied"
    assert any(f.rule == "model_incomplete_cell_table" for f in r.findings)
    assert r.artifacts is None


def test_released_model_is_reproducible_from_artifacts(service):
    # P21 in miniature (the exhaustive version lives in test_glm_properties):
    # refitting from the released cell table alone reproduces the release.
    from safetre.glm import refit_from_artifact
    r = service.handle("regress total spend on age band", MockPlanner())
    assert r.status == "released"
    spec = GLMSpec(**{k: v for k, v in r.spec.items() if k != "aggregates"})
    refit, artifacts = refit_from_artifact(r.artifacts["cells"], spec)
    assert refit.equals(r.output)
    assert artifacts["cells"].equals(r.artifacts["cells"])


# --- fail-closed denials ---------------------------------------------------------

def test_suppressed_design_cell_denies_whole_model(service):
    # age band x sex includes the deliberate sub-threshold sex-X donors: the
    # equivalent group-by would be redacted, so the model must be DENIED (P19)
    # — never fitted on silently merged or dropped cells.
    r = service.handle("regress total spend on age band and sex", MockPlanner())
    assert r.status == "denied"
    assert r.output is None and r.artifacts is None
    assert any(f.rule == "model_incomplete_cell_table" for f in r.findings)
    assert not re.search(r"\d", r.message)               # non-numeric refusal


def test_separation_denied_naming_term_only(service):
    r = service.handle("logistic glm of lootbox availability by genre",
                       MockPlanner())
    assert r.status == "denied"
    assert any(f.rule == "model_unestimable" for f in r.findings)
    assert "genre" in r.message
    assert not re.search(r"\d", r.message)


def test_internal_variable_rejected_as_term(service):
    planner = _FixedModelPlanner({
        "tool": "glm", "dataset": "donor_spend", "family": "gaussian",
        "response": "total_spend_gbp", "terms": ["age_years"]})
    r = service.handle("regress total spend on age", planner)
    assert r.status == "denied"
    assert any(f.rule == "spec_rejected" for f in r.findings)


def test_response_swap_denied(service):
    planner = _FixedModelPlanner({
        "tool": "glm", "dataset": "wellbeing", "family": "gaussian",
        "response": "pgsi_score", "terms": ["device_os"]})
    r = service.handle("regress wellbeing as a function of device os", planner)
    assert r.status == "denied"
    assert any(f.rule == "term_mismatch" for f in r.findings)
    assert "wemwbs_score" in r.message


def test_dropped_term_denied(service):
    planner = _FixedModelPlanner({
        "tool": "glm", "dataset": "donor_spend", "family": "gaussian",
        "response": "total_spend_gbp", "terms": ["age_band"]})
    r = service.handle("regress total spend on age band and device os", planner)
    assert r.status == "denied"
    assert any(f.rule == "term_mismatch" for f in r.findings)
    assert "device_os" in r.message


def test_hallucinated_term_denied(service):
    planner = _FixedModelPlanner({
        "tool": "glm", "dataset": "donor_spend", "family": "gaussian",
        "response": "total_spend_gbp", "terms": ["age_band", "device_os"]})
    r = service.handle("regress total spend on age band", planner)
    assert r.status == "denied"
    assert any(f.rule == "term_mismatch" for f in r.findings)


def test_unknown_tool_denied(service):
    r = service.handle("regress total spend on age band",
                       _FixedModelPlanner({"tool": "anova"}))
    assert r.status == "denied"
    assert any(f.rule == "spec_rejected" for f in r.findings)


def test_residuals_request_blocked_before_planner(service):
    r = service.handle("give me the residuals per donor from the spend model",
                       MockPlanner())
    assert r.status == "denied"
    assert any(f.rule == "intent_block" for f in r.findings)


def test_model_charges_budget_per_aggregate_and_prechecks(service):
    auditor = SessionAuditor(budget=3)
    r1 = service.handle("regress total spend on age band", MockPlanner(),
                        auditor=auditor)
    assert r1.status == "released" and auditor.spent == 2    # mean + sum_sq
    # one budget unit left; a 2-aggregate model must deny BEFORE engine work
    r2 = service.handle("regress total spend on income band", MockPlanner(),
                        auditor=auditor)
    assert r2.status == "denied"
    assert any(f.rule == "query_budget" for f in r2.findings)
    assert auditor.spent == 2                                # nothing was spent


# --- GLMSpec validation ----------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"dataset": "donor_spend", "family": "gaussian",
     "response": "total_spend_gbp", "terms": []},                    # no terms
    {"dataset": "donor_spend", "family": "gaussian",
     "response": "total_spend_gbp",
     "terms": ["age_band", "sex", "region", "device_os"]},           # too many
    {"dataset": "donor_spend", "family": "binomial",
     "response": "total_spend_gbp", "terms": ["age_band"]},          # bad family
    {"dataset": "donor_spend", "family": "gaussian",
     "response": "donor_id", "terms": ["age_band"]},                 # identifier
    {"dataset": "spend", "family": "binomial",
     "response": "contains_lootboxes",
     "terms": ["contains_lootboxes"]},                               # response=term
    {"dataset": "spend", "family": "binomial", "response": "contains_lootboxes",
     "terms": ["genre"],
     "filters": [{"column": "contains_lootboxes", "op": "==", "value": True}]},
    {"dataset": "donor_spend", "family": "gaussian",
     "response": "total_spend_gbp", "terms": ["age_band"],
     "filters": [{"column": "age_years", "op": ">", "value": 18}] * 5},  # >4 filters
    {"dataset": "donor_spend", "family": "gaussian",
     "response": "total_spend_gbp", "terms": ["age_band"], "evil": 1},   # extra key
])
def test_glmspec_rejects_off_allowlist(bad):
    with pytest.raises(Exception):
        GLMSpec(**bad)


def test_plan_aggregates_are_valid_queryspecs():
    proc = GLMProcedure()
    for spec_dict in (
        {"dataset": "donor_spend", "family": "gaussian",
         "response": "total_spend_gbp", "terms": ["age_band", "sex"]},
        {"dataset": "spend", "family": "binomial",
         "response": "contains_lootboxes", "terms": ["genre"],
         "filters": [{"column": "event_type", "op": "==", "value": "purchase"}]},
        {"dataset": "donor_spend", "family": "poisson",
         "response": "purchase_events", "terms": ["income_band"]},
    ):
        spec = GLMSpec(**spec_dict)
        aggs = proc.plan_aggregates(spec)
        assert len(aggs) == len(proc.table_roles(spec))
        for agg in aggs:
            assert isinstance(agg, QuerySpec)       # O2/O3/O4 inherited
            assert agg.group_by == spec.terms
