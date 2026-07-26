"""Literal spec entry (R17): a request that is a single JSON object is an
analyst-authored spec — it bypasses the planner and the natural-language
gates (intent vetting, fidelity checks), while every downstream control
(typed validation, budget, gateway, lineage) applies unchanged. Malformed
JSON is refused loudly, never handed to the planner as text.
"""

from __future__ import annotations

import json

import pytest

from safetre import synth
from safetre.disclosure import SessionAuditor
from safetre.service import QueryService


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


@pytest.fixture()
def service(tables):
    return QueryService(tables)


class RefusingPlanner:
    """A literal spec must never reach the planner."""

    def plan(self, request):
        raise AssertionError("planner was consulted for a literal spec")


# Regions whose cells release: big enough to clear the frequency threshold,
# and outside the planted dominance anchors — a concentrated design cell
# denies the whole model (P19), which is a different test's business.
BIG_REGIONS = [r for r in ("London", "South East", "North West",
                           "East of England", "Yorkshire and The Humber",
                           "West Midlands", "East Midlands", "South West",
                           "Scotland")
               if r not in synth.DOMINANCE_ANCHORS]


def anova_request(**over) -> str:
    spec = {"tool": "anova", "dataset": "spend", "response": "amount_gbp",
            "factor": "region",
            "filters": [{"column": "region", "op": "in", "value": BIG_REGIONS}]}
    spec.update(over)
    return json.dumps(spec)


# --- the release path ------------------------------------------------------------

def test_literal_model_spec_releases_without_planner(service):
    r = service.handle(anova_request(), RefusingPlanner())
    assert r.status == "released"
    assert r.output.iloc[0]["source"] == "region"
    assert any("literal spec" in t for t in r.trace)


def test_literal_aggregate_spec_releases_without_planner(service):
    # The JSON text never phrases "age band", so the grouping fidelity gate
    # would fire on a natural-language request shaped like this; for a literal
    # spec there is no question to be faithful to and it must release.
    req = json.dumps({"dataset": "spend",
                      "measure": {"fn": "mean", "column": "amount_gbp"},
                      "group_by": ["age_band"]})
    r = service.handle(req, RefusingPlanner())
    assert r.status == "released"
    assert any("fidelity gate not applicable" in t for t in r.trace)


# --- loud refusal on malformed input (never re-routed to the planner) ------------

def test_malformed_literal_spec_refused_loudly(service):
    r = service.handle('{"tool": "anova", "dataset":', RefusingPlanner())
    assert r.status == "denied"
    assert [f.rule for f in r.findings] == ["spec_rejected"]
    assert "not valid JSON" in r.message


# --- every downstream control still applies --------------------------------------

def test_literal_spec_still_validated(service):
    r = service.handle(anova_request(dataset="donors"), RefusingPlanner())
    assert r.status == "denied"
    assert [f.rule for f in r.findings] == ["spec_rejected"]


def test_literal_unknown_tool_refused(service):
    r = service.handle(anova_request(tool="manova"), RefusingPlanner())
    assert r.status == "denied"
    assert "unknown tool" in r.message


def test_literal_spec_gateway_still_denies_small_cells(service, audit_spy):
    # No filter: sub-threshold regions are in the design, so P19 denies the
    # whole model exactly as it would for a planner-proposed spec.
    r = service.handle(anova_request(filters=[]), RefusingPlanner(),
                       audit_log=audit_spy)
    assert r.status == "denied"
    assert [f.rule for f in r.findings] == ["nothing_released"]
    assert "model_incomplete_cell_table" in audit_spy.rules()


def test_literal_spec_budget_still_denies_first(service):
    auditor = SessionAuditor(budget=0)
    r = service.handle(anova_request(), RefusingPlanner(), auditor=auditor)
    assert r.status == "denied"
    assert [f.rule for f in r.findings] == ["query_budget"]
