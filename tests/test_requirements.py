"""Requirements the traceability table had no row for.

The table was scoped to the prohibitions — what the system must never do —
and the assurance case surfaced the consequence: twelve requirements were
claimed by the specification with no recorded evidence. Most turned out to be
covered by tests written for other reasons, which is fine once the record says
so. Three were not, and are covered here:

- **R7** — the human-in-the-loop routing. `hitl_decision` is the whole clause,
  and nothing tested it directly. It is also the gate that today's
  `Finding.suppressable` work moved findings through, where a mistake would
  either deny everything or escalate nothing.
- **R11** — a decision must be inspectable. Three of its four artefacts were
  available; the compiled SQL plan was exposed nowhere, so the clause was not
  met. `Result.plans` now carries it.
- **R3** — execution under fixed resource caps. The row cap was checked by the
  SafeSQL shape tests; the memory and thread limits were not checked at all.
"""

from __future__ import annotations

import json
import re

import pytest

from safetre import synth
from safetre.disclosure import Finding, hitl_decision
from safetre.engine import MEMORY_LIMIT, THREADS, QueryEngine
from safetre.service import QueryService


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=17)


# --- R7: residual findings reach a human, or deny ------------------------------

def test_nothing_left_over_releases_automatically():
    assert hitl_decision([]) == "auto"
    assert hitl_decision([Finding("low", "secondary_suppression", "x")]) == "auto"


def test_a_medium_residual_escalates_to_a_human():
    assert hitl_decision([Finding("medium", "too_granular", "x")]) == "human"


def test_a_high_residual_denies():
    assert hitl_decision([Finding("high", "identifier_egress", "x")]) == "deny"
    # severity decides, not order or count: one high among many denies
    assert hitl_decision([Finding("low", "a", "x"), Finding("medium", "b", "x"),
                          Finding("high", "c", "x")]) == "deny"


def test_the_service_routes_on_that_decision(tables, monkeypatch):
    # the clause is about routing, not just the function: a residual medium
    # finding must actually reach the caller as a review, with no data
    import safetre.service as service_module

    monkeypatch.setattr(service_module.D, "hitl_decision", lambda findings: "human")
    spec = {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
            "group_by": ["age_band"]}
    result = QueryService(tables).handle(json.dumps(spec), planner=None)
    assert result.status == "review"
    assert result.output is None


# --- R11: the decision is inspectable ------------------------------------------

def test_a_release_carries_everything_needed_to_audit_it(tables):
    spec = {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
            "group_by": ["age_band"]}
    result = QueryService(tables).handle(json.dumps(spec), planner=None)
    assert result.status in ("released", "redacted")
    assert result.spec == {"dataset": "spend", "filters": [], "group_by": ["age_band"],
                           "measure": {"fn": "mean", "column": "amount_gbp",
                                       "x": None, "y": None}}
    assert result.trace, "no pipeline trace"
    assert result.plans, "no compiled plan"
    sql = result.plans[0]
    assert sql.startswith("SELECT ") and "age_band" in sql


def test_a_denial_is_inspectable_to_the_checker_not_the_analyst(tables, audit_spy):
    """R11, with the "to whom" made explicit (hardening #66).

    A data-derived denial is fully inspectable — in the audit log, which is
    where an output checker reviewing the session reads it. The analyst gets
    the spec and the request-decided trace, and NOT the compiled plan: the plan
    would confirm the spec validated and reached the engine, which is exactly
    the distinction the canonical refusal erases.
    """
    spec = {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
            "group_by": ["age_band", "region", "device_os"],
            "filters": [{"column": "sex", "op": "==", "value": "X"}]}
    result = QueryService(tables).handle(json.dumps(spec), planner=None,
                                         audit_log=audit_spy)
    assert result.status == "denied"
    assert result.spec and result.trace
    assert result.plans == []
    # the checker's half: the real findings, with their counts, are recorded
    assert audit_spy.rules() and audit_spy.last["spec"] == result.spec


def test_a_model_exposes_a_plan_per_design_cell_table(tables):
    raw = {"tool": "glm", "dataset": "donor_spend", "family": "gaussian",
           "response": "total_spend_gbp", "terms": ["age_band"]}
    result = QueryService(tables).handle(json.dumps(raw), planner=None)
    assert len(result.plans) == 2                      # mean and sum_sq cells
    assert all(sql.startswith("SELECT ") for sql in result.plans)


def test_the_plan_carries_no_values_only_placeholders(tables):
    # why it is safe to show: the SafeSQL shape binds every value, so the
    # string names allowlisted columns and nothing an analyst did not supply
    spec = {"dataset": "spend", "measure": {"fn": "count"},
            "filters": [{"column": "region", "op": "==", "value": "Wales"}]}
    result = QueryService(tables).handle(json.dumps(spec), planner=None)
    assert "Wales" not in result.plans[0]
    assert "?" in result.plans[0]


# --- R3: fixed resource caps ---------------------------------------------------

_UNITS = {"KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3,
          "KB": 10 ** 3, "MB": 10 ** 6, "GB": 10 ** 9}


def _bytes(text: str) -> float:
    """`512MB`, `488.2 MiB` — the same quantity, and duckdb hands back the
    unit it prefers rather than the one it was given."""
    match = re.fullmatch(r"([\d.]+)\s*([KMG]i?B)", text.strip(), re.I)
    assert match, f"unparseable size {text!r}"
    return float(match.group(1)) * _UNITS[match.group(2).upper()]


def test_the_engine_runs_under_its_declared_caps(tables):
    # a query that is expensive by accident must hit a bound, not the host's
    engine = QueryEngine(tables)
    settings = dict(engine.con.execute(
        "SELECT name, value FROM duckdb_settings() "
        "WHERE name IN ('memory_limit', 'threads')").fetchall())
    assert settings["threads"] == str(THREADS)
    assert _bytes(settings["memory_limit"]) == pytest.approx(
        _bytes(MEMORY_LIMIT), rel=0.01)
