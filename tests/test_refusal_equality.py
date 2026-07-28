"""A refusal must not be a function of the data it refused to release (R6, P11).

The gateway's job is to decide what leaves the enclave. Everything it hands
back when the answer is "nothing" — the status, the message, the findings, the
trace — is also an output, and it was not being checked as one. Red-teamed on
2026-07-26: a denied query reported how many cells the engine had found, how
many fell below the threshold and how many were dominated, and a cohort
matching nobody came back `released` (with an empty table) while a cohort
matching one person came back `redacted`. Eight refusals recovered a unique
donor's region, sex, income band and device.

The property these tests pin is an equality: two queries that release nothing
must be indistinguishable to the analyst, however different the data behind
them. The audit log is the other half — it still records which rule fired and
on how many cells, because an output checker reviewing a session needs exactly
what the analyst must not have.
"""

from __future__ import annotations

import json

import pytest

from safetre import synth
from safetre.disclosure import DisclosurePolicy, SessionAuditor
from safetre.service import QueryService


class NoPlanner:
    def plan(self, request):                      # pragma: no cover - must not run
        raise AssertionError("a literal spec must not reach the planner")


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


@pytest.fixture
def service(tables):
    return QueryService(tables, DisclosurePolicy(threshold=10))


def visible(result) -> dict:
    """Everything the analyst can see. Deliberately includes the status and the
    row count of the released frame: an empty table released is still an answer
    to "did anyone match?"."""
    return {
        "status": result.status,
        "message": result.message,
        "findings": sorted((f.rule, f.detail) for f in result.findings),
        "trace": result.trace,
        "rows": None if result.output is None else len(result.output),
    }


def probe(service, auditor, filters, group_by=("device_os",)):
    return service.handle(
        json.dumps({"dataset": "donor_spend", "measure": {"fn": "count"},
                    "filters": list(filters), "group_by": list(group_by)}),
        NoPlanner(), auditor=auditor)


def test_a_cohort_of_nobody_looks_like_a_cohort_of_one(service, tables):
    """The existence oracle. A predicate that matches a single donor and one
    that matches none must give the same refusal — otherwise five filter slots
    over the catalogue enumerate an individual's quasi-identifiers.

    Probes use category values, not exact age: since hardening #39 an
    exact-age equality is not expressible at all (it is rejected at
    validation, before the engine — a request-decided refusal, which is
    allowed to look different). "Drop Rows" is a poison-donor region held by
    exactly one donor; "Nowhere Land" matches nobody.
    """
    hit = probe(service, SessionAuditor(budget=99),
                [{"column": "region", "op": "==", "value": "Drop Rows"}])
    miss = probe(service, SessionAuditor(budget=99),
                 [{"column": "region", "op": "==", "value": "Nowhere Land"}])

    assert hit.output is None and miss.output is None
    assert visible(hit) == visible(miss)


def test_a_refusal_carries_no_number_from_the_data(service, tables):
    """Every refusal is the same refusal, whatever the shape of what it hid."""
    auditor = SessionAuditor(budget=99)
    shapes = [
        [{"column": "region", "op": "==", "value": "Nowhere Land"}],    # nobody
        [{"column": "region", "op": "==", "value": "Northern Ireland"},
         {"column": "sex", "op": "==", "value": "X"}],                  # a handful
        [{"column": "income_band", "op": "==", "value": ">150k"},
         {"column": "age_band", "op": "==", "value": "13-15"}],         # a few more
    ]
    seen = {json.dumps(visible(probe(service, auditor, f)), sort_keys=True)
            for f in shapes}
    assert len(seen) == 1, "refusals differ by the data they refused"


def test_the_audit_log_still_gets_the_numbers(service, tables, audit_spy):
    """The other half of the split: an output checker reviewing the session
    must be able to see which rule fired and on how many cells."""
    probe_spec = json.dumps({
        "dataset": "wellbeing", "measure": {"fn": "mean", "column": "pgsi_score"},
        "group_by": ["region", "age_band", "device_os"],
        "filters": [{"column": "sex", "op": "==", "value": "X"}]})
    r = service.handle(probe_spec, NoPlanner(), auditor=SessionAuditor(budget=99),
                       audit_log=audit_spy)
    assert r.status == "denied"
    assert [f.rule for f in r.findings] == ["nothing_released"]
    assert "small_cell" in audit_spy.rules()
    assert any(ch.isdigit() for ch in audit_spy.audit_details()), (
        "the audit trail lost the counts the analyst is no longer shown")


# trace steps decided from the REQUEST alone. An analyst holds their own
# request, so these may be explained in full (and cite clause numbers); the
# steps below them see data and may not.
_REQUEST_STEPS = ("vetting:", "planner:", "validation:", "grouping:", "terms:")


def test_nothing_the_analyst_sees_on_a_refusal_contains_a_digit(service):
    r = probe(service, SessionAuditor(budget=99),
              [{"column": "region", "op": "==", "value": "Nowhere Land"}])
    shown = " ".join(
        [r.status, r.message]
        + [f"{f.rule} {f.detail}" for f in r.findings]
        + [s for s in r.trace if not s.startswith(_REQUEST_STEPS)])
    assert not any(ch.isdigit() for ch in shown), shown
