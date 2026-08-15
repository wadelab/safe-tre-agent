"""Hardening #95, closed: differencing across two views of one population.

The finding (round 11): the lineage was keyed on the dataset name while the
catalogue publishes several views of the same donors, so two individually
safe releases — `sum(total_spend_gbp)` over North West on `donor_spend`, and
`sum(amount_gbp)` over North West excluding `sex=X` on `spend` — differed by
one person and by that person's exact annual spend. Dropping the dataset from
the key was measured and withdrawn: it denied the demo's own benign
correlation after an unrelated query and added no safety, because
differencing binds only between COMMENSURABLE releases.

The close: the definition DECLARES measure equivalence (`quantities:`), the
auditor compares a pair on different views only when both carry the same
declared quantity, and the bound for such a pair is the number of people
whose per-person CONTRIBUTION differs (`engine.contribution_symdiff`) — not
the donor-set difference, which the second reproducer (NIGHTPLAY) shows
overstates the true difference by hundreds of zero-contributors.

Pinned here: both reproducers deny; the benign correlation after an
unrelated query still releases; an undeclared pair is not compared; identical
predicates on two views are not a pair; the contribution count is what it
claims; and the audit accounting carries the quantity so a restart restores
cross-view comparability while pre-#95 rows still restore.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from safetre import dataset as dataset_mod
from safetre import disclosure as D
from safetre import synth
from safetre.audit import AuditLog
from safetre.dataset import DatasetDefinition
from safetre.engine import QueryEngine
from safetre.service import QueryService
from safetre_web.session import SessionStore
from studies.nightplay import generate as G
from studies.nightplay import verify as V

PACKAGED = pathlib.Path(dataset_mod.__file__).with_name("demo_dataset.yaml")


def _q(service, auditor, spec):
    return service.handle(json.dumps(spec), planner=None, auditor=auditor)


# ----------------------------------------------------------------- demo ----

@pytest.fixture
def demo():
    dataset_mod.activate(dataset_mod.load_dataset(PACKAGED))
    tables = synth.generate()
    return QueryService(tables), tables


def test_the_round_11_pair_is_denied_on_the_demo(demo):
    service, _ = demo
    a = D.SessionAuditor()
    r1 = _q(service, a, {"dataset": "donor_spend",
                         "measure": {"fn": "sum", "column": "total_spend_gbp"},
                         "group_by": [],
                         "filters": [{"column": "region", "op": "==", "value": "North West"}]})
    assert r1.status == "released", r1.message
    r2 = _q(service, a, {"dataset": "spend",
                         "measure": {"fn": "sum", "column": "amount_gbp"},
                         "group_by": [],
                         "filters": [{"column": "region", "op": "==", "value": "North West"},
                                     {"column": "sex", "op": "!=", "value": "X"}]})
    assert r2.status == "denied", (r2.status, r2.message)
    # the refusal is the canonical withheld response, indistinguishable from
    # any other (P18/R18): the pin is the denial, not a rule name


def test_the_benign_correlation_after_an_unrelated_query_still_releases(demo):
    """The reason the blanket cross-view rule was withdrawn."""
    service, _ = demo
    a = D.SessionAuditor()
    r1 = _q(service, a, {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
                         "group_by": [], "filters": [{"column": "sex", "op": "!=", "value": "X"}]})
    assert r1.status == "released"
    r2 = _q(service, a, {"dataset": "donor_spend",
                         "measure": {"fn": "corr", "column": None,
                                     "x": "age_years", "y": "total_spend_gbp"},
                         "group_by": [], "filters": []})
    assert r2.status == "released", r2.message


def test_undeclared_measures_are_not_compared_across_views(demo):
    """wellbeing.pgsi_score carries no quantity: a pgsi release after a spend
    release over a near-identical cohort is not a pair, whatever the cohorts."""
    service, _ = demo
    a = D.SessionAuditor()
    r1 = _q(service, a, {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
                         "group_by": [],
                         "filters": [{"column": "region", "op": "==", "value": "North West"}]})
    r2 = _q(service, a, {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "pgsi_score"},
                         "group_by": [],
                         "filters": [{"column": "region", "op": "==", "value": "North West"},
                                     {"column": "sex", "op": "!=", "value": "X"}]})
    assert (r1.status, r2.status) == ("released", "released"), (r1.message, r2.message)


def test_identical_predicates_on_two_views_are_not_a_pair(demo):
    service, _ = demo
    a = D.SessionAuditor()
    f = [{"column": "region", "op": "==", "value": "North West"}]
    r1 = _q(service, a, {"dataset": "donor_spend", "measure": {"fn": "sum", "column": "total_spend_gbp"},
                         "group_by": [], "filters": f})
    r2 = _q(service, a, {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
                         "group_by": [], "filters": f})
    assert (r1.status, r2.status) == ("released", "released")


def test_contribution_symdiff_counts_people_whose_contribution_differs(demo):
    _, tables = demo
    eng = QueryEngine(tables)
    nw = (("region", "==", "North West"),)
    nw_not_x = (("region", "==", "North West"), ("sex", "!=", "X"))
    # the same quantity over the same predicate on two views: nobody differs
    assert eng.contribution_symdiff("donor_spend", "total_spend_gbp", nw,
                                    "spend", "amount_gbp", nw) == 0
    # excluding sex X: exactly the X people in North West with any spend
    donors = tables["donors"]
    events = tables["events"]
    x_nw = donors[(donors["region"] == "North West") & (donors["sex"] == "X")]["donor_id"]
    spenders = set(events[events["amount_gbp"] > 0]["donor_id"])
    expect = len([d for d in x_nw if d in spenders])
    got = eng.contribution_symdiff("donor_spend", "total_spend_gbp", nw,
                                   "spend", "amount_gbp", nw_not_x)
    assert got == expect, (got, expect)
    # whereas the donor-set difference also counts every zero-contributor
    assert eng.cohort_symdiff("donor_spend", nw, nw_not_x, dataset_b="spend") >= got


# ------------------------------------------------------------- nightplay ----

@pytest.fixture
def nightplay():
    tables, truth = G.generate(n_people=2500)
    dataset_mod.activate(dataset_mod.load_dataset(V.DEFINITION))
    try:
        yield V.build_service(tables), tables, truth
    finally:
        dataset_mod.activate(dataset_mod.load_dataset(PACKAGED))


def test_the_second_reproducer_is_denied_on_nightplay(nightplay):
    service, tables, _ = nightplay
    a = D.SessionAuditor()
    r1 = _q(service, a, {"dataset": "bets", "measure": {"fn": "sum", "column": "stake_gbp"},
                         "group_by": ["region"], "filters": []})
    assert r1.status in ("released", "redacted")
    r2 = _q(service, a, {"dataset": "panel", "measure": {"fn": "sum", "column": "stake_gbp"},
                         "group_by": ["region"],
                         "filters": [{"column": "sex", "op": "!=", "value": "X"}]})
    assert r2.status == "denied", (r2.status, r2.message)


def test_donor_set_difference_would_not_have_caught_it(nightplay):
    """Why the cross-view bound is contributions, not donor sets: the panel
    holds every person and the bets view only gamblers, so the donor sets
    differ by every non-gambler while the sums differ by the X gamblers."""
    _, tables, _ = nightplay
    eng = QueryEngine(tables)
    f = (("region", "==", "South East"),)
    g = (("region", "==", "South East"), ("sex", "!=", "X"))
    donor_set = eng.cohort_symdiff("bets", f, g, dataset_b="panel")
    contribution = eng.contribution_symdiff("bets", "stake_gbp", f, "panel", "stake_gbp", g)
    assert contribution < D.SessionAuditor().threshold <= donor_set, (contribution, donor_set)


def test_a_different_quantity_across_the_same_views_is_not_a_pair(nightplay):
    service, _, _ = nightplay
    a = D.SessionAuditor()
    r1 = _q(service, a, {"dataset": "bets", "measure": {"fn": "sum", "column": "stake_gbp"},
                         "group_by": [], "filters": [{"column": "region", "op": "==", "value": "London"}]})
    r2 = _q(service, a, {"dataset": "panel", "measure": {"fn": "sum", "column": "donation_gbp"},
                         "group_by": [], "filters": [{"column": "region", "op": "==", "value": "London"},
                                                     {"column": "sex", "op": "!=", "value": "X"}]})
    assert (r1.status, r2.status) == ("released", "released"), (r1.message, r2.message)


# ---------------------------------------------------------------- replay ----

def test_accounting_carries_the_quantity_and_a_restart_restores_it(demo, tmp_path):
    service, _ = demo
    log = AuditLog(str(tmp_path / "audit.db"))
    a = D.SessionAuditor()
    r1 = service.handle(json.dumps({"dataset": "donor_spend",
                                    "measure": {"fn": "sum", "column": "total_spend_gbp"},
                                    "group_by": [],
                                    "filters": [{"column": "region", "op": "==", "value": "North West"}]}),
                        planner=None, auditor=a, audit_log=log, user="u")
    assert r1.status == "released"
    rows = log.since(0)
    entry = rows[-1]["accounting"]["cohorts"][0]
    assert entry[0] == "donor_spend" and entry[2] == "spend_gbp"
    store = SessionStore(threshold=a.threshold, budget=a.budget)
    store.rehydrate(log, window_hours=24)
    restored = store.get("u").auditor
    assert restored._cohorts == [("donor_spend", a._cohorts[0][1], "spend_gbp")]
    r2 = service.handle(json.dumps({"dataset": "spend",
                                    "measure": {"fn": "sum", "column": "amount_gbp"},
                                    "group_by": [],
                                    "filters": [{"column": "region", "op": "==", "value": "North West"},
                                                {"column": "sex", "op": "!=", "value": "X"}]}),
                        planner=None, auditor=restored)
    assert r2.status == "denied"


def test_pre_95_two_element_cohort_rows_still_restore():
    a = D.SessionAuditor()
    a.record_cohort("spend", (("region", "==", "London"),))
    assert a._cohorts == [("spend", (("region", "==", "London"),), None)]
    findings = a.observe_cohort("donor_spend", (("region", "==", "London"), ("sex", "!=", "X")),
                                lambda *args, **kw: 0, quantity="spend_gbp")
    assert findings == []          # a quantity-less prior cohort is within-view only


def test_quantity_declarations_are_validated():
    base = {"name": "t", "person_key": "pid",
            "tables": {"p": {"pid": "DI", "g": "QI"}, "e": {"pid": "DI", "v": "S", "w": "S"}},
            "columns": {"g": {"desc": "g", "domain": ["a", "b"]}, "v": {"desc": "v"}, "w": {"desc": "w"},
                        "tv": {"desc": "tv"}},
            "derived_roles": {"tv": "S"},
            "datasets": {
                "ev": {"base": "e", "joins": [{"table": "p", "key": "pid"}],
                       "columns": ["p.g", "e.v", "e.w"], "dims": {"g": "cat"}, "measures": ["v", "w"]},
                "roll": {"base": "p", "joins": [{"table": "e", "key": "pid", "how": "left"}],
                         "group_by": ["p.pid", "p.g"],
                         "columns": ["p.g", {"name": "tv", "sum_if": {"column": "e.v", "when": "p.g", "in": ["a", "b"]}}],
                         "dims": {"g": "cat"}, "measures": ["tv"]}}}
    ok = DatasetDefinition.model_validate(dict(base, quantities={"q": ["ev.v", "roll.tv"]}))
    assert ok.quantity_of("ev", "v") == "q" and ok.quantity_columns("q") == {"ev": "v", "roll": "tv"}
    assert ok.population_of("ev") == "pid"
    for bad in ({"q": ["ev.v"]},                       # one member
                {"q": ["ev.v", "ev.w"]},               # same view twice
                {"q": ["ev.v", "roll.nope"]},          # not a measure
                {"q": ["ev.v", "zzz.tv"]},             # unknown view
                {"q": ["ev.v", "roll.tv"], "r": ["ev.v", "roll.tv"]}):   # a measure in two quantities
        with pytest.raises(ValueError):
            DatasetDefinition.model_validate(dict(base, quantities=bad))
