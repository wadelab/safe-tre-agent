"""The red-team oracle has to be able to fail.

The oracle this replaces could not. `leak_detector` on a finalized frame has
nothing left to test — the dominance, influence and donor-count columns are
dropped and the counts rounded before release — so the suite's verdict rested
on "at least one control fired", which the attacker supplies with a decoy.

An oracle is a measuring instrument, and an instrument nobody calibrates
reports whatever you hoped. These tests calibrate it in both directions: it
must stay silent on a correct system, and it must speak up when a control is
removed. The negative direction is the one that matters, because a silent
oracle and a safe system look identical from the outside.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "redteam"))

from fixtures import adversarial                          # noqa: E402
from oracle import SessionOracle                          # noqa: E402

from safetre import synth                                 # noqa: E402
from safetre.disclosure import DisclosurePolicy, SessionAuditor  # noqa: E402
from safetre.service import QueryService                  # noqa: E402

OVERGRANULAR = {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
                "group_by": ["age_band", "region", "device_os"]}
DIFFERENCING_PAIR = [
    {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
     "filters": [{"column": "age_rating", "op": ">=", "value": rating},
                 {"column": "region", "op": "==", "value": "South West"},
                 {"column": "sex", "op": "==", "value": "F"}]}
    for rating in (7, 8)
]


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


def _run(tables, specs, policy=None, auditor=None):
    """Replay a session and return what the oracle saw."""
    service = QueryService(tables, policy or DisclosurePolicy())
    auditor = auditor or SessionAuditor(budget=999)
    oracle = SessionOracle(tables)
    for step, spec in enumerate(specs, 1):
        result = service.handle(json.dumps(spec), planner=None,
                                auditor=auditor, audit_log=None)
        if result.status in ("released", "redacted"):
            oracle.observe(step, result.spec, result.output)
    return oracle.findings()


# --- it must stay silent on a correct system ------------------------------------

def test_no_leak_on_an_intact_gateway(tables):
    assert _run(tables, [OVERGRANULAR]) == []


def test_no_leak_on_ordinary_analysis(tables):
    session = [
        {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
         "group_by": ["age_band"]},
        {"dataset": "spend", "measure": {"fn": "count"}, "group_by": ["region"]},
        {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "pgsi_score"},
         "group_by": ["age_band"]},
        {"dataset": "donor_spend", "measure": {"fn": "corr",
                                               "x": "age_years",
                                               "y": "total_spend_gbp"},
         "group_by": ["age_band"]},
    ]
    assert _run(tables, session) == []


def test_no_leak_on_hostile_data():
    """The gateway must hold on negative, non-finite, NULL and undeclared
    values — and the oracle must not invent leaks because the data are ugly."""
    hostile = adversarial()
    session = [
        {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
         "group_by": ["region"]},
        {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
         "group_by": ["region"]},
        {"dataset": "donor_spend", "measure": {"fn": "count"},
         "group_by": ["income_band"]},
    ]
    assert _run(hostile, session) == []


# --- it must speak up when a control is removed ---------------------------------

def test_a_weakened_threshold_is_detected(tables):
    """The calibration test. With the donor threshold at 1 the same query
    releases cells describing a handful of people, and the oracle must say so
    — from the raw data, since the released frame no longer carries the counts
    that would betray it."""
    # `max_rows` is raised so this isolates the control under test: at
    # threshold=1 the cross-tab releases enough cells to trip the granularity
    # bound as well, which escalates to a human checker and releases nothing —
    # correct behaviour, but it would leave the oracle with no output to judge.
    wide_open = DisclosurePolicy(threshold=1, dom_threshold=1.0, max_rows=10_000)
    leaks = _run(tables, [OVERGRANULAR], policy=wide_open)
    undersized = [x for x in leaks if x.kind == "undersized_cell"]
    assert undersized, "a threshold of 1 released sub-threshold cells unnoticed"
    assert all(step == (1,) for step in (x.steps for x in undersized))


def test_a_weakened_dominance_bound_is_detected(tables):
    wide_open = DisclosurePolicy(threshold=10, dom_threshold=1.0)
    session = [{"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
                "group_by": ["region"]}]
    assert any(x.kind == "dominated_cell" for x in _run(tables, session,
                                                        policy=wide_open))


def test_a_disabled_differencing_auditor_is_detected(tables):
    """The attack the old harness passed. Neither released frame is disclosive
    on its own; only their difference is, so only a compositional oracle sees
    it."""
    class NoLineage(SessionAuditor):
        def observe(self, *args, **kwargs):
            return []

        def observe_cohort(self, *args, **kwargs):
            return []

    leaks = _run(tables, DIFFERENCING_PAIR, auditor=NoLineage(budget=999))
    composed = [x for x in leaks if x.kind == "composable_difference"]
    assert composed, "a differencing pair released with no control and no finding"
    assert composed[0].steps == (1, 2)


def test_the_oracle_sees_every_step_not_only_the_last(tables):
    """An attack that succeeds at step 1 and then issues innocent queries used
    to read as a pass, because only the final frame was inspected."""
    class NoLineage(SessionAuditor):
        def observe(self, *args, **kwargs):
            return []

        def observe_cohort(self, *args, **kwargs):
            return []

    innocent = {"dataset": "spend", "measure": {"fn": "count"},
                "group_by": ["age_band"]}
    leaks = _run(tables, [*DIFFERENCING_PAIR, innocent, innocent],
                 auditor=NoLineage(budget=999))
    assert any(x.kind == "composable_difference" for x in leaks)


def test_a_decoy_control_cannot_manufacture_a_pass(tables):
    """The old verdict was `(nothing in the final frame) and (a control fired)`.
    Appending an over-granular query supplies the second half for free, so the
    session below reported PASS while having recovered a donor's spend. The
    verdict is now the oracle's findings alone."""
    class NoLineage(SessionAuditor):
        def observe(self, *args, **kwargs):
            return []

        def observe_cohort(self, *args, **kwargs):
            return []

    leaks = _run(tables, [*DIFFERENCING_PAIR, OVERGRANULAR],
                 auditor=NoLineage(budget=999))
    assert any(x.kind == "composable_difference" for x in leaks)


# --- egress, which no amount of aggregation excuses -----------------------------

def test_an_identifier_column_in_a_released_frame_is_a_leak(tables):
    import pandas as pd

    oracle = SessionOracle(tables)
    oracle.observe(1, {"dataset": "spend"},
                   pd.DataFrame({"donor_id": ["D1"], "value": [1.0], "n": [50]}))
    assert any(x.kind == "identifier_egress" for x in oracle.findings())


def test_an_internal_variable_in_a_released_frame_is_a_leak(tables):
    import pandas as pd

    oracle = SessionOracle(tables)
    oracle.observe(1, {"dataset": "donor_spend"},
                   pd.DataFrame({"age_years": [41], "value": [1.0], "n": [50]}))
    assert any(x.kind == "internal_variable_egress" for x in oracle.findings())


def test_composition_reports_when_it_stops_looking(tables):
    """A bound that is applied silently reads as "nothing found"."""
    oracle = SessionOracle(tables)
    oracle.MAX_COMPOSED_CELLS = 2
    spec = {"dataset": "spend", "measure": {"fn": "count"}, "group_by": ["region"]}
    service = QueryService(tables)
    result = service.handle(json.dumps(spec), planner=None,
                            auditor=SessionAuditor(budget=999), audit_log=None)
    oracle.observe(1, result.spec, result.output)
    assert any(x.kind == "composition_not_exhausted" for x in oracle.findings())
