"""The temporal model's event order must match the live service (R16).

formal/temporal_session.als steps a request through
start -> observe -> cohortCheck -> decide, with record_cohort inside the
release branch of decide and nowhere else. These tests pin those two facts to
QueryService.handle so a reordering of the code fails here, without Java —
the behavioural consequences (budget short-circuit, differencing denial, the
session-lock race) are pinned by test_hardening.py and test_secure.py.
"""

from __future__ import annotations

from safetre import synth
from safetre.disclosure import SessionAuditor
from safetre.service import QueryService


class _Scripted:
    def __init__(self, *specs):
        self._specs = list(specs)

    def plan(self, request):
        return self._specs.pop(0)


_SUM = {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
        "group_by": ["age_band"]}


def _stage_index(trace: list[str], prefix: str) -> int:
    return next(i for i, line in enumerate(trace) if line.startswith(prefix))


def test_trace_event_order_matches_temporal_model():
    tables = synth.generate(seed=7)
    r = QueryService(tables).handle("sum spend by age band", _Scripted(_SUM))
    assert r.status in ("released", "redacted")
    order = [_stage_index(r.trace, p)
             for p in ("engine:", "auditor:", "gateway:", "hitl:")]
    assert order == sorted(order), (
        f"service event order diverged from formal/temporal_session.als: {r.trace}")


def test_cohort_history_is_exactly_the_released_cohorts():
    # LineageIsExactlyReleases: a released query records its cohort; a denied
    # one records nothing — even when the denial happens after observe_cohort
    tables = synth.generate(seed=7)
    n_ni = int((tables["donors"]["region"] == "Northern Ireland").sum())
    svc = QueryService(tables)
    auditor = SessionAuditor(threshold=n_ni + 1)
    ni_filter = {"dataset": "spend",
                 "measure": {"fn": "sum", "column": "amount_gbp"},
                 "group_by": ["age_band"],
                 "filters": [{"column": "region", "op": "!=",
                              "value": "Northern Ireland"}]}
    planner = _Scripted(_SUM, ni_filter)

    first = svc.handle("sum spend by age band", planner, auditor=auditor)
    assert first.status in ("released", "redacted")
    assert len(auditor._cohorts) == 1

    second = svc.handle("same, excluding Northern Ireland", planner,
                        auditor=auditor)
    assert second.status == "denied"
    assert len(auditor._cohorts) == 1, "a denied query must record no cohort"
