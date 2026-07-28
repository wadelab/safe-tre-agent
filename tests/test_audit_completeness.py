"""Every request produces exactly one audit record — even when the pipeline
raises (hardening #37).

Before the exception boundary, a planner failure, an engine error or a fit
that raised escaped `QueryService.handle` as an un-audited 500: a hole in the
tamper-evident record AND a data-dependent crash oracle. Now any exception is
recorded with status "error" and the exception TYPE only (a message may carry
data), and the caller receives the canonical withheld response, so a crash is
indistinguishable from a data-derived denial.
"""

from __future__ import annotations

import json

import pytest

from safetre import synth
from safetre.audit import AuditLog
from safetre.service import WITHHELD_MESSAGE, QueryService


class RaisingPlanner:
    def plan(self, request):
        raise RuntimeError("model endpoint exploded with secret context")


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


def _records(log):
    return log.con.execute(
        "SELECT user, request, spec, status, findings, output_shape"
        " FROM records").fetchall()


def _assert_canonical_denial(r):
    assert r.status == "denied"
    assert r.message == WITHHELD_MESSAGE
    assert r.output is None and r.artifacts is None
    assert [f.rule for f in r.findings] == ["nothing_released"]


def test_planner_exception_is_audited_and_canonical(tmp_path, tables):
    log = AuditLog(str(tmp_path / "audit.db"), key=b"k")
    svc = QueryService(tables)
    r = svc.handle("mean spend by age band", RaisingPlanner(),
                   audit_log=log, user="eve")
    _assert_canonical_denial(r)
    rows = _records(log)
    assert len(rows) == 1                          # exactly one audit record
    user, request, spec, status, findings, shape = rows[0]
    assert user == "eve" and request == "mean spend by age band"
    assert status == "error"                       # distinguishable in the LOG
    assert "pipeline_error" in findings
    assert "RuntimeError" in findings              # the exception TYPE is kept
    assert "secret context" not in findings        # the message never is
    assert json.loads(shape) is None


def test_engine_exception_is_audited_and_canonical(tmp_path, tables, monkeypatch):
    log = AuditLog(str(tmp_path / "audit.db"), key=b"k")
    svc = QueryService(tables)

    def boom(spec):
        raise ValueError("engine died on a value it should not repeat 12345")

    monkeypatch.setattr(svc.engine, "run", boom)
    r = svc.handle('{"dataset": "spend", "measure": {"fn": "count"}}',
                   None, audit_log=log, user="eve")
    _assert_canonical_denial(r)
    rows = _records(log)
    assert len(rows) == 1
    assert rows[0][3] == "error"
    assert "pipeline_error" in rows[0][4] and "ValueError" in rows[0][4]
    assert "12345" not in rows[0][4]


def test_model_fit_exception_is_audited_and_canonical(tmp_path, tables, monkeypatch):
    log = AuditLog(str(tmp_path / "audit.db"), key=b"k")
    svc = QueryService(tables)

    from safetre.procedures import model_registry
    glm = model_registry()["glm"]
    monkeypatch.setattr(glm, "fit",
                        lambda *a, **k: (_ for _ in ()).throw(
                            ZeroDivisionError("fit blew up on 67890")))
    spec = json.dumps({"tool": "glm", "dataset": "donor_spend", "family": "gaussian",
                       "response": "total_spend_gbp", "terms": ["age_band"]})
    r = svc.handle(spec, None, audit_log=log, user="eve")
    _assert_canonical_denial(r)
    rows = _records(log)
    assert len(rows) == 1
    assert rows[0][3] == "error"
    assert "67890" not in rows[0][4]


def test_handled_refusals_still_record_exactly_once(tmp_path, tables):
    """The boundary must not double-count: ordinary denials were audited
    before #36 and must still produce exactly one record each."""
    log = AuditLog(str(tmp_path / "audit.db"), key=b"k")
    svc = QueryService(tables)
    for q in ['{"dataset": "wellbeing", "measure": {"fn": "count"}, "group_by": ["free_text"]}',
              "summarise the free-text comments",
              '{"dataset": "spend", "measure": {"fn": "count"}}']:
        svc.handle(q, None, audit_log=log, user="eve")
    assert len(_records(log)) == 3
