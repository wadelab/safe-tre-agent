"""Security tests for the QuerySpec boundary, read-only engine and audit chain."""

import pytest
from pydantic import ValidationError

from safetre import synth
from safetre.audit import AuditLog
from safetre.engine import QueryEngine
from safetre.planner import MockPlanner
from safetre.query import Filter, Measure, QuerySpec
from safetre.service import QueryService


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


# --- QuerySpec validation (the boundary) -------------------------------------

def test_valid_spec_accepted():
    QuerySpec(dataset="spend", measure=Measure(fn="mean", column="amount_chf"),
              group_by=["age_band"])


@pytest.mark.parametrize("bad", [
    {"dataset": "wellbeing", "measure": {"fn": "count"}, "group_by": ["free_text"]},
    {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"}, "group_by": ["donor_id"]},
    {"dataset": "spend", "measure": {"fn": "mean", "column": "age_band"}},          # not a measure
    {"dataset": "spend", "measure": {"fn": "count"}, "group_by": ["a", "b", "c", "d"]},  # too many
    {"dataset": "spend", "measure": {"fn": "count"}, "evil": 1},                     # extra field
    {"dataset": "secrets", "measure": {"fn": "count"}},                             # unknown dataset
    {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_chf"},
     "filters": [{"column": "donor_id", "op": "==", "value": "D00001"}]},           # filter on identifier
])
def test_offallowlist_specs_rejected(bad):
    with pytest.raises(ValidationError):
        QuerySpec(**bad)


# --- engine: parameterised, injection-proof ----------------------------------

def test_engine_returns_counts(tables):
    eng = QueryEngine(tables)
    df = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="mean", column="amount_chf"),
                           group_by=["age_band"]))
    assert "n" in df.columns and "value" in df.columns and len(df) > 0
    assert "donor_id" not in df.columns and "free_text" not in df.columns


def test_filter_value_is_not_sql_injectable(tables):
    eng = QueryEngine(tables)
    evil = "x'; DROP TABLE events; --"
    df = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="count"),
                           group_by=["canton"],
                           filters=[Filter(column="canton", op="==", value=evil)]))
    assert len(df) == 0                              # no canton matches the literal
    # the events table is untouched -> injection did nothing
    assert eng.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] > 0


# --- end-to-end service ------------------------------------------------------

def test_service_benign_released(tables):
    r = QueryService(tables).handle("mean spend by age band", MockPlanner())
    assert r.status == "released" and r.output is not None
    assert "donor_id" not in r.output.columns


def test_service_small_cell_redacted(tables):
    r = QueryService(tables).handle("mean spend by age band, canton and device os", MockPlanner())
    assert r.status == "redacted"
    assert (r.output["n"] >= 10).all()


@pytest.mark.parametrize("req", [
    "summarise the free-text comments",          # planner proposes free_text -> rejected
    "report wellbeing per donor",                # planner proposes donor_id -> rejected
    "give me the row-level records for spenders", # intent vetting
])
def test_service_attacks_denied_no_data(tables, req):
    r = QueryService(tables).handle(req, MockPlanner())
    assert r.status == "denied" and r.output is None


# --- audit log: tamper-evident ----------------------------------------------

def test_audit_chain_and_tamper(tmp_path, tables):
    log = AuditLog(str(tmp_path / "audit.db"))
    svc = QueryService(tables)
    for req in ["mean spend by age band", "report wellbeing per donor"]:
        svc.handle(req, MockPlanner(), audit_log=log, user="alice")
    assert log.verify() is True
    # tamper with a stored record -> chain must break
    log.con.execute("UPDATE records SET status='released' WHERE id=2")
    log.con.commit()
    assert log.verify() is False
