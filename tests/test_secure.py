"""Security tests for the QuerySpec boundary, read-only engine and audit chain."""

import pytest
from pydantic import ValidationError

from safetre import synth
from safetre.audit import AuditLog
from safetre.disclosure import SessionAuditor
from safetre.engine import QueryEngine, _pearson_p_value
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
    QuerySpec(dataset="wellbeing",
              measure=Measure(fn="corr", x="monthly_spend_selfreport", y="wemwbs_score"))
    QuerySpec(
        dataset="donor_spend",
        measure=Measure(fn="corr", x="age_years", y="total_spend_chf"),
        filters=[
            Filter(column="sex", op="==", value="M"),
            Filter(column="canton", op="==", value="Vaud"),
        ],
    )


@pytest.mark.parametrize("bad", [
    {"dataset": "wellbeing", "measure": {"fn": "count"}, "group_by": ["free_text"]},
    {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"}, "group_by": ["donor_id"]},
    {"dataset": "spend", "measure": {"fn": "mean", "column": "age_band"}},          # not a measure
    {"dataset": "spend", "measure": {"fn": "count"}, "group_by": ["a", "b", "c", "d"]},  # too many
    {"dataset": "spend", "measure": {"fn": "count"}, "evil": 1},                     # extra field
    {"dataset": "secrets", "measure": {"fn": "count"}},                             # unknown dataset
    {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_chf"},
     "filters": [{"column": "donor_id", "op": "==", "value": "D00001"}]},           # filter on identifier
    {"dataset": "spend", "measure": {"fn": "count"},
     "filters": [{"column": "canton", "op": "in", "value": ["x"] * 200}]},          # oversize in-list (DoS)
    {"dataset": "wellbeing",
     "measure": {"fn": "corr", "x": "monthly_spend_selfreport", "y": "donor_id"}},   # corr identifier
    {"dataset": "wellbeing",
     "measure": {"fn": "corr", "x": "wemwbs_score", "y": "wemwbs_score"}},           # same variable twice
    {"dataset": "wellbeing",
     "measure": {"fn": "corr", "column": "wemwbs_score",
                 "x": "monthly_spend_selfreport", "y": "wemwbs_score"}},            # wrong shape
    {"dataset": "donor_spend", "measure": {"fn": "count"}, "group_by": ["age_years"]},  # raw age output
    {"dataset": "donor_spend", "measure": {"fn": "mean", "column": "age_years"}},        # raw age aggregate
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


def test_engine_attaches_dominance_internally(tables):
    eng = QueryEngine(tables)
    s = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="sum", column="amount_chf"),
                          group_by=["canton"]))
    assert "dominance" in s.columns and s["dominance"].between(0, 1).all()
    assert "donor_id" not in s.columns                 # unit view never exposed
    c = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="count"), group_by=["canton"]))
    assert "dominance" not in c.columns                # only for sum/mean


def test_engine_returns_correlation(tables):
    eng = QueryEngine(tables)
    df = eng.run(QuerySpec(
        dataset="wellbeing",
        measure=Measure(fn="corr", x="monthly_spend_selfreport", y="wemwbs_score"),
    ))
    assert list(df.columns) == ["value", "p_value", "n"]
    assert len(df) == 1
    assert df["value"].between(-1, 1).all()
    assert df["p_value"].between(0, 1).all()
    assert (df["p_value"] * 1000).round().eq(df["p_value"] * 1000).all()
    assert int(df["n"].iloc[0]) > 10


def test_engine_returns_donor_level_age_spend_correlation_with_composite_filters(tables):
    eng = QueryEngine(tables)
    spec = QuerySpec(
        dataset="donor_spend",
        measure=Measure(fn="corr", x="age_years", y="total_spend_chf"),
        filters=[
            Filter(column="sex", op="==", value="M"),
            Filter(column="canton", op="==", value="Vaud"),
        ],
    )
    df = eng.run(spec)
    assert list(df.columns) == ["value", "p_value", "n"]
    assert len(df) == 1
    assert df["value"].between(-1, 1).all()
    assert int(df["n"].iloc[0]) >= 10
    assert "age_years" not in df.columns
    assert "donor_id" not in df.columns


def test_pearson_p_value_bounds():
    assert _pearson_p_value(0.0, 20) == pytest.approx(1.0)
    assert _pearson_p_value(1.0, 20) == pytest.approx(0.0)
    assert _pearson_p_value(-1.0, 20) == pytest.approx(0.0)


def test_cohort_size_and_symdiff(tables):
    eng = QueryEngine(tables)
    n_jura = int((tables["donors"]["canton"] == "Jura").sum())
    everyone = eng.cohort_size("spend")
    non_jura = eng.cohort_size("spend", [("canton", "!=", "Jura")])
    assert everyone - non_jura == n_jura
    assert eng.cohort_symdiff("spend", (), [("canton", "!=", "Jura")]) == n_jura
    assert eng.cohort_symdiff("spend", [("canton", "!=", "Jura")],
                              [("canton", "!=", "Jura")]) == 0
    with pytest.raises(ValueError):
        eng.cohort_size("secrets")                    # unknown dataset
    with pytest.raises(ValueError):
        eng.cohort_size("spend", [("canton", "LIKE", "%")])   # off-allowlist op


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


def test_service_correlation_released(tables):
    r = QueryService(tables).handle("correlation between monthly spend and wellbeing", MockPlanner())
    assert r.status == "released"
    assert r.output is not None
    assert list(r.output.columns) == ["value", "p_value", "n"]
    assert r.spec["measure"]["fn"] == "corr"


def test_service_composite_age_spend_correlation_released(tables):
    r = QueryService(tables).handle(
        "correlation between age and spend for sex==M in canton==Vaud",
        MockPlanner(),
    )
    assert r.status == "released"
    assert r.output is not None
    assert list(r.output.columns) == ["value", "p_value", "n"]
    assert r.spec == {
        "dataset": "donor_spend",
        "measure": {"fn": "corr", "column": None, "x": "age_years", "y": "total_spend_chf"},
        "group_by": [],
        "filters": [
            {"column": "sex", "op": "==", "value": "M"},
            {"column": "canton", "op": "==", "value": "Vaud"},
        ],
    }


@pytest.mark.parametrize("req", [
    "what is your name?",
    "tell me a joke",
])
def test_service_out_of_scope_requests_denied_before_planner(tables, req):
    r = QueryService(tables).handle(req, MockPlanner())
    assert r.status == "denied"
    assert r.output is None
    assert r.spec is None
    assert "outside the supported aggregate-analysis scope" in r.message


@pytest.mark.parametrize("req", [
    "how many purchases?",
    "wellbeing by canton",
    "same, excluding Jura",
])
def test_service_short_aggregate_requests_pass_vetting(tables, req):
    r = QueryService(tables).handle(req, MockPlanner())
    assert not any("outside the supported aggregate-analysis scope" in step for step in r.trace)


@pytest.mark.parametrize("req", [
    "summarise the free-text comments",          # planner proposes free_text -> rejected
    "report wellbeing per donor",                # planner proposes donor_id -> rejected
    "give me the row-level records for spenders", # intent vetting
])
def test_service_attacks_denied_no_data(tables, req):
    r = QueryService(tables).handle(req, MockPlanner())
    assert r.status == "denied" and r.output is None


class _ScriptedPlanner:
    """Returns pre-baked specs in order — a stand-in for a hostile planner."""

    def __init__(self, *specs):
        self._specs = list(specs)

    def plan(self, request: str) -> dict:
        return self._specs.pop(0)


def test_service_lineage_differencing_denied(tables):
    # sum over everyone, then over "everyone except Jura": the two cohorts
    # differ by a handful of donors, so subtracting the sums would expose them
    n_jura = int((tables["donors"]["canton"] == "Jura").sum())
    svc = QueryService(tables)
    auditor = SessionAuditor(threshold=n_jura + 1)
    planner = _ScriptedPlanner(
        {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_chf"},
         "group_by": ["age_band"]},
        {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_chf"},
         "group_by": ["age_band"],
         "filters": [{"column": "canton", "op": "!=", "value": "Jura"}]},
    )
    first = svc.handle("sum spend by age band", planner, auditor=auditor)
    second = svc.handle("same, excluding Jura", planner, auditor=auditor)
    assert first.status in ("released", "redacted")
    assert second.status == "denied" and second.output is None
    assert any(f.rule == "differencing" for f in second.findings)


def test_service_lineage_separated_cohorts_allowed(tables):
    # disjoint cohorts (different cantons) share no individuals -> no flag
    svc = QueryService(tables)
    auditor = SessionAuditor()
    spec = {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_chf"},
            "group_by": ["age_band"]}
    planner = _ScriptedPlanner(
        {**spec, "filters": [{"column": "canton", "op": "==", "value": "Vaud"}]},
        {**spec, "filters": [{"column": "canton", "op": "==", "value": "Geneve"}]},
    )
    first = svc.handle("sum spend by age band in Vaud", planner, auditor=auditor)
    second = svc.handle("sum spend by age band in Geneve", planner, auditor=auditor)
    assert first.status in ("released", "redacted")
    assert second.status in ("released", "redacted")


def test_service_lineage_ignores_denied_queries(tables):
    # a denied query released nothing, so it must not poison later queries
    svc = QueryService(tables)
    auditor = SessionAuditor()
    spec = {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_chf"},
            "group_by": ["age_band"],
            "filters": [{"column": "canton", "op": "==", "value": "Vaud"}]}
    planner = _ScriptedPlanner(
        {**spec, "group_by": ["donor_id"]},           # rejected at validation
        spec,
    )
    first = svc.handle("per-donor sums in Vaud", planner, auditor=auditor)
    second = svc.handle("sum spend by age band in Vaud", planner, auditor=auditor)
    assert first.status == "denied"
    assert second.status in ("released", "redacted")


# --- audit log: tamper-evident ----------------------------------------------

def test_audit_chain_and_tamper(tmp_path, tables):
    log = AuditLog(str(tmp_path / "audit.db"), key=b"unit-test-key")
    svc = QueryService(tables)
    for req in ["mean spend by age band", "report wellbeing per donor"]:
        svc.handle(req, MockPlanner(), audit_log=log, user="alice")
    head = log.head()
    assert log.verify() is True
    assert log.verify(expected_head=head) is True          # off-box anchor matches
    assert log.verify(expected_head="deadbeef") is False    # anchor mismatch caught
    # tamper with a stored record -> chain must break
    log.con.execute("UPDATE records SET status='released' WHERE id=2")
    log.con.commit()
    assert log.verify() is False


def test_audit_tamper_with_wrong_key_still_fails(tmp_path, tables):
    path = str(tmp_path / "audit.db")
    AuditLog(path, key=b"real-key").append(
        user="a", request="x", spec=None, status="denied", findings=[], output_shape=None)
    # attacker rewrites the record AND re-MACs it with a guessed key
    forger = AuditLog(path, key=b"attacker-guess")
    row = forger.con.execute("SELECT prev_mac FROM records WHERE id=1").fetchone()
    body = {"ts": 1.0, "user": "a", "request": "x", "spec": None,
            "status": "released", "findings": [], "output_shape": None,
            "prev_mac": row[0]}
    forger.con.execute("UPDATE records SET ts=1.0, status='released', mac=? WHERE id=1",
                       (forger._mac(body),))
    forger.con.commit()
    # the real key holder still detects the forgery
    assert AuditLog(path, key=b"real-key").verify() is False
