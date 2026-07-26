"""Security tests for the QuerySpec boundary, read-only engine and audit chain."""

import pandas as pd
import pytest
from pydantic import ValidationError

from safetre import synth
from safetre.audit import AuditLog
from safetre.disclosure import DisclosurePolicy, SessionAuditor
from safetre.engine import QueryEngine
from safetre.stats import pearson_p_value
from safetre.planner import MockPlanner
from safetre.query import Filter, Measure, QuerySpec
from safetre.service import QueryService


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


# --- QuerySpec validation (the boundary) -------------------------------------

def test_valid_spec_accepted():
    QuerySpec(dataset="spend", measure=Measure(fn="mean", column="amount_gbp"),
              group_by=["age_band"])
    QuerySpec(dataset="wellbeing",
              measure=Measure(fn="corr", x="monthly_spend_selfreport", y="wemwbs_score"))
    QuerySpec(
        dataset="donor_spend",
        measure=Measure(fn="corr", x="age_years", y="total_spend_gbp"),
        filters=[
            Filter(column="sex", op="==", value="M"),
            Filter(column="region", op="==", value="London"),
        ],
    )


@pytest.mark.parametrize("bad", [
    {"dataset": "wellbeing", "measure": {"fn": "count"}, "group_by": ["free_text"]},
    {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"}, "group_by": ["donor_id"]},
    {"dataset": "spend", "measure": {"fn": "mean", "column": "age_band"}},          # not a measure
    {"dataset": "spend", "measure": {"fn": "count"}, "group_by": ["a", "b", "c", "d"]},  # too many
    {"dataset": "spend", "measure": {"fn": "count"}, "evil": 1},                     # extra field
    {"dataset": "secrets", "measure": {"fn": "count"}},                             # unknown dataset
    {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
     "filters": [{"column": "donor_id", "op": "==", "value": "D00001"}]},           # filter on identifier
    {"dataset": "spend", "measure": {"fn": "count"},
     "filters": [{"column": "region", "op": "in", "value": ["x"] * 200}]},          # oversize in-list (DoS)
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
    df = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="mean", column="amount_gbp"),
                           group_by=["age_band"]))
    assert "n" in df.columns and "value" in df.columns and len(df) > 0
    assert "donor_id" not in df.columns and "free_text" not in df.columns


def test_engine_attaches_dominance_internally(tables):
    eng = QueryEngine(tables)
    s = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="sum", column="amount_gbp"),
                          group_by=["region"]))
    assert "dominance" in s.columns and s["dominance"].between(0, 1).all()
    assert "donor_id" not in s.columns                 # unit view never exposed
    c = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="count"), group_by=["region"]))
    assert "dominance" not in c.columns                # only for sum/mean


def test_engine_returns_correlation(tables):
    eng = QueryEngine(tables)
    df = eng.run(QuerySpec(
        dataset="wellbeing",
        measure=Measure(fn="corr", x="monthly_spend_selfreport", y="wemwbs_score"),
    ))
    # influence and n_donors are internal helpers (like dominance): present in
    # engine output, dropped by the gateway before release. p_value is NOT here:
    # it is derived post-finalize from the rounded n (hardening #26)
    assert list(df.columns) == ["value", "n", "influence", "n_donors"]
    assert len(df) == 1
    assert df["value"].between(-1, 1).all()
    assert int(df["n"].iloc[0]) > 10
    assert df["influence"].ge(0).all()          # max single-donor |Δr|, non-negative


def test_engine_returns_donor_level_age_spend_correlation_with_composite_filters(tables):
    eng = QueryEngine(tables)
    spec = QuerySpec(
        dataset="donor_spend",
        measure=Measure(fn="corr", x="age_years", y="total_spend_gbp"),
        filters=[
            Filter(column="sex", op="==", value="M"),
            Filter(column="region", op="==", value="London"),
        ],
    )
    df = eng.run(spec)
    assert list(df.columns) == ["value", "n", "influence", "n_donors"]
    assert len(df) == 1
    assert df["value"].between(-1, 1).all()
    assert int(df["n"].iloc[0]) >= 10
    assert "age_years" not in df.columns
    assert "donor_id" not in df.columns


def test_corr_influence_detects_dominating_donor(tables):
    # whole-population corr: no single donor can move r much -> low influence.
    # a group with a planted high-leverage donor -> influence must be large.
    # (regression guard: the leave-one-out SQL must not alias per-donor and
    # group sums, or influence collapses to 0/NaN and the control is disabled.)
    eng = QueryEngine(tables)
    spec = QuerySpec(dataset="donor_spend",
                     measure=Measure(fn="corr", x="age_years", y="total_spend_gbp"))
    whole = eng.run(spec)
    assert float(whole["influence"].iloc[0]) < 0.5     # 500 donors: no single one dominates

    t2 = {k: v.copy() for k, v in tables.items()}
    d, e = t2["donors"], t2["events"]
    whale = "DWHALECORR"
    d.loc[len(d)] = {"donor_id": whale, "enrolment_date": d["enrolment_date"].iloc[0],
                     "age_years": 69, "age_band": "50+", "sex": "M", "region": "Northern Ireland",
                     "income_band": ">150k", "device_os": "iOS"}
    e2 = pd.DataFrame([{**e.iloc[0].to_dict(), "event_id": f"EWC{i}", "donor_id": whale,
                        "event_type": "purchase", "amount_gbp": 250000.0} for i in range(4)])
    t2["events"] = pd.concat([e, e2], ignore_index=True)
    small = QueryEngine(t2).run(QuerySpec(
        dataset="donor_spend",
        measure=Measure(fn="corr", x="age_years", y="total_spend_gbp"),
        filters=[Filter(column="region", op="==", value="Northern Ireland"),
                 Filter(column="sex", op="==", value="M")]))
    assert float(small["influence"].iloc[0]) > 0.5     # the whale dominates the correlation


def test_engine_attaches_distinct_donor_count(tables):
    # the frequency threshold must count individuals, not rows. On an
    # event-level dataset rows exceed donors; on the per-donor view they match.
    eng = QueryEngine(tables)
    ev = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="count"), group_by=["region"]))
    assert "n_donors" in ev.columns
    assert (ev["n"] >= ev["n_donors"]).all()            # rows >= distinct donors
    assert (ev["n"] > ev["n_donors"]).any()             # event-level: strictly more rows somewhere
    per_donor = eng.run(QuerySpec(dataset="donor_spend", measure=Measure(fn="count"),
                                  group_by=["region"]))
    assert (per_donor["n"] == per_donor["n_donors"]).all()   # one row per donor
    released, _, _ = DisclosurePolicy().apply(ev)
    assert "n_donors" not in released.columns           # helper dropped before release


def test_service_suppresses_cell_with_many_rows_but_few_donors(tables):
    # one hyperactive donor gives a cell >=10 rows but <10 donors: the old
    # row-count rule would release it; the donor-count rule must suppress it.
    t2 = {k: v.copy() for k, v in tables.items()}
    d, e = t2["donors"], t2["events"]
    heavy = "DHEAVYROWS"
    d.loc[len(d)] = {"donor_id": heavy, "enrolment_date": d["enrolment_date"].iloc[0],
                     "age_years": 16, "age_band": "16-17", "sex": "X", "region": "Northern Ireland",
                     "income_band": ">150k", "device_os": "iOS"}
    e2 = pd.DataFrame([{**e.iloc[0].to_dict(), "event_id": f"EHR{i}", "donor_id": heavy,
                        "event_type": "purchase", "amount_gbp": 5.0} for i in range(14)])
    t2["events"] = pd.concat([e, e2], ignore_index=True)

    class Fixed:
        def plan(self, request):
            return {"dataset": "spend", "measure": {"fn": "count"},
                    "group_by": ["device_os"],
                    "filters": [{"column": "region", "op": "==", "value": "Northern Ireland"},
                                {"column": "age_band", "op": "==", "value": "16-17"}]}

    r = QueryService(t2).handle("count events by device for young Northern Ireland players", Fixed())
    ios = r.output[r.output["device_os"] == "iOS"] if r.output is not None else None
    # the iOS cell has ~14 rows (>=10) but only ~1 donor -> must not be released
    assert ios is None or len(ios) == 0


def test_pearson_p_value_bounds():
    assert pearson_p_value(0.0, 20) == pytest.approx(1.0)
    assert pearson_p_value(1.0, 20) == pytest.approx(0.0)
    assert pearson_p_value(-1.0, 20) == pytest.approx(0.0)


def test_cohort_size_and_symdiff(tables):
    eng = QueryEngine(tables)
    n_ni = int((tables["donors"]["region"] == "Northern Ireland").sum())
    everyone = eng.cohort_size("spend")
    non_ni = eng.cohort_size("spend", [("region", "!=", "Northern Ireland")])
    assert everyone - non_ni == n_ni
    assert eng.cohort_symdiff("spend", (), [("region", "!=", "Northern Ireland")]) == n_ni
    assert eng.cohort_symdiff("spend", [("region", "!=", "Northern Ireland")],
                              [("region", "!=", "Northern Ireland")]) == 0
    with pytest.raises(ValueError):
        eng.cohort_size("secrets")                    # unknown dataset
    with pytest.raises(ValueError):
        eng.cohort_size("spend", [("region", "LIKE", "%")])   # off-allowlist op


def test_filter_value_is_not_sql_injectable(tables):
    eng = QueryEngine(tables)
    evil = "x'; DROP TABLE events; --"
    df = eng.run(QuerySpec(dataset="spend", measure=Measure(fn="count"),
                           group_by=["region"],
                           filters=[Filter(column="region", op="==", value=evil)]))
    assert len(df) == 0                              # no region matches the literal
    # the events table is untouched -> injection did nothing
    assert eng.con.execute("SELECT COUNT(*) FROM events").fetchone()[0] > 0


# --- end-to-end service ------------------------------------------------------

def test_service_benign_released(tables):
    r = QueryService(tables).handle("mean spend by age band", MockPlanner())
    assert r.status == "released" and r.output is not None
    assert "donor_id" not in r.output.columns


def test_service_small_cell_redacted(tables):
    r = QueryService(tables).handle("mean spend by age band, region and device os", MockPlanner())
    assert r.status == "redacted"
    assert (r.output["n"] >= 10).all()


def test_service_correlation_released(tables):
    r = QueryService(tables).handle("correlation between monthly spend and wellbeing", MockPlanner())
    assert r.status == "released"
    assert r.output is not None
    assert list(r.output.columns) == ["value", "p_value", "n"]
    assert r.spec["measure"]["fn"] == "corr"
    assert r.output["p_value"].between(0, 1).all()
    assert (r.output["p_value"] * 1000).round().eq(r.output["p_value"] * 1000).all()


def test_corr_p_value_is_function_of_released_numbers(tables):
    """Hardening #26: a released p_value must be recomputable, bit for bit,
    from the released (value, n) pair alone — i.e. derived from the FINALIZED
    (base-5 rounded) n, never the exact pre-rounding count."""
    svc = QueryService(tables)
    r = svc.handle("correlation between monthly spend and wellbeing", MockPlanner())
    assert r.status == "released"
    row = r.output.iloc[0]
    released_n = int(row["n"])
    assert released_n % 5 == 0                       # n is finalized
    assert row["p_value"] == round(pearson_p_value(float(row["value"]), released_n), 3)


def test_corr_p_value_never_computed_from_exact_count():
    """Hardening #26, the mismatch half, pinned deterministically: push a corr
    cell with an off-lattice exact count (n=13) through the real gateway
    pipeline and check the shaped p comes from the rounded n (15), not 13.
    r=0.5 is chosen so the two round differently at 3 decimals."""
    from safetre.procedures import get_procedure

    raw = pd.DataFrame({"value": [0.5], "n": [13], "influence": [0.01],
                        "n_donors": [13]})
    released, action, _ = DisclosurePolicy().apply(raw)
    assert action == "release"
    assert int(released["n"].iloc[0]) == 15
    spec = QuerySpec(dataset="wellbeing",
                     measure=Measure(fn="corr", x="monthly_spend_selfreport",
                                     y="wemwbs_score"))
    shaped = get_procedure("corr").postprocess(released, spec)
    p = float(shaped["p_value"].iloc[0])
    assert p == round(pearson_p_value(0.5, 15), 3)
    assert p != round(pearson_p_value(0.5, 13), 3)


def test_service_composite_age_spend_correlation_released(tables):
    r = QueryService(tables).handle(
        "correlation between age and spend for sex==M in region==London",
        MockPlanner(),
    )
    assert r.status == "released"
    assert r.output is not None
    assert list(r.output.columns) == ["value", "p_value", "n"]
    assert r.spec == {
        "dataset": "donor_spend",
        "measure": {"fn": "corr", "column": None, "x": "age_years", "y": "total_spend_gbp"},
        "group_by": [],
        "filters": [
            {"column": "sex", "op": "==", "value": "M"},
            {"column": "region", "op": "==", "value": "London"},
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
    "summarise the free-text comments",
    "summarise the survey comments",
    "summarize the open-ended qualitative responses",
])
def test_service_free_text_requests_denied_before_planner(tables, req):
    r = QueryService(tables).handle(req, MockPlanner())
    assert r.status == "denied"
    assert r.output is None
    assert r.spec is None
    assert any(f.rule == "intent_block" for f in r.findings)


@pytest.mark.parametrize("req", [
    "how many purchases?",
    "wellbeing by region",
    "same, excluding Northern Ireland",
])
def test_service_short_aggregate_requests_pass_vetting(tables, req):
    r = QueryService(tables).handle(req, MockPlanner())
    assert not any("outside the supported aggregate-analysis scope" in step for step in r.trace)


@pytest.mark.parametrize("req", [
    "summarise the free-text comments",
    "report wellbeing per donor",                # per-donor intent -> blocked at vetting
    "give me the row-level records for spenders", # intent vetting
])
def test_service_attacks_denied_no_data(tables, req):
    r = QueryService(tables).handle(req, MockPlanner())
    assert r.status == "denied" and r.output is None


@pytest.mark.parametrize("req", [
    "show mean wellbeing per donor by row",
    "mean wellbeing per donor",
    "wellbeing for each donor",
    "one row per participant",
    "spend per respondent",
])
def test_per_individual_intent_blocked_at_vetting(req):
    from safetre.analyst import vet_request
    ok, why = vet_request(req)
    assert not ok and "intent blocked" in why


class _SanitizingPlanner:
    """A capable planner that drops the disallowed per-donor dimension and
    'repairs' the request into a permitted overall aggregate — the silent
    downgrade an online model can perform where the mock proposed donor_id."""

    def plan(self, request):
        return {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"}}


def test_row_level_request_denied_not_silently_downgraded(tables):
    # the user asked for per-donor / row-level output. A planner that quietly
    # substitutes an overall mean must NOT produce a release: the deterministic
    # intent gate denies before the planner is ever consulted.
    r = QueryService(tables).handle("show mean wellbeing per donor by row",
                                    _SanitizingPlanner())
    assert r.status == "denied"
    assert r.output is None
    assert r.spec is None                              # never reached the planner
    assert any(f.rule == "intent_block" for f in r.findings)


class _FixedSpecPlanner:
    """A loose planner that always proposes one (validating) spec, standing in
    for a capable model that 'repairs' a request into a permitted-but-different
    query."""

    def __init__(self, spec):
        self._spec = spec

    def plan(self, request):
        return self._spec


def test_grouping_unsupported_breakdown_denied(tables):
    # 'lootbox' is not a wellbeing dimension. Asked to break wellbeing down by
    # it, a loose planner substitutes group_by=['age_band']; the fidelity gate
    # refuses rather than answer a different question.
    planner = _FixedSpecPlanner(
        {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"},
         "group_by": ["age_band"]})
    r = QueryService(tables).handle("show mean wellbeing per lootbox", planner)
    assert r.status == "denied" and r.output is None
    assert any(f.rule == "grouping_mismatch" for f in r.findings)
    assert "lootbox" in r.message.lower()


def test_grouping_substituted_dimension_denied(tables):
    # asked to break down by region; the planner grouped by age_band instead.
    planner = _FixedSpecPlanner(
        {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"},
         "group_by": ["age_band"]})
    r = QueryService(tables).handle("mean wellbeing by region", planner)
    assert r.status == "denied" and r.output is None
    assert any(f.rule == "grouping_mismatch" for f in r.findings)


def test_grouping_faithful_request_released(tables):
    # a request whose grouping matches the proposed spec is unaffected by the gate.
    r = QueryService(tables).handle("mean spend by age band", MockPlanner())
    assert r.status in ("released", "redacted")
    assert not any(f.rule == "grouping_mismatch" for f in r.findings)


def test_grouping_dropped_dimension_denied(tables):
    # asked to break down by region AND sex; the planner silently dropped sex.
    planner = _FixedSpecPlanner(
        {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"},
         "group_by": ["region"]})
    r = QueryService(tables).handle("mean wellbeing by region and sex", planner)
    assert r.status == "denied" and r.output is None
    assert any(f.rule == "grouping_mismatch" for f in r.findings)
    assert "sex" in r.message


def test_grouping_filter_terms_do_not_force_grouping(tables):
    # "for age over 40" is a filter, not a breakdown: grouping by region alone
    # must still be accepted (no false 'omitted age' denial).
    planner = _FixedSpecPlanner(
        {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"},
         "group_by": ["region"],
         "filters": [{"column": "age_years", "op": ">", "value": 40}]})
    r = QueryService(tables).handle("mean wellbeing by region for age over 40", planner)
    assert r.status in ("released", "redacted")
    assert not any(f.rule == "grouping_mismatch" for f in r.findings)


class _ScriptedPlanner:
    """Returns pre-baked specs in order — a stand-in for a hostile planner."""

    def __init__(self, *specs):
        self._specs = list(specs)

    def plan(self, request: str) -> dict:
        return self._specs.pop(0)


def test_simulatable_cohort_bound(tables):
    from safetre.disclosure import simulatable_cohort_bound
    marg = QueryEngine(tables).marginal_donor_counts()
    n_ni = int((tables["donors"]["region"] == "Northern Ireland").sum())

    # everyone vs everyone-except-Northern Ireland: differ on region by {Northern Ireland};
    # bound is the Northern Ireland donor marginal (a public number), not the live symdiff
    b = simulatable_cohort_bound(marg, "donor_spend", (), (("region", "!=", "Northern Ireland"),))
    assert b == n_ni

    # well-separated cohorts: bound is the sum of both regions' marginals (large)
    big = simulatable_cohort_bound(
        marg, "donor_spend", (("region", "==", "London"),), (("region", "==", "South East"),))
    assert big >= DisclosurePolicy.DEFAULT_THRESHOLD

    # differ on two dimensions -> the bound SUMS them. It used to return a
    # never-denying sentinel here, which let an attacker refused one rare
    # exclusion make two instead and walk through (red-team, 2026-07-26).
    two = simulatable_cohort_bound(
        marg, "donor_spend", (),
        (("region", "!=", "Northern Ireland"), ("sex", "==", "M")))
    n_not_m = sum(c for v, c in marg["donor_spend"]["sex"].items() if v != "M")
    assert two == n_ni + n_not_m

    # two rare exclusions, each individually denied, must not add up to an
    # allow: the summed bound stays under the threshold and still denies
    rare_sex = min((v for v in marg["donor_spend"]["sex"]
                    if 0 < marg["donor_spend"]["sex"][v] < 5),
                   key=lambda v: marg["donor_spend"]["sex"][v])
    rare_age = min((v for v, c in marg["donor_spend"]["age_years"].items() if c == 1),
                   default=None)
    assert rare_age is not None, "expected a singleton age in the fixture"
    combined = simulatable_cohort_bound(
        marg, "donor_spend", (),
        (("sex", "!=", rare_sex), ("age_years", "!=", rare_age)))
    assert combined == (marg["donor_spend"]["sex"][rare_sex]
                        + marg["donor_spend"]["age_years"][rare_age])
    assert combined < DisclosurePolicy.DEFAULT_THRESHOLD   # -> denied

    # the bound depends only on the marginals + predicates: recomputing with a
    # copy of the marginals gives the same answer (nothing from live data)
    assert simulatable_cohort_bound(dict(marg), "donor_spend", (),
                                    (("region", "!=", "Northern Ireland"),)) == b


def test_service_lineage_differencing_denied(tables):
    # sum over everyone, then over "everyone except Northern Ireland": the two cohorts
    # differ by a handful of donors, so subtracting the sums would expose them
    n_ni = int((tables["donors"]["region"] == "Northern Ireland").sum())
    svc = QueryService(tables)
    auditor = SessionAuditor(threshold=n_ni + 1)
    planner = _ScriptedPlanner(
        {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
         "group_by": ["age_band"]},
        {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
         "group_by": ["age_band"],
         "filters": [{"column": "region", "op": "!=", "value": "Northern Ireland"}]},
    )
    first = svc.handle("sum spend by age band", planner, auditor=auditor)
    second = svc.handle("same, excluding Northern Ireland", planner, auditor=auditor)
    assert first.status in ("released", "redacted")
    assert second.status == "denied" and second.output is None
    assert any(f.rule == "differencing" for f in second.findings)


def test_service_lineage_separated_cohorts_allowed(tables):
    # disjoint cohorts (different regions) share no individuals -> no flag
    svc = QueryService(tables)
    auditor = SessionAuditor()
    spec = {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
            "group_by": ["age_band"]}
    planner = _ScriptedPlanner(
        {**spec, "filters": [{"column": "region", "op": "==", "value": "London"}]},
        {**spec, "filters": [{"column": "region", "op": "==", "value": "South East"}]},
    )
    first = svc.handle("sum spend by age band in London", planner, auditor=auditor)
    second = svc.handle("sum spend by age band in South East", planner, auditor=auditor)
    assert first.status in ("released", "redacted")
    assert second.status in ("released", "redacted")


def test_service_lineage_ignores_denied_queries(tables):
    # a denied query released nothing, so it must not poison later queries
    svc = QueryService(tables)
    auditor = SessionAuditor()
    spec = {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
            "group_by": ["age_band"],
            "filters": [{"column": "region", "op": "==", "value": "London"}]}
    planner = _ScriptedPlanner(
        {**spec, "group_by": ["donor_id"]},           # rejected at validation
        spec,
    )
    # request text passes vetting; it is the proposed donor_id spec that is
    # denied at *validation* (the property under test: a validation-denied query
    # released nothing, so it must not poison later lineage).
    first = svc.handle("sum spend in London", planner, auditor=auditor)
    second = svc.handle("sum spend by age band in London", planner, auditor=auditor)
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


@pytest.mark.parametrize("col, bad", [
    ("spec", "NOT_JSON{"),         # malformed JSON in a chained column
    ("findings", "oops"),
    ("output_shape", "["),
    ("spec", None),                # column nulled out
    ("mac", None),                 # MAC itself corrupted to a non-string
])
def test_audit_verify_fails_closed_on_malformed_row(tmp_path, tables, col, bad):
    # A tamperer who can write the DB might corrupt a row into non-JSON or a
    # non-string MAC. verify() must fail CLOSED (return False), never raise — a
    # raised exception would 500 the /api/audit/verify endpoint instead of
    # reporting the tamper (P15).
    log = AuditLog(str(tmp_path / "audit.db"), key=b"unit-test-key")
    svc = QueryService(tables)
    for req in ["mean spend by age band", "mean spend by region"]:
        svc.handle(req, MockPlanner(), audit_log=log, user="alice")
    assert log.verify() is True
    log.con.execute(f"UPDATE records SET {col}=? WHERE id=1", (bad,))
    log.con.commit()
    assert log.verify() is False          # detected, and did not raise


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
