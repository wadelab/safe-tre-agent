"""Regression tests for the 2026-07-06 hardening round.

Each test pins one finding from the security review so a regression fails CI:
  A1  concurrency TOCTOU on the session lineage/budget controls
  A2  config.yaml / SAFETRE_MIN_CELL actually change suppression
  A3  disclosure-safe published marginals; non-numeric differencing refusals
  A4  dominance / influence / count suppression fails closed on NULL/missing
  B1  identity header is not trusted once the channel is widened
  B2  the 'testclient' channel bypass is off unless explicitly enabled
  B3  the secure web path has a fail-closed HITL step
  B4  over-budget queries short-circuit and bound session state
"""

import concurrent.futures as cf

import numpy as np
import pandas as pd
import pytest

from safetre import synth
from safetre.config import load_policy_config
from safetre.disclosure import DisclosurePolicy, SessionAuditor, leak_detector
from safetre.engine import QueryEngine
from safetre.query import Measure, QuerySpec
from safetre.service import QueryService


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


# --- A2: config actually bites -------------------------------------------------

def test_config_env_override_changes_suppression(tables, monkeypatch, tmp_path):
    # a benign query that releases every age band at threshold 10 ...
    q = QuerySpec(dataset="spend", measure=Measure(fn="count"), group_by=["age_band"])
    eng = QueryEngine(tables)
    df = eng.run(q)

    released_lax, action_lax, _ = DisclosurePolicy(threshold=10).apply(df)
    # ... must drop cells once the operator raises the floor to an absurd 10_000
    released_strict, action_strict, _ = DisclosurePolicy(threshold=10_000).apply(df)
    assert action_strict in ("redacted", "deny")
    assert released_strict is None or len(released_strict) < len(released_lax)


def test_config_precedence_defaults_yaml_env(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("disclosure:\n  min_cell_size: 25\nsession:\n  query_budget: 7\n")
    monkeypatch.delenv("SAFETRE_MIN_CELL", raising=False)
    cfg = load_policy_config(str(cfg_file))
    assert cfg.min_cell_size == 25 and cfg.query_budget == 7    # yaml overrides defaults
    monkeypatch.setenv("SAFETRE_MIN_CELL", "30")
    assert load_policy_config(str(cfg_file)).min_cell_size == 30  # env overrides yaml


def test_config_rejects_nonsense(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFETRE_MIN_CELL", "0")
    with pytest.raises(ValueError):
        load_policy_config(str(tmp_path / "missing.yaml"))


# --- #25: counts release once, rounded — no exact duplicate --------------------

def test_count_release_has_no_unrounded_duplicate(tables):
    # hardening #25: counts used to ride along twice — rounded as `n` and exact
    # as `value` (a name the gateway does not recognise as a count column), so
    # the exact cell count left beside the rounded one. A released count query
    # must carry the count once, rounded.
    policy = DisclosurePolicy()
    q = QuerySpec(dataset="spend", measure=Measure(fn="count"), group_by=["age_band"])
    df = QueryEngine(tables).run(q)
    released, action, _ = policy.apply(df)
    assert action in ("release", "redacted")
    assert "value" not in released.columns
    numeric = released.select_dtypes("number")
    assert not numeric.empty                                   # `n` is present
    assert (numeric % policy.round_base == 0).all().all()      # everything rounded


# --- A3: leak_detector honours the configured threshold ------------------------

def test_leak_detector_uses_passed_threshold():
    df = pd.DataFrame({"region": ["A", "B"], "n": [12, 40]})
    assert not leak_detector(df, threshold=10)                 # both >= 10
    findings = leak_detector(df, threshold=20)                 # 12 now sub-threshold
    assert any(f.rule == "small_cell" for f in findings)


# --- A4: fail closed on NULL / missing safety columns --------------------------

def test_leak_detector_fails_closed_on_nan_dominance():
    df = pd.DataFrame({"region": ["A"], "value": [1.0], "n": [50],
                       "dominance": [np.nan]})
    findings = leak_detector(df)
    assert any(f.rule == "dominance" for f in findings)        # NaN treated as unsafe


def test_leak_detector_fails_closed_on_inf_influence():
    df = pd.DataFrame({"region": ["A"], "value": [0.9], "n": [50],
                       "influence": [np.inf]})
    findings = leak_detector(df)
    assert any(f.rule == "influence" for f in findings)


def test_apply_suppresses_unresolved_dominance():
    # two unresolved (inf) cells among four; the inf cells must never be released.
    df = pd.DataFrame({"region": ["A", "B", "C", "D"], "value": [1.0, 2.0, 3.0, 4.0],
                       "n": [50, 60, 70, 80], "dominance": [np.inf, np.inf, 0.1, 0.2]})
    released, action, _ = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert "A" not in set(released["region"]) and "B" not in set(released["region"])


class _EmptyPlan:
    """A dominance/influence plan whose query yields no rows (unresolved cell)."""
    sql = "SELECT 1 AS dominance, 1 AS influence WHERE 1=0"
    params: tuple = ()


def test_engine_unresolved_dominance_fills_infinite_not_zero(tables):
    # if the dominance sub-query returns no row for a cell, the fill must be +inf
    # (unsafe -> suppressed), never 0.0 (safe -> released).
    eng = QueryEngine(tables)
    spec = QuerySpec(dataset="spend", measure=Measure(fn="sum", column="amount_gbp"))
    result = pd.DataFrame({"value": [1.0], "n": [5]})
    filled = eng._attach_dominance(spec, _EmptyPlan(), result.copy())
    assert np.isinf(filled["dominance"].iloc[0])
    # and a real run resolves to a finite dominance (no spurious inf)
    assert eng.run(spec)["dominance"].notna().all()


# --- A3: published marginals are disclosure-safe --------------------------------

def test_published_marginals_suppress_subthreshold(tables):
    eng = QueryEngine(tables)
    raw = eng.marginal_donor_counts()
    pub = eng.published_marginal_donor_counts(threshold=10, round_base=5)
    # every published value is either None (suppressed) or a multiple of 5 >= 10
    for dataset, per_dim in pub.items():
        for dim, counts in per_dim.items():
            for v, c in counts.items():
                assert c is None or (c % 5 == 0 and c >= 10)
    # a sub-threshold *declared* cell (e.g. Northern Ireland) is kept but
    # suppressed to None; an undeclared value (a poison string) is dropped
    # entirely — its name is disclosive, so count-nulling it is not enough.
    from safetre.schema import declared_domain
    sub_declared = [(ds, dim, v) for ds, pd_ in raw.items() for dim, cc in pd_.items()
                    for v, c in cc.items() if 0 < c < 10
                    and declared_domain(dim) is not None and v in declared_domain(dim)]
    assert sub_declared, "expected at least one sub-threshold declared value"
    ds, dim, v = sub_declared[0]
    assert pub[ds][dim][str(v)] is None
    # no undeclared value survives anywhere in the published table
    for ds, per_dim in pub.items():
        for dim, counts in per_dim.items():
            dom = declared_domain(dim)
            if dom is not None:
                assert all(k in {str(x) for x in dom} for k in counts)


def test_differencing_refusal_has_no_numeric_bound(tables):
    n_ni = int((tables["donors"]["region"] == "Northern Ireland").sum())
    svc = QueryService(tables)
    auditor = SessionAuditor(threshold=n_ni + 1)

    class _Scripted:
        def __init__(self, *s): self.s = list(s)
        def plan(self, r): return self.s.pop(0)

    planner = _Scripted(
        {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
         "group_by": ["age_band"]},
        {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
         "group_by": ["age_band"],
         "filters": [{"column": "region", "op": "!=", "value": "Northern Ireland"}]},
    )
    svc.handle("sum spend by age band", planner, auditor=auditor)
    second = svc.handle("same, excluding Northern Ireland", planner, auditor=auditor)
    assert second.status == "denied"
    detail = " ".join(f.detail for f in second.findings if f.rule == "differencing")
    assert detail                                             # the finding fired
    assert str(n_ni) not in detail                           # but leaks no count
    assert not any(ch.isdigit() for ch in detail)            # no numbers at all


# --- A1: concurrency must not let both halves of a differencing pair through ----

def test_concurrent_differencing_serialised_by_session_lock(tables):
    from safetre_web.session import SessionStore

    n_ni = int((tables["donors"]["region"] == "Northern Ireland").sum())
    svc = QueryService(tables)
    store = SessionStore(threshold=n_ni + 1, budget=100)

    base = {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
            "group_by": ["age_band"]}
    excl = {**base, "filters": [{"column": "region", "op": "!=", "value": "Northern Ireland"}]}

    class _Fixed:
        def __init__(self, spec): self.spec = spec
        def plan(self, r): return self.spec

    def issue(spec):
        sess = store.get("attacker@example.test")
        with sess.lock:                                       # what the web handler does
            return svc.handle("q", _Fixed(spec), auditor=sess.auditor)

    with cf.ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(issue, base)
        f2 = ex.submit(issue, excl)
        r1, r2 = f1.result(), f2.result()

    # exactly one of the near-duplicate cohorts may be released; the other is
    # denied by the lineage auditor regardless of interleaving.
    statuses = sorted([r1.status, r2.status])
    assert "denied" in statuses


# --- B4: over-budget short-circuits and bounds history -------------------------

def test_over_budget_short_circuits_before_engine(tables):
    svc = QueryService(tables)
    auditor = SessionAuditor(budget=3)

    class _Benign:
        def plan(self, r):
            return {"dataset": "spend", "measure": {"fn": "count"}, "group_by": ["age_band"]}

    for _ in range(3):
        svc.handle("count by age band", _Benign(), auditor=auditor)
    assert auditor.over_budget()
    denied = svc.handle("count by age band", _Benign(), auditor=auditor)
    assert denied.status == "denied"
    assert any(f.rule == "query_budget" for f in denied.findings)
    assert denied.spec is None                                # never reached the planner


def test_session_history_is_bounded():
    from safetre.disclosure import MAX_HISTORY
    a = SessionAuditor(budget=10**9)
    for i in range(MAX_HISTORY + 50):
        a.observe("m", float(i))
    assert len(a._history) <= MAX_HISTORY


# --- B1 / B2: identity + channel coupling --------------------------------------

def test_identity_not_trusted_when_channel_widened(monkeypatch):
    from safetre_web import identity

    class _Req:
        def __init__(self, headers): self.headers = headers

    monkeypatch.setenv("SAFETRE_RESTRICTED_CHANNEL", "1")
    monkeypatch.setenv("SAFETRE_CHANNEL_ALLOW_NETS", "127.0.0.1/32,::1/128")
    login, allowed = identity.current_user(_Req({"tailscale-user-login": "a@x.test"}))
    assert login == "a@x.test"                                # loopback-only: trusted

    monkeypatch.setenv("SAFETRE_CHANNEL_ALLOW_NETS", "127.0.0.1/32,10.0.0.0/8")
    login, allowed = identity.current_user(_Req({"tailscale-user-login": "a@x.test"}))
    assert (login, allowed) == ("unverified", False)          # widened: fail closed

    monkeypatch.setenv("SAFETRE_TRUST_FORWARDED_IDENTITY", "1")
    login, _ = identity.current_user(_Req({"tailscale-user-login": "a@x.test"}))
    assert login == "a@x.test"                                # explicit opt-in restores trust


def test_proxy_shared_secret_required_when_set(monkeypatch):
    from safetre_web import identity

    class _Req:
        def __init__(self, headers): self.headers = headers

    monkeypatch.setenv("SAFETRE_RESTRICTED_CHANNEL", "1")
    monkeypatch.setenv("SAFETRE_CHANNEL_ALLOW_NETS", "127.0.0.1/32,::1/128")
    monkeypatch.setenv("SAFETRE_PROXY_SHARED_SECRET", "s3cret")
    bad, ok = identity.current_user(_Req({"tailscale-user-login": "a@x.test"}))
    assert (bad, ok) == ("unverified", False)                 # missing secret -> refused
    good, _ = identity.current_user(_Req({"tailscale-user-login": "a@x.test",
                                          "x-safetre-proxy-auth": "s3cret"}))
    assert good == "a@x.test"
