"""Read-only query engine: a validated QuerySpec -> parameterised DuckDB SQL.

Security properties:
- Identifiers come only from the validated allowlist and are regex-checked
  before quoting; filter *values* are always bound parameters (no injection).
- The public views expose only allowlisted columns (no donor_id/free_text/ts/raw age).
- For sum/mean the engine also computes a **dominance** share (largest single
  contributor / total) using INTERNAL unit views that include donor_id — which
  are never selectable via a QuerySpec and never returned. The gateway uses this
  to suppress cells one record could dominate (the p%-rule).
- Resource bounds: per-connection memory/thread limits and a row cap on results.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

import duckdb
import pandas as pd

from .query import CATALOGUE, QuerySpec

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
ROW_CAP = 10_000          # backstop against pathological cross-products
MEMORY_LIMIT = "512MB"
THREADS = 2

# Public views: ONLY public allowlisted columns. donor_id/free_text/ts/raw age never appear.
_VIEWS = {
    "spend": """
        CREATE VIEW spend AS
        SELECT d.age_band, d.sex, d.region, d.income_band, d.device_os,
               a.genre, a.contains_lootboxes, a.price_tier, a.age_rating,
               e.event_type, e.amount_gbp, e.ingame_currency
        FROM events e JOIN donors d ON e.donor_id = d.donor_id
                      JOIN apps a   ON e.app_id   = a.app_id
    """,
    "donor_spend": """
        CREATE VIEW donor_spend AS
        SELECT d.age_band, d.sex, d.region, d.income_band, d.device_os,
               SUM(CASE WHEN e.event_type IN ('purchase', 'lootbox_open')
                        THEN e.amount_gbp ELSE 0 END) AS total_spend_gbp,
               SUM(CASE WHEN e.event_type = 'purchase' THEN 1 ELSE 0 END) AS purchase_events,
               SUM(CASE WHEN e.event_type = 'lootbox_open' THEN 1 ELSE 0 END) AS lootbox_events
        FROM donors d LEFT JOIN events e ON e.donor_id = d.donor_id
        GROUP BY d.donor_id, d.age_band, d.sex, d.region, d.income_band, d.device_os
    """,
    "wellbeing": """
        CREATE VIEW wellbeing AS
        SELECT d.age_band, d.sex, d.region, d.income_band, d.device_os,
               s.wave, s.pgsi_score, s.igds_score, s.wemwbs_score,
               s.monthly_spend_selfreport
        FROM survey s JOIN donors d ON s.donor_id = d.donor_id
    """,
}

# Internal unit views: include donor_id and internal analysis variables, used
# ONLY for fixed tools and disclosure machinery. Not directly queryable.
_UNIT_VIEWS = {
    "spend": """
        CREATE VIEW _spend_u AS
        SELECT e.donor_id, d.age_years, d.age_band, d.sex, d.region, d.income_band, d.device_os,
               a.genre, a.contains_lootboxes, a.price_tier, a.age_rating,
               e.event_type, e.amount_gbp, e.ingame_currency
        FROM events e JOIN donors d ON e.donor_id = d.donor_id
                      JOIN apps a   ON e.app_id   = a.app_id
    """,
    "donor_spend": """
        CREATE VIEW _donor_spend_u AS
        SELECT d.donor_id, d.age_years, d.age_band, d.sex, d.region, d.income_band, d.device_os,
               SUM(CASE WHEN e.event_type IN ('purchase', 'lootbox_open')
                        THEN e.amount_gbp ELSE 0 END) AS total_spend_gbp,
               SUM(CASE WHEN e.event_type = 'purchase' THEN 1 ELSE 0 END) AS purchase_events,
               SUM(CASE WHEN e.event_type = 'lootbox_open' THEN 1 ELSE 0 END) AS lootbox_events
        FROM donors d LEFT JOIN events e ON e.donor_id = d.donor_id
        GROUP BY d.donor_id, d.age_years, d.age_band, d.sex, d.region, d.income_band, d.device_os
    """,
    "wellbeing": """
        CREATE VIEW _wellbeing_u AS
        SELECT s.donor_id, d.age_years, d.age_band, d.sex, d.region, d.income_band, d.device_os,
               s.wave, s.pgsi_score, s.igds_score, s.wemwbs_score,
               s.monthly_spend_selfreport
        FROM survey s JOIN donors d ON s.donor_id = d.donor_id
    """,
}


def _ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"illegal identifier {name!r}")
    return f'"{name}"'


@dataclass(frozen=True)
class SQLPlan:
    """Compiled SQL plus the metadata needed to check its safety boundary."""

    sql: str
    params: tuple[Any, ...]
    output_columns: tuple[str, ...]
    source_view: str


_FILTER_OPS = {"==", "!=", "<", "<=", ">", ">=", "in"}
_BETA_EPS = 3e-14
_BETA_FPMIN = 1e-300
_BETA_MAX_ITER = 200


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _BETA_FPMIN:
        d = _BETA_FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, _BETA_MAX_ITER + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _BETA_FPMIN:
            d = _BETA_FPMIN
        c = 1.0 + aa / c
        if abs(c) < _BETA_FPMIN:
            c = _BETA_FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _BETA_FPMIN:
            d = _BETA_FPMIN
        c = 1.0 + aa / c
        if abs(c) < _BETA_FPMIN:
            c = _BETA_FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _BETA_EPS:
            break
    return h


def _regularized_beta(x: float, a: float, b: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    bt = math.exp(
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
        + a * math.log(x) + b * math.log1p(-x)
    )
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def _pearson_p_value(r: float, n: int) -> float:
    """Two-sided p-value for Pearson r using Student's t distribution."""
    if n < 3 or not math.isfinite(r):
        return float("nan")
    abs_r = min(abs(r), 1.0)
    if abs_r >= 1.0:
        return 0.0
    df = n - 2
    p = _regularized_beta(1.0 - abs_r * abs_r, df / 2.0, 0.5)
    return max(0.0, min(1.0, p))


def _where_triples(filters) -> tuple[str, tuple[Any, ...]]:
    """WHERE clause from (column, op, value) triples; values stay bound params."""
    clauses, params = [], []
    for column, op, value in filters:
        col = _ident(column)
        if op == "in":
            values = list(value)
            placeholders = ", ".join("?" for _ in values)
            clauses.append(f"{col} IN ({placeholders})")
            params.extend(values)
        elif op in _FILTER_OPS:
            clauses.append(f"{col} {op} ?")
            params.append(value)
        else:
            raise ValueError(f"illegal filter operator {op!r}")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, tuple(params)


def _where(spec: QuerySpec, extra_clauses: tuple[str, ...] = ()) -> tuple[str, tuple[Any, ...]]:
    where, params = _where_triples((f.column, f.op, f.value) for f in spec.filters)
    if extra_clauses:
        prefix = " AND " if where else " WHERE "
        where += prefix + " AND ".join(extra_clauses)
    return where, params


def _uses_internal_source(spec: QuerySpec) -> bool:
    cat = CATALOGUE[spec.dataset]
    internal_filters = set(cat.get("internal_filters", {}))
    internal_measures = set(cat.get("internal_measures", set()))
    if any(f.column in internal_filters for f in spec.filters):
        return True
    if spec.measure.fn == "corr":
        return bool({spec.measure.x, spec.measure.y} & internal_measures)
    return False


def _source_view(spec: QuerySpec) -> str:
    return f"_{spec.dataset}_u" if _uses_internal_source(spec) else spec.dataset


def compile_query(spec: QuerySpec) -> SQLPlan:
    """Compile a validated QuerySpec into the public read-only aggregate SQL."""
    extra: tuple[str, ...] = ()
    select = [_ident(g) for g in spec.group_by]
    if spec.measure.fn == "count":
        select.append("COUNT(*) AS value")
    elif spec.measure.fn in ("mean", "sum"):
        # fn is a Literal allowlist; column is allowlist- and regex-validated
        select.append(f"{spec.measure.fn.upper()}({_ident(spec.measure.column)}) AS value")
    else:
        x = _ident(spec.measure.x)
        y = _ident(spec.measure.y)
        extra = (f"{x} IS NOT NULL", f"{y} IS NOT NULL")
        select.append(f"CORR({x}, {y}) AS value")
    select.append("COUNT(*) AS n")

    where, params = _where(spec, extra)
    source = _source_view(spec)
    sql = f"SELECT {', '.join(select)} FROM {_ident(source)}{where}"  # nosec
    if spec.group_by:
        sql += " GROUP BY " + ", ".join(_ident(g) for g in spec.group_by)
    sql += f" ORDER BY n DESC LIMIT {ROW_CAP}"
    return SQLPlan(
        sql=sql,
        params=params,
        output_columns=tuple(spec.group_by) + ("value", "n"),
        source_view=source,
    )


def compile_dominance_query(spec: QuerySpec) -> SQLPlan:
    """Compile the internal donor-level dominance query for sum/mean specs."""
    if spec.measure.fn not in ("mean", "sum"):
        raise ValueError("dominance is only defined for mean/sum measures")

    where, params = _where(spec)
    col = _ident(spec.measure.column)
    unit = _ident(f"_{spec.dataset}_u")
    gsel = ", ".join(_ident(g) for g in spec.group_by)
    gpre = (gsel + ", ") if spec.group_by else ""
    inner = (
        f"SELECT {gpre}donor_id, SUM({col}) AS c FROM {unit}{where} "  # nosec
        f"GROUP BY {gpre}donor_id"
    )
    sql = (
        f"SELECT {gpre}MAX(c) / NULLIF(SUM(c), 0) AS dominance "  # nosec
        f"FROM ({inner}) t" + (f" GROUP BY {gsel}" if spec.group_by else "")
    )
    return SQLPlan(
        sql=sql,
        params=params,
        output_columns=tuple(spec.group_by) + ("dominance",),
        source_view=f"_{spec.dataset}_u",
    )


def compile_influence_query(spec: QuerySpec) -> SQLPlan:
    """Compile the internal leave-one-donor-out influence query for corr specs.

    A correlation has no natural analogue of the sum/mean p%-dominance rule, yet
    a single high-leverage donor can drive it — so a released r on a small group
    can disclose that individual. This computes, per group, the largest change
    in Pearson r that removing any single *donor* produces (their whole set of
    rows, so it is correct even for event-level correlations where one donor has
    many events). The gateway suppresses cells whose influence exceeds the
    policy threshold. Runs on the internal unit view; only the max |Δr| per
    group is used, and it is never released.
    """
    if spec.measure.fn != "corr":
        raise ValueError("influence is only defined for corr measures")

    x = _ident(spec.measure.x)
    y = _ident(spec.measure.y)
    where, params = _where(spec, (f"{x} IS NOT NULL", f"{y} IS NOT NULL"))
    unit = _ident(f"_{spec.dataset}_u")
    gsel = ", ".join(_ident(g) for g in spec.group_by)
    gpre = (gsel + ", ") if spec.group_by else ""

    # per-donor partial sums (d*), then per-group totals (t*), then drop-one
    # recomputation. Note: DuckDB identifiers are case-INSENSITIVE, so the
    # per-donor and group column names must be textually distinct (not just
    # differ in case) or they silently alias each other.
    per_donor = (
        f"SELECT {gpre}donor_id, "  # nosec
        f"SUM({x}) AS dx, SUM({y}) AS dy, SUM({x}*{x}) AS dxx, "
        f"SUM({y}*{y}) AS dyy, SUM({x}*{y}) AS dxy, COUNT(*) AS dm "
        f"FROM {unit}{where} GROUP BY {gpre}donor_id"
    )
    grp = (
        f"SELECT {gpre}SUM(dx) AS tx, SUM(dy) AS ty, SUM(dxx) AS txx, "  # nosec
        f"SUM(dyy) AS tyy, SUM(dxy) AS txy, SUM(dm) AS tn "
        f"FROM per_donor" + (f" GROUP BY {gsel}" if spec.group_by else "")
    )
    join = (f"per_donor p JOIN grp g USING ({gsel})" if spec.group_by
            else "per_donor p, grp g")
    gcols_j = ("g." + ", g.".join(_ident(g) for g in spec.group_by) + ", ") if spec.group_by else ""
    r_full = ("(tn*txy - tx*ty) / "
              "sqrt(NULLIF((tn*txx - tx*tx) * (tn*tyy - ty*ty), 0))")
    # sums with this donor removed (subtract their partials)
    r_drop = ("((tn-dm)*(txy-dxy) - (tx-dx)*(ty-dy)) / "
              "sqrt(NULLIF(((tn-dm)*(txx-dxx) - (tx-dx)*(tx-dx)) * "
              "((tn-dm)*(tyy-dyy) - (ty-dy)*(ty-dy)), 0))")
    sql = (
        f"WITH per_donor AS ({per_donor}), grp AS ({grp}), "  # nosec
        f"j AS (SELECT {gcols_j}"
        f"p.dx, p.dy, p.dxx, p.dyy, p.dxy, p.dm, "
        f"g.tx, g.ty, g.txx, g.tyy, g.txy, g.tn FROM {join}), "
        f"d AS (SELECT {gpre}"
        f"CASE WHEN (tn-dm) >= 3 THEN abs(({r_full}) - ({r_drop})) END AS delta FROM j) "
        f"SELECT {gpre}MAX(delta) AS influence FROM d"
        + (f" GROUP BY {gsel}" if spec.group_by else "")
    )
    return SQLPlan(
        sql=sql,
        params=params,
        output_columns=tuple(spec.group_by) + ("influence",),
        source_view=f"_{spec.dataset}_u",
    )


def _corr_not_null(spec: QuerySpec) -> tuple[str, ...]:
    if spec.measure.fn != "corr":
        return ()
    return (f"{_ident(spec.measure.x)} IS NOT NULL", f"{_ident(spec.measure.y)} IS NOT NULL")


def compile_donor_count_query(spec: QuerySpec) -> SQLPlan:
    """Compile the internal per-cell distinct-donor count.

    The frequency threshold rule protects *individuals* ("respondents"), not
    rows. On event-level datasets a cell can have many rows from few donors, so
    the public `n` (= COUNT(*)) is not a safe individual count. This counts
    distinct donors per cell on the internal unit view, mirroring the public
    query's filters (including the corr NOT-NULL predicates), so the gateway can
    enforce the threshold on donors. The count is a disclosure helper and is
    dropped before release.
    """
    where, params = _where(spec, _corr_not_null(spec))
    unit = _ident(f"_{spec.dataset}_u")
    gsel = ", ".join(_ident(g) for g in spec.group_by)
    gpre = (gsel + ", ") if spec.group_by else ""
    sql = (
        f"SELECT {gpre}COUNT(DISTINCT donor_id) AS n_donors "  # nosec
        f"FROM {unit}{where}" + (f" GROUP BY {gsel}" if spec.group_by else "")
    )
    return SQLPlan(
        sql=sql,
        params=params,
        output_columns=tuple(spec.group_by) + ("n_donors",),
        source_view=f"_{spec.dataset}_u",
    )


def _dim_value_set(universe: set, predicates: list) -> set:
    """The set of a dimension's values selected by a list of (op, value) predicates."""
    s = set(universe)
    for op, value in predicates:
        if op == "==":
            s &= {value}
        elif op == "!=":
            s -= {value}
        elif op == "in":
            s &= set(value)
        elif op == "<":
            s = {u for u in s if u < value}
        elif op == "<=":
            s = {u for u in s if u <= value}
        elif op == ">":
            s = {u for u in s if u > value}
        elif op == ">=":
            s = {u for u in s if u >= value}
    return s


ALLOW_SENTINEL = 10 ** 9


def simulatable_cohort_bound(marginals: dict, dataset: str,
                             filters_a: tuple, filters_b: tuple) -> int:
    """A simulatable upper bound on |A △ B|, from published donor marginals only.

    The session auditor must not decide releases from the live donor sets, or the
    refusal itself leaks (Kenthapadi–Mishra–Nissim, *simulatable auditing*, 2005).
    This decides from `marginals` — a donor-frequency table per (dataset, dim,
    value) that is itself disclosure-safe metadata — so an analyst holding the
    same public marginals could reproduce every decision, and a refusal reveals
    nothing new.

    For two cohorts that differ on exactly one dimension, the whole-population
    donor marginal of the differing values is an *upper* bound on the symmetric
    difference. So a denial (bound < threshold) is always sound, and this catches
    the canonical attack: isolating a globally-rare category by adding or
    removing one predicate ("exclude age 69", "exclude sex X").

    Being an upper bound, it does NOT catch differencing that isolates a small
    group through the *interaction* of a common category with an otherwise-narrow
    cohort (e.g. the over-50s within one small region): the marginal is then
    large even though the real symmetric difference is small. That residual is
    the price of simulatability; it is largely covered by the per-cell donor
    threshold (a narrow cohort's cells are suppressed anyway) and fully by a DP
    accountant. Cohorts differing on more than one dimension return a sentinel
    that never denies and rely on the query-budget and total-delta checks.
    """
    dmap = marginals.get(dataset, {})

    def by_dim(filters: tuple) -> dict:
        grouped: dict = {}
        for column, op, value in filters:
            grouped.setdefault(column, []).append((op, value))
        return grouped

    a, b = by_dim(filters_a), by_dim(filters_b)
    differing = []
    for dim in set(a) | set(b):
        universe = set(dmap.get(dim, {}))
        sa = _dim_value_set(universe, a.get(dim, []))
        sb = _dim_value_set(universe, b.get(dim, []))
        if sa != sb:
            differing.append((dim, sa ^ sb))
    if len(differing) != 1:
        return ALLOW_SENTINEL
    dim, symdiff_values = differing[0]
    return sum(dmap[dim].get(v, 0) for v in symdiff_values)


class QueryEngine:
    def __init__(self, tables: dict[str, pd.DataFrame]):
        self.con = duckdb.connect(database=":memory:")
        self.con.execute(f"SET memory_limit='{MEMORY_LIMIT}'")
        self.con.execute(f"SET threads={THREADS}")
        for name, df in tables.items():
            self.con.register(name, df)
        for ddl in (*_VIEWS.values(), *_UNIT_VIEWS.values()):
            self.con.execute(ddl)
        self._marginals: dict | None = None

    def run(self, spec: QuerySpec) -> pd.DataFrame:
        plan = compile_query(spec)
        result = self.con.execute(plan.sql, plan.params).df()

        if spec.measure.fn in ("mean", "sum"):
            result["value"] = result["value"].round(2)
            result = self._attach_dominance(spec, compile_dominance_query(spec), result)
        elif spec.measure.fn == "corr":
            result["value"] = result["value"].round(4)
            p_values = [
                _pearson_p_value(float(r), int(n))
                for r, n in zip(result["value"], result["n"], strict=True)
            ]
            result.insert(result.columns.get_loc("value") + 1, "p_value", p_values)
            result["p_value"] = result["p_value"].round(3)
            result = self._attach_influence(spec, compile_influence_query(spec), result)

        # every result carries an internal distinct-donor count so the gateway
        # enforces the frequency threshold on individuals, not rows.
        result = self._attach_donor_count(spec, compile_donor_count_query(spec), result)
        return result

    def _attach_dominance(self, spec: QuerySpec, plan: SQLPlan, result: pd.DataFrame):
        """Largest single donor's contribution / cell total, per group.

        A missing/unresolved dominance is filled with +inf, not 0.0: an unresolved
        safety check must fail **closed** (be suppressed), never default to "safe".
        """
        dom = self.con.execute(plan.sql, plan.params).df()
        if spec.group_by:
            result = result.merge(dom, on=spec.group_by, how="left")
        else:
            result = result.assign(dominance=(dom["dominance"].iloc[0]
                                              if len(dom) else float("inf")))
        result["dominance"] = result["dominance"].fillna(float("inf"))
        return result

    def _attach_influence(self, spec: QuerySpec, plan: SQLPlan, result: pd.DataFrame):
        """Max single-donor leave-one-out |Δr| per group (for corr cells).

        Filled with +inf when unresolved (e.g. every leave-one-out drops below the
        3-row floor) so an uncomputed influence is suppressed, not released.
        """
        inf = self.con.execute(plan.sql, plan.params).df()
        if spec.group_by:
            result = result.merge(inf, on=spec.group_by, how="left")
        else:
            result = result.assign(influence=(inf["influence"].iloc[0]
                                             if len(inf) else float("inf")))
        result["influence"] = result["influence"].fillna(float("inf"))
        return result

    def _attach_donor_count(self, spec: QuerySpec, plan: SQLPlan, result: pd.DataFrame):
        """Distinct donors per cell (internal); a missing cell means zero donors."""
        nd = self.con.execute(plan.sql, plan.params).df()
        if spec.group_by:
            result = result.merge(nd, on=spec.group_by, how="left")
        else:
            result = result.assign(n_donors=(nd["n_donors"].iloc[0] if len(nd) else 0))
        result["n_donors"] = result["n_donors"].fillna(0).astype(int)
        return result

    def marginal_donor_counts(self) -> dict:
        """Published donor-frequency metadata: `{dataset: {dim: {value: n_donors}}}`.

        The distinct-donor count of every single filterable predicate value, on
        the internal unit views. This is a donor-frequency table — itself
        releasable under the threshold rule — and it is the only data the session
        auditor's differencing decision depends on, which is what makes that
        decision *simulatable* (see `simulatable_cohort_bound`). Computed once
        and cached. Only the < threshold comparison is used downstream, so a
        production build can publish the sparse-flagged, rounded version.
        """
        if self._marginals is not None:
            return self._marginals
        out: dict = {}
        for dataset in _UNIT_VIEWS:
            cat = CATALOGUE[dataset]
            dims = list(cat["dims"]) + list(cat.get("internal_filters", {}))
            unit = self._unit_view(dataset)
            per_dim: dict = {}
            for dim in dims:
                col = _ident(dim)
                rows = self.con.execute(
                    f"SELECT {col} AS v, COUNT(DISTINCT donor_id) AS c "  # nosec
                    f"FROM {unit} GROUP BY {col}"
                ).fetchall()
                per_dim[dim] = {v: int(c) for v, c in rows}
            out[dataset] = per_dim
        self._marginals = out
        return out

    def published_marginal_donor_counts(self, threshold: int = 10,
                                        round_base: int = 5) -> dict:
        """The disclosure-safe form of `marginal_donor_counts`, safe to expose.

        The simulatable-auditing argument (Kenthapadi–Mishra–Nissim, 2005) only
        holds if the metadata the auditor decides from is genuinely public. The
        raw marginals include sub-threshold cells (e.g. a rare `sex`/`age_years`
        value), which are themselves disclosive, so they are not published as-is.
        This returns the releasable projection: counts at or above `threshold` are
        rounded to `round_base`; counts below it are reported as `None`
        ("< threshold"). The endpoint serving this is what makes the auditor's
        deny/allow decision reproducible by an analyst *up to* that one bit — the
        residual (using the true sub-threshold count internally to actually catch
        rare-category isolation) is the documented, DP-closed deviation.
        """
        raw = self.marginal_donor_counts()
        pub: dict = {}
        for dataset, per_dim in raw.items():
            pub[dataset] = {
                dim: {
                    str(v): (int(round(c / round_base) * round_base) if c >= threshold else None)
                    for v, c in counts.items()
                }
                for dim, counts in per_dim.items()
            }
        return pub

    def _unit_view(self, dataset: str) -> str:
        if dataset not in _UNIT_VIEWS:
            raise ValueError(f"unknown dataset {dataset!r}")
        return _ident(f"_{dataset}_u")

    def cohort_size(self, dataset: str, filters=()) -> int:
        """Distinct-donor count of a cohort, on the INTERNAL unit view.

        `filters` are normalized (column, op, value) triples from a *validated*
        QuerySpec. The count is used only by the session auditor and is never
        released.
        """
        where, params = _where_triples(filters)
        sql = f"SELECT COUNT(DISTINCT donor_id) FROM {self._unit_view(dataset)}{where}"  # nosec
        return int(self.con.execute(sql, params).fetchone()[0])

    def cohort_symdiff(self, dataset: str, filters_a, filters_b) -> int:
        """|A △ B|: distinct donors in exactly one of two cohorts.

        A small symmetric difference means the pair of released aggregates
        differs by only a few individuals — the signature of a differencing
        attack. Computed on the internal unit views; never released.
        """
        unit = self._unit_view(dataset)
        wa, pa = _where_triples(filters_a)
        wb, pb = _where_triples(filters_b)
        a = f"SELECT DISTINCT donor_id FROM {unit}{wa}"  # nosec
        b = f"SELECT DISTINCT donor_id FROM {unit}{wb}"  # nosec
        # EXCEPT halves are distinct and disjoint, so UNION ALL is exact.
        sql = f"SELECT COUNT(*) FROM (({a} EXCEPT {b}) UNION ALL ({b} EXCEPT {a})) t"  # nosec
        return int(self.con.execute(sql, pa + pb + pb + pa).fetchone()[0])
