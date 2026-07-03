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
        SELECT d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               a.genre, a.contains_lootboxes, a.price_tier, a.age_rating,
               e.event_type, e.amount_chf, e.ingame_currency
        FROM events e JOIN donors d ON e.donor_id = d.donor_id
                      JOIN apps a   ON e.app_id   = a.app_id
    """,
    "donor_spend": """
        CREATE VIEW donor_spend AS
        SELECT d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               SUM(CASE WHEN e.event_type IN ('purchase', 'lootbox_open')
                        THEN e.amount_chf ELSE 0 END) AS total_spend_chf,
               SUM(CASE WHEN e.event_type = 'purchase' THEN 1 ELSE 0 END) AS purchase_events,
               SUM(CASE WHEN e.event_type = 'lootbox_open' THEN 1 ELSE 0 END) AS lootbox_events
        FROM donors d LEFT JOIN events e ON e.donor_id = d.donor_id
        GROUP BY d.donor_id, d.age_band, d.sex, d.canton, d.income_band, d.device_os
    """,
    "wellbeing": """
        CREATE VIEW wellbeing AS
        SELECT d.age_band, d.sex, d.canton, d.income_band, d.device_os,
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
        SELECT e.donor_id, d.age_years, d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               a.genre, a.contains_lootboxes, a.price_tier, a.age_rating,
               e.event_type, e.amount_chf, e.ingame_currency
        FROM events e JOIN donors d ON e.donor_id = d.donor_id
                      JOIN apps a   ON e.app_id   = a.app_id
    """,
    "donor_spend": """
        CREATE VIEW _donor_spend_u AS
        SELECT d.donor_id, d.age_years, d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               SUM(CASE WHEN e.event_type IN ('purchase', 'lootbox_open')
                        THEN e.amount_chf ELSE 0 END) AS total_spend_chf,
               SUM(CASE WHEN e.event_type = 'purchase' THEN 1 ELSE 0 END) AS purchase_events,
               SUM(CASE WHEN e.event_type = 'lootbox_open' THEN 1 ELSE 0 END) AS lootbox_events
        FROM donors d LEFT JOIN events e ON e.donor_id = d.donor_id
        GROUP BY d.donor_id, d.age_years, d.age_band, d.sex, d.canton, d.income_band, d.device_os
    """,
    "wellbeing": """
        CREATE VIEW _wellbeing_u AS
        SELECT s.donor_id, d.age_years, d.age_band, d.sex, d.canton, d.income_band, d.device_os,
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


class QueryEngine:
    def __init__(self, tables: dict[str, pd.DataFrame]):
        self.con = duckdb.connect(database=":memory:")
        self.con.execute(f"SET memory_limit='{MEMORY_LIMIT}'")
        self.con.execute(f"SET threads={THREADS}")
        for name, df in tables.items():
            self.con.register(name, df)
        for ddl in (*_VIEWS.values(), *_UNIT_VIEWS.values()):
            self.con.execute(ddl)

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
        return result

    def _attach_dominance(self, spec: QuerySpec, plan: SQLPlan, result: pd.DataFrame):
        """Largest single donor's contribution / cell total, per group."""
        dom = self.con.execute(plan.sql, plan.params).df()
        if spec.group_by:
            result = result.merge(dom, on=spec.group_by, how="left")
        else:
            result = result.assign(dominance=(dom["dominance"].iloc[0] if len(dom) else 0.0))
        result["dominance"] = result["dominance"].fillna(0.0)
        return result

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
