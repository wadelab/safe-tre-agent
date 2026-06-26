"""Read-only query engine: a validated QuerySpec -> parameterised DuckDB SQL.

Security properties:
- Identifiers come only from the validated allowlist and are regex-checked
  before quoting; filter *values* are always bound parameters (no injection).
- The public views expose only allowlisted columns (no donor_id/free_text/ts).
- For sum/mean the engine also computes a **dominance** share (largest single
  contributor / total) using INTERNAL unit views that include donor_id — which
  are never selectable via a QuerySpec and never returned. The gateway uses this
  to suppress cells one record could dominate (the p%-rule).
- Resource bounds: per-connection memory/thread limits and a row cap on results.
"""

from __future__ import annotations

import re

import duckdb
import pandas as pd

from .query import QuerySpec

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
ROW_CAP = 10_000          # backstop against pathological cross-products
MEMORY_LIMIT = "512MB"
THREADS = 2

# Public views: ONLY allowlisted columns. donor_id/free_text/ts never appear.
_VIEWS = {
    "spend": """
        CREATE VIEW spend AS
        SELECT d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               a.genre, a.contains_lootboxes, a.price_tier, a.age_rating,
               e.event_type, e.amount_chf, e.ingame_currency
        FROM events e JOIN donors d ON e.donor_id = d.donor_id
                      JOIN apps a   ON e.app_id   = a.app_id
    """,
    "wellbeing": """
        CREATE VIEW wellbeing AS
        SELECT d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               s.wave, s.pgsi_score, s.igds_score, s.wemwbs_score,
               s.monthly_spend_selfreport
        FROM survey s JOIN donors d ON s.donor_id = d.donor_id
    """,
}

# Internal unit views: include donor_id, used ONLY for dominance. Not queryable.
_UNIT_VIEWS = {
    "spend": """
        CREATE VIEW _spend_u AS
        SELECT e.donor_id, d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               a.genre, a.contains_lootboxes, a.price_tier, a.age_rating,
               e.event_type, e.amount_chf, e.ingame_currency
        FROM events e JOIN donors d ON e.donor_id = d.donor_id
                      JOIN apps a   ON e.app_id   = a.app_id
    """,
    "wellbeing": """
        CREATE VIEW _wellbeing_u AS
        SELECT s.donor_id, d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               s.wave, s.pgsi_score, s.igds_score, s.wemwbs_score,
               s.monthly_spend_selfreport
        FROM survey s JOIN donors d ON s.donor_id = d.donor_id
    """,
}


def _ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"illegal identifier {name!r}")
    return f'"{name}"'


class QueryEngine:
    def __init__(self, tables: dict[str, pd.DataFrame]):
        self.con = duckdb.connect(database=":memory:")
        self.con.execute(f"SET memory_limit='{MEMORY_LIMIT}'")
        self.con.execute(f"SET threads={THREADS}")
        for name, df in tables.items():
            self.con.register(name, df)
        for ddl in (*_VIEWS.values(), *_UNIT_VIEWS.values()):
            self.con.execute(ddl)

    def _where(self, spec: QuerySpec):
        clauses, params = [], []
        for f in spec.filters:
            col = _ident(f.column)
            if f.op == "in":
                placeholders = ", ".join("?" for _ in f.value)
                clauses.append(f"{col} IN ({placeholders})")
                params.extend(f.value)
            else:
                clauses.append(f"{col} {f.op} ?")   # nosec B608 - op is a Literal allowlist; value bound
                params.append(f.value)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def run(self, spec: QuerySpec) -> pd.DataFrame:
        where, params = self._where(spec)
        select = [_ident(g) for g in spec.group_by]
        if spec.measure.fn == "count":
            select.append("COUNT(*) AS value")
        else:
            # fn is a Literal allowlist; column is allowlist- and regex-validated
            select.append(f"{spec.measure.fn.upper()}({_ident(spec.measure.column)}) AS value")  # nosec B608
        select.append("COUNT(*) AS n")

        sql = f"SELECT {', '.join(select)} FROM {_ident(spec.dataset)}{where}"  # nosec B608
        if spec.group_by:
            sql += " GROUP BY " + ", ".join(_ident(g) for g in spec.group_by)
        sql += f" ORDER BY n DESC LIMIT {ROW_CAP}"
        result = self.con.execute(sql, params).df()

        if spec.measure.fn in ("mean", "sum"):
            result["value"] = result["value"].round(2)
            result = self._attach_dominance(spec, where, params, result)
        return result

    def _attach_dominance(self, spec, where, params, result):
        """Largest single donor's contribution / cell total, per group."""
        col = _ident(spec.measure.column)
        unit = _ident(f"_{spec.dataset}_u")
        gsel = ", ".join(_ident(g) for g in spec.group_by)
        gpre = (gsel + ", ") if spec.group_by else ""
        inner = (f"SELECT {gpre}donor_id, SUM({col}) AS c FROM {unit}{where} "  # nosec B608
                 f"GROUP BY {gpre}donor_id")
        outer = (f"SELECT {gpre}MAX(c) / NULLIF(SUM(c), 0) AS dominance "       # nosec B608
                 f"FROM ({inner}) t" + (f" GROUP BY {gsel}" if spec.group_by else ""))
        dom = self.con.execute(outer, params).df()
        if spec.group_by:
            result = result.merge(dom, on=spec.group_by, how="left")
        else:
            result = result.assign(dominance=(dom["dominance"].iloc[0] if len(dom) else 0.0))
        result["dominance"] = result["dominance"].fillna(0.0)
        return result
