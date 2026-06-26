"""Read-only query engine: a validated QuerySpec -> parameterised DuckDB SQL.

Security properties:
- Identifiers (table/column names) come ONLY from the validated allowlist and
  are additionally regex-checked before quoting — never from raw user text.
- Filter *values* are always passed as bound parameters (no string building),
  so injection is impossible.
- The exposed views select only allowlisted columns, so donor_id / free_text /
  timestamps are not present in the query surface at all (defence in depth).
- Every result carries an `n` count column for the disclosure gateway.
"""

from __future__ import annotations

import re

import duckdb
import pandas as pd

from .query import QuerySpec

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")

# Views expose ONLY allowlisted columns. donor_id/free_text/ts never appear.
_VIEWS = {
    "spend": """
        CREATE VIEW spend AS
        SELECT d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               a.genre, a.contains_lootboxes, a.price_tier, a.age_rating,
               e.event_type, e.amount_chf, e.ingame_currency
        FROM events e
        JOIN donors d ON e.donor_id = d.donor_id
        JOIN apps a   ON e.app_id   = a.app_id
    """,
    "wellbeing": """
        CREATE VIEW wellbeing AS
        SELECT d.age_band, d.sex, d.canton, d.income_band, d.device_os,
               s.wave, s.pgsi_score, s.igds_score, s.wemwbs_score,
               s.monthly_spend_selfreport
        FROM survey s
        JOIN donors d ON s.donor_id = d.donor_id
    """,
}


def _ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"illegal identifier {name!r}")  # belt-and-braces
    return f'"{name}"'


class QueryEngine:
    def __init__(self, tables: dict[str, pd.DataFrame]):
        self.con = duckdb.connect(database=":memory:")
        for name, df in tables.items():
            self.con.register(name, df)
        for ddl in _VIEWS.values():
            self.con.execute(ddl)

    def run(self, spec: QuerySpec) -> pd.DataFrame:
        select = [_ident(g) for g in spec.group_by]
        if spec.measure.fn == "count":
            select.append("COUNT(*) AS value")
        else:
            # fn is a Literal allowlist; column is allowlist- and regex-validated
            select.append(f"{spec.measure.fn.upper()}({_ident(spec.measure.column)}) AS value")  # nosec B608
        select.append("COUNT(*) AS n")

        # identifiers are allowlist+regex validated; all values are bound params below
        sql = f"SELECT {', '.join(select)} FROM {_ident(spec.dataset)}"  # nosec B608
        params: list = []
        clauses: list[str] = []
        for f in spec.filters:
            col = _ident(f.column)
            if f.op == "in":
                placeholders = ", ".join("?" for _ in f.value)
                clauses.append(f"{col} IN ({placeholders})")
                params.extend(f.value)
            else:
                clauses.append(f"{col} {f.op} ?")   # nosec B608 - op is a Literal allowlist; value is bound
                params.append(f.value)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        if spec.group_by:
            sql += " GROUP BY " + ", ".join(_ident(g) for g in spec.group_by)
        sql += " ORDER BY n DESC"

        result = self.con.execute(sql, params).df()
        if spec.measure.fn in ("mean", "sum"):
            result["value"] = result["value"].round(2)
        return result
