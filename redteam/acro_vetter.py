"""ACRO's checks, expressed as a `CellVetter` (roadmap item 1, rollout step 2).

This is the rule half of the integration design (`docs/acro-integration.md`):
ACRO's own implementations, wrapped in the seam the gateway now vets through,
so the comparison harness runs both rule sets across one interface rather than
two bespoke code paths.

It is **not** the production path, and deliberately lives in `redteam/` rather
than `safetre/`. ACRO 0.4.x pins `pandas < 3` and cannot be imported into the
service environment at all (C3), so in production the checker runs out of
process behind the boundary of §4 of the design — this in-process vetter is
what that boundary will call, and what proves the rule mapping is right in the
meantime.

Two honest limits of this stage:

- **ACRO decides with its own configuration, not ours.** `VettingParameters`
  is ignored: ACRO's threshold, p%-rule and NK-rule use its defaults, which is
  what the comparison wants (rule set against rule set, each as its authors
  configured it). Making the parameters a function of the released column's
  disclosure class is §3 of the design, and is not done here.
- **Egress checks are not ACRO's job.** `deny` is never set: identifier
  egress, free text and un-aggregated sensitive columns are the stand-in
  vetter's rules and stay with it. A composite runs both.
"""

from __future__ import annotations

import pandas as pd

from safetre.disclosure import (
    CellVetter, Finding, Verdicts, VettingParameters, _group_columns,
)

# ACRO's aggregation name per measure function; a `count` cell needs none
AGGFUNC = {"sum": "sum", "mean": "mean", "sum_sq": "sum"}
RELEASE = "ok"


def cell_key(row, keys: list[str]) -> tuple:
    """The cell's identity: its group-by values as strings, or the single
    `total` cell when a query has no group-by."""
    return tuple(str(row[k]) for k in keys) if keys else ("total",)


class AcroVetter(CellVetter):
    """Vets a cell table with ACRO's real check implementations.

    The donor-level contribution frame is supplied at construction rather than
    through `vet`, because it is not derivable from the cell table: ACRO's
    threshold counts donors and its dominance rules need each donor's share,
    neither of which survives aggregation. In production that frame crosses
    the process boundary with the request; here the harness passes the one it
    already builds.
    """

    name = "acro"

    def __init__(self, contributions: pd.DataFrame, keys: list[str],
                 aggfunc: str | None):
        self.contributions = contributions
        self.keys = list(keys)
        self.aggfunc = aggfunc

    def decisions(self) -> dict[tuple, str]:
        """ACRO's per-cell verdicts: cell key -> the rules it failed, or `ok`.

        Consumes ACRO's own check masks (`create_crosstab_masks`) rather than
        `ACRO.crosstab`, because of C1 (docs/acro-comparison.md): 0.4.12's
        crosstab deletes empty and all-zero rows from the values table while
        building its masks from the raw series, and the misaligned frames make
        its own `apply_suppression` raise. The masks ARE the decisions, so the
        verdict is composed from them exactly as `apply_suppression` would.
        """
        from acro.acro_tables import create_crosstab_masks, get_aggfuncs

        frame = self.contributions
        const = pd.Series(["all"] * len(frame), index=frame.index, name="total")
        dims = [frame[k] for k in self.keys]
        if len(dims) == 0:
            index, columns = const, const.rename("t2")
        elif len(dims) == 1:
            index, columns = dims[0], const
        else:
            index, columns = dims[:-1] if len(dims) > 2 else dims[0], dims[-1]
        values = frame["v"] if self.aggfunc else None
        aggfunc = get_aggfuncs(self.aggfunc) if self.aggfunc else None
        masks = create_crosstab_masks(index, columns, values, None, None, aggfunc,
                                      False, "All", True, False)

        verdicts: dict[tuple, str] = {}
        for rule, mask in masks.items():
            for row_key, row in mask.iterrows():
                for col_key, hit in row.items():
                    parts = row_key if isinstance(row_key, tuple) else (row_key,)
                    if len(self.keys) >= 2:
                        # with an aggfunc the mask columns are a MultiIndex of
                        # (aggregation, column value); the key wants the value
                        col = col_key[-1] if isinstance(col_key, tuple) else col_key
                        parts = parts + (col,)
                    key = (tuple(str(p) for p in parts) if self.keys else ("total",))
                    if pd.notna(hit) and bool(hit):
                        verdicts[key] = verdicts.get(key, "") + f"{rule}; "
                    else:
                        verdicts.setdefault(key, "")
        return {k: (v.strip() if v else RELEASE) for k, v in verdicts.items()}

    def vet(self, df: pd.DataFrame, params: VettingParameters) -> Verdicts:
        verdicts = self.decisions()
        keys = self.keys or _group_columns(df)
        suppress, fired, unknown = [], {}, 0
        for _, row in df.iterrows():
            rule = verdicts.get(cell_key(row, keys))
            if rule is None:
                # a cell ACRO returned no verdict for is a cell nothing
                # checked: suppress it rather than assume it is safe
                unknown += 1
                suppress.append(True)
                continue
            if rule == RELEASE:
                suppress.append(False)
                continue
            suppress.append(True)
            for name in (r.strip() for r in rule.split(";") if r.strip()):
                fired[name] = fired.get(name, 0) + 1

        findings = [Finding("high", f"acro_{name}",
                            f"{count} cell(s) failed ACRO's {name}")
                    for name, count in sorted(fired.items())]
        if unknown:
            findings.append(Finding("high", "acro_unchecked",
                                    f"{unknown} cell(s) received no ACRO verdict"))
        return Verdicts(suppress=pd.Series(suppress, index=df.index, dtype=bool),
                        findings=findings, deny=False)
