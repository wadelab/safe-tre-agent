"""The `normality` model procedure (spec R15) — a Jarque-Bera normality test
of a gaussian response within each level of a factor, from vetted cells.

Like the `anova` tool, this is a function of per-group moments — but the first
FOUR. From the FINALIZED (gateway-vetted, rounded) sums per group:

    n, S1 = Σx, S2 = Σx², S3 = Σx³, S4 = Σx⁴   (sum / sum_sq / sum_cube / sum_quad)

the central moments and shape statistics follow deterministically:

    m  = S1/n
    m2 = S2/n − m²
    m3 = S3/n − 3·m·S2/n + 2·m³
    m4 = S4/n − 4·m·S3/n + 6·m²·S2/n − 3·m⁴
    skewness g1 = m3 / m2^1.5
    kurtosis g2 = m4 / m2² − 3            (excess; 0 for a normal)
    JB = n/6 (g1² + g2²/4)                p = P(chi²₂ > JB)   (stats.jarque_bera)

Each of the four sums is an ordinary `QuerySpec`, so the disclosure claim is
inherited from the gateway: min-donor threshold, rounding, lineage and budget
apply cell by cell, and a suppressed moment cell denies the whole test (P19).
The third moment is SIGNED and the fourth is more concentrated than the square,
so their cells carry the tighter, signed-aware dominance witness (`moment3` /
`moment4` disclosure classes). Every output reproduces from the released `cells`
frame (P21), so an analyst outside the safepod re-derives the whole table.

Numerical note: the central moments are formed from raw power sums, which is
subject to cancellation when the values are large relative to their spread; it
is exact enough for a 3-dp p-value on moderate-magnitude responses and degrades
for extreme-magnitude ones. A mean-centred two-pass variant is the follow-up.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from .glm import _term_levels
from .procedures import MODEL_REGISTRY, DisclosureClass, ModelProcedure
from .query import NormalitySpec, QuerySpec
from .stats import jarque_bera


class NormalityProcedure(ModelProcedure):
    tool = "normality"

    def validate(self, raw: dict) -> NormalitySpec:
        return NormalitySpec(**raw)

    def plan_aggregates(self, spec: NormalitySpec) -> list[QuerySpec]:
        base = dict(dataset=spec.dataset, group_by=[spec.factor],
                    filters=[f.model_copy() for f in spec.filters])
        return [QuerySpec(measure={"fn": fn, "column": spec.response}, **base)
                for fn in ("sum", "sum_sq", "sum_cube", "sum_quad")]

    def table_roles(self, spec: NormalitySpec) -> tuple[str, ...]:
        return ("sum", "sum_sq", "sum_cube", "sum_quad")

    def preconditions(self, finalized: dict[str, pd.DataFrame], spec: NormalitySpec) -> list[str]:
        problems: list[str] = []
        groups = finalized["sum"]
        if groups.empty:
            return ["no groups match the requested cohort"]
        levels = _term_levels(groups, [spec.factor])[spec.factor]
        if len(levels) < 1:
            problems.append(f"factor {spec.factor!r} has no observed level")
        for role, table in finalized.items():
            if "value" in table.columns and table["value"].isna().any():
                problems.append(f"a group has no measurable {spec.response!r} value")
                break
        key_sets = {role: set(finalized[role][spec.factor]) for role in self.table_roles(spec)}
        if any(key_sets[r] != key_sets["sum"] for r in self.table_roles(spec)):
            problems.append("underlying moment aggregates disagree on the groups")
        return problems

    def fit(self, finalized: dict[str, pd.DataFrame], spec: NormalitySpec
            ) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
        cells = self._assemble_cells(finalized, spec)
        rows = []
        for _, c in cells.iterrows():
            n = float(c["n"])
            s1, s2, s3, s4 = (float(c["sum"]), float(c["sum_sq"]),
                              float(c["sum_cube"]), float(c["sum_quad"]))
            g1, g2, jb, p = self._shape(n, s1, s2, s3, s4)
            rows.append({spec.factor: c[spec.factor], "n": int(round(n)),
                         "skewness": round(g1, 4), "kurtosis": round(g2, 4),
                         "jarque_bera": round(jb, 4), "df": 2, "p_value": round(p, 3)})
        table = pd.DataFrame(rows)
        model = pd.DataFrame([{
            "response": spec.response, "factor": spec.factor,
            "n": int(round(float(cells["n"].sum()))), "n_groups": len(cells),
        }])
        return table, {"cells": cells, "model": model}

    @staticmethod
    def _shape(n: float, s1: float, s2: float, s3: float, s4: float
               ) -> tuple[float, float, float, float]:
        """Skewness, excess kurtosis, Jarque-Bera and p from the raw power sums.

        Degenerate (a non-positive variance after rounding, or too few
        observations for a fourth moment) degrades to nan rather than raising.
        """
        if n < 4:
            return (float("nan"),) * 4
        m = s1 / n
        m2 = s2 / n - m * m
        if not (m2 > 0):
            return (float("nan"),) * 4
        m3 = s3 / n - 3.0 * m * (s2 / n) + 2.0 * m ** 3
        m4 = s4 / n - 4.0 * m * (s3 / n) + 6.0 * m * m * (s2 / n) - 3.0 * m ** 4
        g1 = m3 / m2 ** 1.5
        g2 = m4 / (m2 * m2) - 3.0
        jb, p = jarque_bera(n, g1, g2)
        return g1, g2, jb, p

    def _assemble_cells(self, finalized: dict[str, pd.DataFrame], spec: NormalitySpec
                        ) -> pd.DataFrame:
        roles = self.table_roles(spec)
        cells = finalized["sum"].rename(columns={"value": "sum"})
        for role in roles[1:]:
            t = finalized[role].rename(columns={"value": role})
            cells = cells.merge(t[[spec.factor, role]], on=spec.factor, how="inner")
        return cells.sort_values(spec.factor).reset_index(drop=True)

    def output_contract(self, spec: NormalitySpec) -> dict[str, dict[str, DisclosureClass]]:
        return {
            "output": {spec.factor: "cell_key", "n": "count",
                       "skewness": "statistic", "kurtosis": "statistic",
                       "jarque_bera": "statistic", "df": "statistic",
                       "p_value": "p_value"},
            "cells": {spec.factor: "cell_key", "n": "count", "sum": "magnitude",
                      "sum_sq": "moment2", "sum_cube": "moment3", "sum_quad": "moment4"},
            "model": {"response": "cell_key", "factor": "cell_key",
                      "n": "count", "n_groups": "count"},
        }

    def model_key(self, spec: NormalitySpec) -> str:
        return spec.model_key()

    def skeleton(self, catalogue: dict) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for dataset in sorted(catalogue):
            cat = catalogue[dataset]
            dims = sorted(cat["dims"])
            for response, fams in sorted(cat.get("glm_responses", {}).items()):
                if "gaussian" not in fams:
                    continue
                for factor in dims:
                    if factor != response:
                        out.append({"tool": "normality", "dataset": dataset,
                                    "response": response, "factor": factor})
        return out


def refit_from_artifact(cells: pd.DataFrame, spec: NormalitySpec
                        ) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
    """Reproduce a released normality table from its released cell table alone
    (the P21 claim in executable form; mirrors anova.refit_from_artifact)."""
    finalized = {role: cells[[spec.factor, role, "n"]].rename(columns={role: "value"})
                 for role in ("sum", "sum_sq", "sum_cube", "sum_quad")}
    return NormalityProcedure().fit(finalized, spec)


MODEL_REGISTRY[NormalityProcedure.tool] = NormalityProcedure()
