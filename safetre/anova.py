"""The `anova` model procedure (spec R15) — one-way ANOVA from vetted cells.

This is the *smallest possible* new statistical tool, kept deliberately simple
as a worked example of how the framework is extended (see
`docs/adding-a-statistical-tool.md`). It shows that adding a capability is
almost entirely a matter of new *numerics* and a new *output contract*: the
whole disclosure machinery — design-cell QuerySpecs, the gateway, the
fail-closed model path, reproducibility — is inherited unchanged.

A one-way ANOVA over factor A with a gaussian response Y is a function of the
per-group first two moments, which are exactly the aggregates the gaussian GLM
already plans:

    mean   : group cell means   (mean of Y per level of A)   -> ȳ_g
    sum_sq : group cell Σ(Y²)                                 -> S_g
    n      : group cell sizes                                 -> n_g   (from mean's n)

From the FINALIZED (gateway-vetted, rounded) versions of those cells alone:

    N          = Σ n_g            grand_mean ȳ = Σ n_g ȳ_g / N
    SS_between = Σ n_g (ȳ_g − ȳ)²                         df_between = k − 1
    SS_within  = Σ (S_g − n_g ȳ_g²)                       df_within  = N − k
    F          = (SS_between/df_between) / (SS_within/df_within)
    p          = P(F_{df_between, df_within} > F)          (stats.f_sf)

Every ANOVA output is therefore a deterministic function of released-equivalent
cells: the disclosure claim is inherited from the gateway, not re-argued, and
the analyst can reproduce the table from the released `cells` frame (P21). Any
suppressed group cell denies the whole model, loudly (P19); estimability
refusals (a single-level factor, no residual d.f.) are decided from the
finalized tables alone and name the factor, never a quantity (P22).
"""

from __future__ import annotations

import math
from typing import Any

import pandas as pd

from .glm import _term_levels
from .procedures import MODEL_REGISTRY, DisclosureClass, ModelProcedure
from .query import AnovaSpec, QuerySpec
from .stats import chi2_sf, f_sf


class AnovaProcedure(ModelProcedure):
    tool = "anova"

    # --- O1: admissibility ------------------------------------------------------
    def validate(self, raw: dict) -> AnovaSpec:
        return AnovaSpec(**raw)

    # --- the design-cell queries (O2/O3/O4 inherited, identical to gaussian GLM) --
    def plan_aggregates(self, spec: AnovaSpec) -> list[QuerySpec]:
        base = dict(dataset=spec.dataset, group_by=[spec.factor],
                    filters=[f.model_copy() for f in spec.filters])
        return [
            QuerySpec(measure={"fn": "mean", "column": spec.response}, **base),
            QuerySpec(measure={"fn": "sum_sq", "column": spec.response}, **base),
        ]

    def table_roles(self, spec: AnovaSpec) -> tuple[str, ...]:
        return ("mean", "sum_sq")

    # --- estimability, decided from finalized tables alone (P22) -----------------
    def preconditions(self, finalized: dict[str, pd.DataFrame], spec: AnovaSpec) -> list[str]:
        problems: list[str] = []
        groups = finalized["mean"]
        if groups.empty:
            return ["no groups match the requested cohort"]

        levels = _term_levels(groups, [spec.factor])[spec.factor]
        if len(levels) < 2:
            problems.append(
                f"factor {spec.factor!r} has a single observed level — a one-way "
                "ANOVA needs at least two groups to compare")

        for role, table in finalized.items():
            if "value" in table.columns and table["value"].isna().any():
                problems.append(
                    f"a group has no measurable {spec.response!r} value")
                break

        key_sets = {role: set(finalized[role][spec.factor]) for role in ("mean", "sum_sq")}
        if key_sets["mean"] != key_sets["sum_sq"]:
            problems.append("underlying aggregates disagree on the groups")

        if not problems:
            n_total = float(groups["n"].sum())
            if n_total - len(levels) <= 0:
                problems.append(
                    f"factor {spec.factor!r} leaves no residual degrees of freedom "
                    "(as many groups as observations)")
        return problems

    # --- the fit: a pure function of the finalized tables (P21) ------------------
    def fit(self, finalized: dict[str, pd.DataFrame], spec: AnovaSpec
            ) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
        cells = self._assemble_cells(finalized, spec)
        n = [float(v) for v in cells["n"]]
        mean = [float(v) for v in cells["mean"]]
        sum_sq = [float(v) for v in cells["sum_sq"]]

        n_total = sum(n)
        k = len(cells)
        grand_mean = sum(ni * mi for ni, mi in zip(n, mean)) / n_total

        ss_between = sum(ni * (mi - grand_mean) ** 2 for ni, mi in zip(n, mean))
        # within-group SS from the second moment; tiny negatives are rounding
        # artefacts of the finalized (2 dp) inputs, floored at 0 deterministically
        # so the analyst reproduces the same table from the released cells.
        ss_within = sum(max(0.0, si - ni * mi * mi)
                        for si, ni, mi in zip(sum_sq, n, mean))
        ss_total = ss_between + ss_within

        df_between = k - 1
        df_within = int(round(n_total)) - k
        ms_between = ss_between / df_between
        ms_within = ss_within / df_within if df_within > 0 else float("nan")
        f_stat = ms_between / ms_within if ms_within and ms_within > 0 else float("nan")
        p_value = f_sf(f_stat, df_between, df_within)
        eta_squared = ss_between / ss_total if ss_total > 0 else float("nan")

        # Bartlett's test of homogeneity of variance — the equal-variance
        # assumption a one-way ANOVA rests on. It is a function of the SAME
        # finalized cells: the per-group variances and the pooled variance
        # (which is exactly ms_within), so it inherits the gateway's disclosure
        # claim and reproduces from the released cells (P21). NaN where a group
        # variance is not positive after rounding, so it degrades to "not
        # computable" rather than crashing. (Bartlett, not Levene: Levene needs a
        # row-level |x-mean| transform; Bartlett is the moment-native test that
        # rides the cells ANOVA already vetted.)
        var_g = [max(0.0, si - ni * mi * mi) / (ni - 1.0) if ni > 1 else float("nan")
                 for si, ni, mi in zip(sum_sq, n, mean)]
        bartlett_chi2 = float("nan")
        bartlett_p = float("nan")
        if df_within > 0 and ms_within > 0 and all(v == v and v > 0 for v in var_g):
            num = df_within * math.log(ms_within) - sum(
                (ni - 1.0) * math.log(v) for ni, v in zip(n, var_g))
            correction = 1.0 + (sum(1.0 / (ni - 1.0) for ni in n) - 1.0 / df_within
                                ) / (3.0 * (k - 1))
            bartlett_chi2 = num / correction
            bartlett_p = chi2_sf(bartlett_chi2, k - 1)

        table = pd.DataFrame([
            {"source": spec.factor, "df": df_between,
             "sum_sq": round(ss_between, 4), "mean_sq": round(ms_between, 4),
             "statistic": round(f_stat, 4), "p_value": round(p_value, 3)},
            {"source": "Residual", "df": df_within,
             "sum_sq": round(ss_within, 4), "mean_sq": round(ms_within, 4),
             "statistic": float("nan"), "p_value": float("nan")},
        ])
        model = pd.DataFrame([{
            "response": spec.response,
            "factor": spec.factor,
            "n": int(round(n_total)),
            "n_groups": k,
            "grand_mean": round(grand_mean, 4),
            "eta_squared": round(eta_squared, 4),
            "df_between": df_between,
            "df_within": df_within,
            "bartlett_chi2": round(bartlett_chi2, 4),
            "bartlett_df": k - 1,
            "bartlett_p": round(bartlett_p, 3),
        }])
        return table, {"cells": cells, "model": model}

    def _assemble_cells(self, finalized: dict[str, pd.DataFrame], spec: AnovaSpec
                        ) -> pd.DataFrame:
        """The vetted per-group table — fit input and released artifact by
        construction (identical shape to the gaussian GLM's cells)."""
        cells = finalized["mean"].rename(columns={"value": "mean"})
        ss = finalized["sum_sq"].rename(columns={"value": "sum_sq"})
        cells = cells.merge(ss[[spec.factor, "sum_sq"]], on=spec.factor, how="inner")
        return cells.sort_values(spec.factor).reset_index(drop=True)

    # --- contract + identity -------------------------------------------------------
    def output_contract(self, spec: AnovaSpec) -> dict[str, dict[str, DisclosureClass]]:
        return {
            "output": {"source": "cell_key", "df": "statistic",
                       "sum_sq": "statistic", "mean_sq": "statistic",
                       "statistic": "statistic", "p_value": "p_value"},
            "cells": {spec.factor: "cell_key", "mean": "magnitude",
                      "n": "count", "sum_sq": "magnitude"},
            "model": {"response": "cell_key", "factor": "cell_key",
                      "n": "count", "n_groups": "count",
                      "grand_mean": "magnitude", "eta_squared": "statistic",
                      "df_between": "statistic", "df_within": "statistic",
                      "bartlett_chi2": "statistic", "bartlett_df": "statistic",
                      "bartlett_p": "p_value"},
        }

    def model_key(self, spec: AnovaSpec) -> str:
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
                        out.append({"tool": "anova", "dataset": dataset,
                                    "response": response, "factor": factor})
        return out


def refit_from_artifact(cells: pd.DataFrame, spec: AnovaSpec
                        ) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
    """Reproduce a released ANOVA table from its released cell table alone —
    the P21 claim in executable form (mirrors glm.refit_from_artifact)."""
    finalized = {
        "mean": cells[[spec.factor, "mean", "n"]].rename(columns={"mean": "value"}),
        "sum_sq": cells[[spec.factor, "sum_sq", "n"]].rename(columns={"sum_sq": "value"}),
    }
    return AnovaProcedure().fit(finalized, spec)


MODEL_REGISTRY[AnovaProcedure.tool] = AnovaProcedure()
