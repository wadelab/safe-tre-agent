"""The `glm` model procedure (spec R15) — GLMs fitted from vetted cells only.

Cells-first, strict post-processing: a GLMSpec compiles to ordinary design-cell
QuerySpecs (`group_by = terms`); each passes the existing gateway (threshold,
dominance, fail-closed, rounding, suppression) exactly as if the analyst had
asked for it by hand; and the IRLS fitter consumes the FINALIZED tables and
nothing else. The released model is therefore a deterministic function of
released-equivalent data — the disclosure claim is inherited from the gateway,
not re-argued per statistic — and the analyst can reproduce the fit from the
released cell table (P21, machine-checked by the reproducibility meta-test).

Consequences worth stating plainly:

- Any suppressed design cell denies the whole model, loudly (P19). No category
  merging, no cell dropping. For a binomial model that includes cells whose
  *successes* count is sub-threshold: a released count table would suppress
  them, so the model is denied too. A cell absent from the successes table
  because it has zero successes is not suppression — absence is visible in the
  equivalent released table — and enters the fit as k = 0.
- A saturated model is harmless here: its fitted values reproduce the already
  released, rounded cell statistics; it can only re-express what the analyst
  holds.
- The price of fitting on finalized tables is that cell weights are the
  *rounded* counts; the distortion is deterministic, reproducible by the
  analyst, and measured (not asserted) by scripts/measure_rounding_distortion.py.
- Grouped-data identities make the cell fit exact, not approximate: WLS on
  cell means == row-level OLS; grouped binomial == Bernoulli; Poisson totals
  with log-exposure offset == row-level Poisson (see tests/test_glm_oracle.py).

Estimability refusals (grid completeness, aliasing, separation) are decided
from the finalized tables alone, so a refusal discloses nothing an analyst
could not compute from permitted queries (P22); messages name terms, never
quantities.
"""

from __future__ import annotations

import itertools
import math
from typing import Any

import pandas as pd

from .procedures import MODEL_REGISTRY, DisclosureClass, ModelProcedure
from .query import MAX_MODEL_TERMS, Filter, GLMSpec, QuerySpec
from .schema import declared_domain
from .stats import irls_cells, matrix_rank, normal_sf, student_t_sf

_CANONICAL_LINK = {"gaussian": "identity", "binomial": "logit", "poisson": "log"}

# per-family finalized-table roles (the keys of the `finalized` dict)
_TABLE_ROLES = {
    "gaussian": ("mean", "sum_sq"),
    "binomial": ("trials", "successes"),
    "poisson": ("sum",),
}


class GLMProcedure(ModelProcedure):
    tool = "glm"

    # --- O1: admissibility ------------------------------------------------------
    def validate(self, raw: dict) -> GLMSpec:
        return GLMSpec(**raw)

    # --- the design-cell queries (O2/O3/O4 inherited) ----------------------------
    def plan_aggregates(self, spec: GLMSpec) -> list[QuerySpec]:
        base = dict(dataset=spec.dataset, group_by=list(spec.terms),
                    filters=[f.model_copy() for f in spec.filters])
        if spec.family == "gaussian":
            return [
                QuerySpec(measure={"fn": "mean", "column": spec.response}, **base),
                QuerySpec(measure={"fn": "sum_sq", "column": spec.response}, **base),
            ]
        if spec.family == "binomial":
            successes = dict(base, filters=base["filters"] + [
                Filter(column=spec.response, op="==", value=True)])
            return [
                QuerySpec(measure={"fn": "count"}, **base),        # trials
                QuerySpec(measure={"fn": "count"}, **successes),   # successes
            ]
        return [QuerySpec(measure={"fn": "sum", "column": spec.response}, **base)]

    def table_roles(self, spec: GLMSpec) -> tuple[str, ...]:
        return _TABLE_ROLES[spec.family]

    def optional_roles(self, spec: GLMSpec) -> frozenset[str]:
        """The gaussian dispersion cells, and only those.

        Coefficients come from the vetted mean cells and counts alone; the
        sums of squares buy standard errors, t, p and R². Squaring is not
        share-preserving, so that table faces a far tighter dominance bound in
        effect than the means do (see `VettingParameters.dominance_for`) and
        is what refuses most gaussian models. Releasing the point estimates
        without inference releases strictly less than the model would have,
        and nothing derived from the withheld table goes out.

        Not the binomial or poisson tables, which the fit cannot proceed
        without — and not ANOVA's, which IS a variance decomposition.
        """
        return frozenset({"sum_sq"}) if spec.family == "gaussian" else frozenset()

    # --- estimability, decided from finalized tables alone (P22) -----------------
    def preconditions(self, finalized: dict[str, pd.DataFrame], spec: GLMSpec) -> list[str]:
        problems: list[str] = []
        primary = finalized[self.table_roles(spec)[0]]
        if primary.empty:
            return ["no design cells match the requested cohort"]

        levels = _term_levels(primary, spec.terms)
        for term, observed in levels.items():
            if len(observed) < 2:
                problems.append(
                    f"term {term!r} has a single observed level — nothing to estimate")

        # full grid over observed levels (P19): a partially observed cross
        # would silently change what the coefficients mean, so refuse instead.
        expected = math.prod(len(v) for v in levels.values())
        if len(primary) != expected:
            problems.append(
                "design grid is incomplete over the observed levels of "
                f"{', '.join(repr(t) for t in spec.terms)} — refusing rather than "
                "fitting a silently unbalanced design")

        # a cell whose response is unmeasurable poisons the fit
        for role, table in finalized.items():
            if "value" in table.columns and table["value"].isna().any():
                problems.append(
                    f"a design cell has no measurable {spec.response!r} value")
                break

        # paired tables must describe the same cells (binomial successes are
        # exempt: absence there means k = 0, which the release itself shows)
        if spec.family == "gaussian" and "sum_sq" in finalized:
            key_sets = {
                role: set(map(tuple, finalized[role][list(spec.terms)].values))
                for role in ("mean", "sum_sq")
            }
            if key_sets["mean"] != key_sets["sum_sq"]:
                problems.append("underlying aggregates disagree on the design cells")

        if not problems:
            design, _, _ = _design_matrix(primary, spec.terms, levels)
            p = len(design[0])
            if matrix_rank(design) < p:
                problems.append(
                    f"model terms {', '.join(repr(t) for t in spec.terms)} are "
                    "aliased on this cohort — coefficients are not identifiable")

        if spec.family == "binomial" and not problems:
            merged = _merge_binomial(finalized)
            for term in spec.terms:
                margins = merged.groupby(term, observed=True)[["k", "n"]].sum()
                pure = margins[(margins["k"] == 0) | (margins["k"] == margins["n"])]
                if not pure.empty:
                    problems.append(
                        f"term {term!r} separates the response (a level with all or "
                        "no successes) — its coefficient is unestimable")
        return problems

    # --- the fit: a pure function of the finalized tables (P21) ------------------
    def fit(self, finalized: dict[str, pd.DataFrame], spec: GLMSpec
            ) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
        cells = self._assemble_cells(finalized, spec)
        levels = _term_levels(cells, spec.terms)
        design, names, _ = _design_matrix(cells, spec.terms, levels)
        p = len(design[0])
        n_total = float(cells["n"].sum())
        n_cells = len(cells)

        if spec.family == "gaussian":
            result = irls_cells(design, [float(v) for v in cells["mean"]],
                                [float(v) for v in cells["n"]], "gaussian")
            if "sum_sq" not in cells.columns:
                # no dispersion, so no standard error, no t, no p and no R².
                # The estimates are a function of the vetted mean cells alone,
                # which is what makes them releasable without it.
                coef = pd.DataFrame({
                    "term": [t for t, _ in names],
                    "level": [lv for _, lv in names],
                    "estimate": [round(b, 4) for b in result.beta],
                })
                model = pd.DataFrame([{
                    "family": spec.family, "link": _CANONICAL_LINK[spec.family],
                    "response": spec.response, "n": int(n_total),
                    "n_cells": n_cells, "params": p,
                    "df_resid": round(n_total - p, 4),
                    "dispersion_released": False,
                }])
                return coef, {"cells": cells, "model": model}
            # dispersion from the within-cell scatter the sum_sq cells carry,
            # plus the between-cell lack of fit. Tiny negatives are rounding
            # artefacts of the finalized (2 dp / base-5) inputs; the floor at 0
            # is deterministic from released data, so reproducibility holds.
            within = float(sum(
                max(0.0, ss - n * m * m)
                for ss, n, m in zip(cells["sum_sq"], cells["n"], cells["mean"])))
            lack = result.deviance
            df_resid = n_total - p
            if df_resid <= 0:
                raise ValueError("no residual degrees of freedom")
            dispersion = (within + lack) / df_resid
            se = [math.sqrt(dispersion * result.cov_unscaled[i][i]) for i in range(p)]
            stats = [b / s if s > 0 else float("nan") for b, s in zip(result.beta, se)]
            p_values = [2.0 * student_t_sf(abs(t), df_resid) for t in stats]
            grand_mean = float(sum(n * m for n, m in zip(cells["n"], cells["mean"]))) / n_total
            tss = float(sum(cells["sum_sq"])) - n_total * grand_mean * grand_mean
            extra = {
                "df_resid": df_resid,
                "deviance": within + lack,
                "r_squared": 1.0 - (within + lack) / tss if tss > 0 else float("nan"),
            }
        elif spec.family == "binomial":
            result = irls_cells(design, [k / n for k, n in zip(cells["k"], cells["n"])],
                                [float(v) for v in cells["n"]], "binomial")
            se = [math.sqrt(result.cov_unscaled[i][i]) for i in range(p)]
            stats = [b / s if s > 0 else float("nan") for b, s in zip(result.beta, se)]
            p_values = [2.0 * normal_sf(abs(z)) for z in stats]
            extra = {"df_resid": float(n_cells - p), "deviance": result.deviance}
        else:  # poisson
            result = irls_cells(design, [float(v) for v in cells["sum"]],
                                [1.0] * n_cells, "poisson",
                                offset=[math.log(float(v)) for v in cells["n"]])
            se = [math.sqrt(result.cov_unscaled[i][i]) for i in range(p)]
            stats = [b / s if s > 0 else float("nan") for b, s in zip(result.beta, se)]
            p_values = [2.0 * normal_sf(abs(z)) for z in stats]
            extra = {"df_resid": float(n_cells - p), "deviance": result.deviance}

        coef = pd.DataFrame({
            "term": [t for t, _ in names],
            "level": [lv for _, lv in names],
            "estimate": [round(b, 4) for b in result.beta],
            "std_error": [round(s, 4) for s in se],
            "statistic": [round(t, 4) for t in stats],
            "p_value": [round(v, 3) for v in p_values],
        })
        model = pd.DataFrame([{
            "family": spec.family,
            "link": _CANONICAL_LINK[spec.family],
            "response": spec.response,
            "n": int(n_total),          # a sum of finalized (rounded) counts
            "n_cells": n_cells,
            "params": p,
            **{k: (round(v, 4) if isinstance(v, float) else v)
               for k, v in extra.items()},
        }])
        return coef, {"cells": cells, "model": model}

    def _assemble_cells(self, finalized: dict[str, pd.DataFrame], spec: GLMSpec
                        ) -> pd.DataFrame:
        """One deterministic frame holding everything the fit consumes — also
        the released `cells` artifact, so fit input and release coincide by
        construction."""
        keys = list(spec.terms)
        if spec.family == "gaussian":
            cells = finalized["mean"].rename(columns={"value": "mean"})
            if "sum_sq" in finalized:
                ss = finalized["sum_sq"].rename(columns={"value": "sum_sq"})
                cells = cells.merge(ss[keys + ["sum_sq"]], on=keys, how="inner")
        elif spec.family == "binomial":
            cells = _merge_binomial(finalized)
        else:
            cells = finalized["sum"].rename(columns={"value": "sum"})
        return cells.sort_values(keys).reset_index(drop=True)

    # --- contract + identity -------------------------------------------------------
    def output_contract(self, spec: GLMSpec) -> dict[str, dict[str, DisclosureClass]]:
        cell_cols: dict[str, DisclosureClass] = {t: "cell_key" for t in spec.terms}
        cell_cols["n"] = "count"
        if spec.family == "gaussian":
            cell_cols |= {"mean": "magnitude", "sum_sq": "moment2"}
        elif spec.family == "binomial":
            cell_cols |= {"k": "count"}
        else:
            cell_cols |= {"sum": "magnitude"}
        return {
            "output": {"term": "cell_key", "level": "cell_key",
                       "estimate": "statistic", "std_error": "statistic",
                       "statistic": "statistic", "p_value": "p_value"},
            "cells": cell_cols,
            "model": {"family": "cell_key", "link": "cell_key",
                      "response": "cell_key", "n": "count", "n_cells": "count",
                      "params": "count", "df_resid": "statistic",
                      "deviance": "statistic", "r_squared": "statistic",
                      "dispersion_released": "cell_key"},
        }

    def model_key(self, spec: GLMSpec) -> str:
        return spec.model_key()

    def skeleton(self, catalogue: dict) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for dataset in sorted(catalogue):
            cat = catalogue[dataset]
            dims = sorted(cat["dims"])
            for response in sorted(cat.get("glm_responses", {})):
                candidates = [d for d in dims if d != response]
                for family in sorted(cat["glm_responses"][response]):
                    for k in range(1, MAX_MODEL_TERMS + 1):
                        for terms in itertools.combinations(candidates, k):
                            out.append({"tool": "glm", "dataset": dataset,
                                        "family": family, "response": response,
                                        "terms": list(terms)})
        return out


def _term_levels(cells: pd.DataFrame, terms: list[str]) -> dict[str, list[Any]]:
    """Observed levels per term, ordered by the declared domain where one
    exists (deterministic reference levels), else sorted."""
    levels: dict[str, list[Any]] = {}
    for term in terms:
        observed = set(cells[term])
        domain = declared_domain(term)
        if domain:
            ordered = [v for v in domain if v in observed]
            ordered += sorted(v for v in observed if v not in set(domain))
        else:
            ordered = sorted(observed)
        levels[term] = ordered
    return levels


def _design_matrix(cells: pd.DataFrame, terms: list[str],
                   levels: dict[str, list[Any]]
                   ) -> tuple[list[list[float]], list[tuple[str, str]], list[Any]]:
    """Treatment-coded main-effects design over the cell rows, plus the
    (term, level) name of each column; the first level of each term is the
    reference."""
    names: list[tuple[str, str]] = [("(intercept)", "")]
    design: list[list[float]] = []
    for term in terms:
        names += [(term, str(lv)) for lv in levels[term][1:]]
    for _, row in cells.iterrows():
        x = [1.0]
        for term in terms:
            x += [1.0 if row[term] == lv else 0.0 for lv in levels[term][1:]]
        design.append(x)
    return design, names, list(cells.index)


def _merge_binomial(finalized: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """trials ⋈ successes with absent success cells entering as k = 0 — the
    absence of a cell from a released count table is public-equivalent
    information (the equivalent hand query shows the same absence)."""
    trials = finalized["trials"].rename(columns={"n": "n"})
    keys = [c for c in trials.columns if c != "n"]
    successes = finalized["successes"].rename(columns={"n": "k"})
    merged = trials.merge(successes[keys + ["k"]], on=keys, how="left")
    merged["k"] = merged["k"].fillna(0).astype(int)
    return merged


def refit_from_artifact(cells: pd.DataFrame, spec: GLMSpec
                        ) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
    """Reproduce a released fit from its released cell table alone.

    This IS the P21 claim in executable form: an analyst outside the safepod,
    holding only the released artifacts, runs this exact function and obtains
    the released coefficients bit-for-bit. The reproducibility meta-test
    asserts exactly that over the enumerated skeleton.
    """
    keys = list(spec.terms)
    if spec.family == "gaussian":
        finalized = {
            "mean": cells[keys + ["mean", "n"]].rename(columns={"mean": "value"}),
        }
        if "sum_sq" in cells.columns:
            finalized["sum_sq"] = (cells[keys + ["sum_sq", "n"]]
                                   .rename(columns={"sum_sq": "value"}))
    elif spec.family == "binomial":
        finalized = {
            "trials": cells[keys + ["n"]].copy(),
            "successes": cells[keys + ["k"]].rename(columns={"k": "n"}),
        }
    else:
        finalized = {
            "sum": cells[keys + ["sum", "n"]].rename(columns={"sum": "value"}),
        }
    return GLMProcedure().fit(finalized, spec)


MODEL_REGISTRY[GLMProcedure.tool] = GLMProcedure()
