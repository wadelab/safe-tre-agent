"""The `series` model procedure (spec R15) — a time series from vetted windows.

The second worked example of the procedure framework, and the first one that
is not a regression. A time series here is a **vetted per-window aggregate**:
the `stat` (mean or sum) of one measure, grouped by a dimension the dataset
definition DECLARES to be an ordered time axis (`month`, `wave`). That window
table is an ordinary QuerySpec — so it inherits the SafeSQL shape, the
dominance witnesses and the lineage identity (O2/O3/O4) — and it passes the
ordinary gateway, cell by cell. What this procedure adds is arithmetic on the
FINALIZED windows and nothing else:

    trend        OLS of value on window index: slope, intercept, R²
    acf          autocorrelation at lags 1..L, L = min(4, n_windows // 3)
    periodogram  |DFT of the demeaned series|² at frequencies 1..⌊n/2⌋;
                 the dominant period and its share of the spectral power

Every output is a deterministic function of released-equivalent cells, so the
disclosure claim is inherited from the gateway, not re-argued, and an analyst
holding the released `cells` frame (the series itself) reproduces every
diagnostic bit for bit (P21). Any suppressed window denies the whole series,
loudly (P19); a series too short to say anything, or with a gap, is refused
from the finalized table alone and names the axis, never a quantity (P22).

Deliberately stdlib-only, like `stats.py`: the fitter must not be able to
touch the engine, and a dependency is a door.
"""

from __future__ import annotations

import cmath
import math
from typing import Any

import pandas as pd

from .procedures import MODEL_REGISTRY, DisclosureClass, ModelProcedure
from .query import QuerySpec, SeriesSpec

MIN_WINDOWS = 4
MAX_LAGS = 4


class SeriesProcedure(ModelProcedure):
    tool = "series"

    # --- O1: admissibility ------------------------------------------------------
    def validate(self, raw: dict) -> SeriesSpec:
        return SeriesSpec(**raw)

    # --- the window query (O2/O3/O4 inherited: one ordinary QuerySpec) -----------
    def plan_aggregates(self, spec: SeriesSpec) -> list[QuerySpec]:
        return [QuerySpec(dataset=spec.dataset,
                          measure={"fn": spec.stat, "column": spec.response},
                          group_by=[spec.time],
                          filters=[f.model_copy() for f in spec.filters])]

    def table_roles(self, spec: SeriesSpec) -> tuple[str, ...]:
        return ("series",)

    # --- estimability, decided from the finalized table alone (P22) ---------------
    def preconditions(self, finalized: dict[str, pd.DataFrame], spec: SeriesSpec) -> list[str]:
        table = finalized["series"]
        if table.empty:
            return ["no windows match the requested cohort"]
        if "value" in table.columns and table["value"].isna().any():
            return [f"a window has no measurable {spec.response!r} value"]
        times = sorted(int(t) for t in table[spec.time])
        problems: list[str] = []
        if len(times) < MIN_WINDOWS:
            problems.append(
                f"the series over {spec.time!r} has fewer than {MIN_WINDOWS} windows — "
                "too short for a trend or an autocorrelation")
        if len(times) != len(set(times)):
            problems.append(f"the series over {spec.time!r} has a repeated window")
        elif times and times[-1] - times[0] + 1 != len(times):
            problems.append(
                f"the series over {spec.time!r} is not contiguous (a window in the "
                "requested range has no rows)")
        return problems

    # --- the fit: a pure function of the finalized table (P21) -------------------
    def fit(self, finalized: dict[str, pd.DataFrame], spec: SeriesSpec
            ) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
        cells = self._assemble_cells(finalized, spec)
        values = [float(v) for v in cells["value"]]
        diag = series_diagnostics(values)
        rows = [{"quantity": k, "value": v} for k, v in diag.items()]
        output = pd.DataFrame(rows)
        model = pd.DataFrame([{
            "response": spec.response, "time": spec.time, "stat": spec.stat,
            "n_windows": len(values),
            "n": int(cells["n"].sum()) if "n" in cells.columns else len(values),
            "first_window": int(cells[spec.time].iloc[0]),
            "last_window": int(cells[spec.time].iloc[-1]),
        }])
        return output, {"cells": cells, "model": model}

    def _assemble_cells(self, finalized: dict[str, pd.DataFrame], spec: SeriesSpec
                        ) -> pd.DataFrame:
        """The vetted window table, in time order — fit input and released
        artifact by construction."""
        table = finalized["series"]
        cols = [spec.time, "value"] + (["n"] if "n" in table.columns else [])
        return table[cols].sort_values(spec.time).reset_index(drop=True)

    # --- contract + identity -------------------------------------------------------
    def output_contract(self, spec: SeriesSpec) -> dict[str, dict[str, DisclosureClass]]:
        return {
            "output": {"quantity": "cell_key", "value": "statistic"},
            "cells": {spec.time: "cell_key", "value": "magnitude", "n": "count"},
            "model": {"response": "cell_key", "time": "cell_key", "stat": "cell_key",
                      "n_windows": "count", "n": "count",
                      "first_window": "cell_key", "last_window": "cell_key"},
        }

    def model_key(self, spec: SeriesSpec) -> str:
        return spec.model_key()

    def skeleton(self, catalogue: dict) -> list[dict[str, Any]]:
        from .schema import declared_domain
        out: list[dict[str, Any]] = []
        for dataset in sorted(catalogue):
            cat = catalogue[dataset]
            for time in sorted(cat.get("time_dims", [])):
                domain = declared_domain(time)
                if domain is not None and len(domain) < MIN_WINDOWS:
                    continue          # rejected at validation, so not admissible
                for response in sorted(cat["measures"]):
                    for stat in ("mean", "sum"):
                        out.append({"tool": "series", "dataset": dataset,
                                    "response": response, "time": time, "stat": stat})
        return out


# --------------------------------------------------------------------------- #
# numerics — stdlib only, deterministic rounding                                #
# --------------------------------------------------------------------------- #

def _round(x: float, places: int = 4) -> float:
    return float("nan") if (isinstance(x, float) and math.isnan(x)) else round(x, places)


def series_diagnostics(values: list[float]) -> dict[str, float]:
    """Trend, autocorrelation and periodogram of a short series.

    Pure: a list of floats in, a dict of rounded floats out. Zero-variance
    series get NaN where a ratio would divide by zero, deterministically.
    """
    n = len(values)
    mean = sum(values) / n
    dev = [v - mean for v in values]
    ss = sum(d * d for d in dev)
    sd = math.sqrt(ss / (n - 1)) if n > 1 else float("nan")

    # trend: OLS on the window index 0..n-1
    t_mean = (n - 1) / 2.0
    stt = sum((t - t_mean) ** 2 for t in range(n))
    sxy = sum((t - t_mean) * d for t, d in enumerate(dev))
    slope = sxy / stt if stt > 0 else float("nan")
    intercept = mean - slope * t_mean if not math.isnan(slope) else float("nan")
    r2 = (slope * slope * stt / ss) if (ss > 0 and not math.isnan(slope)) else float("nan")

    out: dict[str, float] = {
        "n_windows": float(n),
        "mean": _round(mean), "sd": _round(sd),
        "trend_slope": _round(slope), "trend_intercept": _round(intercept),
        "trend_r_squared": _round(r2),
    }

    # autocorrelation
    lags = min(MAX_LAGS, n // 3)
    for k in range(1, lags + 1):
        num = sum(dev[t] * dev[t + k] for t in range(n - k))
        out[f"acf_lag_{k}"] = _round(num / ss) if ss > 0 else float("nan")

    # periodogram of the demeaned series
    freqs = n // 2
    if freqs >= 1 and ss > 0:
        power = []
        for j in range(1, freqs + 1):
            z = sum(d * cmath.exp(-2j * math.pi * j * t / n) for t, d in enumerate(dev))
            power.append(abs(z) ** 2)
        total = sum(power)
        j_star = max(range(freqs), key=lambda i: (power[i], -i)) + 1
        out["dominant_period"] = _round(n / j_star)
        out["dominant_period_share"] = _round(power[j_star - 1] / total) if total > 0 else float("nan")
    else:
        out["dominant_period"] = float("nan")
        out["dominant_period_share"] = float("nan")
    return out


def refit_from_artifact(cells: pd.DataFrame, spec: SeriesSpec
                        ) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
    """Reproduce a released series' diagnostics from its released window table
    alone — the P21 claim in executable form (mirrors glm/anova)."""
    return SeriesProcedure().fit({"series": cells}, spec)


MODEL_REGISTRY[SeriesProcedure.tool] = SeriesProcedure()
