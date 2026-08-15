"""The `series` model procedure: release contract, fail-closed denials,
estimability, reproducibility, and numerical correctness.

The series tool (safetre/series.py) is the second worked example of adding a
statistical capability and the first non-regression one. These tests pin that
it inherits the R15/P19–P22 guarantees — the window table is an ordinary
QuerySpec that passes the gateway, a suppressed window denies the whole
series, a too-short axis is refused at the REQUEST from the public domain, a
gap is refused from the finalized table naming the axis and never a quantity,
and every diagnostic is reproducible from the released window table — plus
that trend, autocorrelation and periodogram agree with numpy.

The demo dataset has no admissible time axis (its `wave` declares two
windows), so the harness is the NIGHTPLAY study, whose `month` axis carries
twelve; the demo is used for the request-decided refusal.
"""

from __future__ import annotations

import json
import math
import pathlib

import numpy as np
import pandas as pd
import pytest

from safetre import dataset as dataset_mod
from safetre.planner import MockPlanner
from safetre.query import SeriesSpec
from safetre.series import (
    MIN_WINDOWS, SeriesProcedure, refit_from_artifact, series_diagnostics,
)
from studies.nightplay import generate as G
from studies.nightplay import verify as V

PACKAGED = pathlib.Path(dataset_mod.__file__).with_name("demo_dataset.yaml")


@pytest.fixture(scope="module")
def study():
    return G.generate(n_people=2500)


@pytest.fixture
def service(study):
    tables, _ = study
    dataset_mod.activate(dataset_mod.load_dataset(V.DEFINITION))
    try:
        yield V.build_service(tables)
    finally:
        dataset_mod.activate(dataset_mod.load_dataset(PACKAGED))


def _lit(service, spec):
    return service.handle(json.dumps(spec), planner=None)


STAKE_BY_MONTH = {"tool": "series", "dataset": "bets", "response": "stake_gbp",
                  "time": "month", "stat": "mean", "filters": []}


# --- released series: the R15 contract -----------------------------------------

def test_series_released_with_full_contract(service):
    r = _lit(service, STAKE_BY_MONTH)
    assert r.status == "released", r.message
    assert list(r.output.columns) == ["quantity", "value"]
    quantities = list(r.output["quantity"])
    assert quantities[:6] == ["n_windows", "mean", "sd", "trend_slope",
                              "trend_intercept", "trend_r_squared"]
    assert "acf_lag_1" in quantities and "dominant_period" in quantities
    assert set(r.artifacts) == {"cells", "model"}
    cells = r.artifacts["cells"]
    assert list(cells.columns) == ["month", "value", "n"]
    assert list(cells["month"]) == list(range(1, 13))
    assert (cells["n"] % 5 == 0).all() and (cells["n"] >= 10).all()
    model = r.artifacts["model"].iloc[0]
    assert model["n_windows"] == 12 and model["first_window"] == 1 and model["last_window"] == 12
    assert model["stat"] == "mean" and model["time"] == "month"


def test_released_series_is_reproducible_from_its_window_table(service):
    r = _lit(service, STAKE_BY_MONTH)
    spec = SeriesSpec(**STAKE_BY_MONTH)
    again, arts = refit_from_artifact(r.artifacts["cells"], spec)
    pd.testing.assert_frame_equal(again, r.output)
    pd.testing.assert_frame_equal(arts["model"], r.artifacts["model"])


def test_the_planted_seasonality_is_visible_in_the_released_series(service, study):
    """T5: stakes peak in June/July with a smaller December rise, so the
    dominant period of the released monthly mean stake is a half-year or a
    year and the peak windows are the planted ones."""
    r = _lit(service, dict(STAKE_BY_MONTH, dataset="bets"))
    cells = r.artifacts["cells"].set_index("month")["value"]
    assert int(cells.idxmax()) in (6, 7)
    diag = dict(zip(r.output["quantity"], r.output["value"]))
    assert diag["dominant_period"] in (4.0, 6.0, 12.0)


def test_sum_series_over_a_filtered_cohort_releases(service):
    r = _lit(service, {"tool": "series", "dataset": "panel", "response": "stake_gbp",
                       "time": "month", "stat": "sum",
                       "filters": [{"column": "region", "op": "==", "value": "London"}]})
    assert r.status == "released", r.message
    assert r.artifacts["model"].iloc[0]["stat"] == "sum"


# --- fail-closed and estimability -----------------------------------------------

def test_a_suppressed_window_denies_the_whole_series(service):
    r = _lit(service, {"tool": "series", "dataset": "panel", "response": "stake_gbp",
                       "time": "month", "stat": "mean",
                       "filters": [{"column": "region", "op": "==", "value": "Northern Ireland"}]})
    assert r.status == "denied" and r.output is None and r.artifacts is None


def test_a_two_window_axis_is_refused_at_the_request(service):
    """The demo's `wave` declares two windows: refused from the PUBLIC domain,
    at validation, naming the axis — no data touched, no canonical refusal."""
    dataset_mod.activate(dataset_mod.load_dataset(PACKAGED))
    with pytest.raises(ValueError, match="declares only 2 windows"):
        SeriesSpec(dataset="wellbeing", response="pgsi_score", time="wave")


def test_only_declared_time_axes_and_measures_are_admissible(service):
    with pytest.raises(ValueError, match="not a declared time axis"):
        SeriesSpec(dataset="bets", response="stake_gbp", time="product")
    with pytest.raises(ValueError, match="not a measure"):
        SeriesSpec(dataset="bets", response="product", time="month")
    with pytest.raises(ValueError, match="time axis cannot also be filtered"):
        SeriesSpec(dataset="bets", response="stake_gbp", time="month",
                   filters=[{"column": "month", "op": "==", "value": 3}])
    # a measure is not a filterable column at all, so the shared filter check
    # refuses it before the series-specific rule can
    with pytest.raises(ValueError, match="not a permitted dimension|response cannot also be filtered"):
        SeriesSpec(dataset="bets", response="stake_gbp", time="month",
                   filters=[{"column": "stake_gbp", "op": ">", "value": 3}])
    with pytest.raises(ValueError):
        SeriesSpec(dataset="bets", response="stake_gbp", time="month",
                   filters=[{"column": "person_id", "op": "==", "value": "P00001"}])


def test_gap_and_short_series_are_refused_from_the_finalized_table(service):
    proc = SeriesProcedure()
    spec = SeriesSpec(dataset="bets", response="stake_gbp", time="month")
    good = pd.DataFrame({"month": [1, 2, 3, 4, 5], "value": [1.0, 2.0, 3.0, 2.0, 1.0],
                         "n": [10] * 5})
    assert proc.preconditions({"series": good}, spec) == []
    gap = good[good["month"] != 3]
    problems = proc.preconditions({"series": gap}, spec)
    assert problems and "not contiguous" in problems[0] and "3" not in problems[0]
    short = good.head(MIN_WINDOWS - 1)
    problems = proc.preconditions({"series": short}, spec)
    assert problems and f"fewer than {MIN_WINDOWS}" in problems[0]
    nan = good.copy()
    nan.loc[2, "value"] = float("nan")
    assert "no measurable" in proc.preconditions({"series": nan}, spec)[0]


def test_plan_aggregates_are_valid_queryspecs_and_cost_one(service):
    proc = SeriesProcedure()
    spec = SeriesSpec(dataset="bets", response="stake_gbp", time="month", stat="sum",
                      filters=[{"column": "product", "op": "==", "value": "slots"}])
    aggs = proc.plan_aggregates(spec)
    assert len(aggs) == 1 and proc.cost(spec) == 1
    assert aggs[0].measure.fn == "sum" and aggs[0].group_by == ["month"]
    assert aggs[0].filters[0].column == "product"


def test_mock_planner_and_intent_gate_recognise_a_series_request(service):
    r = service.handle("monthly time series of mean stake", MockPlanner())
    # the mock plans against the demo vocabulary (spend.amount_gbp) which the
    # active NIGHTPLAY catalogue rejects — the point here is that the request
    # is in scope and reaches the model path rather than the intent gate
    assert "outside the supported" not in r.message


# --- numerical correctness ---------------------------------------------------------

def test_diagnostics_agree_with_numpy():
    rng = np.random.default_rng(3)
    v = list(10 + 3 * np.sin(2 * np.pi * np.arange(24) / 12) + rng.normal(0, 0.5, 24))
    d = series_diagnostics(v)
    x = np.array(v)
    t = np.arange(len(x))
    slope, intercept = np.polyfit(t, x, 1)
    assert math.isclose(d["trend_slope"], round(slope, 4), abs_tol=1e-4)
    assert math.isclose(d["trend_intercept"], round(intercept, 4), abs_tol=1e-4)
    dev = x - x.mean()
    ss = float((dev * dev).sum())
    for k in range(1, 5):
        acf = float((dev[:-k] * dev[k:]).sum() / ss)
        assert math.isclose(d[f"acf_lag_{k}"], round(acf, 4), abs_tol=1e-4)
    power = np.abs(np.fft.fft(dev)[1:len(x) // 2 + 1]) ** 2
    j = int(np.argmax(power)) + 1
    assert d["dominant_period"] == round(len(x) / j, 4) == 12.0
    assert math.isclose(d["dominant_period_share"], round(float(power[j - 1] / power.sum()), 4),
                        abs_tol=1e-4)
    assert d["n_windows"] == 24.0


def test_zero_variance_series_is_deterministic_nan_not_an_exception():
    d = series_diagnostics([5.0] * 8)
    assert math.isnan(d["acf_lag_1"]) and math.isnan(d["trend_r_squared"])
    assert d["trend_slope"] == 0.0 and math.isnan(d["dominant_period"])


def test_every_admissible_nightplay_series_releases_or_refuses_typed(service):
    """The tool's finite request space on the study that has a time axis:
    every skeleton point through the real service is a release whose
    diagnostics reproduce from its window table, or a typed refusal — never
    an exception, never a frame on a denial."""
    from safetre.query import CATALOGUE
    proc = SeriesProcedure()
    points = proc.skeleton(CATALOGUE)
    assert 20 <= len(points) <= 60, len(points)
    released = 0
    for point in points:
        r = _lit(service, point)
        assert r.status in ("released", "denied", "redacted"), (point, r.status)
        if r.status == "denied":
            assert r.output is None and r.artifacts is None
            continue
        released += 1
        again, _ = refit_from_artifact(r.artifacts["cells"], SeriesSpec(**point))
        pd.testing.assert_frame_equal(again, r.output)
    assert released >= len(points) // 2, released


def test_a_series_request_that_says_monthly_passes_the_term_fidelity_gate(service):
    """The time axis is the natural axis of a series request: 'monthly time
    series of mean stake' models `month` although the request never says the
    word, and rule B does not call it hallucinated. A dropped axis is still
    rule C's business."""
    from safetre.analyst import check_term_coherence
    ok, why = check_term_coherence("monthly time series of mean stake", "bets",
                                   "stake_gbp", ["month"])
    assert ok, why
    ok, why = check_term_coherence("trend in stake over the year", "bets",
                                   "stake_gbp", ["month"])
    assert ok, why
    # a non-time term the request never named is still hallucinated
    ok, why = check_term_coherence("monthly time series of mean stake", "bets",
                                   "stake_gbp", ["month", "product"])
    assert not ok and "product" in why
