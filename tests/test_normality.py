"""Normality (Jarque-Bera) model procedure: release contract, fail-closed
denials, reproducibility, the higher-moment dominance control, and numerics.

Normality is the second worked example of a moment-cell diagnostic (after ANOVA
adds the F test). It fits only from gateway-vetted group cells — now the first
four moments — denies wholesale on any suppressed cell (P19), reproduces from
the released cells (P21), and its released skewness/kurtosis/Jarque-Bera are
correct. The new bit is the 3rd/4th moment cells: signed (sum_cube) and more
concentrated (sum_quad), carrying the tighter dominance witness.
"""

from __future__ import annotations

import math
import re

import pandas as pd
import pytest

from safetre import synth
from safetre.engine import compile_dominance_query
from safetre.normality import NormalityProcedure, refit_from_artifact
from safetre.planner import MockPlanner
from safetre.query import NormalitySpec, QuerySpec
from safetre.service import QueryService


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


@pytest.fixture()
def service(tables):
    return QueryService(tables)


# --- released normality: the R15 contract --------------------------------------

def test_normality_released_with_full_contract(service):
    # a bounded psychometric score by a large-group factor: no whale, no small
    # cell, so the four moment cells all pass and the test releases.
    r = service.handle("normality of wellbeing by age band", MockPlanner())
    assert r.status == "released"
    assert list(r.output.columns) == [
        "age_band", "n", "skewness", "kurtosis", "jarque_bera", "df", "p_value"]
    assert set(r.artifacts) == {"cells", "model"}
    cells = r.artifacts["cells"]
    assert list(cells.columns) == ["age_band", "sum", "n", "sum_sq", "sum_cube", "sum_quad"]
    assert (cells["n"] % 5 == 0).all() and (cells["n"] >= 10).all()
    assert (r.output["df"] == 2).all()
    model = r.artifacts["model"].iloc[0]
    assert model["response"] == "wemwbs_score" and model["factor"] == "age_band"
    assert model["n_groups"] == len(cells)


def test_a_whale_dominated_response_is_denied_by_the_higher_moment_witness(service):
    # total spend is right-skewed with high-spending whales, so its FOURTH-moment
    # cell is dominated by a single donor's x**4 — the dominance witness on the
    # powered scale suppresses it, and the whole normality test denies (P19).
    # The higher-moment control is what makes this a denial rather than a leak.
    r = service.handle("test normality of total spend by age band", MockPlanner())
    assert r.status == "denied"
    assert r.output is None and not re.search(r"\d", r.message)


def test_released_normality_is_reproducible_from_artifacts(service):
    # P21: refitting from the released cell table alone reproduces the table.
    r = service.handle("normality of wellbeing by age band", MockPlanner())
    assert r.status == "released"
    spec = NormalitySpec(**{k: v for k, v in r.spec.items() if k != "aggregates"})
    table, artifacts = refit_from_artifact(r.artifacts["cells"], spec)
    assert table.equals(r.output)
    assert artifacts["model"].equals(r.artifacts["model"])


def test_suppressed_moment_cell_denies_the_whole_test(service):
    # wellbeing by region has sub-threshold groups; any suppressed moment cell
    # denies the whole normality test, and the refusal names no quantity.
    r = service.handle("normality of wellbeing by region", MockPlanner())
    assert r.status == "denied"
    assert r.output is None and r.artifacts is None
    assert not re.search(r"\d", r.message)


def test_non_gaussian_response_rejected():
    with pytest.raises(Exception):
        NormalitySpec(dataset="wellbeing", response="donor_id", factor="region")


# --- the higher-moment dominance witness (the new disclosure surface) -----------

def test_higher_moment_dominance_contributions_are_the_powered_scale():
    # the witness must bound a donor's share of the SAME quantity released:
    # x**3 for sum_cube, x**4 for sum_quad (not the raw column).
    for fn, power in (("sum_cube", "x * x * x"), ("sum_quad", "x * x * x * x")):
        spec = QuerySpec(dataset="donor_spend", group_by=[],
                         measure={"fn": fn, "column": "total_spend_gbp"})
        sql = compile_dominance_query(spec).sql
        # the signed-aware GREATEST(...) witness, on the powered contribution
        assert "GREATEST(" in sql and "abs(c)" in sql


def test_a_single_outlier_dominated_fourth_moment_is_refused(service):
    # one donor with an extreme value holds almost the entire fourth-moment
    # cell; the dominance witness (MAX|c|/SUM|c| on x**4) exceeds the threshold
    # and the cell is suppressed. Asserted on the witness the gateway reads.
    import duckdb

    spec = QuerySpec(dataset="donor_spend", group_by=[],
                     measure={"fn": "sum_quad", "column": "total_spend_gbp"})
    # a tiny cohort where one donor dwarfs the rest on the fourth power
    unit = pd.DataFrame({"donor_id": range(15), "total_spend_gbp": [5.0] * 14 + [500.0]})
    con = duckdb.connect()
    con.register("_donor_spend_u", unit)
    plan = compile_dominance_query(spec)
    dom = con.execute(plan.sql, plan.params).fetchone()[0]
    assert dom is not None and dom > 0.5   # the outlier dominates -> would suppress


# --- numerical correctness against scipy ----------------------------------------

def test_jarque_bera_matches_scipy():
    np = pytest.importorskip("numpy")
    scipy_stats = pytest.importorskip("scipy.stats")
    rng = np.random.default_rng(3)
    normal = rng.normal(50, 8, 500)
    skewed = rng.gamma(2.0, 3.0, 500) * 5 + 10

    def moments(arr, lab):
        n = float(len(arr))
        return {"sum": pd.DataFrame([{"region": lab, "value": float(arr.sum()), "n": n}]),
                "sum_sq": pd.DataFrame([{"region": lab, "value": float((arr ** 2).sum()), "n": n}]),
                "sum_cube": pd.DataFrame([{"region": lab, "value": float((arr ** 3).sum()), "n": n}]),
                "sum_quad": pd.DataFrame([{"region": lab, "value": float((arr ** 4).sum()), "n": n}])}

    spec = NormalitySpec(dataset="wellbeing", response="wemwbs_score", factor="region")
    for arr, lab in ((normal, "N"), (skewed, "S")):
        table, _ = NormalityProcedure().fit(moments(arr, lab), spec)
        row = table.iloc[0]
        jb_ref, p_ref = scipy_stats.jarque_bera(arr)
        assert row["skewness"] == pytest.approx(float(scipy_stats.skew(arr)), abs=1e-3)
        assert row["kurtosis"] == pytest.approx(float(scipy_stats.kurtosis(arr)), abs=1e-3)
        assert row["jarque_bera"] == pytest.approx(float(jb_ref), rel=1e-3)
        assert row["p_value"] == pytest.approx(float(p_ref), abs=1e-3)


def test_degenerate_group_degrades_to_nan():
    # a group with zero variance (all equal) has no defined shape statistics.
    spec = NormalitySpec(dataset="wellbeing", response="wemwbs_score", factor="region")
    n = 20.0
    fin = {"sum": pd.DataFrame([{"region": "A", "value": 10.0 * n, "n": n}]),
           "sum_sq": pd.DataFrame([{"region": "A", "value": 100.0 * n, "n": n}]),
           "sum_cube": pd.DataFrame([{"region": "A", "value": 1000.0 * n, "n": n}]),
           "sum_quad": pd.DataFrame([{"region": "A", "value": 10000.0 * n, "n": n}])}
    table, _ = NormalityProcedure().fit(fin, spec)
    assert math.isnan(table.iloc[0]["jarque_bera"])
