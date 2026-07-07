"""One-way ANOVA model procedure: release contract, fail-closed denials,
estimability, and numerical correctness.

The ANOVA tool is the worked example of adding a statistical capability
(docs/adding-a-statistical-tool.md). These tests pin that it inherits the same
R15/P19–P22 guarantees as the GLM — it fits only from gateway-vetted group
cells, denies wholesale on any suppressed cell, refuses unestimable designs by
naming the factor (never a quantity), and its released table is reproducible
from the released cells — plus that the omnibus F/p it reports are correct.
"""

from __future__ import annotations

import math
import re

import pandas as pd
import pytest

from safetre import synth
from safetre.anova import AnovaProcedure, refit_from_artifact
from safetre.planner import MockPlanner
from safetre.query import CATALOGUE, AnovaSpec, QuerySpec
from safetre.service import QueryService


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=7)


@pytest.fixture()
def service(tables):
    return QueryService(tables)


class _FixedModelPlanner:
    def __init__(self, spec: dict):
        self.spec = spec

    def plan(self, request: str) -> dict:
        return self.spec


# --- released ANOVA: the R15 contract ------------------------------------------

def test_anova_released_with_full_contract(service):
    r = service.handle("one-way anova of total spend by age band", MockPlanner())
    assert r.status == "released"
    assert list(r.output.columns) == [
        "source", "df", "sum_sq", "mean_sq", "statistic", "p_value"]
    # two rows: the factor and the residual
    assert list(r.output["source"]) == ["age_band", "Residual"]
    assert set(r.artifacts) == {"cells", "model"}

    cells = r.artifacts["cells"]
    assert list(cells.columns) == ["age_band", "mean", "n", "sum_sq"]
    assert (cells["n"] % 5 == 0).all() and (cells["n"] >= 10).all()

    model = r.artifacts["model"].iloc[0]
    assert model["response"] == "total_spend_gbp" and model["factor"] == "age_band"
    assert model["n"] == int(cells["n"].sum())
    assert model["n_groups"] == len(cells)
    # df identity: (k-1) + (N-k) = N-1
    between = r.output.iloc[0]
    residual = r.output.iloc[1]
    assert between["df"] + residual["df"] == model["n"] - 1
    assert 0.0 <= model["eta_squared"] <= 1.0


def test_released_anova_is_reproducible_from_artifacts(service):
    # the P21 claim: refitting from the released cell table alone reproduces
    # the released ANOVA table bit-for-bit (mirrors the GLM reproducibility test).
    r = service.handle("one-way anova of total spend by age band", MockPlanner())
    assert r.status == "released"
    spec = AnovaSpec(**{k: v for k, v in r.spec.items() if k != "aggregates"})
    table, artifacts = refit_from_artifact(r.artifacts["cells"], spec)
    assert table.equals(r.output)
    assert artifacts["model"].equals(r.artifacts["model"])


# --- fail-closed: any suppressed group cell denies the whole model (P19) --------

def test_suppressed_group_cell_denies_whole_model(service):
    # wellbeing broken down by region has sub-threshold groups; a released
    # count table would suppress them, so the model is denied too — and the
    # message names the aggregate role only, never which cell or why.
    r = service.handle("one-way anova of wellbeing by region", MockPlanner())
    assert r.status == "denied"
    assert r.output is None and r.artifacts is None
    assert not re.search(r"\d", r.message)  # non-numeric refusal


# --- estimability refusals, decided from finalized tables alone (P22) -----------

def test_single_level_factor_denied_naming_factor_only(service):
    # filtering to one region leaves a single group: nothing to compare.
    spec = {"tool": "anova", "dataset": "wellbeing", "response": "wemwbs_score",
            "factor": "region",
            "filters": [{"column": "region", "op": "==", "value": "London"}]}
    r = service.handle("one-way anova of wellbeing by region in London",
                       _FixedModelPlanner(spec))
    assert r.status == "denied"
    assert "region" in r.message and "single" in r.message
    assert not re.search(r"\d", r.message)


def test_internal_variable_rejected_as_factor():
    # raw age is an internal analysis variable; it can never be a factor.
    with pytest.raises(Exception):
        AnovaSpec(dataset="donor_spend", response="total_spend_gbp",
                  factor="age_years")


def test_non_gaussian_response_rejected():
    # a boolean/count response is not an interval scale: ANOVA refuses it,
    # pointing the analyst at the glm tool's binomial/poisson families instead.
    with pytest.raises(Exception):
        AnovaSpec(dataset="spend", response="contains_lootboxes", factor="genre")


def test_response_swap_denied(service):
    # request names wemwbs but the spec models pgsi: a substituted question.
    spec = {"tool": "anova", "dataset": "wellbeing", "response": "pgsi_score",
            "factor": "region", "filters": []}
    r = service.handle("one-way anova of wemwbs wellbeing by region",
                       _FixedModelPlanner(spec))
    assert r.status == "denied"
    assert "wemwbs_score" in r.message


def test_unknown_tool_denied(service):
    r = service.handle("one-way anova of wellbeing by region",
                       _FixedModelPlanner({"tool": "manova", "dataset": "wellbeing"}))
    assert r.status == "denied"
    assert "manova" in r.message


# --- inheritance: every planned aggregate is an ordinary valid QuerySpec --------

def test_plan_aggregates_are_valid_queryspecs():
    proc = AnovaProcedure()
    for point in proc.skeleton(CATALOGUE):
        spec = proc.validate(point)
        aggs = proc.plan_aggregates(spec)
        assert [a.measure.fn for a in aggs] == ["mean", "sum_sq"]
        assert all(isinstance(a, QuerySpec) for a in aggs)
        assert proc.cost(spec) == 2


# --- numerical correctness against scipy's f_oneway -----------------------------

def test_anova_table_matches_scipy_f_oneway():
    np = pytest.importorskip("numpy")
    scipy_stats = pytest.importorskip("scipy.stats")
    rng = np.random.default_rng(11)

    labels, sizes, shifts = ["A", "B", "C", "D"], [40, 55, 35, 60], [0.0, 1.5, 3.0, 4.5]
    groups, factor_col, y_col = [], [], []
    for lab, n, shift in zip(labels, sizes, shifts):
        y = rng.normal(50.0 + shift, 8.0, n)
        groups.append(y)
        factor_col += [lab] * n
        y_col += list(y)

    df = pd.DataFrame({"region": factor_col, "y": y_col})
    g = df.groupby("region")["y"]
    exact_mean = pd.DataFrame({"region": g.mean().index, "value": g.mean().to_numpy(),
                               "n": g.size().to_numpy()})
    exact_ss = pd.DataFrame({"region": g.apply(lambda s: float((s ** 2).sum())).index,
                             "value": g.apply(lambda s: float((s ** 2).sum())).to_numpy(),
                             "n": g.size().to_numpy()})

    # a valid spec; fit() never re-validates the cell labels against the domain
    spec = AnovaSpec(dataset="wellbeing", response="wemwbs_score", factor="region")
    table, _ = AnovaProcedure().fit({"mean": exact_mean, "sum_sq": exact_ss}, spec)

    f_ref, p_ref = scipy_stats.f_oneway(*groups)
    between = table[table["source"] == "region"].iloc[0]
    assert between["df"] == len(labels) - 1
    assert table.iloc[1]["df"] == sum(sizes) - len(labels)
    assert between["statistic"] == pytest.approx(float(f_ref), rel=1e-4)
    assert between["p_value"] == pytest.approx(float(p_ref), abs=1e-3)


def test_within_ss_floored_when_second_moment_rounds_below_mean_square():
    # a one-cell-per-group degenerate case: with sum_sq == n*mean^2 exactly,
    # within SS is 0 and F is undefined (nan), refused rather than a bogus value.
    spec = AnovaSpec(dataset="wellbeing", response="wemwbs_score", factor="region")
    mean = pd.DataFrame({"region": ["A", "B"], "value": [10.0, 20.0], "n": [1, 1]})
    ss = pd.DataFrame({"region": ["A", "B"], "value": [100.0, 400.0], "n": [1, 1]})
    # N == k here (2 groups, 2 observations) so preconditions would refuse it;
    # fit is exercised directly to confirm the numerics degrade safely to nan.
    table, _ = AnovaProcedure().fit({"mean": mean, "sum_sq": ss}, spec)
    assert math.isnan(table.iloc[0]["statistic"])
