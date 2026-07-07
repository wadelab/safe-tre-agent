"""Cross-validate the stdlib-only numerics in safetre.stats against scipy.

The runtime deliberately avoids a scipy dependency (see the safetre/stats.py
docstring); the price is hand-rolled numerics inside the release path. This
suite pays that down: scipy (dev-only) is the reference implementation, and the
grid covers small-n, large-n, and near-degenerate |r| -> 1 cases.
"""

import math

import pytest
from hypothesis import given, strategies as st

from safetre.stats import pearson_p_value, regularized_beta

scipy_stats = pytest.importorskip("scipy.stats")
scipy_special = pytest.importorskip("scipy.special")


@pytest.mark.parametrize("n", [3, 4, 5, 10, 30, 100, 1000])
@pytest.mark.parametrize("r", [-0.999, -0.9, -0.5, -0.1, 0.0, 0.1, 0.5, 0.9, 0.999])
def test_pearson_p_value_matches_scipy(r, n):
    # scipy's reference: two-sided p from the beta survival function of r^2
    df = n - 2
    expected = scipy_special.betainc(df / 2.0, 0.5, 1.0 - r * r)
    assert pearson_p_value(r, n) == pytest.approx(expected, rel=1e-10, abs=1e-12)


@given(st.floats(0.0, 1.0), st.floats(0.5, 50.0), st.floats(0.5, 50.0))
def test_regularized_beta_matches_scipy(x, a, b):
    # 1e-7 tolerance: the continued fraction and scipy diverge in the ~9th
    # decimal at the x->1 boundary (e.g. a=b=0.5), which is immaterial to a
    # released p-value rounded to three decimals.
    assert regularized_beta(x, a, b) == pytest.approx(
        float(scipy_special.betainc(a, b, x)), rel=1e-7, abs=1e-10)


def test_degenerate_inputs():
    assert math.isnan(pearson_p_value(0.5, 2))     # below the 3-observation floor
    assert math.isnan(pearson_p_value(float("nan"), 20))
    assert pearson_p_value(1.5, 20) == 0.0          # |r| clamped to 1


# --- GLM numerics (round 4: cell-table GLMs) ------------------------------------

from safetre.stats import (  # noqa: E402
    f_sf, inv_symmetric, irls_cells, matrix_rank, normal_sf,
    regularized_gamma_q, student_t_sf,
)


@pytest.mark.parametrize("df2", [1, 2, 5, 30, 499])
@pytest.mark.parametrize("df1", [1, 2, 5, 10])
@pytest.mark.parametrize("f", [0.01, 0.5, 1.0, 2.5, 4.1772, 25.0])
def test_f_sf_matches_scipy(f, df1, df2):
    # the one-way ANOVA omnibus p-value, against scipy's F survival function
    assert f_sf(f, df1, df2) == pytest.approx(
        float(scipy_stats.f.sf(f, df1, df2)), rel=1e-9, abs=1e-12)


def test_f_sf_degenerate_inputs():
    assert f_sf(0.0, 3, 40) == 1.0        # no between-group variance -> p = 1
    assert f_sf(-1.0, 3, 40) == 1.0
    assert math.isnan(f_sf(float("nan"), 3, 40))
    assert math.isnan(f_sf(2.0, 0, 40))   # no between-group d.f.


@pytest.mark.parametrize("z", [-8.0, -3.0, -1.0, -0.1, 0.0, 0.1, 1.0, 3.0, 8.0])
def test_normal_sf_matches_scipy(z):
    assert normal_sf(z) == pytest.approx(
        float(scipy_stats.norm.sf(z)), rel=1e-12, abs=1e-300)


@pytest.mark.parametrize("df", [1, 2, 5, 10, 30, 200])
@pytest.mark.parametrize("t", [-6.0, -2.0, -0.5, 0.0, 0.5, 2.0, 6.0])
def test_student_t_sf_matches_scipy(t, df):
    assert student_t_sf(t, df) == pytest.approx(
        float(scipy_stats.t.sf(t, df)), rel=1e-9, abs=1e-14)


@given(st.floats(0.25, 60.0), st.floats(0.0, 150.0))
def test_regularized_gamma_q_matches_scipy(a, x):
    assert regularized_gamma_q(a, x) == pytest.approx(
        float(scipy_special.gammaincc(a, x)), rel=1e-8, abs=1e-12)


def test_inv_symmetric_and_rank():
    a = [[4.0, 1.0], [1.0, 3.0]]
    inv = inv_symmetric(a)
    ident = [[sum(a[i][k] * inv[k][j] for k in range(2)) for j in range(2)]
             for i in range(2)]
    assert ident[0][0] == pytest.approx(1) and ident[1][1] == pytest.approx(1)
    assert ident[0][1] == pytest.approx(0, abs=1e-12)
    with pytest.raises(ValueError):
        inv_symmetric([[1.0, 2.0], [2.0, 4.0]])          # singular fails loudly
    assert matrix_rank([[1.0, 2.0], [2.0, 4.0]]) == 1
    assert matrix_rank([[1.0, 0.0], [0.0, 1.0], [1.0, 1.0]]) == 2


def test_gaussian_cells_match_closed_form_wls():
    # two cells, intercept + slope; hand-computable weighted least squares
    design = [[1.0, 0.0], [1.0, 1.0]]
    means, sizes = [10.0, 14.0], [20.0, 30.0]
    fit = irls_cells(design, means, sizes, "gaussian")
    # saturated 2-cell design: fit reproduces the cell means exactly
    assert fit.beta[0] == pytest.approx(10.0)
    assert fit.beta[1] == pytest.approx(4.0)
    assert fit.deviance == pytest.approx(0.0, abs=1e-18)


@pytest.mark.parametrize("family", ["binomial", "poisson"])
def test_grouped_fit_equals_cells_of_one(family):
    # the grouped-data identity the release contract rests on, in miniature:
    # fitting per-cell aggregates == fitting the same data as cells of size 1.
    rows = [(0.0, 1.0), (0.0, 0.0), (0.0, 1.0), (0.0, 0.0), (0.0, 0.0),
            (1.0, 1.0), (1.0, 1.0), (1.0, 0.0), (1.0, 1.0), (1.0, 1.0)]
    if family == "binomial":
        singles = irls_cells([[1.0, x] for x, _ in rows], [y for _, y in rows],
                             [1.0] * len(rows), family)
        k0 = sum(y for x, y in rows if x == 0.0)
        n0 = sum(1 for x, _ in rows if x == 0.0)
        k1 = sum(y for x, y in rows if x == 1.0)
        n1 = sum(1 for x, _ in rows if x == 1.0)
        grouped = irls_cells([[1.0, 0.0], [1.0, 1.0]], [k0 / n0, k1 / n1],
                             [float(n0), float(n1)], family)
    else:
        counts = [(0.0, 2.0), (0.0, 1.0), (0.0, 3.0), (1.0, 4.0), (1.0, 6.0), (1.0, 5.0)]
        singles = irls_cells([[1.0, x] for x, _ in counts], [y for _, y in counts],
                             [1.0] * len(counts), family,
                             offset=[0.0] * len(counts))
        t0 = sum(y for x, y in counts if x == 0.0)
        e0 = sum(1 for x, _ in counts if x == 0.0)
        t1 = sum(y for x, y in counts if x == 1.0)
        e1 = sum(1 for x, _ in counts if x == 1.0)
        grouped = irls_cells([[1.0, 0.0], [1.0, 1.0]], [t0, t1], [1.0, 1.0],
                             family, offset=[math.log(e0), math.log(e1)])
    for b_single, b_grouped in zip(singles.beta, grouped.beta):
        assert b_single == pytest.approx(b_grouped, rel=1e-9)
    for row_s, row_g in zip(singles.cov_unscaled, grouped.cov_unscaled):
        for v_s, v_g in zip(row_s, row_g):
            assert v_s == pytest.approx(v_g, rel=1e-7, abs=1e-12)
    # (deviances differ by a data-only constant between grouped and ungrouped
    # binomial likelihoods, so beta/cov equality is the meaningful identity)


def test_irls_refuses_bad_inputs():
    with pytest.raises(ValueError):
        irls_cells([], [], [], "gaussian")                       # empty design
    with pytest.raises(ValueError):
        irls_cells([[1.0]], [1.0], [1.0], "gamma")               # unknown family
    with pytest.raises(ValueError):
        irls_cells([[1.0, 2.0], [2.0, 4.0]], [1.0, 2.0], [1.0, 1.0], "gaussian")
