"""Cross-validate the stdlib-only cell-table IRLS against statsmodels.

statsmodels (dev-only, like scipy) is the reference implementation. Two layers:

1. The grouped-data identities on which the release contract rests, against
   statsmodels' ROW-LEVEL fits: WLS on cell means == OLS on rows; grouped
   binomial == Bernoulli rows; Poisson totals with log-exposure offset ==
   Poisson rows. This is the strongest form — the oracle never sees cells.
2. Hypothesis-generated cell tables, against statsmodels' own grouped GLM
   forms (var_weights / (k, n-k) endog / offset).
"""

from __future__ import annotations

import math

import pytest
from hypothesis import given, settings, strategies as st

from safetre.stats import irls_cells

np = pytest.importorskip("numpy")
sm = pytest.importorskip("statsmodels.api")

RNG = np.random.default_rng(20260707)


def _cells_to_rows(design, weights):
    """Expand a cell design to row-level (one row per unit in the cell)."""
    rows = []
    for x, n in zip(design, weights):
        rows += [x] * int(n)
    return np.array(rows)


def test_gaussian_cells_match_statsmodels_row_level_ols():
    # 3 x 2 grid, integer cell sizes; y values fixed per row for exactness
    design = [[1.0, a1, a2, b] for a1, a2, b in
              [(0, 0, 0), (0, 0, 1), (1, 0, 0), (1, 0, 1), (0, 1, 0), (0, 1, 1)]]
    sizes = [12, 15, 20, 11, 14, 18]
    beta_true = np.array([50.0, 3.0, -2.0, 5.0])
    rows_x, rows_y = [], []
    for x, n in zip(design, sizes):
        mu = float(np.array(x) @ beta_true)
        noise = RNG.normal(0, 4, n)
        rows_x += [x] * n
        rows_y += list(mu + noise)
    rows_x, rows_y = np.array(rows_x), np.array(rows_y)

    # cell statistics (exact, unrounded — this test isolates the maths from
    # the gateway's deliberate rounding, which is measured separately)
    means, ss = [], []
    i = 0
    for x, n in zip(design, sizes):
        ys = rows_y[i:i + n]
        i += n
        means.append(float(ys.mean()))
        ss.append(float((ys ** 2).sum()))

    fit = irls_cells(design, means, [float(n) for n in sizes], "gaussian")
    ref = sm.OLS(rows_y, rows_x).fit()
    assert np.allclose(fit.beta, ref.params, rtol=1e-9)

    # dispersion recovered from sum_sq cells reproduces row-level SEs
    p = len(design[0])
    n_total = float(sum(sizes))
    within = sum(max(0.0, s - n * m * m) for s, n, m in zip(ss, sizes, means))
    dispersion = (within + fit.deviance) / (n_total - p)
    se = [math.sqrt(dispersion * fit.cov_unscaled[i][i]) for i in range(p)]
    assert np.allclose(se, ref.bse, rtol=1e-9)


def test_binomial_cells_match_statsmodels_row_level_bernoulli():
    design = [[1.0, x1, x2] for x1, x2 in [(0, 0), (0, 1), (1, 0), (1, 1)]]
    sizes = [40, 35, 50, 45]
    beta_true = np.array([-0.5, 1.2, 0.7])
    ks, rows_x, rows_y = [], [], []
    for x, n in zip(design, sizes):
        pr = 1 / (1 + np.exp(-(np.array(x) @ beta_true)))
        y = (RNG.random(n) < pr).astype(float)
        ks.append(float(y.sum()))
        rows_x += [x] * n
        rows_y += list(y)

    fit = irls_cells(design, [k / n for k, n in zip(ks, sizes)],
                     [float(n) for n in sizes], "binomial")
    ref = sm.GLM(np.array(rows_y), np.array(rows_x),
                 family=sm.families.Binomial()).fit()
    assert np.allclose(fit.beta, ref.params, rtol=1e-8)
    se = [math.sqrt(fit.cov_unscaled[i][i]) for i in range(len(fit.beta))]
    assert np.allclose(se, ref.bse, rtol=1e-8)


def test_poisson_cells_match_statsmodels_row_level_poisson():
    design = [[1.0, x] for x in (0.0, 1.0, 0.0, 1.0)]
    sizes = [30, 25, 45, 40]
    # merge duplicate design rows the way cells would: 2 distinct cells
    cell_design = [[1.0, 0.0], [1.0, 1.0]]
    beta_true = np.array([0.4, 0.8])
    rows_x, rows_y = [], []
    totals = {0.0: 0.0, 1.0: 0.0}
    exposure = {0.0: 0, 1.0: 0}
    for x, n in zip(design, sizes):
        lam = float(np.exp(np.array(x) @ beta_true))
        y = RNG.poisson(lam, n).astype(float)
        totals[x[1]] += y.sum()
        exposure[x[1]] += n
        rows_x += [x] * n
        rows_y += list(y)

    fit = irls_cells(cell_design, [totals[0.0], totals[1.0]], [1.0, 1.0],
                     "poisson",
                     offset=[math.log(exposure[0.0]), math.log(exposure[1.0])])
    ref = sm.GLM(np.array(rows_y), np.array(rows_x),
                 family=sm.families.Poisson()).fit()
    assert np.allclose(fit.beta, ref.params, rtol=1e-8)
    se = [math.sqrt(fit.cov_unscaled[i][i]) for i in range(len(fit.beta))]
    assert np.allclose(se, ref.bse, rtol=1e-8)


# --- Hypothesis: random grouped tables against statsmodels' grouped forms -------

@st.composite
def binomial_cell_tables(draw):
    n_cells = draw(st.integers(min_value=3, max_value=8))
    design = [[1.0] + [float(draw(st.integers(0, 1))) for _ in range(2)]
              for _ in range(n_cells)]
    trials = [float(draw(st.integers(min_value=15, max_value=200)))
              for _ in range(n_cells)]
    ks = [float(draw(st.integers(min_value=1, max_value=int(t) - 1)))
          for t in trials]
    return design, ks, trials


@given(binomial_cell_tables())
@settings(max_examples=25, deadline=None)
def test_random_binomial_tables_match_statsmodels(table):
    design, ks, trials = table
    x = np.array(design)
    if np.linalg.matrix_rank(x) < x.shape[1]:
        return  # aliased draw: the procedure refuses these before fitting
    fit = irls_cells(design, [k / n for k, n in zip(ks, trials)], trials,
                     "binomial")
    endog = np.column_stack([ks, np.array(trials) - np.array(ks)])
    # statsmodels' default deviance tolerance stops short of the MLE on
    # saturated draws; tighten it so both solvers sit at the same optimum
    ref = sm.GLM(endog, x, family=sm.families.Binomial()).fit(
        tol=1e-12, maxiter=300)
    assert np.allclose(fit.beta, ref.params, rtol=1e-7, atol=1e-9)
    se = [math.sqrt(fit.cov_unscaled[i][i]) for i in range(len(fit.beta))]
    assert np.allclose(se, ref.bse, rtol=1e-6, atol=1e-9)
    assert fit.deviance == pytest.approx(ref.deviance, rel=1e-6, abs=1e-9)
