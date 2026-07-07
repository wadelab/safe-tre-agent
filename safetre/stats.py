"""Statistical helpers for released values (Pearson p-value; cell-table GLMs).

Stdlib-only on purpose: the runtime dependency set is part of the audit surface
a TRE operator must review (`pip-audit` in CI), so the engine does not pull in
scipy (or numpy) for these numerics. The price of hand-rolled numerics is a
correctness risk, which is paid down in `tests/test_stats.py` and
`tests/test_glm_oracle.py`: the implementations are cross-validated against
`scipy.stats` and `statsmodels` (dev-only dependencies), alongside
deterministic bound checks and hand-computable golden fits.

This module is also the **P21 noninterference boundary for model fitting**: it
imports nothing beyond the stdlib and receives plain lists of floats, so the
GLM fitter physically cannot read row-level data, views, or the engine. The
inputs it is handed are gateway-finalized cell aggregates and nothing else
(enforced by an AST check in `tests/test_glm_noninterference.py`).

These functions compute *released* statistics, not disclosure decisions; the
safety checks (dominance, influence, donor counts) live in `engine.py` and
`disclosure.py`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

_BETA_EPS = 3e-14
_BETA_FPMIN = 1e-300
_BETA_MAX_ITER = 200


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _BETA_FPMIN:
        d = _BETA_FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, _BETA_MAX_ITER + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _BETA_FPMIN:
            d = _BETA_FPMIN
        c = 1.0 + aa / c
        if abs(c) < _BETA_FPMIN:
            c = _BETA_FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _BETA_FPMIN:
            d = _BETA_FPMIN
        c = 1.0 + aa / c
        if abs(c) < _BETA_FPMIN:
            c = _BETA_FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _BETA_EPS:
            break
    return h


def regularized_beta(x: float, a: float, b: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    bt = math.exp(
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
        + a * math.log(x) + b * math.log1p(-x)
    )
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def pearson_p_value(r: float, n: int) -> float:
    """Two-sided p-value for Pearson r using Student's t distribution."""
    if n < 3 or not math.isfinite(r):
        return float("nan")
    abs_r = min(abs(r), 1.0)
    if abs_r >= 1.0:
        return 0.0
    df = n - 2
    p = regularized_beta(1.0 - abs_r * abs_r, df / 2.0, 0.5)
    return max(0.0, min(1.0, p))


# --- distribution tails for GLM inference --------------------------------------

def normal_sf(z: float) -> float:
    """Upper tail P(Z > z) of the standard normal."""
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def student_t_sf(t: float, df: float) -> float:
    """Upper tail P(T > t) of Student's t with `df` degrees of freedom."""
    if df <= 0 or not math.isfinite(t):
        return float("nan")
    x = df / (df + t * t)
    p = 0.5 * regularized_beta(x, df / 2.0, 0.5)
    return p if t >= 0 else 1.0 - p


def f_sf(f: float, df1: float, df2: float) -> float:
    """Upper tail P(F > f) of the F distribution with (df1, df2) d.f.

    The one-way ANOVA omnibus p-value. Derived from the same incomplete beta
    as the Pearson/Student tails above (no new special function): the F CDF is
    I_{u}(df1/2, df2/2) with u = df1·f / (df1·f + df2), so the upper tail is
    I_{1-u}(df2/2, df1/2) = regularized_beta(df2/(df2 + df1·f), df2/2, df1/2).
    """
    if df1 <= 0 or df2 <= 0 or not math.isfinite(f):
        return float("nan")
    if f <= 0.0:
        return 1.0
    return regularized_beta(df2 / (df2 + df1 * f), df2 / 2.0, df1 / 2.0)


_GAMMA_EPS = 3e-14
_GAMMA_MAX_ITER = 300


def regularized_gamma_q(a: float, x: float) -> float:
    """Upper regularized incomplete gamma Q(a, x) = Γ(a, x)/Γ(a).

    Series for x < a+1, continued fraction otherwise (the `_betacf` pattern).
    Q(df/2, dev/2) is the chi-square upper tail used for deviance
    goodness-of-fit p-values.
    """
    if a <= 0 or x < 0 or not (math.isfinite(a) and math.isfinite(x)):
        return float("nan")
    if x == 0.0:
        return 1.0
    log_prefactor = a * math.log(x) - x - math.lgamma(a)
    if x < a + 1.0:
        # P(a,x) by series; Q = 1 - P
        term = 1.0 / a
        total = term
        denominator = a
        for _ in range(_GAMMA_MAX_ITER):
            denominator += 1.0
            term *= x / denominator
            total += term
            if abs(term) < abs(total) * _GAMMA_EPS:
                break
        return max(0.0, min(1.0, 1.0 - math.exp(log_prefactor) * total))
    # Q(a,x) by Lentz continued fraction
    b = x + 1.0 - a
    c = 1.0 / _BETA_FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, _GAMMA_MAX_ITER + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _BETA_FPMIN:
            d = _BETA_FPMIN
        c = b + an / c
        if abs(c) < _BETA_FPMIN:
            c = _BETA_FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _GAMMA_EPS:
            break
    return max(0.0, min(1.0, math.exp(log_prefactor) * h))


# --- small dense linear algebra (pure python; p <= a few dozen) -----------------

Matrix = list[list[float]]

_PIVOT_TOL = 1e-12


def inv_symmetric(a: Matrix) -> Matrix:
    """Inverse of a (symmetric positive-definite) matrix by Gauss-Jordan with
    partial pivoting. Raises ValueError on a singular/ill-conditioned matrix —
    the caller treats that as "unestimable", never as a silent repair."""
    p = len(a)
    aug = [list(row) + [1.0 if i == j else 0.0 for j in range(p)]
           for i, row in enumerate(a)]
    scale = max(abs(v) for row in a for v in row) or 1.0
    for col in range(p):
        pivot_row = max(range(col, p), key=lambda r: abs(aug[r][col]))
        if abs(aug[pivot_row][col]) < _PIVOT_TOL * scale:
            raise ValueError("singular matrix (aliased or empty design)")
        aug[col], aug[pivot_row] = aug[pivot_row], aug[col]
        pivot = aug[col][col]
        aug[col] = [v / pivot for v in aug[col]]
        for r in range(p):
            if r != col and aug[r][col] != 0.0:
                factor = aug[r][col]
                aug[r] = [rv - factor * cv for rv, cv in zip(aug[r], aug[col])]
    return [row[p:] for row in aug]


def matrix_rank(a: Matrix, tol: float = 1e-9) -> int:
    """Rank by Gaussian elimination with partial pivoting (row-echelon count)."""
    if not a:
        return 0
    m = [list(row) for row in a]
    rows, cols = len(m), len(m[0])
    scale = max((abs(v) for row in m for v in row), default=0.0) or 1.0
    rank = 0
    for col in range(cols):
        pivot_row = None
        best = tol * scale
        for r in range(rank, rows):
            if abs(m[r][col]) > best:
                best = abs(m[r][col])
                pivot_row = r
        if pivot_row is None:
            continue
        m[rank], m[pivot_row] = m[pivot_row], m[rank]
        pivot = m[rank][col]
        for r in range(rank + 1, rows):
            if m[r][col] != 0.0:
                factor = m[r][col] / pivot
                m[r] = [rv - factor * pv for rv, pv in zip(m[r], m[rank])]
        rank += 1
        if rank == rows:
            break
    return rank


# --- GLM fitting from finalized cell aggregates (P21-pure) ----------------------

GLM_FAMILIES = ("gaussian", "binomial", "poisson")
_IRLS_MAX_ITER = 100
_IRLS_TOL = 1e-10
_MU_FLOOR = 1e-10


@dataclass(frozen=True)
class IRLSResult:
    """A fitted GLM on cell aggregates.

    `cov_unscaled` is (X'WX)^-1 at the final weights; for binomial/poisson it
    is the coefficient covariance (dispersion fixed at 1), for gaussian the
    caller multiplies by the estimated dispersion. `fitted` is the per-cell
    mean response on the response scale (internal — never released; P20).
    `deviance` is the family deviance of the cell fit.
    """

    beta: list[float]
    cov_unscaled: Matrix
    deviance: float
    fitted: list[float]
    iterations: int
    converged: bool


def _xtwx_xtwz(design: Matrix, w: list[float], z: list[float]) -> tuple[Matrix, list[float]]:
    p = len(design[0])
    xtwx = [[0.0] * p for _ in range(p)]
    xtwz = [0.0] * p
    for row, wi, zi in zip(design, w, z):
        for i in range(p):
            xw = row[i] * wi
            xtwz[i] += xw * zi
            for j in range(i, p):
                xtwx[i][j] += xw * row[j]
    for i in range(p):
        for j in range(i):
            xtwx[i][j] = xtwx[j][i]
    return xtwx, xtwz


def _solve(xtwx: Matrix, xtwz: list[float]) -> tuple[list[float], Matrix]:
    inv = inv_symmetric(xtwx)
    beta = [sum(inv[i][j] * xtwz[j] for j in range(len(xtwz))) for i in range(len(xtwz))]
    return beta, inv


def _xlogy(x: float, y: float) -> float:
    return 0.0 if x == 0.0 else x * math.log(y)


def _sigmoid(e: float) -> float:
    """Overflow-safe logistic; exact within float precision (not a repair)."""
    if e >= 0.0:
        return 1.0 / (1.0 + math.exp(-e))
    ex = math.exp(e)
    return ex / (1.0 + ex)


_ETA_CAP = 700.0  # exp() overflow guard; a diverging fit then fails non-convergence


def irls_cells(design: Matrix, response: list[float], weights: list[float],
               family: str, offset: list[float] | None = None) -> IRLSResult:
    """Fit a canonical-link GLM from per-cell aggregates.

    Cell semantics (the grouped-data identities the release contract rests on;
    each matches the row-level fit exactly — see `tests/test_glm_oracle.py`):

    - ``gaussian``:  `response` = cell means, `weights` = cell sizes.
      One weighted least-squares solve (identity link needs no iteration).
    - ``binomial``:  `response` = cell success *proportions*, `weights` = cell
      trials (grouped binomial ≡ row-level Bernoulli, logit link).
    - ``poisson``:   `response` = cell *totals*, `weights` all 1.0, `offset` =
      log cell exposure (log link).

    Raises ValueError on a singular design or non-convergence — an unestimable
    model is refused loudly, never silently repaired (P19/P22).
    """
    if family not in GLM_FAMILIES:
        raise ValueError(f"unknown GLM family {family!r}")
    if not design or len({len(r) for r in design}) != 1:
        raise ValueError("empty or ragged design matrix")
    if not (len(design) == len(response) == len(weights)):
        raise ValueError("design/response/weights length mismatch")
    off = offset if offset is not None else [0.0] * len(design)
    if len(off) != len(design):
        raise ValueError("offset length mismatch")

    if family == "gaussian":
        xtwx, xtwz = _xtwx_xtwz(design, weights, response)
        beta, inv = _solve(xtwx, xtwz)
        fitted = [sum(b * x for b, x in zip(beta, row)) for row in design]
        deviance = sum(w * (y - mu) ** 2
                       for w, y, mu in zip(weights, response, fitted))
        return IRLSResult(beta=beta, cov_unscaled=inv, deviance=deviance,
                          fitted=fitted, iterations=1, converged=True)

    p = len(design[0])
    beta = [0.0] * p
    inv: Matrix = [[]]
    for iteration in range(1, _IRLS_MAX_ITER + 1):
        eta = [sum(b * x for b, x in zip(beta, row)) + o
               for row, o in zip(design, off)]
        if family == "binomial":
            mu = [min(max(_sigmoid(e), _MU_FLOOR), 1.0 - _MU_FLOOR) for e in eta]
            wls_w = [n * m * (1.0 - m) for n, m in zip(weights, mu)]
            z = [e - o + (y - m) / (m * (1.0 - m))
                 for e, o, y, m in zip(eta, off, response, mu)]
        else:  # poisson
            mu = [max(math.exp(min(e, _ETA_CAP)), _MU_FLOOR) for e in eta]
            wls_w = list(mu)
            z = [e - o + (y - m) / m for e, o, y, m in zip(eta, off, response, mu)]
        xtwx, xtwz = _xtwx_xtwz(design, wls_w, z)
        new_beta, inv = _solve(xtwx, xtwz)
        step = max(abs(nb - b) for nb, b in zip(new_beta, beta))
        beta = new_beta
        if step < _IRLS_TOL:
            break
    else:
        raise ValueError("IRLS did not converge")

    eta = [sum(b * x for b, x in zip(beta, row)) + o for row, o in zip(design, off)]
    if family == "binomial":
        fitted = [min(max(_sigmoid(e), _MU_FLOOR), 1.0 - _MU_FLOOR) for e in eta]
        deviance = 2.0 * sum(
            n * (_xlogy(y, y / m) + _xlogy(1.0 - y, (1.0 - y) / (1.0 - m)))
            for n, y, m in zip(weights, response, fitted)
        )
    else:
        fitted = [math.exp(min(e, _ETA_CAP)) for e in eta]
        deviance = 2.0 * sum(_xlogy(y, y / m) - (y - m)
                             for y, m in zip(response, fitted))
    return IRLSResult(beta=beta, cov_unscaled=inv, deviance=deviance,
                      fitted=fitted, iterations=iteration, converged=True)
