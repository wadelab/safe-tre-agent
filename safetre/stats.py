"""Statistical helpers for released values (currently the Pearson p-value).

Stdlib-only on purpose: the runtime dependency set is part of the audit surface
a TRE operator must review (`pip-audit` in CI), so the engine does not pull in
scipy for one p-value. The price of hand-rolled numerics is a correctness risk,
which is paid down in `tests/test_stats.py`: the implementation is
cross-validated against `scipy.stats` (a dev-only dependency) over a grid of
(r, n) values, alongside deterministic bound checks.

These functions compute *released* statistics, not disclosure decisions; the
safety checks (dominance, influence, donor counts) live in `engine.py` and
`disclosure.py`.
"""

from __future__ import annotations

import math

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
