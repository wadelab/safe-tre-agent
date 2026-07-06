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
    assert regularized_beta(x, a, b) == pytest.approx(
        float(scipy_special.betainc(a, b, x)), rel=1e-9, abs=1e-12)


def test_degenerate_inputs():
    assert math.isnan(pearson_p_value(0.5, 2))     # below the 3-observation floor
    assert math.isnan(pearson_p_value(float("nan"), 20))
    assert pearson_p_value(1.5, 20) == 0.0          # |r| clamped to 1
