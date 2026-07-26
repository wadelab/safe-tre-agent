"""Second moments are a different disclosure problem from first moments.

Squaring is not share-preserving. A donor holding a fraction *p* of a cell's
total holds `p² / (p² + (1-p)²/(k-1))` of its sum of squares when the rest of
the cell is equal, which crosses one half at `p = 1/(1+√(k-1))` — 0.19 in a
twenty-donor cell, 0.09 in a hundred. So the *same* nominal dominance bound is
a far tighter rule on a `sum_sq` cell than on a `sum`, and since a gaussian
model dies if either moment table is suppressed, the second moment is what
governs whether models are available at all (measured:
`artifacts/dispersion_sensitivity.json`).

Two consequences are tested here, the two halves of the decision in
`docs/acro-integration.md` §3:

- the bound is now selected by the released value's **disclosure class**
  (R14), so a second moment can be checked at its own stated parameter rather
  than inheriting one calibrated for sums. The default is unchanged;
- a gaussian model whose dispersion cells cannot be released now returns its
  **coefficients** — which are a function of the vetted mean cells alone —
  and withholds only what the dispersion buys: standard errors, t, p and R².
"""

from __future__ import annotations

import json

import pandas as pd
import pytest

from safetre import synth
from safetre.disclosure import (
    CellContext, DisclosurePolicy, StandinVetter, VettingParameters,
)
from safetre.glm import GLMProcedure, refit_from_artifact
from safetre.procedures import REGISTRY
from safetre.query import GLMSpec, Measure
from safetre.service import QueryService

# a spec whose mean cells release but whose sums of squares do not (seed 17)
COEFFICIENTS_ONLY = {"tool": "glm", "dataset": "spend", "family": "gaussian",
                     "response": "amount_gbp",
                     "terms": ["age_band", "contains_lootboxes"]}


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=17)


# --- the bound follows the disclosure class -------------------------------------

def test_a_sum_of_squares_is_not_a_magnitude():
    # the contract is where the distinction is stated, because it is what
    # selects the rule; before this it was labelled exactly like a sum
    assert REGISTRY["sum_sq"].output_contract(
        Measure(fn="sum_sq", column="total_spend_gbp"))["value"] == "moment2"
    assert REGISTRY["sum"].output_contract(
        Measure(fn="sum", column="total_spend_gbp"))["value"] == "magnitude"


def test_the_second_moment_bound_defaults_to_the_ordinary_one():
    # an operator who says nothing gets exactly today's behaviour
    params = VettingParameters(threshold=10, max_rows=100, dom_threshold=0.5,
                               influence_threshold=0.5)
    assert params.dominance_for("moment2") == params.dominance_for("magnitude")
    assert params.dominance_for(None) == 0.5


def test_a_stated_second_moment_bound_applies_only_to_second_moments():
    params = VettingParameters(threshold=10, max_rows=100, dom_threshold=0.5,
                               influence_threshold=0.5, moment2_dom_threshold=0.9)
    assert params.dominance_for("moment2") == 0.9
    assert params.dominance_for("magnitude") == 0.5
    assert params.dominance_for(None) == 0.5


def test_the_same_cell_is_judged_differently_as_a_sum_and_as_a_sum_of_squares():
    # one dominated cell, two classes, one policy: the class is the difference
    cells = pd.DataFrame({"region": ["A", "B", "C"], "value": [1.0, 2.0, 3.0],
                          "n": [40, 50, 60], "dominance": [0.7, 0.1, 0.2]})
    policy = DisclosurePolicy(moment2_dom_threshold=0.9)
    as_sum = policy.apply(cells, CellContext(value_class="magnitude"))
    as_moment2 = policy.apply(cells, CellContext(value_class="moment2"))
    # as a sum: A is dominated, and complementary suppression then sacrifices
    # the smallest survivor to protect the margin
    assert as_sum[1] == "redacted" and set(as_sum[0]["region"]) == {"C"}
    # as a second moment at its own stated bound: nothing is dominated
    assert as_moment2[1] == "release"
    assert set(as_moment2[0]["region"]) == {"A", "B", "C"}


def test_without_a_stated_bound_the_class_changes_nothing():
    cells = pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0],
                          "n": [40, 50], "dominance": [0.7, 0.1]})
    policy = DisclosurePolicy()
    plain = policy.apply(cells)[0]
    for value_class in ("magnitude", "moment2", None):
        assert policy.apply(cells, CellContext(value_class=value_class))[0].equals(plain)


def test_the_vetter_reads_the_class_from_the_context():
    cells = pd.DataFrame({"region": ["A"], "value": [1.0], "n": [40],
                          "dominance": [0.7]})
    params = VettingParameters(threshold=10, max_rows=100, dom_threshold=0.5,
                               influence_threshold=0.5, moment2_dom_threshold=0.9)
    vetter = StandinVetter()
    assert vetter.vet(cells, params).suppress.tolist() == [True]
    assert vetter.vet(cells, params,
                      CellContext(value_class="moment2")).suppress.tolist() == [False]


# --- a model releases its coefficients without its dispersion --------------------

class _Fixed:
    def __init__(self, raw):
        self.raw = raw

    def plan(self, request):
        return self.raw


def _release(tables, raw):
    return QueryService(tables).handle(json.dumps(raw), _Fixed(raw))


def test_a_gaussian_model_releases_coefficients_when_the_dispersion_cannot(tables):
    result = _release(tables, COEFFICIENTS_ONLY)
    assert result.status == "released"
    # the estimates survive: they are a function of the vetted mean cells
    assert "estimate" in result.output.columns
    # and nothing the withheld table would have bought goes out
    for withheld in ("std_error", "statistic", "p_value"):
        assert withheld not in result.output.columns
    model = result.artifacts["model"].iloc[0]
    assert not model["dispersion_released"]
    for withheld in ("deviance", "r_squared"):
        assert withheld not in result.artifacts["model"].columns
    # the released cell table carries no second moment at all
    assert "sum_sq" not in result.artifacts["cells"].columns
    # and the analyst is told, rather than left to notice
    assert any(f.rule == "model_table_withheld" for f in result.findings)


def test_a_coefficients_only_release_is_still_reproducible(tables):
    # P21 holds for the degraded release too: an analyst with the released
    # cell table alone recomputes exactly what was released
    result = _release(tables, COEFFICIENTS_ONLY)
    spec = GLMSpec(**COEFFICIENTS_ONLY)
    refit, artifacts = refit_from_artifact(result.artifacts["cells"], spec)
    assert refit.equals(result.output)
    assert artifacts["model"].equals(result.artifacts["model"])


def test_a_model_still_dies_if_a_required_table_is_suppressed(tables):
    # only the dispersion is optional. A suppressed MEAN cell is a design cell
    # the model cannot be fitted from, and that still refuses (P19).
    raw = {"tool": "glm", "dataset": "donor_spend", "family": "gaussian",
           "response": "total_spend_gbp", "terms": ["age_band", "sex"]}
    result = _release(tables, raw)
    assert result.status == "denied"
    assert any(f.rule == "model_incomplete_cell_table" for f in result.findings)


def test_only_the_gaussian_dispersion_is_optional():
    proc = GLMProcedure()
    base = {"tool": "glm", "dataset": "donor_spend"}
    assert proc.optional_roles(GLMSpec(**base, family="gaussian",
                                       response="total_spend_gbp",
                                       terms=["sex"])) == frozenset({"sum_sq"})
    assert proc.optional_roles(GLMSpec(**base, family="poisson",
                                       response="purchase_events",
                                       terms=["sex"])) == frozenset()
    # ANOVA is a variance decomposition: without the second moment there is no
    # analysis left to release
    from safetre.anova import AnovaProcedure

    assert AnovaProcedure().optional_roles(None) == frozenset()
