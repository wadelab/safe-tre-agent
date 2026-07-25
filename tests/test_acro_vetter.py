"""The ACRO vetter's mapping from ACRO's verdicts onto a cell table.

`redteam/acro_vetter.py` wraps ACRO's own check implementations in the
`CellVetter` seam. ACRO itself lives in a separate dependency group (it pins
`pandas < 3`, C3) and is absent from this environment, so these tests stub the
one method that touches it — `decisions()` — and exercise everything around
it: the cell-key mapping, the finding attribution, and the fail-closed
treatment of a cell ACRO said nothing about.

The rules themselves are checked where ACRO actually is: the `acro-compare`
CI job runs the real implementations over 337 cells of the red-team corpus.
"""

from __future__ import annotations

import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "redteam"))

from acro_vetter import AGGFUNC, AcroVetter                          # noqa: E402

from safetre.disclosure import (                                     # noqa: E402
    CompositeVetter, DisclosurePolicy, StandinVetter, VettingParameters,
)

PARAMS = VettingParameters(threshold=10, max_rows=100, dom_threshold=0.5,
                           influence_threshold=0.5)


def _vetter(verdicts: dict, keys: list[str]) -> AcroVetter:
    """An AcroVetter with ACRO's answers stubbed in — nothing imports acro."""
    vetter = AcroVetter(contributions=pd.DataFrame(), keys=keys, aggfunc="sum")
    vetter.decisions = lambda: verdicts                    # type: ignore[method-assign]
    return vetter


CELLS = pd.DataFrame({"region": ["A", "B", "C"], "value": [1.0, 2.0, 3.0],
                      "n": [40, 50, 60]})


def test_a_failing_rule_suppresses_exactly_its_cell():
    verdicts = _vetter({("A",): "ok", ("B",): "nk-rule;", ("C",): "ok"},
                       ["region"]).vet(CELLS, PARAMS)
    assert verdicts.suppress.tolist() == [False, True, False]
    assert [f.rule for f in verdicts.findings] == ["acro_nk-rule"]


def test_several_rules_on_one_cell_are_reported_separately():
    verdicts = _vetter({("A",): "threshold; p-ratio;", ("B",): "ok", ("C",): "ok"},
                       ["region"]).vet(CELLS, PARAMS)
    assert verdicts.suppress.tolist() == [True, False, False]
    assert sorted(f.rule for f in verdicts.findings) == ["acro_p-ratio",
                                                         "acro_threshold"]


def test_a_cell_acro_said_nothing_about_is_suppressed():
    # fail closed: no verdict is not a release. A vetter that quietly passed
    # unchecked cells would be worse than no vetter at all, because the
    # release would claim a check that never ran.
    verdicts = _vetter({("A",): "ok"}, ["region"]).vet(CELLS, PARAMS)
    assert verdicts.suppress.tolist() == [False, True, True]
    assert [f.rule for f in verdicts.findings] == ["acro_unchecked"]


def test_a_query_with_no_group_by_is_the_single_total_cell():
    total = pd.DataFrame({"value": [1.0], "n": [40]})
    assert _vetter({("total",): "ok"}, []).vet(total, PARAMS).suppress.tolist() \
        == [False]
    assert _vetter({("total",): "nk-rule;"}, []).vet(total, PARAMS) \
        .suppress.tolist() == [True]


def test_the_acro_vetter_never_denies_the_whole_table():
    # egress checks — identifiers, free text, un-aggregated sensitive columns —
    # are the stand-in's rules and stay with it; ACRO only ever suppresses cells
    verdicts = _vetter({("A",): "threshold;", ("B",): "threshold;",
                        ("C",): "threshold;"}, ["region"]).vet(CELLS, PARAMS)
    assert verdicts.suppress.all()
    assert verdicts.deny is False


def test_composed_with_the_standin_it_can_only_take_cells_away():
    # the union in practice: ACRO's verdict removes a cell the stand-in would
    # have released, and removes none that it would have suppressed
    policy = DisclosurePolicy()
    alone, action, _ = policy.apply(CELLS)
    assert action == "release"
    composed, composed_action, findings = DisclosurePolicy(
        vetter=CompositeVetter(StandinVetter(),
                               _vetter({("A",): "ok", ("B",): "nk-rule;",
                                        ("C",): "ok"}, ["region"]))
    ).apply(CELLS)
    assert composed_action == "redacted"
    assert set(composed["region"]) < set(alone["region"])
    assert any(f.rule == "acro_nk-rule" for f in findings)


def test_the_aggregation_map_covers_the_value_measures():
    # a measure ACRO must aggregate but that is missing here would be vetted
    # as a frequency table, silently checking the wrong thing
    assert AGGFUNC == {"sum": "sum", "mean": "mean", "sum_sq": "sum"}
