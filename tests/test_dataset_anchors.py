"""The dataset's planted dominance anchors (`synth.DOMINANCE_ANCHORS`).

Sampled spend is heavy-tailed but not *concentrated*: measured over the whole
skeleton, no cell of ten donors or more reaches even 0.35 single-donor share.
Both dominance rule sets — the stand-in's "one donor over half the cell" and
ACRO's p%/NK defaults, which `redteam/run_acro_compare.py` runs against it —
are therefore dead code on an unplanted corpus, and a comparison of the two
measures nothing on that axis (docs/acro-comparison.md, D3).

The anchors plant three regions whose shapes separate the two rule sets. This
module pins them: that the shares are what the generator says they are, that
planting them changed nothing else about the data, and that the two rule sets
really do disagree on them in both directions.
"""

from __future__ import annotations

import pandas as pd
import pytest

from safetre import synth
from safetre.disclosure import DisclosurePolicy
from safetre.engine import QueryEngine
from safetre.query import QuerySpec

# ACRO's dominance defaults, restated so the anchors can be checked in the
# default environment: ACRO 0.4.x pins pandas < 3 and is installed only in the
# `acro` dependency group, where `redteam/run_acro_compare.py` runs its real
# implementations. These two reproduce the rule attribution that harness
# reports on the anchors — Scotland neither rule, Wales the NK-rule alone,
# East Midlands both — but the harness, not this restatement, is the
# authority.
ACRO_P = 0.1        # p%-rule: spend outside the top two, over the largest
ACRO_NK_N = 2       # NK-rule: the top n donors ...
ACRO_NK_K = 0.9     # ... may not hold k or more of the cell


@pytest.fixture(scope="module")
def tables():
    return synth.generate(seed=17)


@pytest.fixture(scope="module")
def unplanted():
    """The same dataset with the anchors switched off — the before picture."""
    saved = synth.DOMINANCE_ANCHORS
    synth.DOMINANCE_ANCHORS = {}
    try:
        return synth.generate(seed=17)
    finally:
        synth.DOMINANCE_ANCHORS = saved


def _region_spend(tables: dict, region: str) -> pd.Series:
    """Each spending donor's total in a region, largest first."""
    donors = tables["donors"]
    members = donors.loc[donors["region"] == region, "donor_id"]
    events = tables["events"]
    spend = (events[events["donor_id"].isin(members)]
             .groupby("donor_id")["amount_gbp"].sum())
    return spend[spend > 0].sort_values(ascending=False)


def _shares(tables: dict, region: str) -> tuple[int, float, float]:
    """(donors, largest share, top-n share) of a region's spend, for the `n`
    of ACRO's NK-rule."""
    spend = _region_spend(tables, region)
    total = float(spend.sum())
    return (len(spend), float(spend.iloc[0]) / total,
            float(spend.iloc[:ACRO_NK_N].sum()) / total)


def test_anchor_regions_carry_the_planted_shares(tables):
    for region, shares in synth.DOMINANCE_ANCHORS.items():
        spend = _region_spend(tables, region)
        total = float(spend.sum())
        # above the frequency threshold, or the cell would be suppressed for
        # its size before any dominance rule was reached
        assert len(spend) >= DisclosurePolicy.DEFAULT_THRESHOLD, (region, len(spend))
        planted = [float(v) / total for v in spend.iloc[:len(shares)]]
        assert planted == pytest.approx(list(shares), abs=0.01), (region, planted)


def test_anchors_separate_the_two_dominance_rule_sets(tables):
    verdicts = {}
    for region in synth.DOMINANCE_ANCHORS:
        _, top1, top2 = _shares(tables, region)
        remainder = 1.0 - top2
        verdicts[region] = (
            top1 > DisclosurePolicy.dom_threshold,               # the stand-in
            top2 >= ACRO_NK_K or remainder < ACRO_P * top1,      # ACRO
        )
    # each anchor is a different pair of verdicts: the rules are not ordered,
    # neither gateway's dominance control subsumes the other's
    assert verdicts["Scotland"] == (True, False)
    assert verdicts["Wales"] == (False, True)
    assert verdicts["East Midlands"] == (True, True)


def test_the_gateway_suppresses_exactly_the_anchors_its_rule_catches(tables):
    engine = QueryEngine(tables)
    spec = QuerySpec(dataset="donor_spend",
                     measure={"fn": "sum", "column": "total_spend_gbp"},
                     group_by=["region"])
    frame = engine.run(spec)
    released, action, findings = DisclosurePolicy().apply(frame)
    assert action == "redacted"
    assert any(f.rule == "dominance" for f in findings)
    out = set(released["region"])
    assert "Scotland" not in out and "East Midlands" not in out
    # Wales is the cell ACRO's NK-rule would catch and this gateway does not —
    # the under-suppression the comparison exists to measure
    assert "Wales" in out


def test_planting_touches_only_the_anchor_regions(tables, unplanted):
    before, after = unplanted, tables
    # identical row counts everywhere: no event, donor or response added or
    # removed, so every count-based cell and every threshold decision is
    # untouched
    for name in ("donors", "apps", "events", "survey"):
        assert len(before[name]) == len(after[name]), name
    assert before["events"]["event_type"].tolist() == \
        after["events"]["event_type"].tolist()

    # regions outside the anchors are untouched donor for donor
    untouched = set(before["donors"]["region"]) - set(synth.DOMINANCE_ANCHORS)
    ids = before["donors"].loc[before["donors"]["region"].isin(untouched), "donor_id"]

    def spend_of(tbl):
        return (tbl["events"][tbl["events"]["donor_id"].isin(ids)]
                .groupby("donor_id")["amount_gbp"].sum())

    pd.testing.assert_series_equal(spend_of(before), spend_of(after))


def test_planting_introduces_no_donor_richer_than_the_data_already_held(
        tables, unplanted):
    # dominance means an outlier, and an unbounded one does collateral damage:
    # on the squared scale a whale takes essentially all of a `sum_sq` cell, so
    # every gaussian GLM near it loses its dispersion cell and is refused
    # (P19). The planted leaders are capped at the sampler's own maximum.
    def top_spend(tbl):
        return float(tbl["events"].groupby("donor_id")["amount_gbp"].sum().max())

    assert top_spend(tables) <= top_spend(unplanted) + 0.01


def test_a_dataset_too_small_to_carry_an_anchor_still_generates():
    # the Lean/Alloy generators build 30-donor tables just to read view
    # columns; anchors are a property of the demo-sized data and are simply
    # absent below it. That they ARE present at the sizes that matter is what
    # test_anchor_regions_carry_the_planted_shares pins.
    tiny = synth.generate(seed=7, n_donors=30, n_apps=5)
    assert len(tiny["donors"]) == 30 + len(synth.POISON_DONORS)
