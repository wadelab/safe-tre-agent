"""Unit tests for the disclosure gateway and guards. Run: pytest -q"""

import pandas as pd

from safetre.disclosure import DisclosurePolicy, SessionAuditor, leak_detector
from safetre.guards import static_check


def test_dominance_cell_suppressed():
    # two dominated cells: both go, and they protect each other against the
    # margin (a lone suppressed cell would trigger secondary suppression)
    df = pd.DataFrame({"canton": ["A", "B", "C"], "value": [100.0, 200.0, 150.0],
                       "n": [15, 20, 25], "dominance": [0.8, 0.2, 0.6]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "dominance" for f in findings)
    assert "dominance" not in released.columns          # internal helper never released
    assert list(released["canton"]) == ["B"]            # the dominated cells are gone


def test_lone_dominance_cell_triggers_secondary_suppression():
    df = pd.DataFrame({"canton": ["A", "B"], "value": [100.0, 200.0],
                       "n": [15, 20], "dominance": [0.8, 0.2]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "secondary_suppression" for f in findings)
    assert len(released) == 0        # B alone would let the margin recover A


def test_counts_rounded_on_release():
    df = pd.DataFrame({"canton": ["A", "B"], "value": [1.0, 2.0], "n": [123, 47]})
    released, action, _ = DisclosurePolicy().apply(df)
    assert action == "release"
    assert list(released["n"]) == [125, 45]             # rounded to nearest 5


def test_small_cells_redacted():
    df = pd.DataFrame({"age_band": ["a", "b"], "mean_chf": [1.0, 2.0], "n": [50, 3]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert (released["n"] >= 10).all()
    assert any(f.rule == "small_cell" for f in findings)


def test_identifier_egress_denied():
    df = pd.DataFrame({"donor_id": ["D1", "D2"], "wemwbs_score": [40, 55]})
    released, action, _ = DisclosurePolicy().apply(df)
    assert action == "deny" and released is None


def test_free_text_flagged():
    df = pd.DataFrame({"free_text": ["hi", "there"]})
    assert any(f.rule == "free_text_egress" for f in leak_detector(df))


def test_static_check_blocks_import():
    assert not static_check("import os\nresult = 1").ok
    assert static_check("result = donors.groupby('canton').size()").ok


def test_auditor_differencing():
    a = SessionAuditor()
    assert a.observe("pop", 500) == []
    flags = a.observe("pop", 499)
    assert any(f.rule == "differencing" for f in flags)


def test_auditor_cohort_lineage_flags_near_cohort():
    a = SessionAuditor()
    vaud = (("canton", "==", "Vaud"),)
    vaud_minus_elderly = (("age_band", "!=", "50+"), ("canton", "==", "Vaud"))
    a.record_cohort("spend", vaud)
    flags = a.observe_cohort("spend", vaud_minus_elderly, symdiff=lambda a_, b_: 3)
    assert any(f.rule == "differencing" for f in flags)


def test_auditor_cohort_lineage_allows_separated_and_identical():
    a = SessionAuditor()
    vaud = (("canton", "==", "Vaud"),)
    a.record_cohort("spend", vaud)
    # well-separated cohort: symmetric difference is large -> fine
    assert a.observe_cohort("spend", (("canton", "==", "Geneve"),),
                            symdiff=lambda a_, b_: 200) == []
    # identical cohort: same query repeated reveals nothing new -> fine,
    # and the (possibly costly) symdiff is never even computed
    assert a.observe_cohort("spend", vaud,
                            symdiff=lambda a_, b_: 1 / 0) == []
    # other dataset: cohorts do not cross datasets
    assert a.observe_cohort("wellbeing", (("canton", "==", "Vaud"),),
                            symdiff=lambda a_, b_: 1 / 0) == []


def test_secondary_suppression_single_dim():
    # one primary-suppressed cell is recoverable from the grand total
    # (obtainable as a coarser query), so the next-smallest cell must go too
    df = pd.DataFrame({"canton": ["A", "B", "C", "D"],
                       "value": [1.0, 2.0, 3.0, 4.0],
                       "n": [3, 12, 30, 50]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "secondary_suppression" for f in findings)
    assert list(released["canton"]) == ["C", "D"]


def test_no_secondary_suppression_when_two_cells_suppressed():
    # two suppressed cells protect each other: the margin only gives their sum
    df = pd.DataFrame({"canton": ["A", "B", "C", "D"],
                       "value": [1.0, 2.0, 3.0, 4.0],
                       "n": [3, 4, 30, 50]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert not any(f.rule == "secondary_suppression" for f in findings)
    assert list(released["canton"]) == ["C", "D"]


def test_secondary_suppression_two_dims_margin():
    # (A, m) is primary-suppressed; protecting it against row AND column
    # margins forces a suppression rectangle over cantons {A, B} x sexes
    # {m, f}, after which no margin has a lone recoverable cell. Canton C
    # survives. (Minimal patterns are an LP problem -> ACRO, round 3.)
    df = pd.DataFrame({"canton": ["A", "A", "B", "B", "C", "C"],
                       "sex": ["m", "f", "m", "f", "m", "f"],
                       "value": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
                       "n": [3, 20, 40, 50, 60, 70]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "secondary_suppression" for f in findings)
    assert set(released["canton"]) == {"C"}
    assert set(released["sex"]) == {"m", "f"}
    # no margin (canton level or sex level) is left with exactly one
    # suppressed cell, so no cell is recoverable by subtraction
    for dim in ("canton", "sex"):
        for lvl in df[dim].unique():
            n_missing = (df[dim] == lvl).sum() - (released[dim] == lvl).sum()
            assert n_missing != 1
