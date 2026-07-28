"""Unit tests for the disclosure gateway and guards. Run: pytest -q"""

import pandas as pd

from safetre.disclosure import DisclosurePolicy, SessionAuditor, leak_detector
from redteam.legacy.guards import static_check


def test_dominance_cell_suppressed():
    # two dominated cells: both go, and they protect each other against the
    # margin (a lone suppressed cell would trigger secondary suppression)
    df = pd.DataFrame({"region": ["A", "B", "C"], "value": [100.0, 200.0, 150.0],
                       "n": [15, 20, 25], "dominance": [0.8, 0.2, 0.6]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "dominance" for f in findings)
    assert "dominance" not in released.columns          # internal helper never released
    assert list(released["region"]) == ["B"]            # the dominated cells are gone


def test_lone_dominance_cell_triggers_secondary_suppression():
    df = pd.DataFrame({"region": ["A", "B"], "value": [100.0, 200.0],
                       "n": [15, 20], "dominance": [0.8, 0.2]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "secondary_suppression" for f in findings)
    assert len(released) == 0        # B alone would let the margin recover A


def test_influence_cell_suppressed():
    # a correlation cell one donor can move by > influence_threshold is dropped;
    # the well-behaved cell (with a benign neighbour to protect the margin) stays
    df = pd.DataFrame({"region": ["A", "B", "C"],
                       "value": [0.9, 0.1, 0.2], "p_value": [0.01, 0.7, 0.5],
                       "n": [12, 40, 45], "influence": [0.8, 0.05, 0.03]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "influence" for f in findings)
    assert "influence" not in released.columns          # internal helper never released
    assert "A" not in set(released["region"])           # the donor-dominated corr is gone


def test_influence_below_threshold_released():
    df = pd.DataFrame({"region": ["A", "B"],
                       "value": [0.3, 0.2], "p_value": [0.02, 0.1],
                       "n": [50, 60], "influence": [0.1, 0.05]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "release"
    assert not any(f.rule == "influence" for f in findings)
    assert "influence" not in released.columns
    # released rows come back ordered by the RELEASED count, descending (#28)
    assert list(released["region"]) == ["B", "A"]


def test_threshold_counts_donors_not_rows():
    # the frequency threshold protects individuals: a cell with many rows but
    # few distinct donors is disclosive and must be suppressed
    df = pd.DataFrame({"region": ["A", "B", "C"], "value": [1.0, 2.0, 3.0],
                       "n": [40, 50, 60], "n_donors": [3, 4, 50]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "small_cell" for f in findings)
    assert "n_donors" not in released.columns           # internal helper never released
    assert set(released["region"]) == {"C"}             # A,B have <10 donors despite 40-50 rows


def test_counts_rounded_on_release():
    df = pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0],
                       "n": [123, 47], "n_donors": [123, 47]})
    released, action, _ = DisclosurePolicy().apply(df)
    assert action == "release"
    assert list(released["n"]) == [125, 45]             # rounded to nearest 5
    assert "n_donors" not in released.columns


def test_small_cells_redacted():
    df = pd.DataFrame({"age_band": ["a", "b"], "mean_gbp": [1.0, 2.0], "n": [50, 3]})
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
    assert static_check("result = donors.groupby('region').size()").ok


def test_auditor_differencing():
    a = SessionAuditor()
    assert a.observe("pop", 500) == []
    flags = a.observe("pop", 499)
    assert any(f.rule == "differencing" for f in flags)


def test_auditor_cohort_lineage_flags_near_cohort():
    a = SessionAuditor()
    london = (("region", "==", "London"),)
    london_minus_elderly = (("age_band", "!=", "50+"), ("region", "==", "London"))
    a.record_cohort("spend", london)
    # the injected bound is small (< threshold) -> flagged
    flags = a.observe_cohort("spend", london_minus_elderly, bound=lambda a_, b_: 3)
    assert any(f.rule == "differencing" for f in flags)


def test_auditor_cohort_lineage_allows_separated_and_identical():
    a = SessionAuditor()
    london = (("region", "==", "London"),)
    a.record_cohort("spend", london)
    # well-separated cohort: bound is large -> fine
    assert a.observe_cohort("spend", (("region", "==", "South East"),),
                            bound=lambda a_, b_: 200) == []
    # identical cohort: same query repeated reveals nothing new -> fine,
    # and the (possibly costly) bound is never even computed
    assert a.observe_cohort("spend", london,
                            bound=lambda a_, b_: 1 / 0) == []
    # other dataset: cohorts do not cross datasets
    assert a.observe_cohort("wellbeing", (("region", "==", "London"),),
                            bound=lambda a_, b_: 1 / 0) == []


def test_secondary_suppression_single_dim():
    # one primary-suppressed cell is recoverable from the grand total
    # (obtainable as a coarser query), so the next-smallest cell must go too
    df = pd.DataFrame({"region": ["A", "B", "C", "D"],
                       "value": [1.0, 2.0, 3.0, 4.0],
                       "n": [3, 12, 30, 50]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "secondary_suppression" for f in findings)
    assert set(released["region"]) == {"C", "D"}


def test_no_secondary_suppression_when_two_cells_suppressed():
    # two suppressed cells protect each other: the margin only gives their sum
    df = pd.DataFrame({"region": ["A", "B", "C", "D"],
                       "value": [1.0, 2.0, 3.0, 4.0],
                       "n": [3, 4, 30, 50]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert not any(f.rule == "secondary_suppression" for f in findings)
    assert set(released["region"]) == {"C", "D"}


def test_complementary_suppression_choice_ignores_pre_rounding_counts():
    # A is below threshold, so one further cell in the grand-total margin must
    # go. B and C both release as n = 10, so which of them is sacrificed must
    # not depend on their exact counts: ranking on the exact minimum told an
    # analyst which of two equally-released cells was the smaller (#27). The
    # choice is the released count first, then the public cell key.
    def survivors(n_b, n_c):
        df = pd.DataFrame({"region": ["A", "B", "C", "D"],
                           "value": [1.0, 2.0, 3.0, 4.0],
                           "n": [3, n_b, n_c, 50]})
        released, action, findings = DisclosurePolicy().apply(df)
        assert action == "redacted"
        assert any(f.rule == "secondary_suppression" for f in findings)
        return set(released["region"])

    assert survivors(10, 12) == survivors(12, 10)
    assert survivors(10, 12) == {"C", "D"}          # B loses the key tie-break


def test_released_row_order_is_a_function_of_released_counts():
    # the engine hands the gateway cells in ORDER BY n DESC on the EXACT
    # count, so an order inherited from it ranks cells more finely than the
    # released counts do (#28). Two engine frames that differ only inside a
    # rounding bucket must release in the same order.
    def order(cells):
        df = pd.DataFrame({"region": [c for c, _ in cells],
                           "value": [1.0] * len(cells),
                           "n": [n for _, n in cells]})
        released, action, _ = DisclosurePolicy().apply(df)
        assert action == "release"
        return list(zip(released["region"], released["n"], strict=True))

    assert (order([("C", 50), ("A", 21), ("B", 19)])
            == order([("C", 50), ("B", 21), ("A", 19)]))
    assert order([("C", 50), ("A", 21), ("B", 19)]) == [("C", 50), ("A", 20),
                                                        ("B", 20)]


def test_secondary_suppression_two_dims_margin():
    # (A, m) is primary-suppressed; protecting it against row AND column
    # margins forces a suppression rectangle over regions {A, B} x sexes
    # {m, f}, after which no margin has a lone recoverable cell. Region C
    # survives. (Minimal patterns are an LP problem -> ACRO, round 3.)
    df = pd.DataFrame({"region": ["A", "A", "B", "B", "C", "C"],
                       "sex": ["m", "f", "m", "f", "m", "f"],
                       "value": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
                       "n": [3, 20, 40, 50, 60, 70]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "secondary_suppression" for f in findings)
    assert set(released["region"]) == {"C"}
    assert set(released["sex"]) == {"m", "f"}
    # no margin (region level or sex level) is left with exactly one
    # suppressed cell, so no cell is recoverable by subtraction
    for dim in ("region", "sex"):
        for lvl in df[dim].unique():
            n_missing = (df[dim] == lvl).sum() - (released[dim] == lvl).sum()
            assert n_missing != 1


# --- a missing value in an integer cell key (red-team, 2026-07-26) -------------

def test_a_missing_value_in_an_int_key_does_not_disable_suppression():
    """`age_rating` and `wave` are integer dimensions. One unrated app makes
    the column float64 on the way out of DuckDB, and the old "float means
    measure" test then dropped it from the cell keys — which silently returned
    `_secondary_suppress` at its `not group_cols` guard and turned complementary
    suppression off for the whole query."""
    from safetre.disclosure import DisclosurePolicy, _group_columns

    policy = DisclosurePolicy(threshold=10, round_base=5)
    frame = pd.DataFrame({"age_rating": [3, 7, None, 12],
                          "value": [1.0, 2.0, 3.0, 4.0], "n": [40, 30, 20, 3]})
    assert frame["age_rating"].dtype == "float64"
    assert _group_columns(frame) == ["age_rating"]
    assert _group_columns(frame, ("age_rating",)) == ["age_rating"]

    for keys in (None, ("age_rating",)):
        _, extra = policy._secondary_suppress(frame, frame[frame.n >= 10], keys)
        assert extra == 1, "one cell suppressed leaves a recoverable margin"


def test_a_missing_value_in_an_int_key_keeps_the_order_tie_break():
    """Hardening #28: of two cells that both release as n=10, the row order
    must not say which had more rows. The tie-break is the cell key, so losing
    the key loses the protection."""
    from safetre.disclosure import DisclosurePolicy

    policy = DisclosurePolicy(threshold=10, round_base=5)
    columns = {"value": [5.0, 6.0], "n_donors": [12, 9], "dominance": [0.1, 0.1]}
    ordered = pd.DataFrame({"wave": [1.0, 2.0], "n": [12, 9], **columns})
    reversed_ = pd.DataFrame({"wave": [2.0, 1.0], "n": [12, 9], **columns})
    for keys in (None, ("wave",)):
        assert (list(policy._finalize(ordered, keys)["wave"])
                == list(policy._finalize(reversed_, keys)["wave"]))


def test_a_genuine_float_measure_is_not_mistaken_for_a_cell_key():
    from safetre.disclosure import _group_columns

    frame = pd.DataFrame({"region": ["a", "b"], "value": [1.25, 3.5], "n": [40, 30]})
    assert _group_columns(frame) == ["region"]
