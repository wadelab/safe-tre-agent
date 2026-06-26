"""Unit tests for the disclosure gateway and guards. Run: pytest -q"""

import pandas as pd

from safetre.disclosure import DisclosurePolicy, SessionAuditor, leak_detector
from safetre.guards import static_check


def test_dominance_cell_suppressed():
    df = pd.DataFrame({"canton": ["A", "B"], "value": [100.0, 200.0],
                       "n": [15, 20], "dominance": [0.8, 0.2]})
    released, action, findings = DisclosurePolicy().apply(df)
    assert action == "redacted"
    assert any(f.rule == "dominance" for f in findings)
    assert "dominance" not in released.columns          # internal helper never released
    assert list(released["canton"]) == ["B"]            # the dominated cell is gone


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
