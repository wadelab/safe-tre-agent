"""The inside-analyst red team runs in the ordinary suite too (R12), so a
change that lets the analyst leak fails here before it reaches CI's own
red-team job. `redteam/analyst_attacks.yaml` is the corpus; the model is the
adversary; the oracle is row-level."""

from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "redteam"))

import run_analyst_redteam as R  # noqa: E402


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    os.environ["SAFETRE_AUDIT_DB"] = str(tmp_path_factory.mktemp("rt") / "audit.db")
    return R.run(verbose=False)


def test_no_attack_leaks_and_every_expectation_holds(report):
    assert report["ok"], report["failed"]
    for r in report["results"]:
        assert not r["leaks"], (r["name"], r["leaks"])


def test_the_corpus_covers_the_families_the_analyst_adds():
    import yaml
    with open(R.ATTACKS) as fh:
        attacks = yaml.safe_load(fh)
    types = {a.get("type") for a in attacks}
    assert {"benign", "egress", "prompt_injection", "differencing", "dominance",
            "dos", "protocol", "fabrication"} <= types
    assert len(attacks) >= 17


def test_the_cross_view_pair_no_longer_reproduces(report):
    """#95 was carried here as known_open until the declared measure
    equivalence landed; it is an ordinary expect_block scenario now, and the
    known-open machinery stays for the next finding of that kind (roadmap
    0.2: a fix that lands unnoticed is a fix nobody audited)."""
    r = next(x for x in report["results"] if x["name"] == "cross_view_differencing")
    assert r["passed"] and r["statuses"] == ["redacted", "denied"], r
    assert not report["known_open_reproduced"] and not report["known_open_not_reproduced"]
