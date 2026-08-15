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
    assert len(attacks) >= 14


def test_known_open_findings_still_reproduce(report):
    """A fix that lands unnoticed is a fix nobody audited (roadmap 0.2): the
    cross-view differencing pair (#95) is expected to reproduce on the second
    study until the declared measure equivalence lands."""
    assert "cross_view_differencing" in report["known_open_reproduced"], report
    assert not report["known_open_not_reproduced"], report["known_open_not_reproduced"]
