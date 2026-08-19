"""The VRR red team runs, finds nothing, and could still find something.

`redteam/run_vrr_redteam.py` is the corpus; this is the CI gate on it, in the
shape `tests/test_inside_analyst_redteam.py` uses for the analyst corpus.

Three things are pinned, and the second and third matter more than the first:

1. no adversary learns anything from any scenario's exported bundle;
2. **no scenario is vacuous.** A corpus where nothing was withheld proves
   nothing about whether withheld things stay withheld, so every scenario must
   carry a real secret — a refused stage, a suppressed category, or both;
3. **the harness can still fail.** The adversaries are run against a
   deliberately leaky bundle and must report the leak. A red-team suite that has
   quietly become a no-op reads exactly like a red-team suite that passes.

Marked `slow`: six scenarios each generate a study, execute, replay, sign and
export. About a minute.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def report():
    from redteam.run_vrr_redteam import run
    return run(verbose=False)


def test_no_adversary_learns_anything(report):
    leaks = {r["name"]: r["learned"] for r in report["results"] if r["learned"]}
    assert not leaks, leaks
    assert report["ok"], report["failed"]


def test_every_bundle_verifies_offline(report):
    for result in report["results"]:
        assert result["exported"], result["name"]
        assert result["verified"], f"{result['name']}: {result['problems']}"


def test_no_scenario_is_vacuous(report):
    """Each scenario must actually withhold something. Without this the corpus
    can decay into six benign runs that pass because there was no secret."""
    for result in report["results"]:
        if result["type"] == "overclaim":
            continue                     # scores a claim, not a withheld fact
        assert result["refused"] or result["excluded_levels"], (
            f"{result['name']} withholds nothing, so it cannot show that "
            "withheld things stay withheld")


def test_the_corpus_covers_both_subthreshold_groups(report):
    """NIGHTPLAY plants two sub-threshold groups on two different dimensions
    (armed_forces on employment, Northern Ireland on region). A leak keyed to
    one hard-coded category name would pass a corpus that only used the other."""
    excluded = {lv for r in report["results"] for lv in r["excluded_levels"]}
    assert {"armed_forces", "Northern Ireland"} <= excluded, excluded


def test_a_record_that_releases_nothing_is_still_exportable(report):
    """Otherwise the ABSENCE of a bundle answers "did anyone match?" for the
    whole question, which is a worse channel than any this corpus probes."""
    nothing = next(r for r in report["results"] if r["name"] == "everything_refused")
    assert nothing["released"] == [] and nothing["exported"]
    assert nothing["verified"]


def test_the_adversaries_report_a_leak_when_there_is_one():
    """The control: hand the adversaries a bundle that leaks and require them to
    say so. Runs without the harness, so it stays fast."""
    from redteam.vrr_adversary import run_adversaries

    oracle = {
        "declared_stages": ["a", "b"], "declared_stage_count": 2,
        "released_stages": ["a"], "refused_stages": ["b"],
        "excluded_levels": ["armed_forces"],
        "true_group_sizes": {"armed_forces": 6},
        "selection_bits": 1,
        "private_messages": ["blocked by safe-outputs gateway"],
        "private_findings": ["armed_forces has 6 donors"],
        "analyst": "analyst-7",
    }
    leaky = {
        "provenance.json": (
            '{"nodes": [{"stage_id": "a"}], '
            '"committed_plan": {"stages": [{"id": "a"}, {"id": "b"}]}}'),
        "evidence.json": '[{"source_stage": "b", "values": {}}]',
        "README.md": ("excluded armed_forces; selection_bits 1; "
                      "blocked by safe-outputs gateway; "
                      "armed_forces has 6 donors; ran as analyst-7; "
                      "this result IS CORRECT"),
    }
    learned = {k: v for k, v in run_adversaries(leaky, oracle).items() if v}
    for probe in ("declared_topology", "withheld_categories", "subthreshold_counts",
                  "private_prose", "selection_spend", "correctness_badge"):
        assert probe in learned, f"{probe} missed a planted leak: {learned}"


def test_the_hash_dictionary_adversary_breaks_an_unkeyed_commitment():
    """The Glass Safe probe, against a bundle that publishes a raw hash of a
    low-entropy private value. If this stops finding it, the probe has broken."""
    import hashlib

    from redteam.vrr_adversary import hash_dictionary
    from safetre.research_record import canonical_json

    digest = hashlib.sha256(canonical_json({"suppressed_cells": 6}).encode()).hexdigest()
    oracle = {"excluded_levels": [], "true_group_sizes": {}}
    learned = hash_dictionary({"provenance.json": f'{{"c": "sha256:{digest}"}}'}, oracle)
    assert learned and "6" in learned[0], learned
