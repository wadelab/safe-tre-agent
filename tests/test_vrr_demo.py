"""The demonstration command actually runs (build plan, "first demonstration script").

In the default run: the whole thing — generate the study, execute the analysis,
replay it, sign a bundle, tamper with it — takes about four seconds. It is here
because `scripts/run_vrr_demo.py` is the artifact the build plan asks to be built
first and grown around, and an unexercised script rots: the ten steps it prints
would keep printing long after one of them stopped meaning anything.

The script returns nonzero if any step fails to do what it says, so the exit
status is most of the assertion. What is checked beyond that is the part a
passing exit code cannot show: that the bundle it left behind verifies from the
files alone, and that the category its contingency privately excluded is in none
of them.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# `scripts/` is not on the suite's import path, and putting it there globally
# would let a script name shadow a module for every test in the tree. The same
# local insertion `test_counts_current.py` uses for `project_counts`.
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import run_vrr_demo  # noqa: E402

@pytest.fixture
def restore_active_dataset():
    """The demo activates the NIGHTPLAY definition and, being a command, never
    puts it back. Nothing else in the suite should inherit that: a module that
    assumes the packaged demo catalogue would fail depending on test ORDER,
    which is the worst way to find out."""
    from safetre import dataset as dataset_mod

    packaged = os.path.join(os.path.dirname(dataset_mod.__file__), "demo_dataset.yaml")
    try:
        yield
    finally:
        dataset_mod.activate(dataset_mod.load_dataset(packaged))


def test_the_demo_runs_end_to_end_and_leaves_a_verifiable_bundle(
        tmp_path, monkeypatch, capsys, restore_active_dataset):

    monkeypatch.setenv("SAFETRE_VRR_COMMIT_KEY", "demo-internal-commitment-key")
    monkeypatch.setenv("SAFETRE_AUDIT_KEY", "demo-audit-key")
    out = str(tmp_path / "vrr")

    assert run_vrr_demo.main(["--out", out, "--people", "2500"]) == 0

    # the ten steps the build plan asks for, all of them
    printed = capsys.readouterr().out
    for step in range(1, 11):
        assert f"[{step:2d}]" in printed, f"step {step} did not run:\n{printed}"
    assert "COMPUTATION_REPRODUCED" in printed
    assert "EXPLORATORY_POSTHOC" in printed
    assert "fails, as it must" in printed

    from safetre import attestation as A
    from safetre import vrr_bundle as B

    bundles = [d for d in sorted(os.listdir(out)) if d.startswith("vrr-")]
    assert len(bundles) == 1, bundles
    path = os.path.join(out, bundles[0])

    _, public = A.generate_keypair(seed=b"vrr-demo-test-signing-key-32byte")
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert ok, findings

    with open(os.path.join(path, "provenance.json"), encoding="utf-8") as fh:
        provenance = json.load(fh)
    assert provenance["classification"] == "TRE_PRECOMMITTED"
    assert provenance["audit_chain_verified"] is True

    # NIGHTPLAY plants armed_forces as a sub-threshold employment category, and
    # the demo's plan excludes it through the data-sighted contingency. That is
    # the private fact with a name, so it is the one to look for.
    for name in B.FILES:
        with open(os.path.join(path, name), encoding="utf-8") as fh:
            assert "armed_forces" not in fh.read(), name
