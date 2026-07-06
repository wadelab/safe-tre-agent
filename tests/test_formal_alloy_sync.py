"""The committed Alloy model must match the live registry export (R16).

Second hop of the correspondence chain (skeleton -> model), pure Python — no
Java needed in the default test run. `scripts/gen_alloy_catalogue.py` without
--write exits 1 when either formal/skeleton.json or the generated block of
formal/glm_gateway.als is stale; the solver job in CI then only has to prove
the assertions, never to trust a hand-edited catalogue.
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATOR = os.path.join(ROOT, "scripts", "gen_alloy_catalogue.py")


def test_formal_artifacts_match_live_registry():
    proc = subprocess.run([sys.executable, GENERATOR],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, (
        f"formal artifacts are stale:\n{proc.stdout}{proc.stderr}")


def test_alloy_model_declares_the_expected_commands():
    # the CI verdict script fails on missing commands; mirror that here so a
    # renamed assertion is caught without a Java toolchain
    from formal.run_checks import EXPECTED_CHECKS, EXPECTED_RUNS
    with open(os.path.join(ROOT, "formal", "glm_gateway.als")) as fh:
        source = fh.read()
    for name in EXPECTED_CHECKS:
        assert f"check {name}" in source, name
    for name in EXPECTED_RUNS:
        assert f"run {name}" in source, name
