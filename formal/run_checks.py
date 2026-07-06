"""Run the Alloy checks headlessly and turn the receipt into a CI verdict.

The Alloy 6 CLI (`java -jar org.alloytools.alloy.dist.jar exec`) exits 0
whether or not a `check` finds a counterexample; the outcome is encoded in the
receipt.json it writes: a `check` command with any solution instance HAS a
counterexample, a `run` command with none is unsatisfiable. This wrapper runs
every command in the model and fails loudly when:

- any `check` has a counterexample (a P-clause is violated in the model),
- any `run` is unsatisfiable (the model is vacuous — the checks prove nothing),
- an expected command is missing (the model was edited out from under CI).

Usage:
    python formal/run_checks.py --jar /path/to/org.alloytools.alloy.dist.jar
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "glm_gateway.als")

EXPECTED_CHECKS = {
    "P19_noFitOnSuppressedCells",
    "P21_fitterSeesOnlyReleasedCells",
    "P4_internalNeverEntersAModel",
    "AdmissibleSpaceMatchesCatalogue",
}
EXPECTED_RUNS = {"someAdmissibleSpec"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jar", required=True, help="path to org.alloytools.alloy.dist.jar")
    ap.add_argument("--model", default=MODEL)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as out:
        proc = subprocess.run(
            ["java", "-jar", args.jar, "exec", "-f", "-o", out, "-c", "*",
             args.model],
            capture_output=True, text=True)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            print(f"FAIL: alloy exec exited {proc.returncode}")
            return proc.returncode
        receipt_path = os.path.join(out, "receipt.json")
        if not os.path.exists(receipt_path):
            print("FAIL: alloy exec produced no receipt.json")
            return 1
        with open(receipt_path) as fh:
            receipt = json.load(fh)

    failures: list[str] = []
    commands = receipt.get("commands", {})
    for name, cmd in commands.items():
        instances = sum(len(s.get("instances", []))
                        for s in cmd.get("solution", []))
        if cmd.get("type") == "check" and instances:
            failures.append(f"counterexample found for check {name!r}")
        if cmd.get("type") == "run" and not instances:
            failures.append(f"run {name!r} is unsatisfiable — the model is vacuous")

    checks = {n for n, c in commands.items() if c.get("type") == "check"}
    runs = {n for n, c in commands.items() if c.get("type") == "run"}
    if not EXPECTED_CHECKS <= checks:
        failures.append(f"missing expected checks: {sorted(EXPECTED_CHECKS - checks)}")
    if not EXPECTED_RUNS <= runs:
        failures.append(f"missing expected runs: {sorted(EXPECTED_RUNS - runs)}")

    for failure in failures:
        print(f"FAIL: {failure}")
    if not failures:
        print(f"OK: {len(checks)} checks hold (no counterexample), "
              f"{len(runs)} run(s) satisfiable")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
