"""Run the Alloy checks headlessly and turn the receipts into a CI verdict.

The Alloy 6 CLI (`java -jar org.alloytools.alloy.dist.jar exec`) exits 0
whether or not a `check` finds a counterexample; the outcome is encoded in the
receipt.json it writes: a `check` command with any solution instance HAS a
counterexample, a `run` command with none is unsatisfiable. This wrapper runs
every command in every model and fails loudly when:

- any `check` has a counterexample (a modelled property is violated),
- any `run` is unsatisfiable — either the model is vacuous (the checks prove
  nothing) or, for the disclosure model's residual runs, the model disagrees
  with the residual risks the code documents,
- an expected command is missing (a model was edited out from under CI).

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

# model file -> the commands the verdict requires (a renamed or deleted
# assertion fails here rather than silently narrowing coverage)
MODELS: dict[str, dict[str, set[str]]] = {
    "glm_gateway.als": {
        "checks": {
            "P19_noFitOnSuppressedCells",
            "P21_fitterSeesOnlyReleasedCells",
            "P4_internalNeverEntersAModel",
            "AdmissibleSpaceMatchesCatalogue",
        },
        "runs": {"someAdmissibleSpec"},
    },
    "disclosure_policy.als": {
        "checks": {
            "MarginalBoundSound",
            "RareCategoryIsolationBlocked",
        },
        "runs": {
            "someSession",
            "InteractionResidualExists",
            "MultiDimSentinelResidual",
        },
    },
}


def run_model(jar: str, model: str, expected: dict[str, set[str]]) -> list[str]:
    """Execute one model's commands; return the verdict failures."""
    with tempfile.TemporaryDirectory() as out:
        proc = subprocess.run(
            ["java", "-jar", jar, "exec", "-f", "-o", out, "-c", "*", model],
            capture_output=True, text=True)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            return [f"alloy exec exited {proc.returncode} for {model}"]
        receipt_path = os.path.join(out, "receipt.json")
        if not os.path.exists(receipt_path):
            return [f"alloy exec produced no receipt.json for {model}"]
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
            failures.append(
                f"run {name!r} is unsatisfiable — vacuous model or a "
                "documented residual the model no longer exhibits")

    checks = {n for n, c in commands.items() if c.get("type") == "check"}
    runs = {n for n, c in commands.items() if c.get("type") == "run"}
    if not expected["checks"] <= checks:
        failures.append(
            f"missing expected checks: {sorted(expected['checks'] - checks)}")
    if not expected["runs"] <= runs:
        failures.append(
            f"missing expected runs: {sorted(expected['runs'] - runs)}")
    return [f"{os.path.basename(model)}: {f}" for f in failures]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jar", required=True,
                    help="path to org.alloytools.alloy.dist.jar")
    args = ap.parse_args()

    failures: list[str] = []
    ok = 0
    for model, expected in MODELS.items():
        model_failures = run_model(args.jar, os.path.join(HERE, model), expected)
        failures += model_failures
        if not model_failures:
            ok += 1

    for failure in failures:
        print(f"FAIL: {failure}")
    if not failures:
        print(f"OK: {ok} model(s) — every check holds, every run satisfiable")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
