"""Canonical project counts, derived from the repository's own record.

The single source of truth for the numbers the bestiary cites -- findings,
threats, decision records, red-team scenarios -- and for the summary numbers
the plain-language pages hand-type (scenario split, Alloy checks, test count),
so none of them can drift. The artifact generator (`make_bestiary_page.py`)
fills its `{{...}}` placeholders from here; `tests/test_counts_current.py`
fails CI when a hand-written doc or the deck cites a number that no longer
matches. Each derivation fails loud if its source moves rather than reporting
a wrong count.

`counts()` is static and cheap -- it only reads files, so generators can call
it freely. `tests_collected()` shells out to pytest and is for the keeper test
alone.
"""
from __future__ import annotations
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def _alloy() -> tuple[int, int]:
    """(check statements, models containing at least one) across `formal/*.als`.

    A `check` is only a proof obligation when it starts a statement, so anchor
    to column 0 -- the word also appears in the models' prose comments.
    """
    models = sorted(glob.glob(os.path.join(ROOT, "formal", "*.als")))
    if not models:
        raise RuntimeError("no Alloy models in formal/")
    per_model = [len(re.findall(r"(?m)^check\s", open(p, encoding="utf-8").read()))
                 for p in models]
    if not sum(per_model):
        raise RuntimeError("no 'check' statements in formal/*.als")
    return sum(per_model), sum(1 for n in per_model if n)


def tests_collected() -> int:
    """How many tests the default run selects (`-m 'not slow'` from pyproject).

    Deliberately not part of `counts()`: it spawns a collection pass. Raises
    rather than guessing if pytest's summary line cannot be parsed -- a wrong
    number here would be worse than no guard.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
    )
    # "969/972 tests collected (3 deselected) in 4.00s", or plain
    # "972 tests collected in 4.00s" when nothing is deselected.
    m = re.search(r"(?m)^(\d+)(?:/\d+)? tests collected", proc.stdout)
    if not m:
        raise RuntimeError(
            "could not parse pytest's collection summary; "
            f"rc={proc.returncode}\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return int(m.group(1))


def counts() -> dict:
    log = _read("docs", "hardening-log.md")
    # A finding is numbered in its table row (`| 104 | ...`); narrative "#N"
    # mentions also count, but an entry whose prose happens not to cite its own
    # number must not make the tally stop short (round 12 did exactly that).
    nums = [int(n) for n in re.findall(r"#(\d+)", log)]
    nums += [int(n) for n in re.findall(r"(?m)^\|\s*(\d+)\s*\|", log)]
    if not nums:
        raise RuntimeError("no #N findings in docs/hardening-log.md")

    m = re.search(r"## Threats and controls(.*?)(?=\n## |\Z)",
                  _read("docs", "security.md"), re.S)
    if not m:
        raise RuntimeError("no 'Threats and controls' section in docs/security.md")
    rows = [line for line in m.group(1).splitlines()
            if line.strip().startswith("|") and "---" not in line]

    decisions = [f for f in os.listdir(os.path.join(ROOT, "docs", "decisions"))
                 if re.match(r"D\d+.*\.md$", f)]

    atk = _read("redteam", "attacks.yaml")
    scenarios = len(re.findall(r"(?m)^- name:", atk))
    benign = len(re.findall(r"(?m)^  type: benign", atk))
    if not scenarios:
        raise RuntimeError("no scenarios in redteam/attacks.yaml")

    alloy_checks, alloy_models = _alloy()

    return {"findings": max(nums),
            "threats": max(0, len(rows) - 1),   # drop the header row
            "decisions": len(decisions),
            # `redteam` is the attack count -- what the bestiary cites. The
            # plain-language pages quote the whole corpus and its split.
            "redteam": scenarios - benign,
            "scenarios": scenarios,
            "attacks": scenarios - benign,
            "benign": benign,
            "alloy_checks": alloy_checks,
            "alloy_models": alloy_models}


if __name__ == "__main__":
    for k, v in counts().items():
        print(f"{k}: {v}")
