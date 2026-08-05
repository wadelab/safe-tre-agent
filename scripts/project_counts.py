"""Canonical project counts, derived from the repository's own record.

The single source of truth for the numbers the bestiary cites -- findings,
threats, decision records, red-team scenarios -- so they cannot drift. The
artifact generator (`make_bestiary_page.py`) fills its `{{...}}` placeholders
from here; `tests/test_counts_current.py` fails CI when a hand-written doc or
the deck cites a number that no longer matches. Each derivation fails loud if
its source moves rather than reporting a wrong count.
"""
from __future__ import annotations
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


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
    scenarios = (len(re.findall(r"(?m)^- name:", atk))
                 - len(re.findall(r"(?m)^  type: benign", atk)))

    return {"findings": max(nums),
            "threats": max(0, len(rows) - 1),   # drop the header row
            "decisions": len(decisions),
            "redteam": scenarios}


if __name__ == "__main__":
    for k, v in counts().items():
        print(f"{k}: {v}")
