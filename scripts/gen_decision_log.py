"""Render the index of decision records.

A decision record says why the system is the way it is, on the terms that
would let someone disagree: the question, the evidence it rests on, what was
rejected, and — the field usually missing — **what would change our mind**.

The records live in `docs/decisions/` as markdown with a structured header.
This renders their index; `tests/test_decision_log.py` checks that every
record declares its fields, cites clauses that exist and evidence that exists,
says what would revisit it, and that the index is not stale. Nothing here
knows any particular decision: add a file and it appears.

Usage:
    uv run python scripts/gen_decision_log.py            # print
    uv run python scripts/gen_decision_log.py --write    # update the page
"""

from __future__ import annotations

import argparse
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORDS = os.path.join(ROOT, "docs", "decisions")
PAGE = os.path.join(ROOT, "docs", "decision-log.md")

REQUIRED = ("id", "title", "date", "status", "question", "clauses",
            "revisit_when")
STATUSES = ("accepted", "open", "superseded")

HEADER = """# Decision log

Why the system is the way it is. The [hardening log](hardening-log.md) records
what went wrong and was fixed; this records what was *chosen* when more than
one answer was defensible.

Each record states the question, the evidence it rested on, what was rejected,
and **what would change our mind**. That last field is the one that makes a
record worth keeping: a decision whose conditions for revision are not written
down cannot be revisited honestly later, only defended or abandoned. Where a
question is still open, it is recorded as open rather than left out, so the
gaps in the argument are visible in the same place as the answers.

Records are immutable once accepted. A decision that changes gets a new record
superseding the old one, so the reasoning that applied at the time survives
alongside the reasoning that replaced it.

"""

FOOTER = """
## Adding a record

Create `docs/decisions/D<n>-<slug>.md` with the header fields above — `status`
is `accepted`, `open` or `superseded` — and regenerate:

```sh
uv run python scripts/gen_decision_log.py --write
```

`tests/test_decision_log.py` fails the build on a missing field, a clause that
is not in the specification, evidence that does not exist, an empty
`revisit_when`, a duplicate or mismatched id, or a stale index.
"""


def records() -> list[dict]:
    found = []
    for name in sorted(os.listdir(RECORDS)):
        if not name.endswith(".md"):
            continue
        path = os.path.join(RECORDS, name)
        text = open(path).read()
        if not text.startswith("---\n"):
            raise SystemExit(f"{name}: no header block")
        _, header, _ = text.split("---\n", 2)
        meta = yaml.safe_load(header) or {}
        meta["file"] = name
        found.append(meta)
    return sorted(found, key=lambda m: str(m.get("id", "")))


def _relocate(prose: str) -> str:
    """A record cross-references its siblings relative to `docs/decisions/`.
    Inlined into the index, which sits a level up, those links must be
    rewritten — otherwise every cross-reference a record makes is a broken
    link on the index page."""
    return re.sub(r"\]\((D\d+-[a-z0-9-]+\.md)\)", r"](decisions/\1)", prose)


def render() -> str:
    out = [HEADER, "| | Decision | Status | Clauses |", "|---|---|---|---|"]
    for meta in records():
        status = meta.get("status", "?")
        shown = f"**{status}**" if status == "open" else status
        clauses = ", ".join(meta.get("clauses", [])) or "—"
        link = f"decisions/{meta['file']}"
        out.append(f"| {meta.get('id')} | [{meta.get('title')}]({link}) "
                   f"| {shown} | {clauses} |")
    out.append("")
    for meta in records():
        out.append(f"## {meta.get('id')} — {meta.get('title')}\n")
        out.append(f"*{meta.get('date')} · {meta.get('status')}*\n")
        out.append(_relocate(str(meta.get("question", "")).strip()) + "\n")
        out.append("**What would change our mind.** "
                   + _relocate(str(meta.get("revisit_when", "")).strip()) + "\n")
        out.append(f"[Read the record](decisions/{meta['file']})\n")
    out.append(FOOTER)
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    page = render()
    if not args.write:
        sys.stdout.write(page)
        return 0
    with open(PAGE, "w") as fh:
        fh.write(page)
    print(f"wrote {os.path.relpath(PAGE, ROOT)} ({len(records())} records)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
