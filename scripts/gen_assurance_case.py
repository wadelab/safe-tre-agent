"""Render the assurance case: the safety argument, as a structure.

The specification says what must hold; the traceability table says what
enforces and checks each clause; the decision log says what was chosen and
what is still open. None of them says *how the argument fits together* — which
is the thing a certifier, a reviewer, or a maintainer returning in a year
actually needs.

This renders that shape, in the form safety-critical work uses for it: a top
claim, decomposed by an explicit strategy into sub-claims, each resting on
evidence, with assumptions as context and the gaps marked as **undeveloped**
rather than omitted. The strategy here is the Five Safes, because it is the
decomposition TRE accreditation already speaks.

Nothing is written twice. Clauses, their enforcement, their tests and their
status come from the specification's traceability table; the open questions
come from the decision records; the assumptions come from the specification.
The one thing declared here is which Safe each clause serves, and a clause
without one fails the build — the same rule as everywhere else in this
project: you may not add a control without saying what it is for.

Usage:
    uv run python scripts/gen_assurance_case.py            # print
    uv run python scripts/gen_assurance_case.py --write    # update the page
"""

from __future__ import annotations

import argparse
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "docs", "specification.md")
DECISIONS = os.path.join(ROOT, "docs", "decisions")
PAGE = os.path.join(ROOT, "docs", "assurance-case.md")

# Which of the Five Safes each clause serves. This is the only hand-declared
# mapping in the file, and a clause missing from it fails the build: a control
# whose purpose nobody can name is a control nobody can weigh.
SAFES: dict[str, list[str]] = {
    "Safe projects": ["P1", "P2", "P10", "R1", "R12"],
    "Safe people": ["P13", "P14", "R10"],
    "Safe settings": ["P8", "P9", "P12", "P15", "P16", "R3", "R8", "R13"],
    "Safe data": ["P3", "P4", "P5", "P6", "R2", "R9", "R14"],
    "Safe outputs": ["P7", "P11", "P17", "P18", "P19", "P20", "P21", "P22",
                     "R4", "R5", "R6", "R7", "R11", "R15", "R16", "R17"],
}

WHY = {
    "Safe projects": "the request is one this data may be used for at all",
    "Safe people": "the person asking is entitled to ask",
    "Safe settings": "the enclave the analysis runs in does not leak",
    "Safe data": "what the analysis can reach is already limited",
    "Safe outputs": "what leaves the enclave discloses nothing about anyone",
}

TOP = """# Assurance case

The safety argument as a structure rather than a narrative: what is claimed,
how the claim decomposes, what each part rests on, and — the part usually left
out — **where the argument is not finished**.

This page is generated. The clauses, what enforces them, what checks them and
their status come from the [specification](specification.md)'s traceability
table; the open questions come from the [decision log](decision-log.md); the
assumptions come from the specification's trust model. If the code and its
tests move, this moves with them, which is the only way an argument like this
stays worth reading.

## The claim

> Under the stated assumptions, an untrusted language model placed between an
> analyst and sensitive data does not weaken the disclosure guarantee: nothing
> leaves the enclave that discloses an individual, and every release is
> explicable and reproducible from what was released.

It is a *conditional* claim. The assumptions below are not hedges, they are
the boundary — outside them nothing here is claimed at all.

## Context: what is assumed

"""

STRATEGY = """
## Strategy: decompose by the Five Safes

The claim is argued by the framework TRE accreditation already uses, so a
reader can check it against the thing they know. Each Safe carries the clauses
that serve it, each clause names what enforces it and what checks it, and a
clause whose status is *Partial* is shown as an **undeveloped goal** — a place
the argument is honest about being incomplete rather than quiet about it.

"""

FOOTER = """
## How to read a gap

An undeveloped goal is not a defect report. It says the claim at that point
rests on something weaker than proof — a documented residual, a control that
is exact in one dimension and conservative in others, a question with an
answer that has not been measured yet. The value of drawing the argument this
way is that those places are visible at the same resolution as the parts that
are finished, instead of being a sentence in a document nobody reaches.

Three kinds appear above. A *partial clause* is one the specification itself
marks as incompletely discharged. An *unevidenced clause* is one the
traceability table does not reach — it is enforced and tested somewhere, but
the record saying where does not exist, and an argument may not cite evidence
it cannot point at. An *open decision* is a question recorded in the decision
log with no answer yet, carrying its own acceptance criteria for what would
close it.

## Adding to the argument

A new clause must be assigned to a Safe in `scripts/gen_assurance_case.py`,
and `tests/test_assurance_case.py` fails the build until it is. Then:

```sh
uv run python scripts/gen_assurance_case.py --write
```
"""


def assumptions() -> list[tuple[str, str]]:
    spec = open(SPEC).read()
    return [(m.group(1), " ".join(m.group(2).split()))
            for m in re.finditer(r"- \*\*(A\d+)\*\* — (.+?)(?=\n- \*\*A|\n\n)",
                                 spec, re.S)]


def clauses_in_spec() -> set[str]:
    """Every clause the specification states, whether or not the traceability
    table reaches it."""
    return set(re.findall(r"\*\*([RP]\d+)\*\* —", open(SPEC).read()))


def traceability() -> list[dict]:
    """The traceability table, which already says what enforces and checks
    every clause. Parsed rather than restated, so the two cannot disagree."""
    rows = []
    for line in open(SPEC):
        if not line.startswith("| ") or line.startswith("| Clause"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or not re.match(r"^[RP]\d+ ", cells[0]):
            continue
        clause, _, rest = cells[0].partition(" ")
        rows.append({"clause": clause, "what": rest, "where": cells[1],
                     "checked_by": cells[2], "status": cells[3]})
    return rows


def unanswered_decisions() -> list[dict]:
    out = []
    for name in sorted(os.listdir(DECISIONS)):
        if not name.endswith(".md"):
            continue
        _, header, _ = open(os.path.join(DECISIONS, name)).read().split("---\n", 2)
        meta = yaml.safe_load(header) or {}
        if meta.get("status") in ("open", "parked"):
            meta["file"] = name
            out.append(meta)
    return out


def _order(clause: str) -> tuple:
    return (clause[0], int(clause[1:]))


def render() -> str:
    rows = {r["clause"]: r for r in traceability()}
    out = [TOP]
    for ident, text in assumptions():
        out.append(f"- **{ident}** — {text}")
    out.append(STRATEGY)

    undeveloped: list[str] = []
    unevidenced: list[str] = []
    for safe, clauses in SAFES.items():
        out.append(f"### {safe}\n")
        out.append(f"*Claim: {WHY[safe]}.*\n")
        out.append("| Clause | Enforced by | Checked by | |")
        out.append("|---|---|---|---|")
        for clause in clauses:
            row = rows.get(clause)
            if row is None:
                # the traceability table covers the prohibitions; a
                # requirement outside it is a claim this argument cannot
                # currently evidence, which is worth showing rather than
                # dropping the clause and looking complete
                unevidenced.append(clause)
                out.append(f"| {clause} | — | — | **unevidenced** |")
                continue
            partial = row["status"].lower().startswith("partial")
            mark = "**undeveloped**" if partial else "✓"
            if partial:
                undeveloped.append(f"{clause} — {row['what']} ({row['status']})")
            out.append(f"| {clause} {row['what']} | {row['where']} "
                       f"| {row['checked_by']} | {mark} |")
        out.append("")

    out.append("## Where the argument is unfinished\n")
    out.append("**Partial clauses** — discharged, but not completely:\n")
    out.extend(f"- {item}" for item in undeveloped)
    out.append("\n**Clauses with no recorded evidence** — the traceability "
               "table is scoped to the prohibitions, so these requirements "
               "are claimed but not cited. Each is enforced somewhere and "
               "tested somewhere; what is missing is the record saying "
               "where, which is what an assurance argument needs:\n")
    out.append("- " + ", ".join(sorted(unevidenced, key=_order)) + "\n")
    out.append("**Unanswered decisions** — *open* means the work has not been "
               "done; *parked* means it was scoped and deliberately left "
               "undone, with the reasoning recorded:\n")
    for meta in unanswered_decisions():
        question = " ".join(str(meta.get("question", "")).split())
        out.append(f"- **[{meta['id']}](decisions/{meta['file']})** "
                   f"({meta['status']}) {meta['title']} — {question}")
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
    print(f"wrote {os.path.relpath(PAGE, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
