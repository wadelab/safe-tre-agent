"""The safety argument covers every clause, and admits where it is unfinished.

`docs/assurance-case.md` is the shape of the argument: the claim, the Five
Safes it decomposes into, the clauses under each, the evidence under those,
and the places the argument does not reach. It is generated from the
specification's traceability table and the decision records, so it moves when
they do.

What these tests defend is the property that makes such a document worth
trusting rather than reassuring: **it cannot quietly omit anything**. Every
clause must be assigned a purpose, every gap the specification admits must
appear as a gap here, and every open question must be listed. An assurance
case that shows only the discharged parts is worse than none, because it reads
as completeness.
"""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404 - runs this repo's own generator
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from gen_assurance_case import (                                  # noqa: E402
    SAFES, WHY, assumptions, clauses_in_spec, open_decisions, traceability,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "docs", "assurance-case.md")
GENERATOR = os.path.join(ROOT, "scripts", "gen_assurance_case.py")

ASSIGNED = {clause for clauses in SAFES.values() for clause in clauses}
CLAUSES = {row["clause"] for row in traceability()}


def test_the_traceability_table_was_actually_parsed():
    # the argument is generated from it, so an empty parse would silently
    # produce a confident, empty case
    assert len(CLAUSES) > 20, CLAUSES
    assert len(assumptions()) >= 5


def test_every_clause_serves_a_named_safe():
    # a control whose purpose nobody can name is a control nobody can weigh
    unassigned = CLAUSES - ASSIGNED
    assert not unassigned, (
        f"clauses with no Safe: {sorted(unassigned)} — assign them in "
        "scripts/gen_assurance_case.py")


def test_the_argument_invents_no_clauses():
    invented = ASSIGNED - clauses_in_spec()
    assert not invented, f"assigned but not in the specification: {sorted(invented)}"


def test_every_clause_the_specification_states_is_argued():
    # the traceability table is scoped to prohibitions; the argument is not,
    # so a requirement must still be placed under a Safe even though its
    # evidence row does not exist yet
    missing = clauses_in_spec() - ASSIGNED
    assert not missing, (
        f"clauses stated but not argued: {sorted(missing)} — assign them in "
        "scripts/gen_assurance_case.py")


def test_a_clause_without_evidence_is_shown_as_such():
    # the failure mode this whole page exists to avoid: looking complete by
    # omitting what cannot be cited
    page = open(PAGE).read()
    _, _, gaps = page.partition("## Where the argument is unfinished")
    for clause in sorted(ASSIGNED - CLAUSES):
        assert clause in gaps, f"{clause} has no evidence row and is not listed"


def test_every_safe_says_what_it_claims():
    assert set(SAFES) == set(WHY)
    for safe, why in WHY.items():
        assert len(why) > 20, f"{safe}: state the claim, not the label"


def test_every_partial_clause_appears_as_a_gap():
    # the specification's own honesty must survive into the argument
    page = open(PAGE).read()
    _, _, gaps = page.partition("## Where the argument is unfinished")
    for row in traceability():
        if row["status"].lower().startswith("partial"):
            assert row["clause"] in gaps, (
                f"{row['clause']} is Partial but is not listed as a gap")


def test_every_open_decision_appears_as_a_gap():
    page = open(PAGE).read()
    _, _, gaps = page.partition("## Where the argument is unfinished")
    for meta in open_decisions():
        assert meta["id"] in gaps, f"{meta['id']} is open but is not listed"


def test_a_discharged_clause_is_not_marked_undeveloped():
    page = open(PAGE).read()
    for line in page.splitlines():
        if not line.startswith("| ") or "undeveloped" not in line:
            continue
        clause = line.split()[1]
        row = next(r for r in traceability() if r["clause"] == clause)
        assert row["status"].lower().startswith("partial"), (
            f"{clause} is marked undeveloped but its status is {row['status']!r}")


def test_the_page_matches_the_sources():
    proc = subprocess.run(  # nosec B603 - fixed argv, this repo's generator
        [sys.executable, GENERATOR], capture_output=True, text=True, cwd=ROOT,
        check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == open(PAGE).read(), (
        "docs/assurance-case.md is stale — run:\n"
        "  uv run python scripts/gen_assurance_case.py --write")


def test_the_claim_states_its_assumptions_are_a_boundary():
    # the claim is conditional; a reader must not be able to take it otherwise
    page = open(PAGE).read()
    assert re.search(r"conditional", page)
    for ident, _ in assumptions():
        assert f"**{ident}**" in page, f"{ident} is not carried into the case"
