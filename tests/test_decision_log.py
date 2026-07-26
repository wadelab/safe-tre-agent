"""Every decision record says what would change our mind.

`docs/decisions/` holds the reasoning behind choices that had more than one
defensible answer. A record is only worth keeping if it can be argued with
later, which needs four things to be true and checkable: it states the
question, it cites clauses that exist, it cites evidence that exists, and it
says what would make us revisit it.

The last is the one that decays first and matters most. A decision whose
conditions for revision were never written down cannot be reopened honestly —
only defended by whoever remembers it, or abandoned by whoever does not.

Nothing here knows any particular decision. Add a record and these apply to it.
"""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404 - runs this repo's own generator
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from gen_decision_log import REQUIRED, STATUSES   # noqa: E402 - one vocabulary

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORDS = os.path.join(ROOT, "docs", "decisions")
PAGE = os.path.join(ROOT, "docs", "decision-log.md")
GENERATOR = os.path.join(ROOT, "scripts", "gen_decision_log.py")
SPEC = os.path.join(ROOT, "docs", "specification.md")


def _records():
    out = []
    for name in sorted(os.listdir(RECORDS)):
        if name.endswith(".md"):
            text = open(os.path.join(RECORDS, name)).read()
            _, header, body = text.split("---\n", 2)
            out.append((name, yaml.safe_load(header) or {}, body))
    return out


RECORD_LIST = _records()
IDS = [name for name, _, _ in RECORD_LIST]


def test_there_are_records_to_check():
    assert RECORD_LIST, "no decision records found"


@pytest.mark.parametrize("record", RECORD_LIST, ids=IDS)
def test_a_record_declares_every_field(record):
    name, meta, _ = record
    for key in REQUIRED:
        assert meta.get(key), f"{name} declares no {key!r}"
    assert meta["status"] in STATUSES, f"{name}: unknown status {meta['status']!r}"


@pytest.mark.parametrize("record", RECORD_LIST, ids=IDS)
def test_a_record_says_what_would_change_our_mind(record):
    # the field this whole exercise exists for: prose long enough to be a
    # condition rather than a gesture
    name, meta, _ = record
    assert len(str(meta["revisit_when"]).strip()) > 80, (
        f"{name}: 'revisit_when' must state a condition, not a placeholder")


@pytest.mark.parametrize("record", RECORD_LIST, ids=IDS)
def test_a_record_cites_clauses_that_exist(record):
    name, meta, _ = record
    spec = open(SPEC).read()
    for clause in meta["clauses"]:
        assert re.search(rf"\*\*{clause}\*\*", spec), (
            f"{name} cites {clause}, which is not in the specification")


@pytest.mark.parametrize("record", RECORD_LIST, ids=IDS)
def test_a_record_cites_evidence_that_exists(record):
    name, meta, _ = record
    for path in meta.get("evidence", []) or []:
        assert os.path.exists(os.path.join(ROOT, path)), (
            f"{name} cites {path!r}, which does not exist")


@pytest.mark.parametrize("record", RECORD_LIST, ids=IDS)
def test_a_records_id_matches_its_filename(record):
    name, meta, _ = record
    assert name.startswith(f"{meta['id']}-"), (
        f"{name} declares id {meta['id']!r}")


@pytest.mark.parametrize("record", RECORD_LIST, ids=IDS)
def test_a_record_links_only_to_records_that_exist(record):
    # cross-references between decisions are how the argument hangs together;
    # a broken one is a broken argument
    name, _, body = record
    existing = set(os.listdir(RECORDS))
    for target in re.findall(r"\]\((D\d+-[a-z0-9-]+\.md)\)", body):
        assert target in existing, f"{name} links to {target}, which does not exist"


def test_ids_are_unique():
    ids = [meta["id"] for _, meta, _ in RECORD_LIST]
    assert len(ids) == len(set(ids)), f"duplicate ids in {ids}"


def test_an_unanswered_question_is_recorded_as_one():
    # the register is only honest if it holds the unanswered ones too —
    # whether nobody has done the work (open) or the work was scoped and
    # deliberately declined (parked)
    assert any(meta["status"] in ("open", "parked") for _, meta, _ in RECORD_LIST), (
        "no unanswered decisions — either the argument is complete, which is "
        "unlikely, or the questions are being left out of the record")


@pytest.mark.parametrize("record", RECORD_LIST, ids=IDS)
def test_a_parked_record_says_why_it_was_parked(record):
    # parking is a decision and carries the same burden as any other: the
    # reasoning must be in the record, not in whoever's head made the call
    name, meta, body = record
    if meta["status"] != "parked":
        return
    assert re.search(r"[Pp]arked", body), (
        f"{name} is parked but the record does not say why")


def test_the_index_matches_the_records():
    proc = subprocess.run(  # nosec B603 - fixed argv, this repo's generator
        [sys.executable, GENERATOR], capture_output=True, text=True, cwd=ROOT,
        check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == open(PAGE).read(), (
        "docs/decision-log.md is stale — run:\n"
        "  uv run python scripts/gen_decision_log.py --write")
