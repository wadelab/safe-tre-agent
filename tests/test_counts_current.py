"""The counts the docs hand-type match the repository's own record.

The artifact page auto-derives these numbers; `docs/bestiary.md` (the field
guide) and `scripts/make_bestiary_deck.py` (the deck) still write them by hand,
as do the plain-language summaries in `docs/elif.md` and `docs/writeup.md`.
When a hardening round adds a finding, or a threat/decision/scenario/Alloy
check/test changes, this fails until those pages are brought level -- so a
stale number cannot ship unnoticed. `scripts/project_counts.py` is the single
source of truth.

One number in this family is deliberately *not* guarded: "13 of 33 scenarios
would leak with the gateway off" (`docs/writeup.md`). It is an outcome of
running the harness, recorded in `redteam/results.csv`, which is gitignored --
so there is nothing to check against on a fresh checkout. Re-derive it with
`uv run python redteam/run_redteam.py` when the corpus changes.
"""
import os
import re
import sys

import pytest

import conftest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import project_counts  # noqa: E402

_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
          "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
          "thirteen": 13, "twenty-eight": 28, "thirty-three": 33}


def _num(tok):
    return int(tok) if tok.isdigit() else _WORDS.get(tok.lower())


# (file, [(regex capturing the cited count, canonical key)])
CITATIONS = [
    ("docs/bestiary.md", [
        (r"(\w+)\s+numbered\s+hardening\s+findings", "findings"),
        (r"(\w+)\s+decision\s+records", "decisions"),
        (r"(\w+)\s+threats\s+in\s+the\s+security\s+model", "threats"),
        (r"(\w+)\s+red-team\s+scenarios", "redteam"),
    ]),
    ("scripts/make_bestiary_deck.py", [
        (r"(\w+)\s+numbered\s+findings", "findings"),
        (r"(\d+)\s+threats", "threats"),
        (r"(\d+)\s+red-team\s+scenarios", "redteam"),
    ]),
    ("docs/elif.md", [
        (r"a\s+(\S+?)-scenario\s+red-team", "scenarios"),
        (r"replay\s+(\w+)\s+scripted", "scenarios"),
        (r"scripted\s*\n?\s*scenarios\s+\((\w+)\s+attacks", "attacks"),
        (r"scenarios\s+\(\w+\s+attacks,\s+(\w+)\s+benign\)", "benign"),
        (r"named control \|\s*(\w+)\s*\(", "scenarios"),
        (r"named control \|\s*\w+\s*\((\w+)\s+attacks", "attacks"),
        (r"named control \|\s*\w+\s*\(\w+\s+attacks,\s+(\w+)\s+benign\)", "benign"),
        (r"Solver-checked properties[^|]*\|\s*(\w+),\s+across", "alloy_checks"),
        (r"Solver-checked properties[^|]*\|\s*\w+,\s+across\s+(\w+)\s+models",
         "alloy_models"),
    ]),
    ("docs/writeup.md", [
        (r"grown\s+to\s+(\w+)\s*\n?\s*scenarios", "scenarios"),
        (r"scenarios\s+\((\w+)\s+attacks\s+plus", "attacks"),
        (r"attacks\s+plus\s+(\w+)\s+benign\s+baselines", "benign"),
        (r"\*\*(\d+)/\d+\s+attacks\s*\n?\s*neutralised", "attacks"),
        (r"attacks\s*\n?\s*neutralised;\s*\d+/(\d+)\s+scenarios", "scenarios"),
    ]),
]


def test_cited_counts_match_the_repository():
    canon = project_counts.counts()
    problems = []
    for rel, pats in CITATIONS:
        text = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        for pat, key in pats:
            m = re.search(pat, text)
            if not m:
                problems.append(f"{rel}: pattern {pat!r} not found "
                                f"(wording changed? update this keeper)")
                continue
            cited = _num(m.group(1))
            if cited != canon[key]:
                problems.append(f"{rel}: cites {m.group(1)!r} for {key}, "
                                f"repo has {canon[key]}")
    assert not problems, "stale cited counts:\n  " + "\n  ".join(problems)


def test_cited_test_count_matches_the_suite():
    """`docs/elif.md` quotes the size of the default suite.

    Measured from this session's own collection (see `conftest.COLLECTED`), so
    it costs nothing and cannot disagree with the run it is part of. A narrowed
    invocation -- one file, or `-k` -- collects a subset, which would look like
    a shrunken suite; skip rather than check a number that is not the claim.
    """
    if not conftest.COLLECTED.get("whole_tree"):
        pytest.skip("narrowed invocation collects a subset; run the whole "
                    "suite to check the cited test count")
    text = open(os.path.join(ROOT, "docs", "elif.md"), encoding="utf-8").read()
    m = re.search(r"Tests collected in the default suite \|\s*(\d+)", text)
    assert m, ("docs/elif.md no longer cites a default-suite test count in the "
               "expected form (wording changed? update this keeper)")
    actual = conftest.COLLECTED["default_suite"]
    assert int(m.group(1)) == actual, (
        f"docs/elif.md cites {m.group(1)} tests in the default suite, "
        f"this session collects {actual}")
