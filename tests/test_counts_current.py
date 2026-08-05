"""The counts the bestiary hand-types match the repository's own record.

The artifact page auto-derives these numbers; `docs/bestiary.md` (the field
guide) and `scripts/make_bestiary_deck.py` (the deck) still write them by hand.
When a hardening round adds a finding, or a threat/decision/scenario changes,
this fails until those two are brought level -- so a stale number cannot ship
unnoticed. `scripts/project_counts.py` is the single source of truth.
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import project_counts  # noqa: E402

_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
          "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}


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
    assert not problems, "stale bestiary counts:\n  " + "\n  ".join(problems)
