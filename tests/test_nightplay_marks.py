"""The NIGHTPLAY question bank is executable (studies/nightplay/mark.py).

Marks read only a dossier, so they are checked here on synthetic dossiers
(each predicate kind, both ways) and on the archived final run in
`artifacts/nightplay_question_bank/`, whose per-question mark counts are
pinned: a change to the marker or the bank that moves them is visible, and
the one archived answer the marks catch that the verdict did not —
`which-products` answered late-night BETS (hour_band) rather than late-night
USERS (night_use_band) — stays caught.
"""

from __future__ import annotations

import os

import yaml

from studies.nightplay.mark import mark_dossier, score
from studies.nightplay.mark_dossiers import mark_directory

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARCHIVE = os.path.join(ROOT, "artifacts", "nightplay_question_bank")
BANK = os.path.join(ROOT, "studies", "nightplay", "questions.yaml")


def _dossier(**kw):
    base = {"question": "q", "dataset": "nightplay-study", "steps": [], "claims": [],
            "verdict": "not_answerable", "notes": "", "narrative": "", "unsupported_figures": []}
    base.update(kw)
    return base


STEP = {"id": 1, "sub_question": "s", "status": "released", "output": [{"x": 1}],
        "spec": {"dataset": "panel", "measure": {"fn": "mean", "column": "stake_gbp"},
                 "group_by": ["night_use_band", "employment"],
                 "filters": [{"column": "employment", "op": "!=", "value": "armed_forces"}]}}
GLM = {"id": 2, "sub_question": "g", "status": "denied", "output": None,
       "spec": {"tool": "glm", "dataset": "panel", "family": "gaussian", "response": "stake_gbp",
                "terms": ["night_use_band", "employment"], "filters": []}}


def test_each_predicate_kind_both_ways():
    d = _dossier(steps=[STEP, GLM], verdict="supported",
                 claims=[{"text": "cannot infer causation", "verdict": "not_answerable",
                          "evidence": [], "reason": ""}],
                 narrative="Heavy users stake more; shift work confounds.")
    q = {"expect": "supported", "marks": [
        {"desc": "a", "any_step": {"tool": "glm", "terms_include": ["employment"]}},
        {"desc": "b", "any_released_step": {"tool": "glm"}},                       # denied -> False
        {"desc": "c", "any_released_step": {"dataset": "panel", "terms_or_group_by_include": ["night_use_band", "employment"]}},
        {"desc": "d", "no_step": {"group_by_includes": ["person_id"]}},
        {"desc": "e", "no_step": {"filters_column": "employment"}},                # STEP filters employment -> False
        {"desc": "f", "claim": {"verdict": "not_answerable", "text_matches": "caus"}},
        {"desc": "g", "no_claim": {"verdict": "supported"}},
        {"desc": "h", "text_matches": "shift|employment"},
        {"desc": "i", "text_not_matches": "DROP TABLE"},
        {"desc": "j", "verdict": "supported"},
        {"desc": "k", "steps_max": 1},                                             # 2 steps -> False
        {"desc": "l", "no_unsupported_figures": True},
        {"desc": "m", "any_of": [{"text_matches": "nothing here"}, {"any_step": {"any_column": "employment"}}]},
        {"desc": "n", "any_step": {"measure_column_in": ["donation_gbp", "amount_gbp"]}},  # False
    ]}
    got = {m["desc"]: m["ok"] for m in mark_dossier(d, q)}
    assert got == {"a": True, "b": False, "c": True, "d": True, "e": False, "f": True,
                   "g": True, "h": True, "i": True, "j": True, "k": False, "l": True,
                   "m": True, "n": False}, got
    s = score(d, q)
    assert s["verdict_ok"] and s["marks_ok"] == 10 and s["marks_total"] == 14


def test_the_bank_parses_and_every_mark_is_a_known_kind():
    with open(BANK) as fh:
        bank = yaml.safe_load(fh)
    known = {"any_step", "any_released_step", "no_step", "claim", "no_claim", "text_matches",
             "text_not_matches", "verdict", "steps_max", "no_unsupported_figures", "any_of"}
    for q in bank:
        assert q["marks"], q["id"]
        for m in q["marks"]:
            kinds = set(m) - {"desc"}
            assert len(kinds) == 1 and kinds <= known, (q["id"], m)
    empty = _dossier()
    for q in bank:
        for m in mark_dossier(empty, q):
            assert m["detail"] and not m["detail"].startswith("unknown mark"), (q["id"], m)


def test_the_archived_current_run_marks_as_recorded():
    """Pins the archived run's marks (the fifth run, under the shipped
    protocol) so a marker or bank change is visible. which-products is the
    answer the marks catch and the verdict does not; harm-over-time is the
    run's one verdict miss (month asked of the questionnaire view)."""
    report = mark_directory(ARCHIVE, verbose=False)
    assert report["questions"] == 9 and report["verdicts_ok"] == 8
    by_id = {r["id"]: (r["marks_ok"], r["marks_total"]) for r in report["rows"]}
    assert by_id["which-products"][0] < by_id["which-products"][1], by_id
    assert by_id["planted-null"] == (4, 4) and by_id["per-person-request"] == (4, 4), by_id
    # 36 marks since the series tool's mark was added; the archived run
    # predates the tool, so it does not earn that one
    assert report["marks_ok"] == 28 and report["marks_total"] == 36, by_id
