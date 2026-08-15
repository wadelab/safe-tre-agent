"""Re-mark saved dossiers against the current question bank.

    uv run python studies/nightplay/mark_dossiers.py artifacts/nightplay_question_bank

Marks read only the dossier, so a directory of dossiers can be re-scored
whenever the bank's marks are refined, without a model or the data.
"""

from __future__ import annotations

import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from studies.nightplay.mark import score  # noqa: E402


def mark_directory(directory: str, verbose: bool = True) -> dict:
    with open(os.path.join(HERE, "questions.yaml")) as fh:
        bank = yaml.safe_load(fh)
    rows, v_ok, m_ok, m_tot = [], 0, 0, 0
    for q in bank:
        path = os.path.join(directory, f"{q['id']}.json")
        if not os.path.exists(path):
            continue
        with open(path) as fh:
            d = json.load(fh)
        s = score(d, q)
        rows.append({"id": q["id"], **{k: v for k, v in s.items()}})
        v_ok += s["verdict_ok"]
        m_ok += s["marks_ok"]
        m_tot += s["marks_total"]
        if verbose:
            missed = [m["desc"] for m in s["marks"] if not m["ok"]]
            print(f"  {q['id']:24s} verdict {'ok ' if s['verdict_ok'] else 'MISS'} "
                  f"marks {s['marks_ok']}/{s['marks_total']}"
                  + (f"  missed: {missed}" if missed else ""))
    if verbose:
        print(f"verdicts {v_ok}/{len(rows)}; marks {m_ok}/{m_tot}")
    return {"rows": rows, "verdicts_ok": v_ok, "questions": len(rows),
            "marks_ok": m_ok, "marks_total": m_tot}


if __name__ == "__main__":
    sys.exit(0 if mark_directory(sys.argv[1] if len(sys.argv) > 1 else
                                 os.path.join(os.path.dirname(os.path.dirname(HERE)),
                                              "artifacts", "nightplay_question_bank"))
             else 1)
