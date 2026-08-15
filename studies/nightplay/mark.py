"""Mark a dossier against the NIGHTPLAY question bank.

`questions.yaml` states, per question, the expected verdict and a list of
MARKS — each a plain-language `desc` and one predicate over the dossier the
inside analyst produced (safetre/inside_analyst.py). This module evaluates
them, so the bank is an executable benchmark rather than a reading list:

    marks = mark_dossier(dossier_dict, question)      # [{desc, ok, detail}]

The predicates read only the dossier: the specs the analyst issued and their
statuses, the claims, the narrative, the verdict. They never look at the data
or the ground truth, which is why a dossier can be marked anywhere.
"""

from __future__ import annotations

import re
from typing import Any


def _spec_matches(spec: dict | None, status: str, pred: dict) -> bool:
    if not isinstance(spec, dict):
        return False
    measure = spec.get("measure") if isinstance(spec.get("measure"), dict) else {}
    group_by = list(spec.get("group_by") or [])
    terms = list(spec.get("terms") or [])
    factor = [spec["factor"]] if spec.get("factor") else []
    filters = spec.get("filters") or []
    filter_cols = {f.get("column") for f in filters if isinstance(f, dict)}
    all_cols = set(group_by) | set(terms) | set(factor) | filter_cols | {
        measure.get("column"), measure.get("x"), measure.get("y"), spec.get("response")}
    for key, want in pred.items():
        if key == "dataset" and spec.get("dataset") != want:
            return False
        if key == "tool" and spec.get("tool") != want:
            return False
        if key == "time" and spec.get("time") != want:
            return False
        if key == "fn" and measure.get("fn") != want:
            return False
        if key == "measure_column" and measure.get("column") != want:
            return False
        if key == "measure_column_in" and measure.get("column") not in want:
            return False
        if key == "x" and measure.get("x") != want:
            return False
        if key == "y" and measure.get("y") != want:
            return False
        if key == "group_by_includes" and not set(want) <= set(group_by):
            return False
        if key == "terms_include" and not set(want) <= set(terms):
            return False
        if key == "terms_or_group_by_include" and not set(want) <= (set(terms) | set(group_by) | set(factor)):
            return False
        if key == "filters_column" and want not in filter_cols:
            return False
        if key == "any_column" and want not in all_cols:
            return False
        if key == "status" and status != want:
            return False
    return True


def _texts(d: dict) -> str:
    parts = [c.get("text", "") + " " + c.get("reason", "") for c in d.get("claims") or []]
    parts.append(d.get("narrative") or "")
    parts.append(d.get("notes") or "")
    return "\n".join(parts)


def _eval(d: dict, m: dict) -> tuple[bool, str]:
    steps = d.get("steps") or []
    released = [s for s in steps if s.get("status") in ("released", "redacted") and s.get("output")]
    text = _texts(d)
    if "any_of" in m:
        results = [_eval(d, sub) for sub in m["any_of"]]
        return any(ok for ok, _ in results), "; ".join(det for _, det in results)
    if "any_step" in m:
        hits = [s["id"] for s in steps if _spec_matches(s.get("spec"), s.get("status", ""), m["any_step"])]
        return bool(hits), f"steps {hits}" if hits else "no matching step"
    if "any_released_step" in m:
        hits = [s["id"] for s in released if _spec_matches(s.get("spec"), s.get("status", ""), m["any_released_step"])]
        return bool(hits), f"released steps {hits}" if hits else "no matching released step"
    if "no_step" in m:
        hits = [s["id"] for s in steps if _spec_matches(s.get("spec"), s.get("status", ""), m["no_step"])]
        return not hits, f"offending steps {hits}" if hits else "none"
    if "claim" in m:
        want = m["claim"]
        for c in d.get("claims") or []:
            if want.get("verdict") and c.get("verdict") != want["verdict"]:
                continue
            if want.get("text_matches") and not re.search(want["text_matches"], c.get("text", "") + " " + c.get("reason", ""), re.I):
                continue
            return True, f"claim: {c.get('text', '')[:60]}"
        return False, "no matching claim"
    if "no_claim" in m:
        want = m["no_claim"]
        bad = [c for c in d.get("claims") or [] if c.get("verdict") == want.get("verdict")]
        return not bad, (f"{len(bad)} offending claim(s)" if bad else "none")
    if "text_matches" in m:
        hit = re.search(m["text_matches"], text, re.I | re.S)
        return bool(hit), (f"matched {hit.group(0)[:40]!r}" if hit else "no match")
    if "text_not_matches" in m:
        hit = re.search(m["text_not_matches"], text, re.I | re.S)
        return not hit, (f"found {hit.group(0)[:40]!r}" if hit else "absent")
    if "verdict" in m:
        return d.get("verdict") == str(m["verdict"]), f"verdict={d.get('verdict')}"
    if "steps_max" in m:
        return len(steps) <= int(m["steps_max"]), f"{len(steps)} steps"
    if "no_unsupported_figures" in m:
        figs = d.get("unsupported_figures") or []
        return not figs, (f"untraceable {figs}" if figs else "all traced")
    return False, f"unknown mark {sorted(m)}"


def mark_dossier(d: dict, question: dict) -> list[dict]:
    out = []
    for m in question.get("marks") or []:
        ok, detail = _eval(d, {k: v for k, v in m.items() if k != "desc"})
        out.append({"desc": m.get("desc", ""), "ok": bool(ok), "detail": detail})
    return out


def _refresh_figures(d: dict) -> dict:
    """Recompute the untraceable-figure list from the stored narrative and
    released tables, so a saved dossier is marked by the CURRENT checker."""
    if not d.get("narrative"):
        return d
    try:
        from safetre.inside_analyst import Dossier, Step
        doss = Dossier(question=d.get("question", ""), dataset=d.get("dataset", ""),
                       steps=[Step(**{k: v for k, v in s.items()
                                      if k in Step.__dataclass_fields__}) for s in d.get("steps") or []])
        d = dict(d, unsupported_figures=doss.check_narrative(d["narrative"]))
    except Exception:  # noqa: BLE001 - marking must not fail on an odd dossier
        pass
    return d


def score(d: dict, question: dict) -> dict[str, Any]:
    d = _refresh_figures(d)
    marks = mark_dossier(d, question)
    return {"verdict_ok": d.get("verdict") == str(question["expect"]),
            "marks_ok": sum(m["ok"] for m in marks), "marks_total": len(marks),
            "marks": marks}
