"""Planner-quality evaluation: score a planner against a reference corpus.

The gateway makes planner mistakes safe, not invisible: a valid but wrong
QuerySpec (a missing filter, the wrong dataset) releases a misleading answer.
This harness measures that gap. For every corpus item the planner proposes a
spec, and we score it after canonicalisation (order-insensitive group_by and
filters, via QuerySpec.normalized_filters):

- valid      — the proposal passes QuerySpec validation
- primary    — canonically equal to the first (intended) reference spec
- accepted   — canonically equal to any acceptable reference variant
- cohort     — right dataset and filters, wrong measure or grouping
- rejected   — for `reject: true` items, the proposal failed validation
               (correct: no legal spec exists for the request)

Usage:
    uv run python evals/run_planner_eval.py                # mock planner
    uv run python evals/run_planner_eval.py --planner real # SAFETRE_LLM_* env
    uv run python evals/run_planner_eval.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pydantic import ValidationError               # noqa: E402

from safetre.planner import LLMPlanner, MockPlanner  # noqa: E402
from safetre.procedures import model_registry      # noqa: E402
from safetre.query import GLMSpec, QuerySpec       # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def canonical(spec) -> tuple:
    """Order-insensitive identity of a spec: dataset, measure/model, grouping
    or terms, cohort. Works for QuerySpec and model specs alike."""
    if isinstance(spec, GLMSpec):
        return (spec.dataset, spec.model_key(), frozenset(spec.terms),
                spec.normalized_filters())
    return (spec.dataset, spec.measure_key(), frozenset(spec.group_by),
            spec.normalized_filters())


def try_spec(raw: dict):
    """Validate an untrusted proposal exactly as the service would: by the
    `tool` key into a model spec, else as a QuerySpec. None if invalid."""
    if not isinstance(raw, dict):
        return None
    try:
        if "tool" in raw:
            proc = model_registry().get(raw.get("tool"))
            return proc.validate(raw) if proc is not None else None
        return QuerySpec(**raw)
    except (ValidationError, TypeError):
        return None


def score_item(item: dict, planner) -> dict:
    out = {"id": item["id"], "tags": item.get("tags", []),
           "valid": False, "primary": False, "accepted": False,
           "cohort": False, "rejected_ok": False, "error": None}
    try:
        raw = planner.plan(item["request"])
    except Exception as exc:                        # planner crashed or refused
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["rejected_ok"] = bool(item.get("reject"))
        return out
    out["proposal"] = raw                            # kept for qualitative review

    spec = try_spec(raw) if isinstance(raw, dict) else None

    if item.get("reject"):
        # correct behaviour: no valid spec can answer this request
        out["rejected_ok"] = spec is None
        out["valid"] = spec is not None
        return out

    if spec is None:
        return out
    out["valid"] = True

    got = canonical(spec)
    refs = [try_spec(e) for e in item["expect"]]
    assert all(r is not None for r in refs), f"corpus item {item['id']} has an invalid reference spec"
    ref_canon = [canonical(r) for r in refs]
    out["primary"] = got == ref_canon[0]
    out["accepted"] = got in ref_canon
    out["cohort"] = any(got[0] == rc[0] and got[3] == rc[3] for rc in ref_canon)
    return out


def summarise(results: list[dict]) -> dict:
    answer = [r for r in results if "reject" not in r["tags"]]
    reject = [r for r in results if "reject" in r["tags"]]
    pct = lambda k, rs: round(100 * sum(r[k] for r in rs) / len(rs), 1) if rs else None  # noqa: E731
    return {
        "n_answerable": len(answer),
        "valid_pct": pct("valid", answer),
        "primary_pct": pct("primary", answer),
        "accepted_pct": pct("accepted", answer),
        "cohort_pct": pct("cohort", answer),
        "n_reject": len(reject),
        "rejected_ok_pct": pct("rejected_ok", reject),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--planner", choices=["mock", "real"], default="mock")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.yaml"))
    ap.add_argument("--json", dest="json_out", default=None,
                    help="write per-item results and the summary as JSON")
    args = ap.parse_args()

    with open(args.corpus) as fh:
        corpus = yaml.safe_load(fh)

    if args.planner == "mock":
        planner = MockPlanner()
    else:
        from safetre.llm import LLMClient
        planner = LLMPlanner(LLMClient())

    results = [score_item(item, planner) for item in corpus]
    summary = summarise(results)

    wid = max(len(r["id"]) for r in results)
    print(f"{'item'.ljust(wid)}  valid  primary  accepted  cohort  reject_ok")
    for r in results:
        flag = lambda k: "  yes " if r[k] else "   -  "  # noqa: E731
        print(f"{r['id'].ljust(wid)}  {flag('valid')}{flag('primary')} "
              f"{flag('accepted')}  {flag('cohort')} {flag('rejected_ok')}"
              + (f"   [{r['error']}]" if r["error"] else ""))
    print(f"\nplanner={args.planner}  answerable n={summary['n_answerable']}: "
          f"valid {summary['valid_pct']}% · primary {summary['primary_pct']}% · "
          f"accepted {summary['accepted_pct']}% · cohort {summary['cohort_pct']}%")
    print(f"reject n={summary['n_reject']}: correctly rejected "
          f"{summary['rejected_ok_pct']}%")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump({"planner": args.planner, "summary": summary,
                       "results": results}, fh, indent=2)
        print(f"results -> {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
