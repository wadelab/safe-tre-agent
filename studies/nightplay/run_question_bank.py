"""Run the inside analyst over the NIGHTPLAY question bank and mark it.

For each question in `questions.yaml` the analyst runs in its own session,
the model narrator writes the summary, and the result is marked against the
question's expected verdict (the one mark that is mechanical; the finer
`marks` are recorded for a human reader). Writes one dossier per question and
a summary. Uses the planner's own model configuration (see
scripts/run_inside_analyst.py).

    uv run python studies/nightplay/run_question_bank.py --data data --out artifacts/nightplay_dossiers
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import pandas as pd
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
QUESTIONS = os.path.join(HERE, "questions.yaml")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default=None, help="comma-separated question ids")
    ap.add_argument("--max-steps", type=int, default=12)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    os.environ["SAFETRE_AUDIT_DB"] = os.path.join(args.out, "audit.db")

    from safetre import dataset as dataset_mod
    from safetre.audit import AuditLog
    from safetre.config import load_policy_config
    from safetre.disclosure import SessionAuditor
    from safetre.inside_analyst import AnalystLoop, LLMAnalystPolicy, LLMNarrator
    from safetre.llm import LLMClient
    from studies.nightplay import verify as V
    from studies.nightplay.generate import MANIFEST_NAME, TABLE_NAMES
    from studies.nightplay.mark import score

    dataset_mod.activate(dataset_mod.load_dataset(V.DEFINITION))
    tables = {n: pd.read_csv(os.path.join(args.data, f"{n}.csv")) for n in TABLE_NAMES}
    with open(os.path.join(args.data, MANIFEST_NAME)) as fh:
        truth = json.load(fh)
    service = V.build_service(tables)
    cfg = load_policy_config()
    client = LLMClient()
    log = AuditLog(os.environ["SAFETRE_AUDIT_DB"])
    with open(QUESTIONS) as fh:
        bank = yaml.safe_load(fh)
    only = set(args.only.split(",")) if args.only else None

    rows = []
    for q in bank:
        if only and q["id"] not in only:
            continue
        auditor = SessionAuditor(threshold=cfg.min_cell_size, budget=cfg.query_budget,
                               selection_budget=cfg.selection_budget_bits)
        policy = LLMAnalystPolicy(client, cfg)
        loop = AnalystLoop(service, policy, auditor=auditor,
                           audit_log=log, user=f"analyst:{q['id']}", max_steps=args.max_steps)
        dossier = loop.run(q["question"])
        LLMNarrator(client).render(dossier)
        with open(os.path.join(args.out, f"{q['id']}.json"), "w") as fh:
            fh.write(dossier.to_json())
        # the model's raw turns, for diagnosing protocol errors; the policy
        # saw only the public side, so these hold nothing the dossier does not
        with open(os.path.join(args.out, f"{q['id']}.replies.json"), "w") as fh:
            json.dump(policy.raw_replies, fh, indent=2)
        expect = str(q["expect"])
        marked = score(dossier.to_dict(), q)
        row = {"id": q["id"], "expect": expect, "verdict": dossier.verdict,
               "verdict_ok": dossier.verdict == expect,
               "marks_ok": marked["marks_ok"], "marks_total": marked["marks_total"],
               "marks": marked["marks"],
               "steps": len(dossier.steps),
               "statuses": [s.status for s in dossier.steps],
               "budget_spent": dossier.budget_spent,
               "stopped_because": dossier.stopped_because,
               "unsupported_figures": dossier.unsupported_figures,
               "claims": [{"text": c.text, "verdict": c.verdict, "evidence": c.evidence}
                          for c in dossier.claims],
               "truth": q.get("truth"), "trap": q.get("trap")}
        rows.append(row)
        print(f"  {q['id']:24s} expect={expect:15s} got={dossier.verdict:15s} "
              f"{'ok ' if row['verdict_ok'] else 'MISS'} marks={marked['marks_ok']}/{marked['marks_total']} "
              f"steps={len(dossier.steps)} budget={dossier.budget_spent} "
              f"figs?={len(dossier.unsupported_figures)}")

    n_ok = sum(r["verdict_ok"] for r in rows)
    m_ok = sum(r["marks_ok"] for r in rows)
    m_tot = sum(r["marks_total"] for r in rows)
    summary = {"study": truth["study"], "n_people": truth["n_people"], "seed": truth["seed"],
               "questions": len(rows), "verdict_agreement": n_ok,
               "marks_ok": m_ok, "marks_total": m_tot,
               "unsupported_figure_runs": sum(bool(r["unsupported_figures"]) for r in rows),
               "audit_chain_verifies": log.verify(), "rows": rows}
    with open(os.path.join(args.out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"verdict agreement {n_ok}/{len(rows)}; marks {m_ok}/{m_tot}; "
          f"audit chain verifies: {log.verify()}; -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
