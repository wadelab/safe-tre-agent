"""Run the inside analyst on one research question and write the dossier.

    uv run python scripts/run_inside_analyst.py \\
        --question "Is late-night phone use linked to gambling?" \\
        --dataset studies/nightplay/nightplay.yaml --data data --out /tmp/dossier

Uses the planner's own model configuration (SAFETRE_LLM=real and the
SAFETRE_LLM_* endpoint variables; a remote endpoint additionally needs
SAFETRE_ALLOW_REMOTE_LLM=1 and is for synthetic data only). Writes
`dossier.json`, `narrative.md` (the model narrator's text, with any figure
the check could not trace listed beneath it) and `reference.md` (the
deterministic rendering that invents nothing), and keeps its own audit chain
at `audit.db` beside them — never the operator's.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--question", required=True)
    ap.add_argument("--dataset", default=None, help="dataset definition YAML (default: packaged demo)")
    ap.add_argument("--data", default="data", help="directory holding one CSV per base table")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--no-narrator", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    os.environ["SAFETRE_AUDIT_DB"] = os.path.join(args.out, "audit.db")

    from safetre import dataset as dataset_mod
    from safetre import synth
    from safetre.audit import AuditLog
    from safetre.config import load_policy_config
    from safetre.disclosure import DisclosurePolicy, SessionAuditor, build_vetter
    from safetre.inside_analyst import (
        AnalystLoop, LLMAnalystPolicy, LLMNarrator, render_dossier_markdown,
    )
    from safetre.llm import LLMClient
    from safetre.service import QueryService

    if args.dataset:
        dataset_mod.activate(dataset_mod.load_dataset(args.dataset))
    defn = dataset_mod.active()
    names = defn.table_names()
    if synth.csvs_present(args.data, names=names):
        tables = {n: pd.read_csv(os.path.join(args.data, f"{n}.csv")) for n in names}
    elif dataset_mod.is_packaged_demo():
        tables = synth.generate()
    else:
        sys.exit(f"{args.data}/ does not hold one CSV per base table ({', '.join(names)})")

    cfg = load_policy_config()
    policy = DisclosurePolicy(
        threshold=cfg.min_cell_size, max_rows=cfg.max_output_rows,
        dom_threshold=cfg.dom_threshold, influence_threshold=cfg.influence_threshold,
        round_base=cfg.round_base, moment2_dom_threshold=cfg.moment2_dom_threshold,
        vetter=build_vetter(cfg.vetter, cfg.checker_cmd))
    service = QueryService(tables, policy)
    client = LLMClient()
    auditor = SessionAuditor(threshold=cfg.min_cell_size, budget=cfg.query_budget,
                               selection_budget=cfg.selection_budget_bits)
    log = AuditLog(os.environ["SAFETRE_AUDIT_DB"])
    policy = LLMAnalystPolicy(client, cfg)
    loop = AnalystLoop(service, policy, auditor=auditor,
                       audit_log=log, max_steps=args.max_steps)
    dossier = loop.run(args.question)
    with open(os.path.join(args.out, "replies.json"), "w") as fh:
        json.dump(policy.raw_replies, fh, indent=2)
    if not args.no_narrator:
        LLMNarrator(client).render(dossier)

    with open(os.path.join(args.out, "dossier.json"), "w") as fh:
        fh.write(dossier.to_json())
    with open(os.path.join(args.out, "reference.md"), "w") as fh:
        fh.write(render_dossier_markdown(dossier) + "\n")
    if dossier.narrative:
        with open(os.path.join(args.out, "narrative.md"), "w") as fh:
            fh.write(dossier.narrative.rstrip() + "\n")
            if dossier.unsupported_figures:
                fh.write("\n---\nFigures the check could not trace to a released table: "
                         + ", ".join(dossier.unsupported_figures) + "\n")
    print(render_dossier_markdown(dossier))
    if dossier.unsupported_figures:
        print(f"\nnarrative figures NOT traceable to a release: {dossier.unsupported_figures}")
    print(f"\nwritten -> {args.out}  (audit chain verifies: {log.verify()})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
