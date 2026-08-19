"""Red-team the published research record (D9; R12's rules, applied to the bundle).

    uv run python redteam/run_vrr_redteam.py
    uv run python redteam/run_vrr_redteam.py --json redteam/vrr_results.json

*The query red team asks what the gateway lets out. This asks what the RECORD OF
a release lets out afterwards — which is a different question, because the record
is published, permanent, signed, and read by people who never saw the session.*

Each scenario in `redteam/vrr_attacks.yaml` runs a committed plan through the
unchanged gateway against the NIGHTPLAY study, builds a research record, replays
it, signs it and exports a bundle. Then the adversaries in
`redteam/vrr_adversary.py` are handed nothing but that directory and try to
recover what the gateway withheld, scored against an oracle computed from the
row-level rows and the private trace.

**A scenario passes when the adversary learned nothing.** A control having fired
is not a pass — the compiler dropping a field says nothing about whether the fact
is recoverable some other way, and finding #109 was exactly a fact that stayed
recoverable while every control fired correctly.

Exit status is nonzero if any adversary learned something, or if a scenario's
declared expectations did not hold.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml                                                    # noqa: E402

from redteam.vrr_adversary import oracle_for, run_adversaries  # noqa: E402
from safetre import attestation as A                            # noqa: E402
from safetre import dataset as dataset_mod                      # noqa: E402
from safetre import disclosure as D                             # noqa: E402
from safetre import evidence as E                               # noqa: E402
from safetre import recorder as R                               # noqa: E402
from safetre import vrr_bundle as B                             # noqa: E402
from safetre.audit import AuditLog                              # noqa: E402
from safetre.config import load_policy_config                   # noqa: E402
from safetre.plan import Plan, PlanExecutor                     # noqa: E402
from safetre.provenance import compile_public_provenance         # noqa: E402
from safetre.replay import REPRODUCED, ReplayContext, replay     # noqa: E402
from safetre.research_record import ResearchRecord               # noqa: E402
from studies.nightplay import generate as G                      # noqa: E402
from studies.nightplay import verify as V                        # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ATTACKS = os.path.join(HERE, "vrr_attacks.yaml")
N_PEOPLE = 2500
KEY = b"redteam-internal-commitment-key"
SIGNING_SEED = b"redteam-vrr-signing-key-32-bytes"
SNAPSHOT = "nightplay-redteam"
POPULATION = "synthetic person x month panel (red-team fixture)"
CUSTODIAN = "red-team custodian"


def _auditor(cfg):
    return D.SessionAuditor(threshold=cfg.min_cell_size, budget=cfg.query_budget,
                            selection_budget=cfg.selection_budget_bits)


def _read_bundle(path: str) -> dict[str, str]:
    """The bundle as an adversary holds it: filename -> text, nothing else."""
    out = {}
    for name in sorted(os.listdir(path)):
        with open(os.path.join(path, name), encoding="utf-8") as fh:
            out[name] = fh.read()
    return out


def run_attack(attack: dict, tables: dict, cfg, manifests, workdir: str) -> dict:
    plan = Plan(question=attack["question"], stages=attack["stages"])
    service = V.build_service(tables)
    log = AuditLog(os.path.join(tempfile.mkdtemp(dir=workdir), "audit.db"))
    run = PlanExecutor(service, auditor=_auditor(cfg), audit_log=log,
                       user="redteam-analyst").run(plan)

    record_id = R.record_id_for(plan.question, plan.canonical_hash(), manifests)
    trace = R.trace_from_plan_run(run, plan, record_id=record_id, manifests=manifests,
                                  audit_log=log, key=KEY, user="redteam-analyst",
                                  release_domain="nightplay/redteam")
    released = {sr.id: {"output": sr.output, "artifacts": sr.artifacts}
                for sr in run.stages}
    evidence = E.extract_run(trace.stages, released, include_not_answerable=True)
    trace = trace.model_copy(
        update={"evidence_refs": [e.evidence_id for e in evidence]})
    record = ResearchRecord(record_id=record_id, trace=trace, evidence=evidence,
                            provenance=compile_public_provenance(trace, evidence))

    context = ReplayContext(
        tables=tables, policy_config=cfg, service_factory=V.build_service,
        snapshot_id=SNAPSHOT, commitment_key=KEY, population=POPULATION,
        custodian=CUSTODIAN)
    certificate = replay(record, context)
    record = record.model_copy(update={"certificate": certificate})

    secret, public = A.generate_keypair(seed=SIGNING_SEED)
    out = os.path.join(workdir, attack["name"])
    exported, export_error = True, ""
    try:
        B.export_bundle(record, out, attestation=A.attest(record, secret, public))
    except Exception as exc:                             # noqa: BLE001 - reported
        exported, export_error = False, f"{type(exc).__name__}: {exc}"

    oracle = oracle_for(run, trace, tables)
    learned: dict[str, list[str]] = {}
    verified = None
    if exported:
        bundle = _read_bundle(out)
        learned = {k: v for k, v in run_adversaries(bundle, oracle).items() if v}
        verified, _ = B.verify_bundle_dir(out, public_key=public)

    expect = attack.get("expect") or {}
    problems = []
    if "released" in expect and sorted(oracle["released_stages"]) != sorted(expect["released"]):
        problems.append(f"released {oracle['released_stages']}, "
                        f"expected {expect['released']}")
    if expect.get("exportable") and not exported:
        problems.append(f"the record was not exportable ({export_error}); the "
                        "absence of a bundle would itself answer the question")
    if expect.get("replays") and certificate.outcome != REPRODUCED:
        problems.append(f"replay said {certificate.outcome.value}")
    if exported and not verified:
        problems.append("the exported bundle does not verify offline")

    return {
        "name": attack["name"], "type": attack.get("type", "unclassified"),
        "known_open": bool(attack.get("known_open")),
        "released": oracle["released_stages"], "refused": oracle["refused_stages"],
        "excluded_levels": oracle["excluded_levels"],
        "replay": certificate.outcome.value, "exported": exported,
        "verified": verified, "learned": learned, "problems": problems,
        "ok": not learned and not problems,
    }


def run(attacks_path: str = ATTACKS, n_people: int = N_PEOPLE,
        verbose: bool = True) -> dict:
    os.environ.setdefault("SAFETRE_AUDIT_KEY", "redteam-audit-key")
    with open(attacks_path, encoding="utf-8") as fh:
        attacks = yaml.safe_load(fh)

    tables, _truth = G.generate(n_people=n_people)
    packaged = os.path.join(os.path.dirname(dataset_mod.__file__), "demo_dataset.yaml")
    dataset_mod.activate(dataset_mod.load_dataset(V.DEFINITION))
    cfg = load_policy_config()
    manifests = R.build_manifests(cfg, tables, snapshot_id=SNAPSHOT,
                                  population=POPULATION, custodian=CUSTODIAN, key=KEY)
    workdir = tempfile.mkdtemp(prefix="vrr-redteam-")
    try:
        results = [run_attack(a, tables, cfg, manifests, workdir) for a in attacks]
    finally:
        dataset_mod.activate(dataset_mod.load_dataset(packaged))

    failed = [r for r in results if not r["ok"] and not r["known_open"]]
    open_repro = [r for r in results if r["known_open"] and not r["ok"]]

    if verbose:
        print(f"{'scenario':38s} {'type':11s} {'released':10s} {'replay':26s} adversaries")
        for r in results:
            print(f"{r['name'][:37]:38s} {r['type'][:10]:11s} "
                  f"{len(r['released'])}/{len(r['released']) + len(r['refused']):<8d} "
                  f"{r['replay'][:25]:26s} "
                  + ("none" if not r["learned"]
                     else "; ".join(sorted(r["learned"]))))
        print()
        for r in results:
            for probe, facts in sorted(r["learned"].items()):
                for fact in facts:
                    print(f"  LEAK  {r['name']} / {probe}: {fact}")
            for problem in r["problems"]:
                print(f"  FAIL  {r['name']}: {problem}")
        print()
        print(f"scenarios                             : {len(results)}")
        print(f"adversaries per scenario              : "
              f"{len(run_adversaries({}, oracle_for_empty()))}")
        print(f"scenarios where nothing was learned   : "
              f"{sum(1 for r in results if not r['learned'])}/{len(results)}")
        print(f"bundles that verify offline           : "
              f"{sum(1 for r in results if r['verified'])}/"
              f"{sum(1 for r in results if r['exported'])}")
        print(f"all checks passed                     : {not failed}")

    return {"results": results, "failed": [r["name"] for r in failed],
            "known_open_reproduced": [r["name"] for r in open_repro],
            "ok": not failed}


def oracle_for_empty() -> dict:
    """An empty oracle, only so the summary can count the adversaries without
    inventing a scenario to count them against."""
    return {"declared_stages": [], "declared_stage_count": 0, "released_stages": [],
            "refused_stages": [], "excluded_levels": [], "true_group_sizes": {},
            "selection_bits": 0, "private_messages": [], "private_findings": [],
            "analyst": ""}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--attacks", default=ATTACKS)
    ap.add_argument("--people", type=int, default=N_PEOPLE)
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()
    report = run(args.attacks, args.people)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
