"""The verifiable research record vertical slice, end to end.

    uv run python scripts/run_vrr_demo.py --question headline-association \\
        --out artifacts/vrr-demo

*The build plan asks for one command, built as early as possible, that a
research increment can grow around. It does the ten things the plan lists, in
order, against the NIGHTPLAY study, and it uses no language model anywhere: a
failure here is a provenance failure, not a planner failure.*

     1. choose a fixed question from the NIGHTPLAY bank
     2. commit its plan to the audit chain
     3. run the existing scripted analysis through the unchanged gateway
     4. release one model/aggregate result
     5. build the private execution trace
     6. compile the public provenance
     7. replay the computation from the attested snapshot
     8. export the public bundle
     9. run a post-hoc follow-up and watch it get labelled exploratory
    10. tamper with the exported bundle and watch verification fail

The exit status is nonzero if any step does not do what it says.

## What this demonstrates, and what it does not

It demonstrates that a protected analysis can produce a record a reviewer can
check without the data: the numbers replay byte for byte from the snapshot, the
pre-specification label comes from audit event order rather than anyone's
assertion, the public provenance carries no trace of what the gateway refused,
and a single edited digit anywhere in the bundle breaks the signature.

It does not demonstrate differential privacy, cross-user accounting, an
authenticated release domain or a production signing service. Those are later
milestones, and the record says so in its own `not_verified` list rather than
leaving a reader to assume otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
# One fixed `git rev-parse HEAD`, to put the repository commit in the software
# manifest. Fixed argv, no shell, no caller input.
import subprocess  # nosec B404
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml                                                    # noqa: E402

from safetre import attestation as A                           # noqa: E402
from safetre import dataset as dataset_mod                     # noqa: E402
from safetre import disclosure as D                            # noqa: E402
from safetre import evidence as E                              # noqa: E402
from safetre import recorder as R                              # noqa: E402
from safetre import vrr_bundle as B                            # noqa: E402
from safetre.audit import AuditLog                             # noqa: E402
from safetre.config import load_policy_config                  # noqa: E402
from safetre.plan import Plan, PlanExecutor                     # noqa: E402
from safetre.provenance import (                                # noqa: E402
    audit_public_leakage, compile_public_provenance)
from safetre.replay import REPRODUCED, ReplayContext, replay    # noqa: E402
from safetre.research_record import (                            # noqa: E402
    ResearchRecord, internal_commitment_key)
from studies.nightplay import generate as G                     # noqa: E402
from studies.nightplay import verify as V                       # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BANK = os.path.join(ROOT, "studies", "nightplay", "questions.yaml")

CUSTODIAN = "NIGHTPLAY synthetic study custodian (demo)"
POPULATION = ("a synthetic person x month panel of adult phone users, generated "
              "for methods development; no real person is described")

# The demo's committed plans, one per question the bank offers a scripted path
# for. Written here rather than derived from the bank's `good_answer_uses`
# prose: a locked plan is a typed program, and inferring one from English is
# the job this whole design exists to keep out of the release path.
PLANS: dict[str, dict] = {
    "headline-association": {
        "question": "Is late-night phone use linked to gambling, once employment is accounted for?",
        "stages": [
            {"id": "adjusted",
             "sub_question": "regress stake on night use band and employment, sparse groups excluded",
             "spec": {"tool": "glm", "dataset": "panel", "family": "gaussian",
                      "response": "stake_gbp",
                      "terms": ["night_use_band", "employment"], "filters": []},
             "contingency": {"kind": "exclude_sparse", "dimension": "employment"}},
        ],
    },
}

# Step 9's follow-up: a question nobody committed in advance. NIGHTPLAY plants a
# null here — late-night use does not drive charitable giving — so it is also a
# question an over-eager analyst gets wrong, which makes it the right one to
# show a reader labelled EXPLORATORY_POSTHOC.
POSTHOC = {
    "question": "Does late-night phone use go with charitable giving?",
    "stages": [
        {"id": "giving",
         "sub_question": "mean donation amount by night use band",
         "spec": {"dataset": "giving", "measure": {"fn": "mean", "column": "amount_gbp"},
                  "group_by": ["night_use_band"], "filters": []}},
    ],
}


class _Uncommitted:
    """An audit log that records stages but never a plan commitment.

    Step 9 needs a follow-up that genuinely was not pre-declared, and
    `PlanExecutor` always commits the plan it is handed. Wrapping the log so the
    commitment never reaches the chain gives the chain an ordinary analyst would
    produce by asking a follow-up question directly — stage rows, no plan row —
    which is the input the classification is supposed to be derived from.
    """

    def __init__(self, log):
        self._log = log

    def append(self, **kw):
        if kw.get("status") == "plan":
            return "not committed"
        return self._log.append(**kw)

    def __getattr__(self, name):
        return getattr(self._log, name)


def _say(step: int, message: str) -> None:
    print(f"[{step:2d}] {message}", flush=True)


def _repository_commit() -> str | None:
    try:
        out = subprocess.run(  # nosec B603 B607
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
            text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def _lockfile_digest() -> str | None:
    path = os.path.join(ROOT, "uv.lock")
    if not os.path.exists(path):
        return None
    import hashlib
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _run_plan(service, spec: dict, *, audit_log=None, user: str, cfg):
    plan = Plan(**spec)
    auditor = D.SessionAuditor(threshold=cfg.min_cell_size, budget=cfg.query_budget,
                              selection_budget=cfg.selection_budget_bits)
    run = PlanExecutor(service, auditor=auditor, audit_log=audit_log, user=user).run(plan)
    return plan, run


def _released(run) -> dict[str, dict]:
    return {sr.id: {"output": sr.output, "artifacts": sr.artifacts} for sr in run.stages}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--question", default="headline-association",
                        help="a question id from the NIGHTPLAY bank")
    parser.add_argument("--out", default=os.path.join(ROOT, "artifacts", "vrr-demo"))
    parser.add_argument("--people", type=int, default=2500)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args(argv)

    if args.question not in PLANS:
        parser.error(f"no committed plan for {args.question!r}; "
                     f"have {', '.join(sorted(PLANS))}")

    os.environ.setdefault("SAFETRE_VRR_COMMIT_KEY", "demo-internal-commitment-key")
    os.environ.setdefault("SAFETRE_AUDIT_KEY", "demo-audit-key")

    with open(BANK, encoding="utf-8") as fh:
        bank = {q["id"]: q for q in yaml.safe_load(fh)}
    asked = bank[args.question]["question"]

    _say(1, f"question {args.question!r}: {asked}")

    tables, _truth = G.generate(seed=args.seed, n_people=args.people)
    dataset_mod.activate(dataset_mod.load_dataset(V.DEFINITION))
    service = V.build_service(tables)
    cfg = load_policy_config()
    snapshot_id = f"nightplay-{args.seed if args.seed is not None else 'default'}-{args.people}"

    key = internal_commitment_key()
    manifests = R.build_manifests(
        cfg, tables, snapshot_id=snapshot_id, population=POPULATION,
        custodian=CUSTODIAN, key=key, repository_commit=_repository_commit(),
        lockfile_digest=_lockfile_digest())

    workdir = tempfile.mkdtemp(prefix="vrr-demo-audit-")
    log = AuditLog(os.path.join(workdir, "audit.db"))

    # --- 2, 3, 4 ---------------------------------------------------------- #
    plan, run = _run_plan(service, PLANS[args.question], audit_log=log,
                          user="vrr-demo", cfg=cfg)
    _say(2, f"plan committed to the audit chain before execution: {plan.canonical_hash()}")
    statuses = ", ".join(f"{sr.id}={sr.status}" for sr in run.stages)
    _say(3, f"scripted analysis ran through the unchanged gateway: {statuses}")
    if not any(sr.released() for sr in run.stages):
        print("FAIL: nothing was released; there is no record to make", file=sys.stderr)
        return 1
    _say(4, "released one adjusted model fit with its vetted design-cell table")

    # --- 5 ---------------------------------------------------------------- #
    record_id = R.record_id_for(plan.question, plan.canonical_hash(), manifests)
    trace = R.trace_from_plan_run(
        run, plan, record_id=record_id, manifests=manifests, audit_log=log,
        key=key, user="vrr-demo", release_domain="nightplay/demo")
    private_only = sum(1 for st in trace.stages for a in st.output_refs if not a.is_public())
    _say(5, f"private execution trace: {len(trace.stages)} stage(s), "
            f"{private_only} private artifact commitment(s) that no reader will see")
    if not trace.audit_chain_verified:
        print("FAIL: the audit chain does not verify, so no pre-specification "
              "claim can be made", file=sys.stderr)
        return 1
    _say(5, "audit chain verifies; the pre-specification label rests on its order")

    # --- 6 ---------------------------------------------------------------- #
    evidence = E.extract_run(trace.stages, _released(run))
    provenance = compile_public_provenance(trace, evidence)
    trace = trace.model_copy(update={"evidence_refs": [e.evidence_id for e in evidence]})
    leaks = audit_public_leakage(provenance, trace)
    if leaks:
        print("FAIL: private content reached the public provenance: "
              + "; ".join(leaks), file=sys.stderr)
        return 1
    _say(6, f"public provenance: {len(provenance.nodes)} node(s), "
            f"{len(evidence)} evidence item(s), classified "
            f"{provenance.classification.value}, no private content")

    record = ResearchRecord(record_id=record_id, trace=trace, evidence=evidence,
                            provenance=provenance)
    record.validate_record()

    # --- 7 ---------------------------------------------------------------- #
    context = ReplayContext(
        tables=tables, policy_config=cfg, service_factory=V.build_service,
        snapshot_id=snapshot_id, commitment_key=key, population=POPULATION,
        custodian=CUSTODIAN,
        software={"repository_commit": _repository_commit(),
                  "lockfile_digest": _lockfile_digest()})
    certificate = replay(record, context)
    record = record.model_copy(update={"certificate": certificate})
    _say(7, f"replay: {certificate.outcome.value} ({certificate.certificate_id})")
    if certificate.outcome != REPRODUCED:
        print(f"FAIL: {certificate.detail}", file=sys.stderr)
        return 1

    # --- 8 ---------------------------------------------------------------- #
    secret, public = A.generate_keypair(seed=b"vrr-demo-test-signing-key-32byte")
    block = A.attest(record, secret, public)
    out_dir = os.path.join(args.out, record_id)
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    B.export_bundle(record, out_dir, attestation=block)
    ok, findings = B.verify_bundle_dir(out_dir, public_key=public)
    _say(8, f"bundle exported to {os.path.relpath(out_dir, ROOT)} "
            f"({len(B.FILES)} files); offline verification: "
            f"{'passes' if ok else 'FAILS — ' + '; '.join(findings)}")
    if not ok:
        return 1
    excluded = [level for st in trace.stages for level in st.excluded_levels]
    if excluded:
        _say(8, f"({len(excluded)} category level(s) excluded privately by the "
                "plan's contingency; none of them appear anywhere in the bundle)")

    # --- 9 ---------------------------------------------------------------- #
    # Run it with NO plan commitment reaching the chain — what an analyst asking
    # a follow-up question as ordinary session queries produces. Nothing here
    # ASSERTS that the follow-up is exploratory: the stages execute, the chain
    # records them, no commitment precedes them, and the label falls out of the
    # event order in `recorder.trace_from_plan_run`.
    posthoc_plan, posthoc_run = _run_plan(service, POSTHOC,
                                          audit_log=_Uncommitted(log),
                                          user="vrr-demo", cfg=cfg)
    posthoc_trace = R.trace_from_plan_run(
        posthoc_run, posthoc_plan, record_id=record_id + "-posthoc",
        manifests=manifests, audit_log=log, key=key, user="vrr-demo",
        release_domain="nightplay/demo")
    posthoc_evidence = E.extract_run(posthoc_trace.stages, _released(posthoc_run),
                                     include_not_answerable=True)
    posthoc_provenance = compile_public_provenance(posthoc_trace, posthoc_evidence)
    _say(9, f"post-hoc follow-up ({POSTHOC['question']}) classified "
            f"{posthoc_provenance.classification.value}")
    if posthoc_provenance.classification.value != "EXPLORATORY_POSTHOC":
        print("FAIL: an uncommitted analysis was not labelled exploratory",
              file=sys.stderr)
        return 1

    # --- 10 --------------------------------------------------------------- #
    tampered = os.path.join(args.out, record_id + "-tampered")
    if os.path.isdir(tampered):
        shutil.rmtree(tampered)
    shutil.copytree(out_dir, tampered)
    path = os.path.join(tampered, "evidence.json")
    with open(path, encoding="utf-8") as fh:
        items = json.load(fh)
    edited = False
    for item in items:
        if "estimate" in item.get("values", {}):
            item["values"]["estimate"] = round(item["values"]["estimate"] + 1.0, 4)
            edited = True
            break
    if not edited:
        items[0]["values"] = dict(items[0].get("values", {}), value=0.0)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(items, fh, indent=2, sort_keys=True)
    bad, why = B.verify_bundle_dir(tampered, public_key=public)
    _say(10, "tamper check: one coefficient edited by +1.00 -> verification "
             + ("FAILS TO NOTICE" if bad else "fails, as it must"))
    for finding in why:
        print(f"     - {finding}")
    shutil.rmtree(tampered)
    if bad:
        return 1

    print()
    print(f"record  {record_id}")
    print(f"bundle  {out_dir}")
    print(f"replay  {certificate.outcome.value}")
    print(f"signed  {A.backend()} (test key)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
