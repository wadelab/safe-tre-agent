"""Shared harness for the verifiable-research-record tests.

Not a test module. It holds the committed plans the VRR tests run and the
helpers that turn a plan run into a record, so that the record under test is
built the same way in every file — a private/public boundary tested against one
construction and exported by another would be tested against nothing.

The fixtures themselves (`vrr_study`, `vrr_service`, `vrr_manifests`,
`vrr_log`) live in `tests/conftest.py` under prefixed names, so that importing
this module does not drag pytest fixtures across files and shadow the ones a
test module defines for itself.
"""

from __future__ import annotations

from safetre import disclosure as D
from safetre import evidence as E
from safetre import recorder as R
from safetre.config import load_policy_config
from safetre.plan import Plan, PlanExecutor
from safetre.provenance import compile_public_provenance
from safetre.research_record import ResearchRecord

KEY = b"test-internal-commitment-key"
SNAPSHOT = "nightplay-test-2500"
POPULATION = "synthetic panel"
CUSTODIAN = "test custodian"

# The vertical slice's committed plan: the adjusted model NIGHTPLAY plants a
# confounder in, with the one data-sighted contingency that lets it release at
# all (armed_forces is sub-threshold). Chosen because it is the case where the
# private trace is genuinely richer than the public one — there is a privileged
# probe, an excluded category and a rewritten filter to keep out of the bundle.
ADJUSTED = {
    "question": "Is late-night phone use linked to gambling, once employment is accounted for?",
    "stages": [
        {"id": "adjusted",
         "sub_question": "regress stake on night use band and employment, sparse groups excluded",
         "spec": {"tool": "glm", "dataset": "panel", "family": "gaussian",
                  "response": "stake_gbp", "terms": ["night_use_band", "employment"],
                  "filters": []},
         "contingency": {"kind": "exclude_sparse", "dimension": "employment"}},
    ],
}

POSTHOC = {
    "question": "Does late-night phone use go with charitable giving?",
    "stages": [
        {"id": "giving", "sub_question": "mean donation amount by night use band",
         "spec": {"dataset": "giving", "measure": {"fn": "mean", "column": "amount_gbp"},
                  "group_by": ["night_use_band"], "filters": []}},
    ],
}


class SwallowsThePlanCommit:
    """An audit log that records every stage but drops the plan commitment.

    The laundering attack, faithfully: an analyst who runs their analysis as
    ordinary session queries and only afterwards writes a plan into the chain
    produces exactly this chain — stage rows first, a plan row last. Simulating
    it by running with no log at all would be a weaker test, and one an
    implementation can pass for the wrong reason (no stage rows at all is not
    the same evidence as stage rows in the wrong place).
    """

    def __init__(self, log):
        self._log = log

    def append(self, **kw):
        if kw.get("status") == "plan":
            return "swallowed"
        return self._log.append(**kw)

    def __getattr__(self, name):
        return getattr(self._log, name)


def auditor():
    cfg = load_policy_config()
    return D.SessionAuditor(threshold=cfg.min_cell_size, budget=cfg.query_budget,
                            selection_budget=cfg.selection_budget_bits)


def build_manifests(tables):
    return R.build_manifests(load_policy_config(), tables, snapshot_id=SNAPSHOT,
                             population=POPULATION, custodian=CUSTODIAN, key=KEY)


def run_plan(service, spec, log, *, user="vrr-test"):
    plan = Plan(**spec)
    run = PlanExecutor(service, auditor=auditor(), audit_log=log, user=user).run(plan)
    return plan, run


def released_of(run):
    return {sr.id: {"output": sr.output, "artifacts": sr.artifacts} for sr in run.stages}


def build_record(service, manifests, log, spec=ADJUSTED, *, committed=True):
    """A whole record from one plan run. `committed=False` runs the laundering
    shape: stages first, plan commitment afterwards."""
    plan, run = run_plan(service, spec, log if committed else SwallowsThePlanCommit(log))
    if not committed:
        PlanExecutor(service, auditor=auditor(), audit_log=log)._commit(
            plan, plan.canonical_hash())
    record_id = R.record_id_for(plan.question, plan.canonical_hash(), manifests)
    trace = R.trace_from_plan_run(run, plan, record_id=record_id, manifests=manifests,
                                  audit_rows=log.rows_since(0), key=KEY,
                                  user="vrr-test", audit_head=log.head())
    evidence = E.extract_run(trace.stages, released_of(run))
    trace = trace.model_copy(update={"evidence_refs": [e.evidence_id for e in evidence]})
    record = ResearchRecord(record_id=record_id, trace=trace, evidence=evidence,
                            provenance=compile_public_provenance(trace, evidence))
    record.validate_record()
    return plan, run, record
