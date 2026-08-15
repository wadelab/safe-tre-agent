"""Locked analysis plans — the data-sighted tier (spec R20, P24; safetre/plan.py).

The phase-3 core of the inside analyst ("Chimp"). A locked plan is the only
way an automated analyst may act on cohort structure the gateway withheld,
and it is safe only because it is declared in advance, its hash committed to
the audit chain before it runs, executed by deterministic code, and metered:
the one data-sighted move (`exclude_sparse`) runs a privileged probe for the
levels a model would suppress, excludes them, and charges one bit per revealed
level against a small selection budget.

What is pinned here, and why each is a safety pin:

- R20: the plan hash is written to the audit chain BEFORE any stage runs; a
  stage's spec is executed through the unchanged service (so the gateway,
  budget and lineage apply); the released frame's digest is recorded (a stage
  commitment); a guard reads a prior stage's OUTCOME only.
- P24: the sparse-exclusion is charged in bits; a contingency the ledger
  cannot afford is refused and spends nothing; the exact sparse counts never
  appear in what leaves the executor. THE SELECTION CHANNEL IS BOUNDED — the
  test replays the round-8 shape (recover a rare category by exclusion) and
  shows the ledger caps how much of it a session can buy.

The harness is the NIGHTPLAY study, whose planted sub-threshold groups
(armed_forces = 6, Northern Ireland = 8) are exactly the withheld structure
the contingency is for.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from safetre import dataset as dataset_mod
from safetre import disclosure as D
from safetre.audit import AuditLog
from safetre.config import load_policy_config
from safetre.plan import Guard, Plan, PlanExecutor, Stage
from studies.nightplay import generate as G
from studies.nightplay import verify as V

PACKAGED = pathlib.Path(dataset_mod.__file__).with_name("demo_dataset.yaml")

ADJ_SPEC = {"tool": "glm", "dataset": "panel", "family": "gaussian",
            "response": "stake_gbp", "terms": ["night_use_band", "employment"],
            "filters": []}
MEAN_BY_BAND = {"dataset": "panel", "measure": {"fn": "mean", "column": "stake_gbp"},
                "group_by": ["night_use_band"], "filters": []}


@pytest.fixture(scope="module")
def study():
    return G.generate(n_people=2500)


@pytest.fixture
def service(study):
    tables, _ = study
    dataset_mod.activate(dataset_mod.load_dataset(V.DEFINITION))
    try:
        yield V.build_service(tables)
    finally:
        dataset_mod.activate(dataset_mod.load_dataset(PACKAGED))


def _auditor(**kw):
    cfg = load_policy_config()
    return D.SessionAuditor(threshold=cfg.min_cell_size, budget=cfg.query_budget,
                            selection_budget=kw.get("selection_budget", cfg.selection_budget_bits))


# --------------------------------------------------------------------------- #
# the plan model                                                              #
# --------------------------------------------------------------------------- #

def test_plan_is_a_closed_typed_program():
    # a guard must name an earlier stage; ids unique; unknown fields rejected
    with pytest.raises(Exception):
        Plan(question="q", stages=[
            {"id": "a", "sub_question": "x", "spec": MEAN_BY_BAND,
             "guard": {"from_stage": "b", "statuses": ["released"]}},
            {"id": "b", "sub_question": "y", "spec": MEAN_BY_BAND}])
    with pytest.raises(Exception):
        Plan(question="q", stages=[{"id": "a", "sub_question": "x", "spec": MEAN_BY_BAND},
                                   {"id": "a", "sub_question": "y", "spec": MEAN_BY_BAND}])
    with pytest.raises(Exception):
        Guard(from_stage="a", statuses=["maybe"])
    with pytest.raises(Exception):
        Stage(id="bad id!", sub_question="x", spec=MEAN_BY_BAND)


def test_the_plan_hash_is_stable_and_order_sensitive():
    p1 = Plan(question="q", stages=[{"id": "a", "sub_question": "x", "spec": MEAN_BY_BAND},
                                    {"id": "b", "sub_question": "y", "spec": MEAN_BY_BAND}])
    p2 = Plan(question="q", stages=[{"id": "b", "sub_question": "y", "spec": MEAN_BY_BAND},
                                    {"id": "a", "sub_question": "x", "spec": MEAN_BY_BAND}])
    assert p1.canonical_hash() == p1.canonical_hash()
    assert p1.canonical_hash() != p2.canonical_hash()


# --------------------------------------------------------------------------- #
# R20: commit before run, deterministic execution, stage commitments          #
# --------------------------------------------------------------------------- #

def test_the_plan_hash_is_committed_before_any_stage_runs(service, tmp_path):
    log = AuditLog(str(tmp_path / "audit.db"))
    plan = Plan(question="does night use predict stake?", stages=[
        {"id": "headline", "sub_question": "mean stake by night use band", "spec": MEAN_BY_BAND}])
    run = PlanExecutor(service, auditor=_auditor(), audit_log=log, user="chimp-1").run(plan)
    rows = log.since(0)
    # the very first record is the plan commitment, before the stage's release
    assert rows[0]["status"] == "plan"
    assert rows[0]["accounting"]["plan_hash"] == plan.canonical_hash() == run.plan_hash
    assert rows[0]["spec"]["stage_ids"] == ["headline"]
    assert rows[1]["status"] == "released"
    assert log.verify() is True


def test_a_released_stage_carries_its_digest_as_a_stage_commitment(service):
    plan = Plan(question="q", stages=[
        {"id": "h", "sub_question": "mean stake by night use band", "spec": MEAN_BY_BAND}])
    run = PlanExecutor(service, auditor=_auditor()).run(plan)
    st = run.stages[0]
    assert st.released() and st.output_sha256 and len(st.output_sha256) == 64
    # the digest is of what was released, recomputable by a verifier
    from safetre.plan import frame_digest
    import pandas as pd
    assert frame_digest(pd.DataFrame(st.output)) == st.output_sha256


def test_a_guard_reads_a_prior_stage_outcome_only(service):
    # the deep dive runs only if the headline released; here the headline is a
    # per-person request that is denied, so the guarded stage is skipped
    plan = Plan(question="q", stages=[
        {"id": "head", "sub_question": "mean stake per person",
         "spec": {"dataset": "panel", "measure": {"fn": "mean", "column": "stake_gbp"},
                  "group_by": ["person_id"], "filters": []}},
        {"id": "deep", "sub_question": "mean stake by night use band", "spec": MEAN_BY_BAND,
         "guard": {"from_stage": "head", "statuses": ["released"]}}])
    run = PlanExecutor(service, auditor=_auditor()).run(plan)
    assert run.stages[0].status == "denied"
    assert run.stages[1].status == "skipped" and run.stages[1].output is None


def test_every_stage_goes_through_the_gateway_and_the_lineage_binds(service):
    # a stage that would differencing-pair a prior released stage is denied
    plan = Plan(question="q", stages=[
        {"id": "a", "sub_question": "mean stake by night use band", "spec": MEAN_BY_BAND},
        {"id": "b", "sub_question": "mean stake by night use band excluding armed forces",
         "spec": dict(MEAN_BY_BAND,
                      filters=[{"column": "employment", "op": "!=", "value": "armed_forces"}])}])
    run = PlanExecutor(service, auditor=_auditor()).run(plan)
    assert [s.status for s in run.stages] == ["released", "denied"]


# --------------------------------------------------------------------------- #
# P24: the metered sparse-exclusion, and the bounded selection channel        #
# --------------------------------------------------------------------------- #

def test_exclude_sparse_probes_charges_a_bit_and_lets_the_model_release(service):
    # the adjusted model is denied outright (armed_forces cell suppressed, P19);
    # the contingency privately finds that armed_forces is the sparse level,
    # charges one bit, excludes it, and the model releases
    a = _auditor()
    denied = service.handle("regress stake on night use band and employment",
                            _planner(ADJ_SPEC), auditor=D.SessionAuditor(threshold=a.threshold))
    assert denied.status == "denied"

    plan = Plan(question="q", stages=[
        {"id": "adj", "sub_question": "regress stake on night use band and employment, sparse groups excluded",
         "spec": ADJ_SPEC, "contingency": {"kind": "exclude_sparse", "dimension": "employment"}}])
    run = PlanExecutor(service, auditor=a).run(plan)
    st = run.stages[0]
    assert st.status in ("released", "redacted"), st.message
    assert st.selection_bits == 1 and st.excluded == ["armed_forces"]
    assert {"column": "employment", "op": "!=", "value": "armed_forces"} in st.spec["filters"]
    assert run.selection_spent == 1


def test_the_exact_sparse_counts_never_leave_the_executor(service):
    plan = Plan(question="q", stages=[
        {"id": "adj", "sub_question": "adjusted, sparse excluded", "spec": ADJ_SPEC,
         "contingency": {"kind": "exclude_sparse", "dimension": "employment"}}])
    run = PlanExecutor(service, auditor=_auditor()).run(plan)
    blob = run.to_json()
    # armed_forces's true size (6) must not appear anywhere the plan run exposes
    assert '"6"' not in blob and ": 6" not in blob
    # what IS exposed: the level name and the bit cost, both intended
    assert "armed_forces" in blob and '"selection_bits": 1' in blob


def test_a_contingency_the_budget_cannot_afford_is_refused_and_spends_nothing(service):
    a = _auditor(selection_budget=0)
    plan = Plan(question="q", stages=[
        {"id": "adj", "sub_question": "adjusted, sparse excluded", "spec": ADJ_SPEC,
         "contingency": {"kind": "exclude_sparse", "dimension": "employment"}}])
    run = PlanExecutor(service, auditor=a).run(plan)
    st = run.stages[0]
    assert st.status == "denied" and "selection budget" in st.message
    assert st.selection_bits == 0 and st.excluded == []
    assert a.selection_spent == 0            # a refusal is free (P24)
    assert st.output is None


def test_the_selection_channel_is_bounded_across_a_session(service):
    """The round-8 shape: exclusion reveals a rare category exists. One
    session may buy only `selection_budget` bits of that, whatever the plan."""
    a = _auditor(selection_budget=2)
    # three stages each excluding one sparse group (1 bit apiece); the third
    # cannot be paid and is refused, and the ledger stops at the budget
    stages = []
    for i, (dim, ds) in enumerate([("employment", "panel"), ("region", "panel"),
                                   ("employment", "bets")]):
        stages.append({"id": f"s{i}", "sub_question": f"probe {dim}",
                       "spec": {"dataset": ds, "measure": {"fn": "mean", "column": "stake_gbp"},
                                "group_by": [dim], "filters": []},
                       "contingency": {"kind": "exclude_sparse", "dimension": dim}})
    run = PlanExecutor(service, auditor=a).run(Plan(question="q", stages=stages))
    spent = [s.selection_bits for s in run.stages]
    assert sum(spent) <= 2 and a.selection_spent <= 2
    assert any(s.status == "denied" and "selection budget" in s.message for s in run.stages)


def test_exclude_sparse_rejects_a_non_dimension(service):
    plan = Plan(question="q", stages=[
        {"id": "a", "sub_question": "x", "spec": MEAN_BY_BAND,
         "contingency": {"kind": "exclude_sparse", "dimension": "stake_gbp"}}])
    run = PlanExecutor(service, auditor=_auditor()).run(plan)
    assert run.stages[0].status == "denied" and "not a dimension" in run.stages[0].message


def test_selection_bits_replay_across_a_restart(service, tmp_path, study):
    from safetre_web.session import SessionStore
    log = AuditLog(str(tmp_path / "audit.db"))
    a = _auditor()
    plan = Plan(question="q", stages=[
        {"id": "adj", "sub_question": "adjusted, sparse excluded", "spec": ADJ_SPEC,
         "contingency": {"kind": "exclude_sparse", "dimension": "employment"}}])
    PlanExecutor(service, auditor=a, audit_log=log, user="chimp-9").run(plan)
    assert a.selection_spent == 1
    store = SessionStore(threshold=a.threshold, budget=a.budget,
                         selection_budget=a.selection_budget)
    store.rehydrate(log, window_hours=24)
    assert store.get("chimp-9").auditor.selection_spent == 1


def _planner(spec):
    class _P:
        def plan(self, request):
            return json.loads(json.dumps(spec))
    return _P()
