"""The private/public boundary of the record itself, and the label on it.

Milestones 4 and 5 of `docs/verifiable-research-record-build-plan.md`.

**Milestone 4 is a release-equality test one layer up.** The gateway already
guarantees that two cohorts differing only in withheld structure get the same
answer; this pins the same property for the *record*. Two executions that
released the same approved evidence must produce byte-identical public
provenance however differently they got there — a different number of suppressed
cells, a rejected candidate model, a private branch taken the other way, a
retry, a sparse category excluded by a contingency, a private diagnostic. Every
one of those is a fact about the data, and a public graph whose shape moved with
any of them would be answering the questions `service.WITHHELD_MESSAGE` exists
to refuse.

The paired traces below are built by perturbing exactly one private thing at a
time and holding the approved evidence fixed, which is the shape the build plan
asks for. `test_the_pairing_is_not_vacuous` is the control: change something
PUBLIC and the bytes must move, or the whole file would pass by comparing
nothing to nothing.

**Milestone 5 is the plan-order property.** `TRE_PRECOMMITTED` is derived from
audit event order, never asserted, and the attack test is the laundering one:
run the analysis first, commit the plan afterwards, and try to issue a record
that claims pre-specification. It must come out post-hoc.
"""

from __future__ import annotations

import pytest

from safetre import evidence as E
from safetre import recorder as R
from safetre.provenance import (
    analysis_classification, audit_public_leakage, compile_public_provenance,
)
from safetre.research_record import (
    AnalysisClassification, Disclosure, RecordError, ResearchRecord, StageStatus,
    StageType,
)
from tests.vrr_harness import (
    ADJUSTED, KEY, POSTHOC, SwallowsThePlanCommit, build_record, released_of,
    run_plan,
)


# --------------------------------------------------------------------------- #
# the six perturbations                                                       #
# --------------------------------------------------------------------------- #

def _perturb(trace, **stage_updates):
    """The same trace with one private thing changed on its first stage."""
    head, *rest = trace.stages
    return trace.model_copy(update={"stages": [head.model_copy(update=stage_updates), *rest]})


def _with_extra_private_stage(trace, **stage_updates):
    """The same trace plus a stage that released nothing — a rejected candidate
    model, a private branch taken and abandoned. It ran; the reviewer must not
    be able to tell."""
    template = trace.stages[0]
    extra = template.model_copy(update={
        "stage_id": "rejected_candidate", "status": StageStatus.DENIED,
        "output_refs": [], "input_refs": [], **stage_updates})
    return trace.model_copy(update={"stages": [*trace.stages, extra]})


PERTURBATIONS = {
    "suppressed cell count": lambda t: _perturb(
        t, private_detail={"suppressed_cells": 7}),
    "rejected candidate model": lambda t: _with_extra_private_stage(t),
    "private branch decision": lambda t: _perturb(
        t, private_detail={"branch": "took the other arm"}),
    "retry count": lambda t: _perturb(t, private_detail={"retries": 3}),
    "sparse category": lambda t: _perturb(
        t, excluded_levels=["armed_forces", "clergy"], selection_bits=2),
    "private diagnostic": lambda t: _perturb(
        t, findings=[{"rule": "dominance", "detail": "one donor holds 91% of the cell"}],
        message="blocked by safe-outputs gateway: nothing from this query can be released"),
}


@pytest.fixture
def pair(vrr_service, vrr_manifests, vrr_log):
    _, _, record = build_record(vrr_service, vrr_manifests, vrr_log)
    return record.trace, record.evidence


@pytest.mark.parametrize("name", sorted(PERTURBATIONS))
def test_public_provenance_survives_private_trace_perturbation(pair, name):
    trace, evidence = pair
    baseline = compile_public_provenance(trace, evidence)
    perturbed = compile_public_provenance(PERTURBATIONS[name](trace), evidence)
    assert perturbed.canonical() == baseline.canonical(), \
        f"the public provenance moved when only {name} changed"


def test_all_six_perturbations_at_once_still_change_nothing(pair):
    trace, evidence = pair
    mutated = trace
    for perturb in PERTURBATIONS.values():
        mutated = perturb(mutated)
    assert compile_public_provenance(mutated, evidence).canonical() == \
        compile_public_provenance(trace, evidence).canonical()


def test_the_pairing_is_not_vacuous(pair):
    # the control. If changing something PUBLIC did not move the bytes, the
    # tests above would be comparing two constants.
    trace, evidence = pair
    head = trace.stages[0]
    changed = trace.model_copy(update={"stages": [
        head.model_copy(update={"public_parameters": dict(head.public_parameters,
                                                          family="poisson")})]})
    assert compile_public_provenance(changed, evidence).canonical() != \
        compile_public_provenance(trace, evidence).canonical()


def test_dropping_an_evidence_item_does_move_the_public_bytes(pair):
    trace, evidence = pair
    assert compile_public_provenance(trace, evidence[1:]).canonical() != \
        compile_public_provenance(trace, evidence).canonical()


# --------------------------------------------------------------------------- #
# what the public layer refuses to publish                                    #
# --------------------------------------------------------------------------- #

def test_a_node_exists_because_evidence_needs_explaining_not_because_a_stage_ran(pair):
    trace, evidence = pair
    with_denial = _with_extra_private_stage(trace)
    provenance = compile_public_provenance(with_denial, evidence)
    assert [n["stage_id"] for n in provenance.nodes] == ["adjusted"]
    assert "rejected_candidate" not in provenance.canonical()


def test_no_private_string_reaches_the_public_provenance(pair):
    trace, evidence = pair
    assert trace.stages[0].excluded_levels, "the contingency should have excluded a level"
    provenance = compile_public_provenance(trace, evidence)
    assert audit_public_leakage(provenance, trace) == []
    blob = provenance.canonical()
    for stage in trace.stages:
        for level in stage.excluded_levels:
            assert level not in blob
        assert str(stage.status.value) not in ("denied",) or "denied" not in blob


def test_the_executed_spec_never_becomes_a_public_parameter(pair):
    trace, evidence = pair
    stage = trace.stages[0]
    # the contingency rewrote the filter list from the data; the committed plan
    # did not have it, and the public parameters are the committed plan's
    assert stage.executed_parameters["filters"], "the contingency should have filtered"
    assert not stage.public_parameters.get("filters")
    blob = compile_public_provenance(trace, evidence).canonical()
    assert "armed_forces" not in blob


def test_the_public_node_keys_are_an_allowlist(pair):
    trace, evidence = pair
    node = compile_public_provenance(trace, evidence).nodes[0]
    assert set(node) == {"stage_id", "stage_type", "procedure", "public_parameters",
                         "input_refs", "replay_class", "classification", "artifacts"}
    private = {k for k, v in trace.stages[0].DISCLOSURE.items()
               if v is Disclosure.PRIVATE_ONLY}
    assert private and not (private & set(node))


def test_a_private_artifact_never_reaches_a_node(pair):
    trace, evidence = pair
    node = compile_public_provenance(trace, evidence).nodes[0]
    ids = {a["artifact_id"] for a in node["artifacts"]}
    assert ids == {"adjusted:cells", "adjusted:model", "adjusted:output"}
    assert not any(a["commitment"].startswith("hmac-") for a in node["artifacts"])


def test_evidence_from_a_stage_that_released_nothing_is_refused(pair):
    trace, evidence = pair
    head = trace.stages[0]
    denied = trace.model_copy(update={"stages": [
        head.model_copy(update={"status": StageStatus.DENIED})]})
    with pytest.raises(RecordError, match="released nothing"):
        compile_public_provenance(denied, evidence)


def test_a_probe_cannot_carry_public_evidence(pair):
    trace, evidence = pair
    head = trace.stages[0]
    probed = trace.model_copy(update={"stages": [
        head.model_copy(update={"stage_type": StageType.PROBE})]})
    with pytest.raises(RecordError, match="privileged probe"):
        compile_public_provenance(probed, evidence)


def test_a_dependency_on_an_unpublished_stage_is_pruned(pair):
    # a guarded stage whose predecessor was denied is a legal run; publishing
    # the edge would publish the predecessor's existence, and its verdict
    trace, evidence = pair
    head = trace.stages[0]
    trace = trace.model_copy(update={"stages": [
        head.model_copy(update={"stage_id": "hidden", "status": StageStatus.DENIED,
                                "output_refs": []}),
        head.model_copy(update={"input_refs": ["hidden"]})]})
    node = compile_public_provenance(trace, evidence).nodes[0]
    assert node["input_refs"] == []


# --------------------------------------------------------------------------- #
# milestone 5 — classification from event order                               #
# --------------------------------------------------------------------------- #

def test_a_committed_plan_earns_precommitment(vrr_service, vrr_manifests, vrr_log):
    _, _, record = build_record(vrr_service, vrr_manifests, vrr_log)
    assert all(st.classification is AnalysisClassification.TRE_PRECOMMITTED
               for st in record.trace.stages)
    provenance = compile_public_provenance(record.trace, record.evidence)
    assert provenance.classification is AnalysisClassification.TRE_PRECOMMITTED


def test_executing_first_and_committing_afterwards_is_post_hoc(vrr_service, vrr_manifests, vrr_log):
    """The plan-laundering attack: run it, see the answer, then write the plan
    into the chain and claim it was pre-specified."""
    _, _, record = build_record(vrr_service, vrr_manifests, vrr_log, committed=False)
    rows = vrr_log.rows_since(0)
    assert rows[-1]["status"] == "plan", "the commit really did come last"
    assert all(st.classification is AnalysisClassification.EXPLORATORY_POSTHOC
               for st in record.trace.stages)
    assert compile_public_provenance(record.trace, record.evidence).classification \
        is AnalysisClassification.EXPLORATORY_POSTHOC


def test_an_uncommitted_analysis_is_post_hoc(vrr_service, vrr_manifests, vrr_log):
    # nothing asserts the label: the stages run, the chain records them, no
    # commitment precedes them, and the classification falls out of the order
    plan, run = run_plan(vrr_service, POSTHOC, SwallowsThePlanCommit(vrr_log))
    trace = R.trace_from_plan_run(
        run, plan, record_id="vrr-posthoc", manifests=vrr_manifests,
        audit_log=vrr_log, key=KEY)
    assert trace.plan_ref is None and trace.committed_plan is None
    evidence = E.extract_run(trace.stages, released_of(run))
    assert compile_public_provenance(trace, evidence).classification \
        is AnalysisClassification.EXPLORATORY_POSTHOC


def test_the_headline_classification_is_the_weakest_evidence_bearing_stage(pair):
    trace, evidence = pair
    head = trace.stages[0]
    mixed = trace.model_copy(update={"stages": [
        head,
        head.model_copy(update={
            "stage_id": "later",
            "classification": AnalysisClassification.EXPLORATORY_POSTHOC})]})
    also = [evidence[0].model_copy(update={"evidence_id": "ev-later",
                                           "source_stage": "later"})]
    assert analysis_classification(mixed, {"adjusted"}) \
        is AnalysisClassification.TRE_PRECOMMITTED
    assert analysis_classification(mixed, {"adjusted", "later"}) \
        is AnalysisClassification.EXPLORATORY_POSTHOC
    assert compile_public_provenance(mixed, evidence + also).classification \
        is AnalysisClassification.EXPLORATORY_POSTHOC


def test_a_stage_with_no_evidence_cannot_drag_the_label_down(pair):
    trace, evidence = pair
    posthoc_only = _with_extra_private_stage(
        trace, classification=AnalysisClassification.EXPLORATORY_POSTHOC)
    assert compile_public_provenance(posthoc_only, evidence).classification \
        is AnalysisClassification.TRE_PRECOMMITTED


# --------------------------------------------------------------------------- #
# the chain has to be authentic before its order means anything               #
# --------------------------------------------------------------------------- #
#
# Found by re-auditing this module's own first version, which took a list of
# audit rows and trusted it. `AuditLog.since` states the rule these break —
# "any future caller that rebuilds a control from these rows owes the same
# gate" `SessionStore.rehydrate` pays (hardening #59) — and a record that
# derives a PUBLISHED scientific claim from row order is exactly such a caller.

def test_reordering_the_chain_does_not_buy_a_precommitment_label(
        vrr_service, vrr_manifests, vrr_log):
    """The measured attack. Run the laundering flow so the chain honestly reads
    `EXPLORATORY_POSTHOC`, then reorder the rows in the database so the plan
    commitment comes first. Before the fix this returned `TRE_PRECOMMITTED`
    while `verify()` returned False to nobody."""
    _, _, honest = build_record(vrr_service, vrr_manifests, vrr_log, committed=False)
    assert honest.trace.stages[0].classification is \
        AnalysisClassification.EXPLORATORY_POSTHOC
    assert vrr_log.verify()

    plan_row = next(r for r in vrr_log.rows_since(0) if r["status"] == "plan")
    vrr_log.con.execute("UPDATE records SET id = -1 WHERE id = ?", (plan_row["id"],))
    vrr_log.con.commit()
    assert not vrr_log.verify(), "the tamper should break the chain"

    _, _, after = build_record(vrr_service, vrr_manifests, vrr_log, committed=False)
    assert all(st.classification is AnalysisClassification.EXPLORATORY_POSTHOC
               for st in after.trace.stages)
    assert not after.trace.audit_chain_verified


def test_an_unverified_chain_keeps_the_evidence_and_drops_the_claim(
        vrr_service, vrr_manifests, vrr_log):
    """Fail closed on the claim, not on the record. The evidence lineage and the
    replay rest on the released artifacts, not on chain order, so they survive;
    the pre-specification label and the audit citations do not."""
    _, run, _ = build_record(vrr_service, vrr_manifests, vrr_log)
    vrr_log.con.execute("UPDATE records SET user = 'someone-else' WHERE id = 1")
    vrr_log.con.commit()
    assert not vrr_log.verify()

    plan, rerun = run_plan(vrr_service, ADJUSTED, None)
    trace = R.trace_from_plan_run(rerun, plan, record_id="vrr-unverified",
                                  manifests=vrr_manifests, audit_log=vrr_log, key=KEY)
    assert trace.audit_chain_verified is False
    assert trace.plan_ref is None and trace.committed_plan is None
    assert all(st.audit_ref == "" for st in trace.stages), \
        "a row whose authenticity is unknown is not a citation"
    # but the released artifacts are still all there, with their commitments
    assert trace.stages[0].public_artifacts()
    evidence = E.extract_run(trace.stages, released_of(rerun))
    assert evidence and compile_public_provenance(trace, evidence).nodes


def test_a_record_cannot_claim_precommitment_on_an_unverified_chain(vrr_record):
    forged = vrr_record.trace.model_copy(update={"audit_chain_verified": False})
    with pytest.raises(RecordError, match="does not verify"):
        forged.validate_lineage()


def test_the_public_provenance_publishes_whether_the_chain_verified(pair):
    trace, evidence = pair
    provenance = compile_public_provenance(trace, evidence)
    assert provenance.audit_chain_verified is True
    # and it is part of the canonical bytes, so it cannot be dropped quietly
    assert "audit_chain_verified" in provenance.canonical()


def test_a_decoy_row_impersonating_a_stage_is_not_cited(vrr_service, vrr_manifests,
                                                        vrr_log):
    """A request is untrusted content, so an analyst can submit an ordinary
    query whose text is a plan stage's sub-question verbatim. Matching on the
    text alone would cite the decoy; the outcome has to agree too."""
    sub_question = ADJUSTED["stages"][0]["sub_question"]
    decoy = vrr_log.append(user="attacker", request=sub_question,
                           spec={"dataset": "panel"}, status="denied",
                           findings=[], output_shape=None)
    _, _, record = build_record(vrr_service, vrr_manifests, vrr_log)
    assert record.trace.stages[0].audit_ref != decoy
    assert record.trace.stages[0].classification is \
        AnalysisClassification.TRE_PRECOMMITTED


# --------------------------------------------------------------------------- #
# executable twins for formal/vrr_record.als                                  #
# --------------------------------------------------------------------------- #
#
# Each attack run in the Alloy model drops one clause of the compiler and shows
# a disclosure. `formal/correspondence.yaml` requires a twin for every one of
# them: if the model exhibits an attack and nothing executes it, the model is the
# only thing claiming the attack is real.

def test_publishing_the_plan_body_would_name_the_refused_stages(pair):
    """Twin of `vrr_record.als::F109PlanBodyPublished`.

    Runs the disclosure rather than asserting its absence: reconstruct what the
    bundle used to publish, take the set difference the way a reader would, and
    show it names the stage the gateway refused. Then show the shipped provenance
    has no field to do it with.
    """
    trace, evidence = pair
    head = trace.stages[0]
    refused = head.model_copy(update={"stage_id": "refused_stage",
                                      "status": StageStatus.DENIED,
                                      "output_refs": []})
    with_refusal = trace.model_copy(update={"stages": [head, refused]})
    provenance = compile_public_provenance(with_refusal, evidence)

    declared = {st.stage_id for st in with_refusal.stages}
    published = {n["stage_id"] for n in provenance.nodes}
    assert declared - published == {"refused_stage"}, \
        "the set difference is the gateway's verdict, so the plan body and the " \
        "node list must not both be published"

    # and the shipped public provenance carries no plan body to difference against
    assert "committed_plan" not in provenance.model_dump()
    assert "committed_plan" not in provenance.canonical()
    assert "refused_stage" not in provenance.canonical()


def test_not_answerable_evidence_never_reaches_the_public_evidence_set(pair):
    """Twin of `vrr_record.als::F110NotAnswerablePublished`.

    An evidence item citing a stage that released nothing names that stage. The
    kind is legitimate internally — it is how a record says "nothing came back
    for this sub-question" — so the control is that the PUBLIC set excludes it,
    not that it cannot exist.
    """
    trace, evidence = pair
    head = trace.stages[0]
    refused = head.model_copy(update={"stage_id": "refused_stage",
                                      "status": StageStatus.DENIED,
                                      "output_refs": []})
    with_refusal = trace.model_copy(update={"stages": [head, refused]})
    unanswerable = E.not_answerable(refused)
    assert unanswerable.source_stage == "refused_stage", \
        "the item names the refused stage, which is why it cannot be published"

    provenance = compile_public_provenance(with_refusal, [*evidence, unanswerable])
    record = ResearchRecord(record_id=with_refusal.record_id, trace=with_refusal,
                            evidence=[*evidence, unanswerable],
                            provenance=provenance)
    record.validate_record()

    public = {e.evidence_id for e in record.public_evidence()}
    assert unanswerable.evidence_id not in public
    assert unanswerable.evidence_id in {e.evidence_id for e in record.evidence}, \
        "the item still exists in the private record; only publication is refused"
    assert "refused_stage" not in provenance.canonical()
