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
    AnalysisClassification, Disclosure, RecordError, StageStatus, StageType,
)
from tests.vrr_harness import (
    KEY, POSTHOC, build_record, released_of, run_plan,
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
    plan, run = run_plan(vrr_service, POSTHOC, vrr_log)
    trace = R.trace_from_plan_run(
        run, plan, record_id="vrr-posthoc", manifests=vrr_manifests,
        audit_rows=vrr_log.rows_since(0), key=KEY, committed=False)
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
