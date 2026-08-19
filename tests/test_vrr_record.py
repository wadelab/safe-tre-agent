"""Verifiable research records: the vocabulary, the record, and its lineage.

Milestones 0, 1, 3 and 6 of `docs/verifiable-research-record-build-plan.md`,
under D9 and the corrections in `docs/vrr-critical-review.md`.

What is pinned here, and why each is a safety pin rather than a schema check:

- **M0.** Every one of the five record types carries a one-sentence authority
  boundary; every field of every type is classified `PUBLIC`,
  `OPAQUE_ATTESTATION` or `PRIVATE_ONLY` at class-creation time; no type can
  hold model reasoning; `PublicProvenance` has no `PRIVATE_ONLY` field to put a
  raw private value in. The point of testing the vocabulary is that a field
  which reaches a record unclassified is a field that will be published by
  whoever writes the next exporter.
- **M1.** One scripted NIGHTPLAY analysis yields a record containing every
  registered stage needed to explain a released result, with immutable ids and
  typed dependencies — and REMOVING one dependency makes validation fail.
- **M3.** Every released number maps to an evidence item; an item cannot cite a
  denied stage or a privileged probe; mutating a source result invalidates the
  evidence; renaming a figure does not change what the evidence IS.
- **M6.** The manifests fix the semantics a replay must match, and the dataset
  snapshot is committed with a KEY rather than a bare hash.

The harness is the NIGHTPLAY vrr_study through the ordinary gateway — the same
`build_service` the web app uses — so a record here is a record a real session
would have produced. Fixtures come from `tests/conftest.py` (`vrr_*`) and the
plans and builders from `tests/vrr_harness.py`.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from safetre import evidence as E
from safetre import recorder as R
from safetre.audit import AuditLog
from safetre.config import load_policy_config
from safetre.research_record import (
    VRR_OBJECTS, ArtifactRef, Disclosure, PublicProvenance, RecordError,
    ReplayClass, StageStatus, StageType, commit_private, commit_public,
    internal_commitment_key,
)
from tests.vrr_harness import (
    ADJUSTED, CUSTODIAN, KEY, POPULATION, SNAPSHOT, build_record, run_plan,
)


# --------------------------------------------------------------------------- #
# milestone 0 — the vocabulary                                                #
# --------------------------------------------------------------------------- #

def test_the_five_objects_are_the_five_objects():
    assert sorted(c.__name__ for c in VRR_OBJECTS) == [
        "EvidenceItem", "PrivateExecutionTrace", "PublicProvenance",
        "ReplayCertificate", "ResearchRecord"]


@pytest.mark.parametrize("cls", VRR_OBJECTS, ids=lambda c: c.__name__)
def test_every_object_states_one_sentence_of_authority(cls):
    text = cls.AUTHORITY.strip()
    assert text.endswith(".") and text.count(".") == 1, cls.__name__


@pytest.mark.parametrize("cls", VRR_OBJECTS, ids=lambda c: c.__name__)
def test_every_field_is_classified(cls):
    assert set(cls.DISCLOSURE) == set(cls.model_fields), cls.__name__
    assert all(isinstance(v, Disclosure) for v in cls.DISCLOSURE.values())


def test_an_unclassified_field_cannot_be_declared():
    # the fail-closed rule, at class creation rather than at serialization: a
    # field nobody classified must not be storable in the first place
    from safetre.research_record import _VrrModel

    with pytest.raises(RecordError, match="unclassified field"):
        class Leaky(_VrrModel):
            AUTHORITY = "Leaks."
            DISCLOSURE = {"a": Disclosure.PUBLIC}
            a: str = ""
            b: str = ""


def test_a_record_type_cannot_carry_model_reasoning():
    from safetre.research_record import _VrrModel

    with pytest.raises(RecordError, match="chain-of-thought"):
        class Confessional(_VrrModel):
            AUTHORITY = "Confesses."
            DISCLOSURE = {"model_rationale": Disclosure.PRIVATE_ONLY}
            model_rationale: str = ""


def test_public_provenance_has_no_private_field():
    # the object a reviewer sees cannot even name a private raw value: there is
    # no PRIVATE_ONLY slot in it for one to sit in
    assert Disclosure.PRIVATE_ONLY not in set(PublicProvenance.DISCLOSURE.values())


def test_public_fields_drops_private_ones_including_nested(vrr_record):
    reduced = vrr_record.trace.public_fields()
    assert "stages" not in reduced and "user" not in reduced
    assert reduced["record_id"] == vrr_record.record_id


# --------------------------------------------------------------------------- #
# commitments                                                                 #
# --------------------------------------------------------------------------- #

def test_a_private_commitment_needs_a_key():
    with pytest.raises(RecordError, match="lookup table"):
        commit_private({"suppressed": 6}, b"")


def test_a_private_commitment_is_not_a_bare_hash_of_the_value():
    # the failure D9 names: a hash of a small count is brute-forceable, so a
    # keyed commitment must not equal the public digest of the same value
    value = {"suppressed_cells": 6}
    assert commit_private(value, KEY) != commit_public(value)
    assert commit_private(value, KEY) != commit_private(value, b"another-key")


def test_the_internal_commitment_key_has_no_default(monkeypatch):
    monkeypatch.delenv("SAFETRE_VRR_COMMIT_KEY", raising=False)
    with pytest.raises(RecordError, match="no safe default"):
        internal_commitment_key()
    monkeypatch.setenv("SAFETRE_VRR_COMMIT_KEY", "k")
    assert internal_commitment_key() == b"k"


# --------------------------------------------------------------------------- #
# milestone 1 — one deterministic record                                      #
# --------------------------------------------------------------------------- #

def test_a_scripted_analysis_yields_a_record_of_every_stage(vrr_service, vrr_manifests, vrr_log):
    _, run, record = build_record(vrr_service, vrr_manifests, vrr_log)
    assert [sr.status for sr in run.stages] == ["released"]
    assert [st.stage_id for st in record.trace.stages] == ["adjusted"]
    stage = record.trace.stages[0]
    assert stage.stage_type is StageType.MODEL and stage.procedure == "glm"
    assert stage.replay_class is ReplayClass.TRE_REPLAYABLE_EXACT
    # the released model output, its vetted design-cell table and its fit block
    assert {a.artifact_id for a in stage.public_artifacts()} == {
        "adjusted:output", "adjusted:cells", "adjusted:model"}
    record.validate_record()


def test_every_stage_carries_an_audit_reference_into_the_chain(vrr_service, vrr_manifests, vrr_log):
    _, _, record = build_record(vrr_service, vrr_manifests, vrr_log)
    macs = {row["mac"] for row in vrr_log.rows_since(0)}
    for stage in record.trace.stages:
        assert stage.audit_ref in macs
    # and the record REFERENCES the chain rather than replacing it: the row is
    # still the audit log's, and the trace holds only its MAC
    assert all(len(st.audit_ref) == 64 for st in record.trace.stages)


def test_record_ids_and_evidence_ids_are_deterministic(vrr_service, vrr_manifests, vrr_log, tmp_path):
    _, _, first = build_record(vrr_service, vrr_manifests, vrr_log)
    second_log = AuditLog(str(tmp_path / "second.db"))
    _, _, second = build_record(vrr_service, vrr_manifests, second_log)
    assert first.record_id == second.record_id
    assert ([e.evidence_id for e in first.evidence]
            == [e.evidence_id for e in second.evidence])


def test_removing_a_dependency_makes_validation_fail(vrr_record):
    stage = vrr_record.trace.stages[0]
    orphan = stage.model_copy(update={"stage_id": "downstream",
                                      "input_refs": ["a-stage-that-is-not-here"]})
    broken = vrr_record.trace.model_copy(update={"stages": [stage, orphan]})
    with pytest.raises(RecordError, match="not an earlier stage"):
        broken.validate_lineage()


def test_a_dependency_pointing_forwards_makes_validation_fail(vrr_record):
    stage = vrr_record.trace.stages[0]
    first = stage.model_copy(update={"stage_id": "first", "input_refs": ["second"]})
    second = stage.model_copy(update={"stage_id": "second", "input_refs": []})
    with pytest.raises(RecordError, match="not an earlier stage"):
        vrr_record.trace.model_copy(update={"stages": [first, second]}).validate_lineage()


def test_stage_ids_are_immutable(vrr_record):
    stage = vrr_record.trace.stages[0]
    with pytest.raises(ValidationError):
        stage.stage_id = "renamed"


def test_a_trace_cannot_claim_precommitment_without_committing_a_plan(vrr_record):
    forged = vrr_record.trace.model_copy(update={"plan_ref": None, "committed_plan": None})
    with pytest.raises(RecordError, match="commits no plan"):
        forged.validate_lineage()


def test_building_the_record_changes_no_release_behaviour(vrr_service, vrr_log):
    # the same plan, run with and without anything recording it, releases the
    # same bytes: instrumentation reads existing seams and adds no path
    plan_a, run_a = run_plan(vrr_service, ADJUSTED, vrr_log)
    plan_b, run_b = run_plan(vrr_service, ADJUSTED, None)
    assert [s.status for s in run_a.stages] == [s.status for s in run_b.stages]
    assert [s.output_sha256 for s in run_a.stages] == [s.output_sha256 for s in run_b.stages]
    assert plan_a.canonical_hash() == plan_b.canonical_hash()


# --------------------------------------------------------------------------- #
# milestone 3 — evidence lineage                                              #
# --------------------------------------------------------------------------- #

def test_every_released_number_maps_to_an_evidence_item(vrr_service, vrr_manifests, vrr_log):
    _, run, record = build_record(vrr_service, vrr_manifests, vrr_log)
    stage = run.stages[0]
    released_rows = len(stage.output or []) + sum(
        len(rows) for rows in (stage.artifacts or {}).values())
    assert len(record.evidence) == released_rows
    assert {e.kind for e in record.evidence} == {
        E.MODEL_COEFFICIENT, E.GROUP_STATISTIC, E.MODEL_FIT}


def test_evidence_renders_back_to_the_released_number(vrr_service, vrr_manifests, vrr_log):
    _, run, record = build_record(vrr_service, vrr_manifests, vrr_log)
    coefficients = {(r["term"], r["level"]): r["estimate"]
                    for r in run.stages[0].output}
    for item in record.evidence:
        if item.kind != E.MODEL_COEFFICIENT:
            continue
        released = coefficients[(item.keys["term"], item.keys["level"])]
        assert E.render(item).startswith(f"{released:.{item.precision}f}")


def test_evidence_cannot_cite_a_stage_that_released_nothing(vrr_record):
    denied = vrr_record.trace.stages[0].model_copy(
        update={"stage_id": "denied", "status": StageStatus.DENIED, "output_refs": []})
    trace = vrr_record.trace.model_copy(update={"stages": [*vrr_record.trace.stages, denied]})
    bad = vrr_record.evidence[0].model_copy(update={"source_stage": "denied"})
    broken = vrr_record.model_copy(update={"trace": trace, "evidence": [bad]})
    with pytest.raises(RecordError, match="released nothing"):
        broken.validate_record()


def test_evidence_cannot_cite_a_privileged_probe(vrr_record):
    probe = vrr_record.trace.stages[0].model_copy(
        update={"stage_id": "probe", "stage_type": StageType.PROBE})
    with pytest.raises(RecordError, match="privileged probe"):
        E.extract(probe, output=[{"value": 1}])


def test_mutating_a_source_result_invalidates_the_evidence(vrr_service, vrr_manifests, vrr_log):
    _, run, record = build_record(vrr_service, vrr_manifests, vrr_log)
    before = {e.identity_digest() for e in record.evidence}
    tampered = [dict(r) for r in run.stages[0].output]
    tampered[1]["estimate"] = tampered[1]["estimate"] + 1.0
    after = {e.identity_digest() for e in E.extract_run(
        record.trace.stages,
        {"adjusted": {"output": tampered, "artifacts": run.stages[0].artifacts}})}
    assert before != after


def test_a_figure_label_is_metadata_not_identity(vrr_record):
    item = vrr_record.evidence[0]
    labelled = E.label(item, "Figure 2b")
    assert labelled.manuscript_ref == "Figure 2b"
    assert labelled.identity_digest() == item.identity_digest()
    assert E.render(labelled) == E.render(item)


def test_not_answerable_carries_no_number(vrr_record):
    stage = vrr_record.trace.stages[0].model_copy(update={"status": StageStatus.DENIED})
    items = E.extract(stage, output=None, include_not_answerable=True)
    assert len(items) == 1 and items[0].kind == E.NOT_ANSWERABLE
    assert items[0].values == {} and E.render(items[0]) == "not answerable"


def test_two_released_values_cannot_share_an_evidence_identity(vrr_record):
    stage = vrr_record.trace.stages[0]
    rows = [{"night_use_band": "heavy", "value": 1.0, "n": 100}] * 2
    with pytest.raises(RecordError, match="not distinguishing them"):
        E.extract_run([stage], {stage.stage_id: {"output": rows}})


# --------------------------------------------------------------------------- #
# milestone 6 — manifests                                                     #
# --------------------------------------------------------------------------- #

def test_the_manifests_name_the_semantics_a_replay_must_match(vrr_manifests):
    semantics = vrr_manifests.replay_semantics()
    assert set(semantics) == {
        "package_version", "procedure_registry_digest", "catalogue_digest",
        "policy_digest", "tool_manifest_digest", "dataset_snapshot_id",
        "dataset_snapshot_commitment"}
    assert all(semantics.values())


def test_the_dataset_snapshot_is_committed_with_a_key(vrr_manifests, vrr_study):
    tables, _ = vrr_study
    assert vrr_manifests.dataset.snapshot_commitment.startswith("hmac-sha256/vrr-v1:")
    other = R.dataset_manifest(tables, snapshot_id=SNAPSHOT, population=POPULATION,
                               custodian=CUSTODIAN, key=b"a-different-key")
    assert other.snapshot_commitment != vrr_manifests.dataset.snapshot_commitment


def test_a_changed_snapshot_changes_the_commitment(vrr_manifests, vrr_study):
    tables, _ = vrr_study
    shrunk = dict(tables)
    first = next(iter(sorted(shrunk)))
    shrunk[first] = shrunk[first].iloc[:-1]
    changed = R.dataset_manifest(shrunk, snapshot_id=SNAPSHOT,
                                 population=POPULATION, custodian=CUSTODIAN, key=KEY)
    assert changed.snapshot_commitment != vrr_manifests.dataset.snapshot_commitment


def test_the_manifests_carry_no_private_field(vrr_manifests):
    for part in (vrr_manifests.software, vrr_manifests.dataset, vrr_manifests.disclosure):
        assert Disclosure.PRIVATE_ONLY not in set(part.DISCLOSURE.values())
    assert vrr_manifests.dataset.DISCLOSURE["snapshot_commitment"] is \
        Disclosure.OPAQUE_ATTESTATION


def test_the_software_manifest_tracks_the_live_registry(vrr_manifests):
    # the digest comes from the registries a replay dispatches through, not
    # from a checked-in file that could have drifted from them
    assert vrr_manifests.software.procedure_registry_digest == \
        R.software_manifest(load_policy_config()).procedure_registry_digest
    assert vrr_manifests.software.package_version


# --------------------------------------------------------------------------- #
# an ArtifactRef says how much of itself may be shown                         #
# --------------------------------------------------------------------------- #

def test_a_private_artifact_is_not_a_public_one(vrr_record):
    stage = vrr_record.trace.stages[0]
    private = [a for a in stage.output_refs if not a.is_public()]
    assert private, "the contingency's privileged probe should be recorded"
    assert all(a.disclosure_class is Disclosure.PRIVATE_ONLY for a in private)
    assert all(a.commitment.startswith("hmac-") for a in private)
    assert all(a.shape is None for a in private), \
        "the shape of a withheld artifact is itself a fact about withheld data"


def test_a_released_artifact_commits_with_a_recomputable_hash(vrr_service, vrr_manifests, vrr_log):
    _, run, record = build_record(vrr_service, vrr_manifests, vrr_log)
    ref = next(a for a in record.trace.stages[0].output_refs
               if a.artifact_id == "adjusted:output")
    assert ref.commitment == commit_public(run.stages[0].output)
    assert ref.commitment.startswith("sha256:")


def test_an_artifact_ref_needs_a_disclosure_class():
    with pytest.raises(ValidationError):
        ArtifactRef(artifact_id="a", role="released_output",
                    commitment="sha256:x", commitment_scheme="sha256")
