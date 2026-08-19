"""Deterministic replay and the certificate it issues (build plan M2).

A record that cannot be re-run is a description of an analysis. What is pinned
here is that this one can be, and — more importantly — that it *stops* being
re-runnable the moment anything it depends on moves.

The build plan lists six things a replay must fail on, and there is a test for
each: the dataset snapshot identity, the QuerySpec/procedure parameters, the
policy digest, the procedure-registry digest, the expected output, and the
replay class. Five of them are caught before a single query runs, by comparing
the record's declared semantics against the semantics the replay is standing in
— because "the numbers came out the same under today's code" is a different
claim from "this record reproduces", and a replay facility that silently
substitutes the first has stopped meaning anything.

The last acceptance criterion is a word: a successful certificate says
`COMPUTATION_REPRODUCED`, never a bare `VERIFIED`. It is pinned literally, and
so is the caveat list the certificate carries with it.
"""

from __future__ import annotations

import pytest

from safetre.config import load_policy_config
from safetre import recorder as R
from safetre.replay import (
    NOT_REPRODUCED, REFUSED, REPRODUCED, SEMANTICS_MISMATCH, ReplayContext,
    certifies, replay,
)
from safetre.research_record import ReplayClass
from studies.nightplay import verify as V
from tests.vrr_harness import (
    CUSTODIAN, KEY, POPULATION, SNAPSHOT, build_record,
)


@pytest.fixture
def context(vrr_study, vrr_service):
    tables, _ = vrr_study
    return ReplayContext(
        tables=tables, policy_config=load_policy_config(),
        service_factory=V.build_service, snapshot_id=SNAPSHOT,
        commitment_key=KEY, population=POPULATION, custodian=CUSTODIAN)


@pytest.fixture
def record(vrr_service, vrr_manifests, vrr_log):
    _, _, rec = build_record(vrr_service, vrr_manifests, vrr_log)
    return rec


# --------------------------------------------------------------------------- #
# the happy path                                                              #
# --------------------------------------------------------------------------- #

def test_a_record_replays_from_the_attested_snapshot(record, context):
    certificate = replay(record, context)
    assert certificate.outcome == REPRODUCED, certificate.detail
    assert certificate.stages and all(s["reproduced"] for s in certificate.stages)
    assert certificate.replay_semantics == record.trace.manifests.replay_semantics()


def test_a_successful_certificate_does_not_say_verified(record, context):
    certificate = replay(record, context)
    assert certificate.outcome == "COMPUTATION_REPRODUCED"
    assert certificate.outcome != "VERIFIED"
    assert certificate.reproduced()


def test_the_certificate_carries_what_it_does_not_verify(record, context):
    certificate = replay(record, context)
    assert len(certificate.not_verified) >= 4
    joined = " ".join(certificate.not_verified).lower()
    for topic in ("population", "scientifically appropriate", "conclusion",
                  "prior human exploration"):
        assert topic in joined


def test_a_certificate_binds_to_the_record_it_verified(record, context):
    certificate = replay(record, context)
    assert certifies(certificate, record)
    edited = record.evidence[0].model_copy(update={"values": {"estimate": 999.0}})
    moved = record.model_copy(update={"evidence": [edited, *record.evidence[1:]]})
    assert not certifies(certificate, moved), \
        "a certificate that survives an edited value is a stale certificate"


def test_replay_is_deterministic(record, context):
    first, second = replay(record, context), replay(record, context)
    assert first.certificate_id == second.certificate_id
    assert first.model_dump() == second.model_dump()


def test_the_certificate_carries_no_wall_clock_time(record, context):
    # the bundle has to be byte-deterministic, and "when" is already in the
    # audit chain, which is the tamper-evident place for it
    fields = set(type(replay(record, context)).model_fields)
    assert not {f for f in fields if "time" in f or "_at" in f or "stamp" in f}


# --------------------------------------------------------------------------- #
# the six failures                                                            #
# --------------------------------------------------------------------------- #

def test_replay_fails_if_the_dataset_snapshot_identity_changes(record, context):
    certificate = replay(record, ReplayContext(**{**vars(context),
                                                 "snapshot_id": "some-other-snapshot"}))
    assert certificate.outcome == SEMANTICS_MISMATCH
    assert "dataset_snapshot_id" in certificate.detail


def test_replay_fails_if_the_snapshot_contents_change(record, context, vrr_study):
    tables, _ = vrr_study
    shrunk = dict(tables)
    first = sorted(shrunk)[0]
    shrunk[first] = shrunk[first].iloc[:-1]
    certificate = replay(record, ReplayContext(**{**vars(context), "tables": shrunk}))
    assert certificate.outcome == SEMANTICS_MISMATCH
    assert "dataset_snapshot_commitment" in certificate.detail


def test_replay_fails_if_the_policy_digest_changes(record, context):
    weaker = load_policy_config()
    object.__setattr__(weaker, "min_cell_size", weaker.min_cell_size + 1)
    certificate = replay(record, ReplayContext(**{**vars(context),
                                                 "policy_config": weaker}))
    assert certificate.outcome == SEMANTICS_MISMATCH
    assert "policy_digest" in certificate.detail


def test_replay_fails_if_the_procedure_registry_digest_changes(record, context):
    forged = record.trace.manifests.software.model_copy(
        update={"procedure_registry_digest": "0" * 64})
    manifests = record.trace.manifests.model_copy(update={"software": forged})
    trace = record.trace.model_copy(update={"manifests": manifests})
    certificate = replay(record.model_copy(update={"trace": trace}), context)
    assert certificate.outcome == SEMANTICS_MISMATCH
    assert "procedure_registry_digest" in certificate.detail


def test_replay_fails_if_the_query_parameters_change(record, context):
    plan = dict(record.trace.committed_plan)
    stages = [dict(s) for s in plan["stages"]]
    stages[0] = dict(stages[0],
                     spec=dict(stages[0]["spec"], terms=["night_use_band"]))
    trace = record.trace.model_copy(update={"committed_plan": dict(plan, stages=stages)})
    certificate = replay(record.model_copy(update={"trace": trace}), context)
    assert certificate.outcome == REFUSED
    assert "does not hash to the plan reference" in certificate.detail


def test_replay_fails_if_the_expected_output_changes(record, context):
    stage = record.trace.stages[0]
    refs = [a.model_copy(update={"commitment": "sha256:" + "0" * 64})
            if a.artifact_id == "adjusted:output" else a for a in stage.output_refs]
    trace = record.trace.model_copy(update={
        "stages": [stage.model_copy(update={"output_refs": refs})]})
    certificate = replay(record.model_copy(update={"trace": trace}), context)
    assert certificate.outcome == NOT_REPRODUCED
    assert any(not s["reproduced"] for s in certificate.stages)


def test_replay_fails_if_a_reported_value_was_edited(record, context):
    # the commitments still agree — they were copied across with the edit — and
    # the evidence identities do not, which is the tamper the commitments alone
    # cannot see
    edited = record.evidence[0].model_copy(
        update={"values": dict(record.evidence[0].values, estimate=99.9)})
    certificate = replay(
        record.model_copy(update={"evidence": [edited, *record.evidence[1:]]}), context)
    assert certificate.outcome == NOT_REPRODUCED
    assert "does not match what the replay released" in certificate.detail


def test_replay_really_recomputes_from_the_context_snapshot(record, context,
                                                            vrr_study):
    """The execution leg, isolated.

    Every other failure test here is caught by the semantics comparison before a
    query runs, which means none of them would notice a `replay` that compared
    the record's recorded commitments against themselves. So: change the
    snapshot AND forge the dataset manifest to match it, so the semantics agree
    and the replay proceeds — then the only thing that can tell the difference
    is actually re-running the analysis over the tables the context holds.
    """
    tables, _ = vrr_study
    shrunk = dict(tables)
    shrunk["person_month"] = shrunk["person_month"].iloc[:-500]

    honest = R.dataset_manifest(shrunk, snapshot_id=SNAPSHOT, population=POPULATION,
                               custodian=CUSTODIAN, key=KEY)
    manifests = record.trace.manifests.model_copy(update={"dataset": honest})
    trace = record.trace.model_copy(update={"manifests": manifests})
    relabelled = record.model_copy(update={"trace": trace})

    certificate = replay(relabelled, ReplayContext(**{**vars(context),
                                                     "tables": shrunk}))
    assert certificate.outcome == NOT_REPRODUCED, certificate.detail
    assert any(not s["reproduced"] for s in certificate.stages), \
        "the replay did not recompute anything from the context's tables"


def test_replay_refuses_a_released_stage_that_is_not_exactly_replayable(record, context):
    stage = record.trace.stages[0].model_copy(
        update={"replay_class": ReplayClass.NOT_REPLAYABLE})
    trace = record.trace.model_copy(update={"stages": [stage]})
    certificate = replay(record.model_copy(update={"trace": trace}), context)
    assert certificate.outcome == REFUSED
    assert "not recorded as exactly replayable" in certificate.detail


def test_replay_refuses_a_record_with_no_committed_plan(record, context):
    trace = record.trace.model_copy(update={"committed_plan": None, "plan_ref": None})
    certificate = replay(record.model_copy(update={"trace": trace}), context)
    assert certificate.outcome == REFUSED
    assert "commits no plan" in certificate.detail


def test_a_refused_replay_runs_no_query(record, context, monkeypatch):
    """No silent replay under newer code — and no *loud* one either: when the
    semantics do not match, nothing is executed at all."""
    def refuse(*a, **kw):
        raise AssertionError("replay executed a query after refusing the semantics")

    monkeypatch.setattr(context, "service_factory", refuse)
    certificate = replay(record, ReplayContext(**{**vars(context),
                                                 "snapshot_id": "elsewhere"}))
    assert certificate.outcome == SEMANTICS_MISMATCH
