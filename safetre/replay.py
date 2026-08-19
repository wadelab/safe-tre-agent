"""Deterministic replay: proving the record is useful rather than decorative (M2).

*A record that nobody can re-run is a description of an analysis. A record a
custodian can re-run, byte for byte, from an attested snapshot under frozen
semantics, is evidence about one. This module is the difference.*

    replay(record, context) -> ReplayCertificate

## No silent replay under newer code

The first thing `replay` does is compare the semantics it is standing in —
package version, procedure-registry digest, catalogue digest, policy digest,
tool-manifest digest, dataset snapshot id and commitment — against the semantics
the record was written under. A mismatch ends the replay *there*, with
`SEMANTICS_MISMATCH` and the differing keys named. It does not fall back to
re-running under whatever is installed: "the numbers came out the same under
today's code" is a different claim from "this record reproduces", and quietly
substituting the first for the second is how a replay facility stops meaning
anything.

## What a successful certificate says

`COMPUTATION_REPRODUCED`, never `VERIFIED`. The build plan asks for the narrow
word and the narrow word is the honest one: re-running a registered procedure
over the same snapshot and getting the same bytes says the record describes a
computation that really happened and really produced those numbers. It says
nothing about whether the cohort was the right cohort, the model the right
model, or the conclusion supported. Those caveats ship inside the certificate
in `not_verified`, because the certificate is the part that gets quoted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from . import disclosure as D
from . import evidence as _evidence
from .config import PolicyConfig
from .plan import Plan, PlanExecutor
from .recorder import build_manifests
from .research_record import (
    Manifests, ReplayCertificate, ReplayClass, ReplayOutcome, ResearchRecord,
    StageRecord, StageType, canonical_json, commit_public, sha256_hex,
)

# Aliases onto the closed vocabulary in `research_record`, kept because they
# read better at the call sites here. The vocabulary is the control; these are
# spellings of it, and there is no way to add a sixth outcome by writing one.
REPRODUCED = ReplayOutcome.COMPUTATION_REPRODUCED
NOT_REPRODUCED = ReplayOutcome.COMPUTATION_NOT_REPRODUCED
SEMANTICS_MISMATCH = ReplayOutcome.SEMANTICS_MISMATCH
REFUSED = ReplayOutcome.REPLAY_REFUSED

# Shipped with every certificate. Machine verification is not scientific
# validity, and a reviewer who reads only this list should still come away
# knowing what they have to trust somebody about.
NOT_VERIFIED = (
    "that the snapshot is the population it claims to be — only the custodian "
    "can attest that",
    "that the cohort, model and covariates were scientifically appropriate",
    "that the released numbers support the manuscript's conclusion",
    "that no prior human exploration informed the plan before this execution",
    "that the disclosure policy in force is strong enough for this data",
)


@dataclass
class ReplayContext:
    """What a custodian brings to a replay: the snapshot, the policy, and the
    service the two build. Nothing here is taken from the record — that is the
    point. The record says what the semantics must be; the context says what
    they are; `replay` compares them and refuses when they differ."""

    tables: dict[str, Any]
    policy_config: PolicyConfig
    service_factory: Callable[[dict[str, Any]], Any]
    snapshot_id: str
    commitment_key: bytes
    population: str = ""
    custodian: str = ""
    software: dict[str, Any] = field(default_factory=dict)

    def manifests(self) -> Manifests:
        return build_manifests(
            self.policy_config, self.tables, snapshot_id=self.snapshot_id,
            population=self.population, custodian=self.custodian,
            key=self.commitment_key, **self.software)


def _semantics_diff(recorded: dict[str, str], observed: dict[str, str]) -> list[str]:
    keys = sorted(set(recorded) | set(observed))
    return [f"{k}: record={recorded.get(k)!r} replay={observed.get(k)!r}"
            for k in keys if recorded.get(k) != observed.get(k)]


def _certificate(record_id: str, record_digest: str, outcome: ReplayOutcome,
                 semantics: dict[str, str], stages: list[dict[str, Any]],
                 detail: str) -> ReplayCertificate:
    body = {"record_id": record_id, "record_digest": record_digest,
            "outcome": outcome.value, "replay_semantics": semantics,
            "stages": stages, "detail": detail,
            "not_verified": list(NOT_VERIFIED)}
    return ReplayCertificate(
        certificate_id="rc-" + sha256_hex(canonical_json(body))[:24], **body)


def _observed_commitments(stage_id: str, result: Any) -> dict[str, str]:
    """The commitments a replayed stage produces, in the recorder's own scheme
    so the two are comparable at all."""
    out: dict[str, str] = {}
    if result is not None and result.output is not None:
        out[f"{stage_id}:output"] = commit_public(result.output)
    for name, rows in sorted((getattr(result, "artifacts", None) or {}).items()):
        out[f"{stage_id}:{name}"] = commit_public(rows)
    return out


def _replayable(stage: StageRecord) -> bool:
    return (stage.replay_class is ReplayClass.TRE_REPLAYABLE_EXACT
            and stage.stage_type is not StageType.PROBE
            and bool(stage.public_artifacts()))


def replay(record: ResearchRecord, context: ReplayContext) -> ReplayCertificate:
    """Re-run this record's committed plan against the context's snapshot and
    say whether it reproduces.

    Replays the PLAN, not the executed specs. That is the stronger claim and
    the only honest one where a locked plan carries a data-sighted contingency:
    replaying the executed spec would take the contingency's decision as given
    and verify a computation downstream of it, whereas replaying the plan makes
    the contingency run again and reach the same decision, or fail.
    """
    trace = record.trace
    recorded = trace.manifests.replay_semantics()
    digest = record.verified_digest()

    observed_semantics = context.manifests().replay_semantics()
    diff = _semantics_diff(recorded, observed_semantics)
    if diff:
        return _certificate(
            record.record_id, digest, SEMANTICS_MISMATCH, recorded, [],
            "replay refused: the record's semantics are not the semantics here "
            "(" + "; ".join(diff) + "). A record replays under the implementation "
            "it was written under, or not at all.")

    if trace.committed_plan is None:
        return _certificate(
            record.record_id, digest, REFUSED, recorded, [],
            "replay refused: this record commits no plan, so there is no "
            "pre-declared program to re-run.")

    plan = Plan(**trace.committed_plan)
    if plan.canonical_hash() != trace.plan_ref:
        return _certificate(
            record.record_id, digest, REFUSED, recorded, [],
            "replay refused: the plan carried by the record does not hash to "
            "the plan reference committed to the audit chain.")

    wanted = [st for st in trace.stages if _replayable(st)]
    unreplayable = sorted(
        st.stage_id for st in trace.stages
        if st.public_artifacts() and st.replay_class is not ReplayClass.TRE_REPLAYABLE_EXACT)
    if unreplayable:
        return _certificate(
            record.record_id, digest, REFUSED, recorded, [],
            "replay refused: stage(s) " + ", ".join(unreplayable) + " released "
            "public artifacts but are not recorded as exactly replayable.")
    if not wanted:
        return _certificate(
            record.record_id, digest, REFUSED, recorded, [],
            "replay refused: this record has no exactly-replayable released "
            "stage to reproduce.")

    service = context.service_factory(context.tables)
    cfg = context.policy_config
    auditor = D.SessionAuditor(threshold=cfg.min_cell_size, budget=cfg.query_budget,
                               selection_budget=cfg.selection_budget_bits)
    run = PlanExecutor(service, auditor=auditor).run(plan)
    by_id = {sr.id: sr for sr in run.stages}

    stages: list[dict[str, Any]] = []
    replayed_evidence: list[Any] = []
    ok = True
    for stage in wanted:
        result = by_id.get(stage.stage_id)
        observed = _observed_commitments(stage.stage_id, result)
        for ref in stage.public_artifacts():
            match = observed.get(ref.artifact_id) == ref.commitment
            ok = ok and match
            stages.append({
                "stage_id": stage.stage_id, "artifact_id": ref.artifact_id,
                "expected": ref.commitment,
                "observed": observed.get(ref.artifact_id, "<absent>"),
                "reproduced": match})
        if result is not None and result.status in ("released", "redacted"):
            replayed_evidence += _evidence.extract(
                stage, output=result.output, artifacts=result.artifacts)

    # The commitments agreeing is the computation reproducing. The evidence
    # identities agreeing is the RECORD reproducing — it is what catches a
    # bundle whose reported numbers were edited after the commitments were
    # taken, which is the tamper the commitments alone cannot see because they
    # were copied across with the edit.
    recorded_ids = sorted(e.identity_digest() for e in record.evidence
                          if e.kind != _evidence.NOT_ANSWERABLE)
    observed_ids = sorted(e.identity_digest() for e in replayed_evidence)
    evidence_ok = recorded_ids == observed_ids
    ok = ok and evidence_ok

    detail = (f"re-ran {len(wanted)} exactly-replayable stage(s) of plan "
              f"{trace.plan_ref} against snapshot {context.snapshot_id} under "
              f"the recorded semantics; "
              + ("every released artifact and every evidence identity matched."
                 if ok else
                 "at least one released artifact or evidence identity differed"
                 + ("" if evidence_ok else "; the reported evidence does not "
                    "match what the replay released") + "."))
    return _certificate(record.record_id, digest,
                        REPRODUCED if ok else NOT_REPRODUCED,
                        recorded, stages, detail)


def certifies(certificate: ReplayCertificate, record: ResearchRecord) -> bool:
    """Whether this certificate is about THIS record, as it now stands.

    A certificate that verified an earlier version of a record is not evidence
    about the current one, and a bundle carrying one is the stale-certificate
    attack. Checked by digest rather than by record id, because the id is
    exactly the part an attacker would keep.
    """
    return (certificate.record_id == record.record_id
            and certificate.record_digest == record.verified_digest())


__all__ = ["NOT_REPRODUCED", "NOT_VERIFIED", "REFUSED", "REPRODUCED",
           "SEMANTICS_MISMATCH", "ReplayContext", "ReplayOutcome", "certifies",
           "replay"]
