"""Turning a plan run into a research record (build plan M1, M5, M6).

*No new execution path. The gateway, the session auditor and the audit chain do
exactly what they did before; this module reads what they produced and writes it
down in the vocabulary of `safetre.research_record`.*

The build plan's instrumentation principle is to record at existing stable seams
rather than scatter logging calls, and there are two seams here that already
carry everything a record needs:

- `PlanExecutor.run` returns a `PlanRun` whose `StageResult`s hold the executed
  spec, the gateway's verdict, the released rows and the released frame's
  digest (the R20 stage commitment);
- `AuditLog` holds the same events in chain order, which is the only place the
  pre-specification property can be decided from.

So the recorder takes those two and correlates them. Nothing in `plan.py`,
`service.py` or `disclosure.py` changed to make this work, which is the point:
if building the record had required touching the release path, the record would
be evidence about a path that only exists when someone is recording.

## Where the classification comes from

`TRE_PRECOMMITTED` is derived, never asserted. A stage earns it only if the row
committing its governing plan sits EARLIER IN THE CHAIN than the row the stage
itself wrote. Committing a plan after running it therefore produces
`EXPLORATORY_POSTHOC` — the plan-laundering attack test — and so does running
with no commitment at all.

Note what this does not prove, because the label is quoted in isolation and D9's
critical review is explicit about it: event order inside one TRE execution says
the recorded execution did not choose its plan after seeing its own protected
intermediates. It says nothing about what the researcher had seen before the
session opened.

## The chain has to be authentic before its order means anything

`TRE_PRECOMMITTED` is a claim about the ORDER of audit rows, so it is only as
good as the chain's tamper-evidence — and tamper-evidence that nobody consults
is decoration. `AuditLog.since` says so in as many words: any caller that
rebuilds a control from those rows owes the same gate `SessionStore.rehydrate`
pays (hardening #59).

Measured, on the first version of this module, which took a list of rows and
trusted it: run the laundering flow so the chain reads stage-rows-then-plan-row
(correctly `EXPLORATORY_POSTHOC`), then reorder the rows in the database so the
plan row comes first. The label became `TRE_PRECOMMITTED` while `verify()`
returned False to nobody.

So this module takes the LOG, not a list of rows, and verifies it. It cannot be
handed rows whose provenance it has not checked, because there is no parameter
for them. An unverified chain does not refuse to build a record — the evidence
lineage and the replay stand on their own and are worth having — it refuses to
issue the ONE claim that rests on chain order: every stage comes out
`EXPLORATORY_POSTHOC`, and the trace records that the chain did not verify so
the bundle says so out loud rather than quietly reading as exploratory work.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import dataset as _dataset
from . import manifest as _manifest
from .config import PolicyConfig
from .procedures import model_registry, registry_skeleton
from .research_record import (
    AnalysisClassification, ArtifactRef, ArtifactRole, DatasetManifest, Disclosure,
    DisclosureManifest, Manifests, PrivateExecutionTrace, ReplayClass,
    SoftwareManifest, StageRecord, StageStatus, StageType,
    canonical_json, commit_private, commit_public, digest_of,
)

SCHEMA_VERSION = 1

# What the disclosure manifest names as being in force. Read from the shipped
# controls rather than invented here; a reviewer who wants the definitions has
# the tool manifest and the specification, and this list exists so they know
# which document to go and read.
CONTROLS = (
    "small_cell_suppression", "dominance", "correlation_influence",
    "count_rounding", "query_budget", "differencing_lineage",
    "second_moment_dominance", "selection_budget",
)


# --------------------------------------------------------------------------- #
# manifests                                                                   #
# --------------------------------------------------------------------------- #

def software_manifest(policy: PolicyConfig, *, repository_commit: str | None = None,
                      lockfile_digest: str | None = None,
                      formal_artifact_digest: str | None = None) -> SoftwareManifest:
    """The implementation semantics, digested from the live registries.

    The three digests that matter for replay are taken from the objects a
    replay actually dispatches through — the procedure registry, the catalogue
    and the resolved policy — rather than from a checked-in file that could
    have drifted from them. `registry_skeleton()` is already the repository's
    answer to "what is the finite request space right now" and is pytest-pinned
    against the formal model, so reusing it means a replay's identity check and
    the formal correspondence chain cannot disagree about what the code is.
    """
    from . import __version__

    skeleton = registry_skeleton()
    return SoftwareManifest(
        package_version=__version__,
        repository_commit=repository_commit,
        lockfile_digest=lockfile_digest,
        procedure_registry_digest=digest_of(
            {"aggregate": skeleton["aggregate"], "model": skeleton["model"],
             "tools": sorted(model_registry())}),
        catalogue_digest=digest_of(skeleton["catalogue"]),
        policy_digest=hashlib.sha256(policy.digest().encode("utf-8")).hexdigest(),
        tool_manifest_digest=_manifest.manifest_sha256(policy),
        external_checker=policy.checker_cmd or "none",
        formal_artifact_digest=formal_artifact_digest,
    )


def dataset_manifest(tables: dict[str, Any], *, snapshot_id: str, population: str,
                     custodian: str, key: bytes,
                     logical_name: str | None = None) -> DatasetManifest:
    """Identify the snapshot without disclosing it.

    The commitment is keyed. A synthetic study is generated from a seed, so an
    unkeyed digest of its tables would let anyone with the generator confirm a
    guess at the parameters that made them — and on a real snapshot the same
    argument is worse, not better. What goes into the commitment is the shape
    and column names of every table plus a digest of the row bytes, so it binds
    the data without the manifest having to hold any.
    """
    defn = _dataset.active()
    shape = {
        name: {"rows": int(len(df)), "columns": [str(c) for c in df.columns],
               "content": hashlib.sha256(
                   df.to_csv(index=False, lineterminator="\n").encode("utf-8")).hexdigest()}
        for name, df in sorted(tables.items())
    }
    return DatasetManifest(
        logical_name=logical_name or defn.name,
        snapshot_id=snapshot_id,
        schema_version=str(SCHEMA_VERSION),
        population=population,
        custodian=custodian,
        views=sorted(defn.datasets),
        snapshot_commitment=commit_private(shape, key),
    )


def disclosure_manifest(policy: PolicyConfig) -> DisclosureManifest:
    return DisclosureManifest(
        policy_digest=hashlib.sha256(policy.digest().encode("utf-8")).hexdigest(),
        min_cell_size=policy.min_cell_size,
        counts_rounded_to_nearest=policy.round_base,
        vetter=policy.vetter,
        public_manifest_sha256=_manifest.manifest_sha256(policy),
        controls=list(CONTROLS),
    )


def build_manifests(policy: PolicyConfig, tables: dict[str, Any], *, snapshot_id: str,
                    population: str, custodian: str, key: bytes, **software) -> Manifests:
    return Manifests(
        software=software_manifest(policy, **software),
        dataset=dataset_manifest(tables, snapshot_id=snapshot_id, population=population,
                                 custodian=custodian, key=key),
        disclosure=disclosure_manifest(policy),
    )


# --------------------------------------------------------------------------- #
# correlating a plan run with the chain                                       #
# --------------------------------------------------------------------------- #

def _commit_position(rows: list[dict], plan_hash: str | None) -> int | None:
    """Where the plan's commitment sits in the chain, or None if it never did."""
    if plan_hash is None:
        return None
    for i, row in enumerate(rows):
        if row.get("status") == "plan" and (row.get("spec") or {}).get("plan_hash") == plan_hash:
            return i
    return None


def _stage_rows(rows: list[dict], stages: list[tuple[str, str]]) -> list[int | None]:
    """The chain position each stage wrote to, matched forward in order.

    `stages` is (sub_question, status) per stage, and BOTH have to match. The
    sub-question alone is not enough, because a request is untrusted content
    (`AuditLog.append`): an analyst can submit an ordinary query whose text is
    a plan stage's sub-question verbatim, and a decoy row sitting between the
    commitment and the real stage would then be the row this record cites.
    Requiring the outcome to agree too means a decoy has to reproduce the
    gateway's verdict as well as the text, and a mismatch resolves to None —
    unwitnessed, and therefore not pre-committed.

    Forward-with-a-cursor rather than by content: two stages of one plan may
    carry the same sub-question and the same outcome, and the executor runs
    stages in order, so position disambiguates where equality cannot. A stage
    that wrote nothing — a guard skipped it — gets None, and no audit reference.
    """
    out: list[int | None] = []
    cursor = 0
    for question, status in stages:
        found = None
        for i in range(cursor, len(rows)):
            if rows[i].get("status") == "plan":
                continue
            if rows[i].get("request") == question and rows[i].get("status") == status:
                found = i
                cursor = i + 1
                break
        out.append(found)
    return out


def _stage_type(spec: dict[str, Any]) -> StageType:
    return StageType.MODEL if spec.get("tool") else StageType.AGGREGATE


def _procedure(spec: dict[str, Any]) -> str:
    if spec.get("tool"):
        return str(spec["tool"])
    measure = spec.get("measure") or {}
    return str(measure.get("fn") or "count")


# Spec keys that are REQUEST-decided and therefore publishable. A key not on
# this list does not reach the public parameters, whatever it is: the executed
# spec can carry filters a contingency derived from the data, and the way to be
# sure those never surface is to name what may, not what may not.
_PUBLIC_SPEC_KEYS = ("dataset", "tool", "measure", "group_by", "terms", "family",
                     "response", "x", "y", "time", "window")


def _public_parameters(spec: dict[str, Any]) -> dict[str, Any]:
    out = {k: spec[k] for k in _PUBLIC_SPEC_KEYS if k in spec and spec[k] not in (None, [])}
    # The committed plan's own filters are request-decided and already inside
    # the published plan, so they are public — but only the committed ones, and
    # the caller passes the COMMITTED spec here, never the executed one.
    if spec.get("filters"):
        out["filters"] = spec["filters"]
    return out


def _artifacts(stage_id: str, sr: Any, key: bytes) -> list[ArtifactRef]:
    """Commitments to what the stage produced.

    Released tables get a public SHA-256 over their canonical rows: the rows are
    in the bundle, so the commitment is one a reviewer can recompute, and making
    it keyed would only mean nobody could check it. A stage that released
    nothing gets no artifact reference at all rather than an opaque one —
    a commitment whose very presence says "something was computed and withheld"
    is a fact about the cohort, and the public layer would then have to strip
    what this layer should not have created.
    """
    refs: list[ArtifactRef] = []
    if sr.output is not None:
        refs.append(ArtifactRef(
            artifact_id=f"{stage_id}:output", role=ArtifactRole.RELEASED_OUTPUT,
            disclosure_class=Disclosure.PUBLIC,
            commitment=commit_public(sr.output), commitment_scheme="sha256",
            shape=[len(sr.output), len(sr.output[0]) if sr.output else 0]))
    for name, rows in sorted((sr.artifacts or {}).items()):
        refs.append(ArtifactRef(
            artifact_id=f"{stage_id}:{name}", role=ArtifactRole.RELEASED_ARTIFACT,
            disclosure_class=Disclosure.PUBLIC,
            commitment=commit_public(rows), commitment_scheme="sha256",
            shape=[len(rows), len(rows[0]) if rows else 0]))
    if sr.excluded:
        # The privileged sparseness probe DID read protected rows, and a record
        # that omitted it would understate what the execution saw. It is bound,
        # keyed, and never surfaced: the level names it found are the levels the
        # gateway suppresses.
        refs.append(ArtifactRef(
            artifact_id=f"{stage_id}:probe", role=ArtifactRole.PRIVATE_PROBE,
            disclosure_class=Disclosure.PRIVATE_ONLY,
            commitment=commit_private({"excluded": sorted(sr.excluded)}, key),
            commitment_scheme="hmac-sha256/vrr-v1", shape=None))
    return refs


def trace_from_plan_run(run: Any, plan: Any, *, record_id: str, manifests: Manifests,
                        audit_log: Any, key: bytes, user: str = "",
                        release_domain: str = "unspecified") -> PrivateExecutionTrace:
    """One `PlanRun` plus the chain it wrote, as a private execution trace.

    Takes the audit LOG rather than a list of rows, and verifies it: whether a
    stage was pre-committed is a statement about chain order, and chain order
    means nothing until the chain is known to be authentic (see the module
    docstring for the measured attack). There is deliberately no parameter for
    pre-read rows and no flag to assert the chain is fine.

    Nothing here is told whether the plan was committed. It is read off the
    chain, so a caller cannot assert it — which is the whole property.
    """
    if not audit_log.verify():
        return _unwitnessed_trace(run, plan, record_id=record_id, manifests=manifests,
                                  key=key, user=user, release_domain=release_domain)

    audit_rows = audit_log.rows_since(0)
    plan_hash = plan.canonical_hash()
    commit_at = _commit_position(audit_rows, plan_hash)
    positions = _stage_rows(audit_rows,
                            [(s.sub_question, r.status)
                             for s, r in zip(plan.stages, run.stages, strict=True)])
    by_id = {s.id: s for s in plan.stages}

    stages: list[StageRecord] = []
    previous: str | None = None
    for sr, at in zip(run.stages, positions, strict=True):
        declared = by_id[sr.id]
        row = audit_rows[at] if at is not None else None
        # Fail closed on a stage the chain never witnessed. `at is None` means
        # no audit row carries this stage's sub-question, which happens two
        # ways: a guard skipped it, or it ran somewhere the chain could not see
        # — and the second is the laundering shape, an analysis executed as
        # ordinary session queries and fitted with a plan afterwards. The chain
        # cannot tell those apart, so neither may this: a stage the audit
        # history does not witness is not a stage the audit history can vouch
        # for, and it carries no evidence anyway.
        precommitted = commit_at is not None and at is not None and at > commit_at
        status = StageStatus(sr.status)
        stages.append(StageRecord(
            stage_id=sr.id,
            stage_type=_stage_type(declared.spec),
            procedure=_procedure(declared.spec),
            public_parameters=_public_parameters(declared.spec),
            input_refs=[previous] if (previous and declared.guard is not None) else [],
            output_refs=_artifacts(sr.id, sr, key),
            replay_class=(ReplayClass.TRE_REPLAYABLE_EXACT if status in
                          (StageStatus.RELEASED, StageStatus.REDACTED)
                          else ReplayClass.NOT_REPLAYABLE),
            classification=(AnalysisClassification.TRE_PRECOMMITTED if precommitted
                            else AnalysisClassification.EXPLORATORY_POSTHOC),
            audit_ref=(row or {}).get("mac", ""),
            status=status,
            executed_parameters=dict(sr.spec or {}),
            findings=list(sr.findings or []),
            message=sr.message or "",
            selection_bits=int(sr.selection_bits or 0),
            excluded_levels=[str(x) for x in (sr.excluded or [])],
            private_detail={"released_frame_sha256": sr.output_sha256},
        ))
        previous = sr.id

    trace = PrivateExecutionTrace(
        record_id=record_id,
        question=run.question,
        plan_ref=plan_hash if commit_at is not None else None,
        committed_plan=plan.model_dump() if commit_at is not None else None,
        manifests=manifests,
        stages=stages,
        evidence_refs=[],
        audit_head=audit_log.head(),
        user=user,
        release_domain=release_domain,
        audit_chain_verified=True,
    )
    trace.validate_lineage()
    return trace


def _unwitnessed_trace(run: Any, plan: Any, *, record_id: str, manifests: Manifests,
                       key: bytes, user: str, release_domain: str
                       ) -> PrivateExecutionTrace:
    """The record a chain that does not verify can still support.

    Everything that does not rest on chain order survives: the stages, their
    public parameters, the commitments to what was released, the evidence
    lineage and the replay all stand on the artifacts themselves. What does not
    survive is the pre-specification claim and the audit references — a row
    whose authenticity is unknown is not a citation — so the plan reference goes
    too, since a `plan_ref` a reviewer would read as "committed in advance" is
    the claim being withdrawn.
    """
    by_id = {s.id: s for s in plan.stages}
    stages = [
        StageRecord(
            stage_id=sr.id,
            stage_type=_stage_type(by_id[sr.id].spec),
            procedure=_procedure(by_id[sr.id].spec),
            public_parameters=_public_parameters(by_id[sr.id].spec),
            input_refs=[],
            output_refs=_artifacts(sr.id, sr, key),
            replay_class=(ReplayClass.TRE_REPLAYABLE_EXACT
                          if sr.status in ("released", "redacted")
                          else ReplayClass.NOT_REPLAYABLE),
            classification=AnalysisClassification.EXPLORATORY_POSTHOC,
            audit_ref="",
            status=StageStatus(sr.status),
            executed_parameters=dict(sr.spec or {}),
            findings=list(sr.findings or []),
            message=sr.message or "",
            selection_bits=int(sr.selection_bits or 0),
            excluded_levels=[str(x) for x in (sr.excluded or [])],
            private_detail={"released_frame_sha256": sr.output_sha256},
        )
        for sr in run.stages
    ]
    trace = PrivateExecutionTrace(
        record_id=record_id, question=run.question, plan_ref=None,
        committed_plan=None, manifests=manifests, stages=stages, evidence_refs=[],
        audit_head="", user=user, release_domain=release_domain,
        audit_chain_verified=False)
    trace.validate_lineage()
    return trace


def record_id_for(question: str, plan_hash: str, manifests: Manifests) -> str:
    """A record's identity: its question, its plan and the semantics it ran
    under. Deterministic, so re-running the same analysis over the same
    snapshot with the same code produces the same record id — and changing any
    of the three produces a different one rather than silently overwriting."""
    return "vrr-" + hashlib.sha256(canonical_json({
        "question": question, "plan_hash": plan_hash,
        "semantics": manifests.replay_semantics(),
    }).encode("utf-8")).hexdigest()[:24]


__all__ = ["CONTROLS", "SCHEMA_VERSION", "build_manifests", "dataset_manifest",
           "disclosure_manifest", "record_id_for", "software_manifest",
           "trace_from_plan_run"]
