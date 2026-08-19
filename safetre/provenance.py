"""Compiling public provenance out of a private trace (build plan M4).

*The record itself is a disclosure surface. This is the layer that decides what
a reviewer outside the TRE is told about HOW a number was produced, and it is
the layer with the most inviting mistakes in it, because every one of them looks
like transparency.*

## The property

Two executions that released the same approved evidence must produce
byte-identical public provenance, however differently they got there. Different
suppressed cell counts, a rejected candidate model, a private branch taken the
other way, a retry, a sparse category excluded by a contingency, a private
diagnostic — none of it may move a byte. That is a release-equality test for the
provenance layer, and it is the reason this module selects nodes by *public
evidence* rather than by walking the trace's stage list:

    a node exists because a released number needs explaining,
    never because a stage ran.

Walk the stage list instead and the shape of the public graph starts answering
questions about the cohort: how many stages the gateway denied, whether a
contingency fired, how many retries a fit needed. The single canonical refusal
in `service.py` exists to refuse exactly those questions one layer down, and it
would be undone here by a provenance node that said `status: denied`.

## Fail closed

`compile_public_provenance` never introspects a field it has not been told
about. Every record type classifies its own fields at class-creation time
(`research_record._VrrModel`), so an unclassified field cannot exist; what this
module adds is the second half — a node is assembled from an explicit list of
public keys, so a field added to `StageRecord` in future appears in the public
provenance only when somebody puts it there on purpose.
"""

from __future__ import annotations

from typing import Any

from .research_record import (
    AnalysisClassification, Disclosure, EvidenceItem, PrivateExecutionTrace,
    PublicProvenance, RecordError, StageRecord, StageType,
)

# The stage fields that may appear in a public provenance node. An allowlist,
# not a denylist: the failure mode this guards against is a new private field
# being added to StageRecord and inheriting publication by default.
_PUBLIC_NODE_KEYS = ("stage_id", "stage_type", "procedure", "public_parameters",
                     "input_refs", "replay_class", "classification")


def _node(stage: StageRecord) -> dict[str, Any]:
    node: dict[str, Any] = {}
    for key in _PUBLIC_NODE_KEYS:
        if stage.DISCLOSURE[key] is Disclosure.PRIVATE_ONLY:
            raise RecordError(
                f"{key!r} is PRIVATE_ONLY and cannot be a public provenance key")
        value = getattr(stage, key)
        node[key] = value.value if hasattr(value, "value") else value
    node["artifacts"] = [a.public_fields() for a in stage.public_artifacts()]
    return node


def analysis_classification(trace: PrivateExecutionTrace,
                            evidence_stages: set[str]) -> AnalysisClassification:
    """The record's headline classification: the weakest of the stages that
    carry public evidence.

    Weakest, not strongest, and not "the plan's". A record whose headline
    number is pre-committed and whose second number is post-hoc is not a
    pre-committed record; per-stage labels stay on the nodes for a reviewer who
    wants the detail.
    """
    labels = {st.classification for st in trace.stages
              if st.stage_id in evidence_stages}
    if not labels or AnalysisClassification.EXPLORATORY_POSTHOC in labels:
        return AnalysisClassification.EXPLORATORY_POSTHOC
    return AnalysisClassification.TRE_PRECOMMITTED


def compile_public_provenance(trace: PrivateExecutionTrace,
                              evidence: list[EvidenceItem]) -> PublicProvenance:
    """The public half of a record, derived from the private trace and the
    evidence that was actually approved for release.

    `evidence` is the selector. Nothing else in the trace decides which nodes
    exist, so perturbing the private trace without changing the approved
    evidence cannot change the output — which is the milestone-4 property,
    stated as the shape of the function rather than as a rule someone has to
    remember to obey.
    """
    cited = [e for e in evidence if e.kind != "NotAnswerable"]
    evidence_stages = {e.source_stage for e in cited}

    nodes: list[dict[str, Any]] = []
    for stage in trace.stages:
        if stage.stage_id not in evidence_stages:
            continue
        if stage.stage_type is StageType.PROBE:
            raise RecordError(
                f"stage {stage.stage_id!r} is a privileged probe and cannot "
                "carry public evidence")
        if not stage.released():
            raise RecordError(
                f"stage {stage.stage_id!r} carries public evidence but released "
                "nothing")
        nodes.append(_node(stage))

    # Dependencies that point at stages with no public node would publish the
    # existence of a stage the reviewer is not shown — and the reason a stage
    # has no node is that the gateway withheld it. Prune rather than raise: a
    # guarded stage whose predecessor was denied is an ordinary, legal run.
    published = {n["stage_id"] for n in nodes}
    for node in nodes:
        node["input_refs"] = [d for d in node["input_refs"] if d in published]

    classification = analysis_classification(trace, evidence_stages)
    return PublicProvenance(
        record_id=trace.record_id,
        question=trace.question,
        plan_ref=trace.plan_ref,
        committed_plan=trace.committed_plan,
        classification=classification,
        replay_semantics=trace.manifests.replay_semantics(),
        nodes=sorted(nodes, key=lambda n: n["stage_id"]),
        evidence_ids=sorted(e.evidence_id for e in cited),
        release_domain=trace.release_domain,
        policy_version=trace.manifests.disclosure.policy_digest,
    )


def audit_public_leakage(provenance: PublicProvenance,
                         trace: PrivateExecutionTrace) -> list[str]:
    """Every private string of this trace that appears in the public bytes.

    A belt-and-braces check for the values a structural argument cannot cover:
    an excluded sparse level is a category NAME, and a name that reached the
    public provenance through a parameter, a key or a message would be a
    disclosure however correctly the node list was assembled. Returns findings
    rather than raising, so a caller can decide whether it is looking at a
    defect or at a level the committed plan already names in public.
    """
    blob = provenance.canonical()
    found = []
    for stage in trace.stages:
        for level in stage.excluded_levels:
            if level and level in blob:
                found.append(f"stage {stage.stage_id}: excluded level {level!r} "
                             "appears in the public provenance")
        if stage.message and stage.message in blob:
            found.append(f"stage {stage.stage_id}: private message text appears "
                         "in the public provenance")
        for finding in stage.findings:
            detail = str(finding.get("detail", ""))
            if detail and detail in blob:
                found.append(f"stage {stage.stage_id}: finding detail appears in "
                             "the public provenance")
    return found


__all__ = ["analysis_classification", "audit_public_leakage",
           "compile_public_provenance"]
