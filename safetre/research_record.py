"""Verifiable Research Records — the frozen object model (D9; build plan M0/M1/M6).

*A published result should be a record a reviewer can inspect without seeing the
protected data and without trusting the AI's narrative. This module is the
vocabulary that record is written in; the behaviour lives beside it —
`safetre.evidence` extracts claims, `safetre.provenance` compiles the public
half, `safetre.replay` re-runs the computation, `safetre.attestation` signs the
export and `safetre.vrr_bundle` writes it out.*

The build plan's milestone 0 asks for the smallest object model, agreed before
any code, with five names in it:

    ResearchRecord            the whole publishable object
    PrivateExecutionTrace     what happened inside the TRE
    PublicProvenance          what a reviewer is allowed to see of that
    EvidenceItem              one released number with lineage
    ReplayCertificate         the verdict of re-running the computation

All five are declared HERE rather than in the module that manipulates each,
because the milestone-0 acceptance tests are properties of the *vocabulary* —
every object carries a one-sentence authority boundary, every field carries a
disclosure class, no object holds model reasoning, and `PublicProvenance` cannot
name a private raw value. A property of the vocabulary is checkable only where
the vocabulary is whole, and splitting the five across four modules would also
have made `ResearchRecord` import its own parts in a cycle.

## The two boundaries this module enforces

**Disclosure.** Every field of every record type is classified `PUBLIC`,
`OPAQUE_ATTESTATION` or `PRIVATE_ONLY`, and the classification is checked when
the class is *created*, not when it is serialized: `_VrrModel.__pydantic_init_subclass__`
raises if a field is missing from `DISCLOSURE`, so a new field cannot reach a
record without someone deciding what it is. That is the fail-closed rule the
build plan asks for, moved as early as it will go.

**Commitment.** A raw content hash is a commitment only when the committed
bytes are high-entropy. A hash of a suppressed cell count, a Boolean branch or a
category name is a *lookup table*, not a hiding commitment, and publishing one
while calling the value hidden is the failure mode D9 names explicitly. So the
two cases have two schemes and the type says which:

- artifacts that were RELEASED through the gateway are already public, so their
  commitment is a plain SHA-256 a reviewer can recompute from the values in the
  bundle (`commit_public`);
- everything else gets a keyed HMAC under a key that never leaves the safepod
  (`commit_private`), and surfaces as `OPAQUE_ATTESTATION` — an internal binding
  tool, never advertised as publicly verifiable.

Asymmetric, publicly verifiable attestation of the *bundle* is a separate
concern and a separate key; see `safetre.attestation`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict


class RecordError(RuntimeError):
    """A record that does not hold together: an unclassified field, a dangling
    dependency, an evidence item citing a stage that released nothing."""


# --------------------------------------------------------------------------- #
# canonical form                                                              #
# --------------------------------------------------------------------------- #

def canonical_json(obj: Any) -> str:
    """The one serialization every digest, commitment and signature is taken
    over: sorted keys, no insignificant whitespace, ASCII-escaped.

    `ensure_ascii=True` on purpose. The bundle is signed as bytes and verified
    on machines whose default encoding is not ours; a canonical form that is
    pure ASCII cannot be re-encoded into a different byte string by a reader
    that means no harm.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def sha256_hex(text: str | bytes) -> str:
    raw = text.encode("utf-8") if isinstance(text, str) else text
    return hashlib.sha256(raw).hexdigest()


def digest_of(obj: Any) -> str:
    """SHA-256 of the canonical rendering of `obj`."""
    return sha256_hex(canonical_json(obj))


# --------------------------------------------------------------------------- #
# commitments                                                                 #
# --------------------------------------------------------------------------- #

PUBLIC_SCHEME = "sha256"
PRIVATE_SCHEME = "hmac-sha256/vrr-v1"


def commit_public(artifact: Any) -> str:
    """A commitment to something the gateway already RELEASED.

    Its preimage is in the bundle, so a plain hash is a real commitment here and
    a reviewer can recompute it. Using a keyed MAC instead would be worse, not
    safer: it would make a public value unverifiable for no gain.
    """
    return f"{PUBLIC_SCHEME}:{digest_of(artifact)}"


def commit_private(artifact: Any, key: bytes) -> str:
    """A commitment to something that stayed inside.

    Keyed, because the private artifacts a record needs to bind are exactly the
    low-entropy ones — a suppressed count, a branch outcome, a category name —
    and an unkeyed hash of any of those is brute-forceable in microseconds. The
    key is an internal binding secret: public code never receives it, and the
    resulting commitment is an `OPAQUE_ATTESTATION`, which is a promise that the
    custodian can later prove a binding, NOT a claim the reviewer can check.
    """
    if not key:
        raise RecordError("commit_private needs a key; an unkeyed commitment "
                          "over a private value is a lookup table, not a hiding "
                          "commitment")
    mac = hmac.new(key, canonical_json(artifact).encode("utf-8"), hashlib.sha256)
    return f"{PRIVATE_SCHEME}:{mac.hexdigest()}"


def internal_commitment_key() -> bytes:
    """The internal binding key, from `SAFETRE_VRR_COMMIT_KEY`.

    Deliberately a *different* key from the audit chain's HMAC key and from the
    bundle signing key. Reusing the audit key would make every party who can
    verify the chain able to test guesses at private values; reusing the signing
    key would put a public-verification secret on the data host.
    """
    raw = os.environ.get("SAFETRE_VRR_COMMIT_KEY", "")
    if not raw:
        raise RecordError(
            "SAFETRE_VRR_COMMIT_KEY is unset. A verifiable research record "
            "binds private artifacts with a keyed commitment; there is no "
            "safe default, because the fallback would be an unkeyed hash of "
            "low-entropy values (D9).")
    return raw.encode("utf-8")


# --------------------------------------------------------------------------- #
# vocabulary                                                                  #
# --------------------------------------------------------------------------- #

class Disclosure(str, Enum):
    """What may be said about a field outside the safepod."""

    PUBLIC = "PUBLIC"
    """Reproduced verbatim in the public provenance and the reviewer bundle."""

    OPAQUE_ATTESTATION = "OPAQUE_ATTESTATION"
    """A keyed commitment: it appears, its preimage does not, and it is not a
    publicly verifiable proof of anything — only the custodian can open it."""

    PRIVATE_ONLY = "PRIVATE_ONLY"
    """Never crosses the boundary in any form, not even as a hash."""


class ReplayClass(str, Enum):
    """How, and by whom, a stage can be re-run."""

    TRE_REPLAYABLE_EXACT = "TRE_REPLAYABLE_EXACT"
    """Deterministic given the snapshot, the spec and the frozen semantics; a
    custodian re-running it must get the identical released bytes."""

    EXTERNAL_REPLAYABLE = "EXTERNAL_REPLAYABLE"
    """Recomputable from released artifacts alone — a fit refitted from a
    released design-cell table — so a reviewer needs no data access."""

    NOT_REPLAYABLE = "NOT_REPLAYABLE"
    """Recorded, not reproducible. v0 releases nothing in this class; the name
    exists so a future stochastic or externally-timed stage cannot be silently
    filed under one of the other two."""


class AnalysisClassification(str, Enum):
    """Where a stage sits on the pre-specification axis.

    Only two members, and the missing ones are the point. The critical review's
    correction was that `plan_commit < first_private_observation` proves
    something narrower than scientific pre-registration, so the label says where
    it was proved: *inside this TRE execution*. `PUBLIC_ADAPTIVE`,
    `PRIVATE_ADAPTIVE_ACCOUNTED` and `EXTERNAL_PREREGISTRATION_ATTESTED` are
    named in D9 and the critical review and are deliberately absent here — each
    needs machinery that does not exist yet (an information-flow account of what
    the adaptation saw; an external timestamping authority), and a label the
    system cannot derive is a label a researcher would end up asserting.
    """

    TRE_PRECOMMITTED = "TRE_PRECOMMITTED"
    """The governing plan commitment entered the audit chain before this stage
    observed any protected result. Evidence about machine-speed forking paths
    during the recorded execution — NOT evidence that no prior human
    exploration occurred."""

    EXPLORATORY_POSTHOC = "EXPLORATORY_POSTHOC"
    """Everything else. The honest default, and what a laundered plan gets."""


class StageType(str, Enum):
    AGGREGATE = "aggregate"
    MODEL = "model"
    PROBE = "probe"
    """A privileged internal query whose result is never released — the sparse
    -level probe behind a locked plan's contingency. Recorded because it read
    protected data; never public, because what it read is what the gateway
    withheld."""


class StageStatus(str, Enum):
    RELEASED = "released"
    REDACTED = "redacted"
    DENIED = "denied"
    REVIEW = "review"
    SKIPPED = "skipped"


# --------------------------------------------------------------------------- #
# the base type: classification is a construction-time obligation             #
# --------------------------------------------------------------------------- #

# Field names that would mean the record had started carrying the model's
# reasoning. D9 is explicit that a trace is actions and artifacts: a chain of
# thought is unverifiable, unbounded and — since it is produced by a component
# that has seen protected values — a disclosure channel in its own right.
_REASONING_WORDS = ("chain_of_thought", "cot", "reasoning", "rationale",
                    "thought", "thoughts", "deliberation", "scratchpad",
                    "completion", "prompt", "system_prompt", "narrative",
                    "explanation", "justification")


class _VrrModel(BaseModel):
    """Base for every record type: forbids unknown fields, and refuses to exist
    at all unless every field it declares has been given a disclosure class and
    the class carries a one-sentence authority boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    AUTHORITY: ClassVar[str] = ""
    DISCLOSURE: ClassVar[dict[str, Disclosure]] = {}

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        if not cls.AUTHORITY.strip():
            raise RecordError(f"{cls.__name__} declares no authority boundary")
        if cls.AUTHORITY.strip().count(".") != 1 or not cls.AUTHORITY.strip().endswith("."):
            raise RecordError(
                f"{cls.__name__}'s authority boundary must be ONE sentence: "
                "a boundary that needs a paragraph has not been decided.")
        declared = set(cls.model_fields)
        classified = set(cls.DISCLOSURE)
        missing = sorted(declared - classified)
        if missing:
            raise RecordError(
                f"{cls.__name__} has unclassified field(s) {missing}: every "
                "field of a record type must be PUBLIC, OPAQUE_ATTESTATION or "
                "PRIVATE_ONLY before it can be stored (fail closed).")
        extra = sorted(classified - declared)
        if extra:
            raise RecordError(
                f"{cls.__name__} classifies field(s) {extra} it does not have; "
                "a stale classification silently stops covering anything.")
        for name in sorted(declared):
            low = name.lower()
            if any(w == low or low.endswith("_" + w) for w in _REASONING_WORDS):
                raise RecordError(
                    f"{cls.__name__}.{name} looks like model reasoning. A trace "
                    "records actions and artifacts, never chain-of-thought (D9).")

    def public_fields(self) -> dict[str, Any]:
        """This object reduced to what may cross the boundary.

        `OPAQUE_ATTESTATION` fields survive (they are already commitments);
        `PRIVATE_ONLY` fields are dropped whole. Nested records reduce
        themselves, so a private field cannot ride out inside a public one.
        """
        out: dict[str, Any] = {}
        for name in type(self).model_fields:
            cls = self.DISCLOSURE[name]
            if cls is Disclosure.PRIVATE_ONLY:
                continue
            out[name] = _reduce_public(getattr(self, name))
        return out

    def canonical(self) -> str:
        return canonical_json(self.model_dump(mode="json"))

    def digest(self) -> str:
        return sha256_hex(self.canonical())


def _reduce_public(value: Any) -> Any:
    if isinstance(value, _VrrModel):
        return value.public_fields()
    if isinstance(value, (list, tuple)):
        return [_reduce_public(v) for v in value]
    if isinstance(value, dict):
        return {k: _reduce_public(v) for k, v in value.items()}
    if isinstance(value, Enum):
        return value.value
    return value


# --------------------------------------------------------------------------- #
# artifacts and stages                                                        #
# --------------------------------------------------------------------------- #

class ArtifactRef(_VrrModel):
    AUTHORITY = ("Names one artifact a stage consumed or produced and commits "
                 "to it, and carries its own disclosure class so a reference "
                 "to a withheld table cannot be surfaced by the layer above.")
    DISCLOSURE = {
        "artifact_id": Disclosure.PUBLIC,
        "role": Disclosure.PUBLIC,
        "disclosure_class": Disclosure.PUBLIC,
        "commitment": Disclosure.PUBLIC,
        "commitment_scheme": Disclosure.PUBLIC,
        "shape": Disclosure.PUBLIC,
    }

    artifact_id: str
    role: str
    """`released_output`, `released_artifact`, `input_cells`, `private_probe`."""
    disclosure_class: Disclosure
    commitment: str
    commitment_scheme: str
    shape: list[int] | None = None
    """(rows, columns) of a RELEASED table; None for anything private, where the
    shape is itself a fact about withheld data."""

    def is_public(self) -> bool:
        return self.disclosure_class is Disclosure.PUBLIC


class StageRecord(_VrrModel):
    AUTHORITY = ("Records one registered computational step: what was asked of "
                 "the registry, what it consumed and produced, and how the "
                 "gateway ruled on it.")
    DISCLOSURE = {
        "stage_id": Disclosure.PUBLIC,
        "stage_type": Disclosure.PUBLIC,
        "procedure": Disclosure.PUBLIC,
        "public_parameters": Disclosure.PUBLIC,
        "input_refs": Disclosure.PUBLIC,
        "output_refs": Disclosure.PUBLIC,
        "replay_class": Disclosure.PUBLIC,
        "classification": Disclosure.PUBLIC,
        "audit_ref": Disclosure.OPAQUE_ATTESTATION,
        # --- everything below is decided by the DATA, and none of it may be
        # inferable from the public record. `status` is the sharpest of them:
        # "this stage was denied" answers a question about the cohort that the
        # gateway's single canonical refusal exists to refuse (service.py's
        # WITHHELD_MESSAGE), and it must not be reintroduced one layer up.
        "status": Disclosure.PRIVATE_ONLY,
        "executed_parameters": Disclosure.PRIVATE_ONLY,
        "findings": Disclosure.PRIVATE_ONLY,
        "message": Disclosure.PRIVATE_ONLY,
        "selection_bits": Disclosure.PRIVATE_ONLY,
        "excluded_levels": Disclosure.PRIVATE_ONLY,
        "private_detail": Disclosure.PRIVATE_ONLY,
    }

    stage_id: str
    stage_type: StageType
    procedure: str
    public_parameters: dict[str, Any]
    """The spec as COMMITTED — request-decided, and therefore something the
    researcher already holds. Not what ran: a locked plan's contingency may add
    a filter derived from the data, and that lands in `executed_parameters`."""
    input_refs: list[str] = []
    output_refs: list[ArtifactRef] = []
    replay_class: ReplayClass
    classification: AnalysisClassification
    audit_ref: str
    """The audit chain MAC of the row this stage wrote. Opaque: it identifies a
    row without disclosing it, and it is a MAC, so it proves nothing to anyone
    without the chain key."""

    status: StageStatus
    executed_parameters: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    message: str = ""
    selection_bits: int = 0
    excluded_levels: list[str] = []
    private_detail: dict[str, Any] = {}
    """Free-form private bookkeeping — retry counts, rejected candidate models,
    branch outcomes, diagnostics. Deliberately untyped and deliberately sealed:
    the noninterference tests perturb exactly this and require the public
    provenance not to move."""

    def released(self) -> bool:
        return self.status in (StageStatus.RELEASED, StageStatus.REDACTED)

    def public_artifacts(self) -> list[ArtifactRef]:
        return [a for a in self.output_refs if a.is_public()]


# --------------------------------------------------------------------------- #
# manifests (milestone 6)                                                     #
# --------------------------------------------------------------------------- #

class SoftwareManifest(_VrrModel):
    AUTHORITY = ("Fixes the implementation semantics a replay must match, so a "
                 "certificate cannot be read as a claim about code that has "
                 "since changed.")
    DISCLOSURE = {
        "package_version": Disclosure.PUBLIC,
        "repository_commit": Disclosure.PUBLIC,
        "lockfile_digest": Disclosure.PUBLIC,
        "procedure_registry_digest": Disclosure.PUBLIC,
        "catalogue_digest": Disclosure.PUBLIC,
        "policy_digest": Disclosure.PUBLIC,
        "tool_manifest_digest": Disclosure.PUBLIC,
        "external_checker": Disclosure.PUBLIC,
        "formal_artifact_digest": Disclosure.PUBLIC,
    }

    package_version: str
    repository_commit: str | None = None
    lockfile_digest: str | None = None
    procedure_registry_digest: str
    catalogue_digest: str
    policy_digest: str
    tool_manifest_digest: str
    external_checker: str = "none"
    formal_artifact_digest: str | None = None


class DatasetManifest(_VrrModel):
    AUTHORITY = ("Identifies the snapshot a record was computed over without "
                 "disclosing anything in it.")
    DISCLOSURE = {
        "logical_name": Disclosure.PUBLIC,
        "snapshot_id": Disclosure.PUBLIC,
        "schema_version": Disclosure.PUBLIC,
        "population": Disclosure.PUBLIC,
        "custodian": Disclosure.PUBLIC,
        "views": Disclosure.PUBLIC,
        "snapshot_commitment": Disclosure.OPAQUE_ATTESTATION,
    }

    logical_name: str
    snapshot_id: str
    schema_version: str
    population: str
    """What the snapshot is a population OF, in words a reviewer can read: the
    denominator no number in the bundle states for itself."""
    custodian: str
    views: list[str] = []
    snapshot_commitment: str
    """Keyed, not a raw hash: a synthetic study's tables are reconstructible
    from a seed, so an unkeyed digest of them would let anyone confirm a guess
    at the generating parameters. Opens only for the custodian."""


class DisclosureManifest(_VrrModel):
    AUTHORITY = ("States the disclosure rules that approved every release in "
                 "this record, so a reviewer can see which regime a number "
                 "cleared.")
    DISCLOSURE = {
        "policy_digest": Disclosure.PUBLIC,
        "min_cell_size": Disclosure.PUBLIC,
        "counts_rounded_to_nearest": Disclosure.PUBLIC,
        "vetter": Disclosure.PUBLIC,
        "public_manifest_sha256": Disclosure.PUBLIC,
        "controls": Disclosure.PUBLIC,
    }

    policy_digest: str
    min_cell_size: int
    counts_rounded_to_nearest: int
    vetter: str
    public_manifest_sha256: str
    controls: list[str] = []
    """The named controls in force. Already published in the tool manifest —
    restating them here costs nothing and saves a reviewer a second document."""


class Manifests(_VrrModel):
    AUTHORITY = ("Bundles the three identity manifests a replay and a reviewer "
                 "both need to read a record.")
    DISCLOSURE = {
        "software": Disclosure.PUBLIC,
        "dataset": Disclosure.PUBLIC,
        "disclosure": Disclosure.PUBLIC,
    }

    software: SoftwareManifest
    dataset: DatasetManifest
    disclosure: DisclosureManifest

    def replay_semantics(self) -> dict[str, str]:
        """The identity a replay must match exactly. Anything not in here is
        something a replay is allowed to differ in, so the list is the whole
        claim: change any of it and the certificate must not verify."""
        return {
            "package_version": self.software.package_version,
            "procedure_registry_digest": self.software.procedure_registry_digest,
            "catalogue_digest": self.software.catalogue_digest,
            "policy_digest": self.software.policy_digest,
            "tool_manifest_digest": self.software.tool_manifest_digest,
            "dataset_snapshot_id": self.dataset.snapshot_id,
            "dataset_snapshot_commitment": self.dataset.snapshot_commitment,
        }


# --------------------------------------------------------------------------- #
# the five objects                                                            #
# --------------------------------------------------------------------------- #

class EvidenceItem(_VrrModel):
    AUTHORITY = ("Gives one released number a stable machine identity and a "
                 "lineage back to the stage and audit row that released it.")
    DISCLOSURE = {
        "evidence_id": Disclosure.PUBLIC,
        "kind": Disclosure.PUBLIC,
        "source_stage": Disclosure.PUBLIC,
        "audit_ref": Disclosure.OPAQUE_ATTESTATION,
        "procedure": Disclosure.PUBLIC,
        "keys": Disclosure.PUBLIC,
        "values": Disclosure.PUBLIC,
        "precision": Disclosure.PUBLIC,
        "units": Disclosure.PUBLIC,
        "manuscript_ref": Disclosure.PUBLIC,
    }

    evidence_id: str
    kind: str
    """`GroupStatistic`, `ModelCoefficient`, `ConfidenceInterval`,
    `NotAnswerable`."""
    source_stage: str
    audit_ref: str
    procedure: str
    keys: dict[str, Any] = {}
    """What the number is ABOUT — the cell keys, or the term and level."""
    values: dict[str, Any] = {}
    """What was released. Empty for `NotAnswerable`, which is a claim that the
    gateway released nothing, and therefore has no number to carry."""
    precision: int | None = None
    units: str | None = None
    manuscript_ref: str | None = None
    """Where the researcher put it — "Figure 2b". METADATA: excluded from
    `identity_digest`, so renaming a figure cannot change what the scientific
    artifact is."""

    IDENTITY_FIELDS: ClassVar[tuple[str, ...]] = (
        "kind", "source_stage", "procedure", "keys", "values", "precision", "units")

    def identity_digest(self) -> str:
        """What this evidence IS, independent of where it was printed."""
        payload = {f: _reduce_public(getattr(self, f)) for f in self.IDENTITY_FIELDS}
        return sha256_hex(canonical_json(payload))


class PrivateExecutionTrace(_VrrModel):
    AUTHORITY = ("Holds everything the TRE actually did for one question, "
                 "including what it refused, and never leaves the safepod.")
    DISCLOSURE = {
        "record_id": Disclosure.PUBLIC,
        "question": Disclosure.PUBLIC,
        "plan_ref": Disclosure.PUBLIC,
        "committed_plan": Disclosure.PUBLIC,
        "manifests": Disclosure.PUBLIC,
        "stages": Disclosure.PRIVATE_ONLY,
        "evidence_refs": Disclosure.PUBLIC,
        "audit_head": Disclosure.OPAQUE_ATTESTATION,
        "user": Disclosure.PRIVATE_ONLY,
        "release_domain": Disclosure.PUBLIC,
    }

    record_id: str
    question: str
    plan_ref: str | None = None
    """The committed plan's hash, or None when nothing was committed — which is
    itself the proof that every stage here is post-hoc."""
    committed_plan: dict[str, Any] | None = None
    """The plan itself. Request-decided and therefore publishable: a reviewer
    who can read the plan can check that the pre-specification label is about
    the analysis they were shown."""
    manifests: Manifests
    stages: list[StageRecord] = []
    """PRIVATE_ONLY as a LIST, even though a stage classifies its own fields.
    The list's *membership* is data-derived — which stages ran, how many were
    denied, whether a contingency fired — so the public layer must select
    nodes by public evidence rather than inherit this sequence. `provenance.py`
    does the selecting; nothing here hands it a default."""
    evidence_refs: list[str] = []
    audit_head: str = ""
    user: str = ""
    release_domain: str = "unspecified"
    """The custodian-defined domain this release was accounted against (D10). A
    placeholder in v0: cross-user safety keys off this, and recording the name
    now means the field exists before the machinery that enforces it."""

    def stage(self, stage_id: str) -> StageRecord | None:
        for st in self.stages:
            if st.stage_id == stage_id:
                return st
        return None

    def released_stages(self) -> list[StageRecord]:
        return [st for st in self.stages if st.released()]

    def validate_lineage(self) -> None:
        """Every dependency resolves, backwards, to a stage that exists.

        Milestone 1's acceptance test is the negative of this: remove one
        dependency and record validation must fail. It fails here.
        """
        seen: set[str] = set()
        for st in self.stages:
            if st.stage_id in seen:
                raise RecordError(f"duplicate stage id {st.stage_id!r}")
            for dep in st.input_refs:
                if dep not in seen:
                    raise RecordError(
                        f"stage {st.stage_id!r} depends on {dep!r}, which is "
                        "not an earlier stage of this trace")
            seen.add(st.stage_id)
        if self.plan_ref is None and any(
                st.classification is AnalysisClassification.TRE_PRECOMMITTED
                for st in self.stages):
            raise RecordError(
                "a stage claims TRE_PRECOMMITTED but the trace commits no plan")


class PublicProvenance(_VrrModel):
    AUTHORITY = ("Says what a reviewer outside the TRE may know about how a "
                 "released result was computed, and is itself a disclosure "
                 "surface rather than a summary.")
    DISCLOSURE = {
        "record_id": Disclosure.PUBLIC,
        "question": Disclosure.PUBLIC,
        "plan_ref": Disclosure.PUBLIC,
        "committed_plan": Disclosure.PUBLIC,
        "classification": Disclosure.PUBLIC,
        "replay_semantics": Disclosure.PUBLIC,
        "nodes": Disclosure.PUBLIC,
        "evidence_ids": Disclosure.PUBLIC,
        "release_domain": Disclosure.PUBLIC,
        "policy_version": Disclosure.PUBLIC,
    }

    record_id: str
    question: str
    plan_ref: str | None = None
    committed_plan: dict[str, Any] | None = None
    classification: AnalysisClassification
    replay_semantics: dict[str, str]
    nodes: list[dict[str, Any]] = []
    """One entry per stage that carries public evidence — and ONLY those. A node
    for a denied stage would publish the gateway's verdict on a cohort."""
    evidence_ids: list[str] = []
    release_domain: str = "unspecified"
    policy_version: str = ""

    def canonical(self) -> str:
        """Byte-equality of this string is the noninterference property: two
        executions differing only in private detail must produce the same
        bytes here."""
        return canonical_json(self.model_dump(mode="json"))


class ReplayCertificate(_VrrModel):
    AUTHORITY = ("States that a named computation was re-run under named "
                 "semantics and reproduced named bytes, and states nothing "
                 "about whether the science is right.")
    DISCLOSURE = {
        "certificate_id": Disclosure.PUBLIC,
        "record_id": Disclosure.PUBLIC,
        "record_digest": Disclosure.PUBLIC,
        "outcome": Disclosure.PUBLIC,
        "replay_semantics": Disclosure.PUBLIC,
        "stages": Disclosure.PUBLIC,
        "detail": Disclosure.PUBLIC,
        "not_verified": Disclosure.PUBLIC,
    }

    certificate_id: str
    record_id: str
    record_digest: str
    """Binds to the EXACT record: change a reported value and this moves, so a
    certificate cannot be carried across to a record it never saw."""
    outcome: str
    replay_semantics: dict[str, str]
    stages: list[dict[str, Any]] = []
    detail: str = ""
    not_verified: list[str] = []
    """What a reader must NOT conclude from this certificate. Carried in the
    certificate rather than the surrounding prose because the certificate is
    what gets quoted."""

    # A replay certificate carries no wall-clock time, on purpose. The bundle
    # has to be byte-deterministic — the noninterference and tamper tests both
    # compare canonical bytes, and a reviewer regenerating the README must get
    # the file that was signed — and "when" is already in the audit chain,
    # which is the tamper-evident place for it.

    def reproduced(self) -> bool:
        return self.outcome == "COMPUTATION_REPRODUCED"


class ResearchRecord(_VrrModel):
    AUTHORITY = ("Is the whole publishable object for one question, binding "
                 "the private trace, its evidence, its public provenance and "
                 "its replay verdict into one identity.")
    DISCLOSURE = {
        "record_id": Disclosure.PUBLIC,
        "schema_version": Disclosure.PUBLIC,
        "trace": Disclosure.PRIVATE_ONLY,
        "evidence": Disclosure.PUBLIC,
        "provenance": Disclosure.PUBLIC,
        "certificate": Disclosure.PUBLIC,
    }

    record_id: str
    schema_version: int = 1
    trace: PrivateExecutionTrace
    evidence: list[EvidenceItem] = []
    provenance: PublicProvenance | None = None
    certificate: ReplayCertificate | None = None

    def validate_record(self) -> None:
        """Everything milestone 1 asks a record to hold together on."""
        self.trace.validate_lineage()
        by_id = {e.evidence_id: e for e in self.evidence}
        if len(by_id) != len(self.evidence):
            raise RecordError("duplicate evidence ids")
        for ev in self.evidence:
            st = self.trace.stage(ev.source_stage)
            if st is None:
                raise RecordError(
                    f"evidence {ev.evidence_id!r} cites stage "
                    f"{ev.source_stage!r}, which is not in the trace")
            if ev.kind != "NotAnswerable" and not st.released():
                raise RecordError(
                    f"evidence {ev.evidence_id!r} cites stage "
                    f"{ev.source_stage!r}, which released nothing; a number "
                    "the gateway withheld is not evidence")
            if st.stage_type is StageType.PROBE:
                raise RecordError(
                    f"evidence {ev.evidence_id!r} cites a privileged probe; "
                    "a probe's result is exactly what was withheld")
        for ref in self.trace.evidence_refs:
            if ref not in by_id:
                raise RecordError(f"trace references missing evidence {ref!r}")

    def verified_digest(self) -> str:
        """What a replay certificate binds to: the public provenance and the
        evidence, and NOT the certificate itself.

        The certificate has to name the thing it verified, and the thing it
        verified is the record as it stood before there was a certificate.
        Binding to `public_digest` instead would be circular, and the natural
        way out of the circle — leave the certificate out of the signature —
        is the stale-certificate attack: a valid signature over a record whose
        verdict nobody checked.
        """
        payload = {
            "record_id": self.record_id,
            "schema_version": self.schema_version,
            "provenance": None if self.provenance is None
            else json.loads(self.provenance.canonical()),
            "evidence": [json.loads(canonical_json(e.model_dump(mode="json")))
                         for e in self.evidence],
        }
        return sha256_hex(canonical_json(payload))

    def public_digest(self) -> str:
        """The digest a signature covers: the public half only, so a signature
        cannot be checked by anyone holding the private trace and refused by
        anyone holding only the bundle."""
        payload = {
            "record_id": self.record_id,
            "schema_version": self.schema_version,
            "provenance": None if self.provenance is None
            else json.loads(self.provenance.canonical()),
            "evidence": [json.loads(canonical_json(e.model_dump(mode="json")))
                         for e in self.evidence],
            "certificate": None if self.certificate is None
            else json.loads(canonical_json(self.certificate.model_dump(mode="json"))),
        }
        return sha256_hex(canonical_json(payload))


VRR_OBJECTS: tuple[type[_VrrModel], ...] = (
    ResearchRecord, PrivateExecutionTrace, PublicProvenance, EvidenceItem,
    ReplayCertificate,
)
"""The five names milestone 0 froze, for the acceptance tests to iterate over."""


__all__ = [
    "AnalysisClassification", "ArtifactRef", "DatasetManifest", "Disclosure",
    "DisclosureManifest", "EvidenceItem", "Manifests", "PrivateExecutionTrace",
    "PublicProvenance", "RecordError", "ReplayCertificate", "ReplayClass",
    "ResearchRecord", "SoftwareManifest", "StageRecord", "StageStatus",
    "StageType", "VRR_OBJECTS", "canonical_json", "commit_private",
    "commit_public", "digest_of", "internal_commitment_key", "sha256_hex",
]
