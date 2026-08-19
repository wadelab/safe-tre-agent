# Verifiable Research Records

*A post-v1.0 architecture plan for making AI-assisted research inspectable,
replayable and publishable without exposing protected data. This document
implements the direction recorded in
[D9](decisions/D9-verifiable-research-record.md). It is a design plan, not yet a
normative security claim.*

## Goal

A researcher should be able to publish a result from the Safe TRE and give a
reviewer substantially more than:

> "The AI analysed the confidential data and told us this."

The target is:

> **This result came from this declared scientific question and analysis plan,
> executed by this version of the software against this attested data snapshot;
> every computational stage has typed provenance, every released value passed
> the declared disclosure policy, and an independent deterministic verifier
> reproduced the result inside the TRE.**

The external artifact carrying that claim is the **Verifiable Research Record
(VRR)**.

The VRR is designed around one principle:

> **Reviewers should verify the computation and provenance, not trust the
> intelligence that proposed it.**

## What reviewers actually need to trust

There are four different assurance questions. They must remain separate in the
format and UI.

| Dimension | Question | Who/what answers it? |
|---|---|---|
| Scientific validity | Was this a sensible analysis for the scientific question? | researchers, reviewers, domain expertise |
| Computational integrity | Did the declared computation produce the reported result? | deterministic replay + typed provenance |
| Data provenance | Was it run against the declared protected snapshot? | TRE custodian attestation |
| Disclosure/privacy | Was every outward value permitted by the release policy/accounting state? | gateway + formal/tests/accountant |

A "verified" result that conflates these is misleading. The VRR should report
all four dimensions explicitly.

## The record hierarchy

The VRR has three layers with different audiences and disclosure properties.

### 1. `PrivateExecutionTrace`

TRE-internal only. Complete enough for audit and replay. It may contain:

- full `QuestionSpec` and plan;
- every registered procedure invocation;
- private/intermediate artifact references;
- withheld values and gateway findings;
- data-sighted branch decisions;
- adaptation-budget events;
- exceptions and retries;
- software/runtime identifiers;
- internal commitments and audit-row identifiers.

It is **not** released simply because it is a trace. Trace shape and hashes can
be disclosive.

### 2. `PublicProvenance`

Compiled by deterministic code from the private trace. It contains only
information approved for release, for example:

- scientific question identity and public plan;
- analysis classification (pre-specified/exploratory/etc.);
- registered procedure names and public parameters;
- public software and policy digests;
- opaque commitments to private stages where safe;
- public stage status/attestation classes;
- links to released evidence objects;
- replay certificate;
- custodian signature.

The compiler, not the model, decides which private-trace fields have a public
representation.

### 3. `ResearchVerificationBundle`

The publishable package. It includes:

```text
ResearchVerificationBundle/
  record.json
  question.json
  public_plan.json
  provenance.json
  evidence/
  replay_certificate.json
  software_manifest.json
  disclosure_manifest.json
  attestations/
  README.md
```

Optional human-readable rendering can be generated from the machine-readable
record, but the JSON objects are the source of truth.

## Proposed top-level schema

Illustrative rather than final:

```json
{
  "vrr_version": "0.1",
  "record_id": "...",
  "question": {...},
  "analysis_classification": {...},
  "data_provenance": {...},
  "software_provenance": {...},
  "public_provenance": {...},
  "released_evidence": [...],
  "privacy": {...},
  "replay": {...},
  "attestations": [...]
}
```

Every field should have one of three explicit disclosure classes in the schema:

- `PUBLIC`;
- `OPAQUE_ATTESTATION`;
- `PRIVATE_ONLY`.

The public serializer must fail closed if a field lacks a disclosure class.

## Question and plan provenance

The record begins with the scientific object, not the model transcript.

A useful `QuestionSpec` should identify, where applicable:

```text
population / cohort
predictor or exposure
outcome
estimand / relation type
adjustment set
primary vs sensitivity analyses
reporting precision/class
release domain / project context
```

The public plan is a typed finite plan built from registered procedures. The
plan's canonical encoding is committed before it runs when the analysis is to
be called pre-specified.

### Classification is derived, not claimed

For each stage, classify its relation to the plan:

- `PRESPECIFIED` — the governing plan commitment predates the first private
  observation relevant to that stage;
- `PUBLIC_ADAPTIVE` — chosen using only already released information;
- `PRIVATE_ADAPTIVE_ACCOUNTED` — chosen using protected information through a
  metered/DP-accounted channel;
- `EXPLORATORY_POSTHOC` — not governed by the prior commitment.

The classification comes from audit event order and information-flow metadata.
Neither the researcher nor the model may set `PRESPECIFIED=true` as a free
field.

## Data provenance

The data custodian must attest the identity of the protected input without
revealing it.

A `DatasetManifest` should record public facts such as:

```text
dataset logical name
snapshot/version identifier
schema version
population declaration
creation/freeze timestamp
custodian identity
opaque snapshot commitment
```

### Do not publish naïve hashes of low-entropy secrets

A public SHA-256 is hiding only for high-entropy values. A hash of a private
count, Boolean, category, or tiny table can be reversed by enumerating likely
values.

For private artifacts use one of:

1. a keyed commitment (e.g. HMAC under an off-box TRE key), with the public
   record carrying only the commitment and custodian attestation;
2. a salted commitment whose high-entropy salt remains private until disclosure
   is intended; or
3. no public commitment at all, only an internal audit-chain reference plus a
   signed statement that replay matched.

Choice (1) fits the existing trust model best initially because the project
already has an off-box audit key/anchor concept.

The custodian's attestation means:

> "The TRE replay service executed against the protected snapshot identified by
> this internal commitment."

It does **not** mean the public can independently reconstruct the dataset hash.

## Software provenance

A result must identify the executable semantics, not merely a package name.
Record at least:

```text
safe-tre-agent git commit/tag
package version
Python/runtime version
lockfile digest
container/image digest where used
procedure-registry digest
catalogue digest
policy/config digest
formal-artifact digest
external checker identity/version
```

The software manifest should distinguish:

- source identity;
- dependency identity;
- policy identity;
- formal-model identity.

For a publication-quality bundle, the code commit/tag should be archived
separately and DOI-citable.

## Provenance graph

The computational trace should be a DAG of registered actions and artifacts.
It is **not** a transcript of model reasoning.

A node has approximately:

```text
node_id
stage_type
registered_procedure
public_parameters
input_refs
output_refs
execution_status
plan_classification
replay_class
release_refs
internal_audit_ref
```

Edges mean data/control dependency. They are not automatically public.

Example private DAG:

```text
DatasetSnapshot
      |
      v
PopulationSelection
      |
      +----------------------+
      |                      |
      v                      v
DesignCellMeans         DesignCellMoments
      |                      |
      +-------> Gateway <-----+
                   |
                   v
               GLM Fit
                   |
                   v
             Evidence Item
                   |
                   v
             Release Compiler
```

### Public graph compilation

The public graph must be compiled under an explicit policy because the *shape*
of the private graph may disclose information. For example:

```text
if rare subgroup exists:
    run fallback model
else:
    run primary model
```

Publishing which branch exists reveals the condition.

Therefore public provenance may:

- collapse private subgraphs into one opaque stage;
- publish a fixed plan skeleton rather than the path actually taken;
- expose only stage classes that are themselves release-approved;
- hide counts of retries/candidates when those counts depend on private data.

The desired invariant is:

> Two executions that yield the same approved public evidence and public
> analysis classification must not become distinguishable merely through
> public provenance fields that were supposed to be private.

This deserves a release-equality/property-test analogue of the current output
boundary.

## Replay semantics

"Reproducible" needs explicit semantics per stage.

### `PUBLIC_REPLAYABLE`

All required inputs are public/released. Example: a GLM fitted solely from a
released finalized cell table.

A reviewer can rerun it externally. The VRR should provide the exact artifact
and deterministic procedure/version.

### `TRE_REPLAYABLE_EXACT`

Inputs are protected but the deterministic TRE-side verifier should reproduce
the artifact bit-for-bit from the committed snapshot and manifest.

This should be the default for deterministic aggregation and registered
procedures where numeric semantics are stable.

### `TRE_REPLAYABLE_TOLERANCE`

Some numerical kernels may be platform-dependent. Where bit equality is not a
reasonable contract, the procedure must state a tolerance *before* replay and
why it is safe.

Do not silently downgrade exact replay to tolerant replay on failure.

### `STOCHASTIC_VERIFIABLE`

For DP mechanisms or legitimately stochastic statistics, replay should not
pretend that rerunning with fresh randomness must give the same answer.

Instead the record needs:

```text
mechanism identity
mechanism parameters
privacy/accounting event
RNG implementation identity
opaque commitment to protected randomness/seed or randomness receipt
verification rule
```

Two possible modes:

- **same-randomness audit replay** inside the TRE reproduces the exact release
  using protected seed material;
- **mechanism verification** checks that the recorded release could only have
  arisen through the declared mechanism and that the accountant was charged.

The first is easiest for v0; the seed is never public.

## The deterministic verifier

Introduce a verifier that is explicitly outside the model trust boundary:

```text
verify(record_id) -> ReplayCertificate
```

It should:

1. load the private execution record and immutable manifests;
2. verify the audit-chain/plan commitments;
3. resolve the attested data snapshot;
4. reconstruct registered procedure inputs;
5. rerun replayable stages under the recorded software/policy semantics;
6. compare stage outputs according to each replay class;
7. verify every public evidence item has a release path;
8. verify public provenance was compiled from the same private record;
9. emit a certificate with per-stage verdicts and an overall computational
   integrity verdict.

The verifier never asks an LLM whether two results "look equivalent".

## Replay certificate

Example:

```json
{
  "record_id": "VRR-...",
  "verifier_version": "...",
  "data_snapshot_attested": true,
  "audit_chain_verified": true,
  "plan_commitment_verified": true,
  "stages": [
    {"id":"s1", "class":"TRE_REPLAYABLE_EXACT", "status":"MATCH"},
    {"id":"s2", "class":"PUBLIC_REPLAYABLE", "status":"MATCH"}
  ],
  "released_evidence_verified": true,
  "public_provenance_verified": true,
  "overall": "COMPUTATION_REPRODUCED"
}
```

Avoid a generic `VERIFIED` status. A reviewer should be able to distinguish
`COMPUTATION_REPRODUCED` from `DISCLOSURE_POLICY_VERIFIED` and from the entirely
human judgement of scientific validity.

## Evidence lineage

Every value that appears in a publication should be traceable to an
`EvidenceItem` in the VRR.

Candidate evidence types:

```text
EffectEstimate
ConfidenceInterval
ModelCoefficient
GroupStatistic
Contrast
TrendEstimate
RobustnessFlag
NullResult
NotAnswerable
```

Each carries:

```text
source_stage
release_id
public value(s)
reporting precision
procedure/policy identity
optional manuscript labels (table/figure/result IDs)
```

This enables a manuscript mapping:

```text
Figure 3b -> EvidenceItem E17 -> Release R88 -> Stage S12 -> Plan P4
```

The mapping can be public even if the inputs to S12 are private, because the
private stage is represented by a non-reversible attestation rather than raw
content.

## Reviewer-facing verification

A reviewer should not need to read the raw JSON first. Build a deterministic
HTML/Markdown report from the bundle with sections:

### Scientific question

What was estimated? Which components were primary vs sensitivity/exploratory?

### Data

What dataset/snapshot did the custodian attest? What population/schema/version?

### Analysis

Which registered procedures ran? Which parameters are public? Which stages were
private?

### Adaptation history

What was pre-specified, public-adaptive, privately adaptive/accounted, or
post-hoc?

### Results

Which released evidence items support each claim/figure/table?

### Privacy/disclosure

Which policy/checker/accountant governed the release? What public privacy
budget/accounting statement is safe to disclose?

### Reproduction

Which stages were externally replayable? Which were TRE-replayed? Did the replay
match? On what verifier/software version?

### Custodian attestation

Signature/verification state and the public key/certificate chain needed to
verify it.

The reviewer should be able to inspect the analysis without being shown hidden
cells or model chain-of-thought.

## Signatures and attestations

The current HMAC audit chain authenticates history to the TRE, but a publishable
VRR needs an externally verifiable signature over the public bundle.

Longer-term design:

```text
bundle_digest = hash(canonical_public_bundle)
signature = custodian_sign(bundle_digest)
```

Use an asymmetric signing key held by the TRE/custodian so reviewers can verify
without possessing a secret.

The signature asserts:

- this public bundle was issued by this TRE;
- it corresponds to an internal record whose replay certificate is as stated;
- the stated data/software/policy manifests were the ones used.

It does not assert scientific correctness.

For the first research implementation, a test key is sufficient; production
key management is a separate deployment problem.

## Formal-methods programme

The VRR adds a promising set of properties that fit the project's current
Lean/Alloy split.

### Lean / structural proofs

Candidate types and theorems:

1. `PublicAnswer` and `PublicProvenance` have no constructor carrying
   `PrivateArtifact` values.
2. `EvidenceItem` must reference a registered release class.
3. every public numeric claim has an `EvidenceItem` source.
4. the outward renderer is a function of `(PublicEvidence,
   PublicProvenance)` only.
5. private-trace perturbations that leave the compiled public record fixed leave
   the outward bundle fixed.
6. public serialization cannot include a field whose disclosure class is
   `PRIVATE_ONLY`.

The key theorem shape is noninterference through the record compiler, not
correctness of the AI's reasoning.

### Alloy / temporal and stateful checks

Model:

- plan commit before first private observation;
- stage event ordering;
- a result cannot be labelled `PRESPECIFIED` if the plan commit happened
  afterwards;
- every public evidence item has exactly one authorized release lineage;
- replay certificate refers to the same manifests as the issued record;
- private branch choice does not alter public graph shape unless an approved
  evidence field also changes;
- global accounting and record issue order compose across users/projects.

Every attack `run` should have an executable twin under the existing
correspondence discipline.

## Testing programme

### Unit and schema tests

- round-trip canonical serialization;
- all public fields carry disclosure classes;
- unknown/new fields fail public serialization until classified;
- record IDs and DAG references are immutable/canonical;
- evidence cannot reference private-only artifacts directly.

### Metamorphic/noninterference tests

Generate two private traces that differ in:

- suppressed count;
- rejected model candidate;
- branch path;
- retry count;
- private diagnostic;
- data-sighted sparse category.

Hold approved public evidence constant. Assert identical public VRRs.

### Replay tests

For each registered procedure:

- generate an execution record;
- replay from the frozen snapshot;
- assert exact/tolerance contract;
- mutate one manifest and assert verification fails;
- mutate one output and assert verification fails;
- mutate the replay classification and assert fail closed.

### Red-team tests

Add attacks for:

- dictionary-attacking public commitments;
- leaking secrets through public DAG topology;
- claiming post-hoc work was pre-registered;
- attaching a result to the wrong dataset snapshot;
- attaching a result to the wrong code/policy digest;
- editing the public bundle after custodian signing;
- laundering an unsupported narrator claim into the manuscript mapping;
- using a stale successful replay certificate after the record changes.

## Scientific-integrity opportunities

This architecture makes several things possible that ordinary notebook-based
research does poorly.

### Machine-enforced pre-registration

The timestamp/order relation between plan commitment and data-sighted execution
is part of the record. No retrospective prose can rewrite it.

### Honest exploration

Exploration is not banned. It is labelled. A paper can publish both confirmatory
and exploratory evidence while making the distinction mechanically visible.

### Complete analytical provenance

The researcher no longer has to remember which notebook cell or prompt created
Figure 3. The figure maps to typed evidence and a reproducible stage.

### Reanalysis without data release

A reviewer/custodian can request a TRE-side replay or an approved alternative
analysis while the protected rows remain inside.

### Independent renderer/narrator

The public narrative can be regenerated from the VRR. A model can improve prose
without changing the underlying scientific record.

## Non-goals

The VRR does not:

- prove that the dataset is unbiased or accurately collected;
- prove causal validity;
- prove that a covariate choice is scientifically defensible;
- publish model chain-of-thought;
- expose private intermediate values for the sake of "transparency";
- make a TRE operator unnecessary as a trust root;
- replace differential privacy or SDC;
- make arbitrary code formally verifiable.

## Success criterion

A compelling first demonstration is an end-to-end NIGHTPLAY result where a
reviewer receives a VRR and can establish all of the following:

1. the question and primary analysis were committed before execution;
2. the protected snapshot and software/policy identities are attested;
3. the private trace contains a richer analysis than the public evidence;
4. every public result maps to a release-approved evidence object;
5. public provenance reveals none of several planted private branch facts;
6. the deterministic TRE verifier reproduces the reported computation;
7. the public bundle verifies against a custodian signature;
8. an intentionally post-hoc analysis is correctly labelled exploratory;
9. tampering with the result, manifest or certificate is detected.

If we can do that without turning the codebase into a general workflow engine,
we have a substantial new research contribution rather than an audit-log
feature.
