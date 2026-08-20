# Verifiable Research Record: build plan

*Execution plan for [the VRR architecture](verifiable-research-record.md) and
[D9](decisions/D9-verifiable-research-record.md). The order is intentionally
conservative: prove the record/replay idea on today's deterministic path before
connecting it to the more intelligent inside analyst.*

## Guiding rule

Do **not** start by building a generic provenance framework.

Start with one concrete question, one existing registered procedure path and one
publishable record. Extract abstractions only after the first end-to-end record
works.

The first milestone should be possible without:

- differential privacy;
- cross-user/global accounting;
- data-sighted LLM adaptation;
- zero-knowledge proofs;
- a production signing service;
- a web UI;
- arbitrary workflow execution.

Those are later integrations, not prerequisites for proving that a protected
analysis can yield a replayable, reviewer-facing record.

## Milestone 0 — freeze the vocabulary before writing code

**Goal:** agree on the smallest object model.

Create/update a short schema note or code comments defining exactly these five
objects:

```text
ResearchRecord
PrivateExecutionTrace
PublicProvenance
EvidenceItem
ReplayCertificate
```

Do not add `QuestionSpec` here if its separate answer-level implementation is
not ready; the first record can carry today's original question plus an existing
locked/scripted plan reference. Keep the dependency one-way: VRR can later
consume `QuestionSpec`.

### Acceptance tests

- each object has a one-sentence authority boundary;
- public/private fields are explicit;
- no object contains LLM chain-of-thought;
- `PublicProvenance` cannot directly reference a private raw value.

## Milestone 1 — one deterministic record from an existing analysis

**Goal:** generate a complete private record for one path that already exists.

Use a scripted NIGHTPLAY analysis with a registered aggregate or GLM. Avoid the
LLM initially so failures are provenance failures rather than planner failures.

Suggested new module:

```text
safetre/research_record.py
```

Minimum types:

```python
class ArtifactRef(...):
    artifact_id
    disclosure_class
    commitment

class StageRecord(...):
    stage_id
    stage_type
    procedure
    public_parameters
    input_refs
    output_refs
    status
    replay_class
    audit_ref

class PrivateExecutionTrace(...):
    record_id
    question
    plan_ref
    manifests
    stages
    evidence_refs
```

### Instrumentation principle

Prefer recording at existing stable seams rather than scattering logging calls:

- `QueryService` request/release boundary;
- procedure registry dispatch;
- model fit from finalized cells;
- plan executor stage boundaries;
- audit append.

The record should reference existing audit rows rather than replacing the audit
log.

### Acceptance tests

- run one scripted NIGHTPLAY question;
- private record contains all registered computational stages needed to explain
  one released result;
- every stage has immutable IDs and typed dependencies;
- intentionally removing one dependency makes record validation fail;
- no existing release behaviour changes.

## Milestone 2 — deterministic replay

**Goal:** prove the record is useful, not decorative.

Suggested module:

```text
safetre/replay.py
```

Interface:

```python
replay(record_id, context) -> ReplayCertificate
```

For the first slice, support only `TRE_REPLAYABLE_EXACT` stages.

Replay should reconstruct from:

- recorded dataset/snapshot identity;
- recorded public query/procedure spec;
- recorded policy/config identity;
- current implementation only if its identity matches the record.

Do not silently replay an old record with new code.

### Initial replay target

Use the strongest existing deterministic path:

```text
QuerySpec -> aggregate cells -> gateway finalization -> GLM/refit -> release
```

Where a released finalized cell table exists, test external-style
`refit_from_artifact` separately from protected TRE replay.

### Failure tests

Replay must fail if any of these change:

- dataset snapshot identity;
- QuerySpec/procedure parameters;
- policy digest;
- procedure-registry digest;
- expected output;
- replay class.

### Acceptance criterion

A successful certificate says `COMPUTATION_REPRODUCED`, never generic
`VERIFIED`.

## Milestone 3 — evidence lineage

**Goal:** give manuscript claims stable machine identities.

Suggested module:

```text
safetre/evidence.py
```

Start with only a few types:

```text
GroupStatistic
ModelCoefficient
ConfidenceInterval
NotAnswerable
```

Each evidence item references:

```text
source_stage
release/audit record
value(s)
precision
procedure identity
```

Add optional publication labels:

```text
manuscript_ref: "Figure 2b"
```

but keep them metadata: changing a figure label must not change the scientific
artifact identity.

### Acceptance tests

- every released numeric claim in the test dossier maps to an evidence item;
- an evidence item cannot cite a denied/private-only stage;
- mutating source result invalidates evidence validation;
- deterministic rendering from evidence reproduces the reported number.

## Milestone 4 — split private trace from public provenance

**Goal:** make privacy of the record itself a first-class boundary.

Suggested module:

```text
safetre/provenance.py
```

Implement:

```python
compile_public_provenance(private_trace, policy) -> PublicProvenance
```

Every serializable field has a disclosure class:

```text
PUBLIC
OPAQUE_ATTESTATION
PRIVATE_ONLY
```

Unknown fields fail closed.

### Do not use raw content hashes for arbitrary private values

For v0, introduce a narrow commitment interface:

```python
commit_private(artifact_bytes, key) -> opaque_commitment
```

Use a keyed commitment/HMAC under an internal/off-box key. Public code does not
receive the key.

Do not expose a hash of a small count/Boolean/category and call that hidden.

### Public-topology noninterference tests

Construct paired private traces with equal approved evidence but different:

- suppressed cell count;
- rejected candidate model;
- private branch decision;
- retry count;
- sparse category;
- private diagnostic.

Require byte-identical canonical `PublicProvenance` unless an explicitly public
classification/evidence item differs.

This is a release-equality test for the provenance layer.

## Milestone 5 — analysis classification and pre-registration proof

**Goal:** turn `pre-specified` from prose into an event-order property.

Reuse the locked-plan audit commitment machinery.

Derive stage classification from facts:

```text
PRESPECIFIED
PUBLIC_ADAPTIVE
PRIVATE_ADAPTIVE_ACCOUNTED
EXPLORATORY_POSTHOC
```

Minimal first implementation needs only:

```text
PRESPECIFIED
EXPLORATORY_POSTHOC
```

Add the other two when the corresponding information-flow/accounting machinery
is stable.

### Property

A stage cannot be `PRESPECIFIED` unless:

```text
plan_commit_event < first_private_observation_for_stage
```

### Attack test

Execute first, commit plan second, then try to issue a public record marked
pre-specified. It must fail or be labelled post-hoc.

## Milestone 6 — software/data manifests

**Goal:** make replay attributable to immutable semantics.

Implement canonical manifests:

```text
SoftwareManifest
DatasetManifest
DisclosureManifest
```

### Software manifest minimum

- repository commit/tag;
- package version;
- lockfile digest;
- procedure-registry digest;
- catalogue digest;
- config/policy digest;
- external checker identity;
- formal-artifact digest/version.

### Dataset manifest minimum

- logical dataset/study name;
- snapshot/version identifier;
- schema version;
- population declaration;
- opaque private snapshot commitment;
- custodian identity placeholder.

Do not block research v0 on solving production snapshot infrastructure. NIGHTPLAY
can have a deterministic fixture snapshot ID and internal commitment.

## Milestone 7 — public bundle and deterministic reviewer report

**Goal:** make the artifact usable without a bespoke UI.

Implement export:

```text
artifacts/vrr/<record_id>/
  record.json
  provenance.json
  evidence.json
  replay_certificate.json
  software_manifest.json
  disclosure_manifest.json
  README.md
```

Generate `README.md` deterministically from the JSON; no LLM required.

Recommended sections:

1. Scientific question
2. Analysis status/classification
3. Data provenance
4. Software/policy provenance
5. Public computational provenance
6. Released evidence
7. Disclosure/privacy statement
8. Replay result
9. What is and is not verified

### Acceptance test

A technically competent reviewer who sees only the exported bundle and source
repository should be able to answer:

- what was asked;
- what public method ran;
- what evidence was released;
- whether the computation replayed;
- whether the analysis was pre-specified or exploratory;
- what they still have to trust the custodian/researcher about.

## Milestone 8 — asymmetric attestation

**Goal:** make the exported bundle tamper-evident to an external reviewer.

Do not repurpose the internal HMAC key for public verification.

Introduce a test signing interface:

```text
sign_bundle(bundle_digest) -> signature
verify_bundle(bundle_digest, signature, public_key) -> bool
```

Use asymmetric signing. Exact algorithm/key management can be chosen when
implementing; keep the interface independent.

The signed payload should include or cover:

- canonical public bundle digest;
- replay certificate digest;
- manifest digests;
- record ID/version.

### Attack tests

Signature verification fails after:

- changing a reported value;
- swapping dataset manifests;
- swapping replay certificate;
- deleting a provenance node;
- changing analysis classification.

## Milestone 9 — formalisation slice

**Goal:** prove the new authority boundary, not the whole workflow.

Do this only after the Python types settle.

### Lean first targets

1. public record types contain no `PrivateArtifact` payload;
2. every `EvidenceItem` references an allowed release class;
3. public renderer takes only public evidence/provenance;
4. canonical public serialization excludes `PRIVATE_ONLY` fields.

A useful theorem shape:

```text
compile_public t1 = compile_public t2
  -> render_public t1 = render_public t2
```

with the renderer defined only over public compiled state.

### Alloy first targets

1. plan commit before private observation for `PRESPECIFIED`;
2. each evidence item has authorized release lineage;
3. stale replay certificate cannot authenticate a changed record;
4. a private branch cannot change public topology when approved evidence is
   held fixed.

Every Alloy attack run gets an executable twin and correspondence entry.

## Milestone 10 — connect the inside analyst

**Goal:** let the safe analysis engine produce VRRs without making the safe analysis engine part of the trust claim.

Only after Milestones 1--9 work on scripted analyses:

- `AnalystLoop` emits typed stage/action records;
- dossier claims become/wrap `EvidenceItem`s;
- narrator consumes the same public evidence used by the VRR;
- private model actions appear only in `PrivateExecutionTrace`;
- public provenance exposes approved action classes, not model reasoning;
- locked-plan commitments feed analysis classification.

The LLM should require almost no special handling in replay. Replay starts from
the **typed actions it caused**, not from regenerating the model's text.

## Milestone 11 — DP/global-accounting integration

**Goal:** add quantitative privacy provenance when that subsystem exists.

VRR should eventually record safe public statements such as:

```text
privacy mechanism class
accounting domain
policy version
budget consumed by this release
remaining budget only if safe to reveal
```

Do not export internal accountant state if it creates an oracle.

For stochastic DP releases, add `STOCHASTIC_VERIFIABLE` replay semantics with
protected randomness provenance.

## First demonstration script

Build one command as early as possible:

```sh
uv run python scripts/run_vrr_demo.py --question <bank-id> --out artifacts/vrr-demo
```

It should:

1. choose a fixed NIGHTPLAY question;
2. commit its plan;
3. run an existing scripted analysis;
4. release one GLM/aggregate evidence object;
5. generate the private execution trace;
6. compile public provenance;
7. replay the computation;
8. generate the public bundle;
9. deliberately run one post-hoc follow-up and label it exploratory;
10. run a tamper check against the exported bundle.

This becomes the vertical slice around which abstractions evolve.

## Suggested first-day order

If starting fresh tomorrow, resist parallelising too early. The fastest route to
truth is:

1. `research_record.py`: types + canonical serialization;
2. instrument one existing deterministic path;
3. write a failing replay test;
4. make replay pass;
5. export one ugly JSON record;
6. only then design public provenance/evidence niceties.

A successful first day is **one genuinely replayed record**, not a polished
schema.

## Definition of done for research v0

Research v0 is complete when one NIGHTPLAY result has a public VRR for which:

- the private trace is richer than the public trace;
- public provenance survives private-trace perturbation tests;
- every public number has evidence lineage;
- the plan-order classification is mechanically correct;
- deterministic replay reproduces the result;
- changing the dataset/code/policy/result makes verification fail;
- the bundle is externally signature-verifiable using a test key;
- an exploratory follow-up is labelled as such;
- red-team cases for trace topology, weak commitments, plan laundering and stale
  certificates all fail;
- the existing query/disclosure red team still passes unchanged.

Only then should the VRR become a normative part of the system claim.
