---
id: D9
title: A published result is a verifiable research record, not an AI narrative
date: 2026-08-19
status: accepted
question: >
  If an automated analyst performs increasingly rich and adaptive work inside
  the TRE, what must a researcher be able to show a reviewer so that the
  scientific result is inspectable and reproducible without exposing protected
  data or trusting the model's prose?
clauses: [R6, R8, R11, R19, R20]
evidence:
  - docs/inside-analyst.md
  - docs/answer-level-release.md
  - docs/verifiable-research-record.md
  - docs/verifiable-research-record-build-plan.md
  - docs/vrr-critical-review.md
revisit_when: >
  The first implementation slice has produced a complete record and replay
  certificate for an end-to-end NIGHTPLAY question. At that point promote the
  stable parts into normative R/P clauses. Revisit earlier if public provenance
  itself proves disclosive, or if deterministic replay cannot be made stable
  enough for the registered procedure set.
---

**Status: accepted 2026-08-19 — design direction only; no new security claim is
made until the record/export/replay path is implemented and red-teamed.**

## The decision, stated once

The external artifact of an AI-assisted analysis will be a **Verifiable Research
Record (VRR)**. The VRR is not the model's transcript and does not ask a reviewer
to trust the model. It is a typed, machine-readable record connecting:

1. the scientific question and declared analysis plan;
2. the identity of the protected data snapshot as attested by the TRE custodian;
3. the exact software, procedure registry and disclosure policy that ran;
4. a provenance graph of registered computations;
5. the disclosure-approved evidence that crossed the boundary;
6. a deterministic TRE-side replay result; and
7. an operator/custodian attestation over the resulting record.

The human-facing narrative is downstream of the VRR. It may be written by a
model that sees **public evidence only**, but every data claim in it must trace
to a release object in the record.

## The trust split

The VRR deliberately separates four questions that must not collapse into one
"verified" badge:

- **Scientific validity** — was the question sensible and was the estimand/model
  appropriate? Reviewers and researchers judge this. Formal methods cannot.
- **Computational integrity** — did the declared computation produce the
  reported result under the recorded software/data context? Deterministic replay
  and typed provenance answer this within the stated replay semantics.
- **Data provenance** — did the TRE custodian attest that the computation used
  the declared protected snapshot? The custodian is the trust root for this
  statement; the VRR does not independently prove that the snapshot represents
  reality or was collected correctly.
- **Disclosure/privacy** — was every outward value approved under the declared
  release policy/accounting state? The release boundary and its formal/test
  machinery answer this within their stated assumptions.

A record may be strong on one dimension and weak on another. The format must
state the dimensions separately rather than issue a single boolean.

## The trace is not chain of thought

No model free-text reasoning is required or desired in the VRR. The trace is a
typed DAG of **actions and artifacts**: registered procedure calls, declared
parameters, input references, output identifiers/attestations, release decisions
and plan status. This is enough to reconstruct what happened computationally
without making model reasoning part of the trusted or public surface.

For stochastic planner decisions, the record preserves the typed action that was
chosen and the model/runtime identity needed for provenance. Replay verifies the
scientific computation that followed; it does not need to regenerate the same
language-model token sequence.

## Private trace and public provenance are different types

The complete execution trace stays inside the TRE. A separately compiled
`PublicProvenance` is releasable.

This separation is mandatory for two reasons:

1. **Trace topology can leak.** If a private result determines which branch ran,
   publishing the branch structure can disclose information even when no value
   is shown.
2. **A raw hash can leak.** Hashing a low-entropy private intermediate (for
   example a small count or a Boolean branch result) does not hide it from an
   attacker who can hash every candidate.

Public/high-entropy artifacts may use ordinary content hashes. Private artifacts
instead remain under the internal audit/MAC machinery and are represented
publicly by opaque IDs plus custodian attestation unless a separately specified
hiding-and-binding commitment scheme is introduced. An HMAC is useful for
internal integrity and opaque reference; it is not advertised as an
independently verifiable public commitment.

## Replay, not reenactment

A deterministic verifier inside the TRE re-executes registered computational
stages from the attested data snapshot and recorded execution manifest. The
verifier is ordinary deterministic code, not an LLM.

A stage records one of explicit replay classes:

- **PUBLIC_REPLAYABLE** — all required inputs are releasable; an external
  reviewer can recompute it independently.
- **TRE_REPLAYABLE_EXACT** — some inputs are protected; the verifier reproduces
  it bit-for-bit under the recorded/frozen semantics.
- **TRE_REPLAYABLE_TOLERANCE** — an explicitly registered numerical contract
  permits a pre-declared tolerance; this is never a silent fallback from failed
  exact replay.
- **STOCHASTIC_VERIFIABLE** — an approved stochastic mechanism was used; its
  mechanism, parameters and hidden randomness provenance are recorded, and
  verification follows its declared rule rather than pretending fresh random
  draws should be identical.

Existing cells-first model releases are a particularly strong case: where the
vetted design-cell table is itself released, the statistical fit should remain
externally reproducible from that table.

## TRE precommit becomes a machine property

A plan is `TRE_PRECOMMITTED` only if its commitment entered the append-only audit
history **before the first data-sighted stage it governs**. The label is derived
from event order, never supplied by the model or researcher after the fact.

This is deliberately narrower than claiming full scientific preregistration. It
proves that the recorded TRE execution did not choose the governed plan after
seeing its protected intermediate results. It cannot prove that the researcher
had never seen related data or results before this execution. A future VRR may
separately reference an externally timestamped preregistration as
`EXTERNAL_PREREGISTRATION_ATTESTED`.

Additional analyses remain allowed, but the record distinguishes:

- `TRE_PRECOMMITTED`;
- adaptation based only on already released information;
- privately data-adaptive and explicitly accounted;
- post-hoc exploratory.

This is both a disclosure control and a scientific-integrity control: it makes
machine-speed forking paths visible without forbidding exploration.

## What this decision does not claim

The VRR does not prove that the scientific hypothesis was good, that the dataset
was collected correctly, or that the custodian's declared snapshot represents
reality. It does not make an LLM trustworthy. It does not make a deterministic
SDC system equivalent to differential privacy. It does not prove that no human
exploration occurred before a TRE-precommitted plan.

It aims at a narrower and useful statement:

> **A reviewer can establish what question was asked, what computation ran, on
> which custodian-attested data snapshot and software state, which parts were
> TRE-precommitted or adaptive, what evidence was actually released, and whether
> a deterministic verifier reproduced the reported computation under the
> recorded semantics — without seeing the protected data or trusting the AI's
> narrative.**
