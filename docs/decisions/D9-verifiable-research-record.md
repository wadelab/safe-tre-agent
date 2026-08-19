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
clauses: []
evidence:
  - docs/inside-analyst.md
  - docs/answer-level-release.md
  - docs/verifiable-research-record.md
  - docs/verifiable-research-record-build-plan.md
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
- **Computational integrity** — did the declared computation actually produce
  the reported result? Deterministic replay and stage provenance answer this.
- **Data provenance** — was the computation run against the declared protected
  data snapshot? The TRE custodian is the trust root for this statement.
- **Disclosure/privacy** — was every outward value approved under the declared
  release policy/accounting state? The release boundary and its formal/test
  machinery answer this.

A record may be strong on one dimension and weak on another. The format must
state the dimensions separately rather than issue a single boolean.

## The trace is not chain of thought

No model free-text reasoning is required or desired in the VRR. The trace is a
typed DAG of **actions and artifacts**: registered procedure calls, declared
parameters, input references, output commitments, release decisions and plan
status. This is enough to reconstruct what happened computationally without
making model reasoning part of the trusted or public surface.

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

Therefore public artifacts may use ordinary content hashes, but private
artifacts require a hiding/keyed commitment or remain solely under the internal
MAC chain. The public VRR carries only an opaque commitment/attestation that
cannot be dictionary-attacked into the private value.

## Replay, not reenactment

A deterministic verifier inside the TRE re-executes registered computational
stages from the committed data snapshot and execution manifest. The verifier is
ordinary deterministic code, not an LLM.

A stage records one of explicit replay classes:

- **PUBLIC_REPLAYABLE** — all required inputs are releasable; an external
  reviewer can recompute it independently.
- **TRE_REPLAYABLE** — some inputs are protected; the deterministic verifier
  reproduces it inside the TRE and emits an attestation.
- **NONDETERMINISTIC_ACCOUNTED** — an approved stochastic mechanism was used;
  its mechanism, parameters and hidden randomness provenance are recorded, and
  replay follows its declared rule rather than pretending bit equality where it
  is inappropriate.

Existing cells-first model releases are a particularly strong case: where the
vetted design-cell table is itself released, the statistical fit should remain
externally reproducible from that table.

## Pre-registration becomes a machine property

A plan is `pre_registered` only if its commitment entered the append-only audit
history **before the first data-sighted stage it governs**. The label is derived
from event order, never supplied by the model or researcher after the fact.

Additional analyses remain allowed, but the record distinguishes:

- pre-specified;
- adaptation based only on already released information;
- privately data-adaptive and explicitly accounted;
- post-hoc exploratory.

This is both a disclosure control and a scientific-integrity control: it makes
machine-speed forking paths visible without forbidding exploration.

## What this decision does not claim

The VRR does not prove that the scientific hypothesis was good, that the dataset
was collected correctly, or that the custodian's declared snapshot represents
reality. It does not make an LLM trustworthy. It does not make a deterministic
SDC system equivalent to differential privacy.

It aims at a narrower and useful statement:

> **A reviewer can establish what question was asked, what computation ran, on
> which attested data snapshot and software state, which parts were
> pre-specified or adaptive, what evidence was actually released, and whether a
> deterministic verifier reproduced the reported computation — without seeing
> the protected data or trusting the AI's narrative.**
