# Next phase: Verifiable Research Records

This is the entry point for the next major research increment.

The aim is to make an AI-assisted protected-data analysis something a researcher
can publish and a reviewer can inspect **without seeing the protected data and
without trusting the AI's narrative**.

Start here, in this order:

1. **Decision:** [D9 — a published result is a verifiable research record](decisions/D9-verifiable-research-record.md)
2. **Architecture:** [Verifiable Research Records](verifiable-research-record.md)
3. **Build order:** [VRR build plan](verifiable-research-record-build-plan.md)
4. **Answer-level privacy motivation:** [From query access to answer access](answer-level-release.md)
5. **Existing analyst architecture:** [The inside analyst](inside-analyst.md)
6. **New attack mnemonics:** [VRR bestiary additions](bestiary-vrr-additions.md)

## First target

Do not begin with DP, global ledgers, a web UI, or a generic workflow engine.

Build one vertical slice:

```text
fixed NIGHTPLAY question
  -> committed plan
  -> existing registered analysis
  -> released evidence
  -> PrivateExecutionTrace
  -> PublicProvenance
  -> deterministic TRE replay
  -> ReplayCertificate
  -> publishable ResearchVerificationBundle
```

The first meaningful success is **one result that genuinely replays from an
attested snapshot and whose public record remains unchanged when irrelevant
private trace details are perturbed**.

Suggested command target:

```sh
uv run python scripts/run_vrr_demo.py --question <bank-id> --out artifacts/vrr-demo
```

## Non-negotiable boundaries

- The LLM is not the verifier.
- The trace is actions/artifacts, not chain-of-thought.
- Private trace and public provenance are different types.
- A raw hash is not a hiding commitment for low-entropy private values.
- `PRESPECIFIED` is derived from audit event order, never asserted by a user or
  model.
- A replay certificate binds to the exact record/manifests/results it verified.
- Machine verification does not claim scientific validity.

## What comes later

Once the deterministic vertical slice is working and red-teamed:

- asymmetric custodian signing;
- Lean proofs of the public/private type boundary;
- Alloy checks for plan order, evidence lineage and provenance noninterference;
- integration with Chimp / adaptive inside analysis;
- differential-privacy provenance and global/cross-user accounting;
- reviewer-facing web rendering if useful.

Until those pieces exist, this work is a research plan rather than part of the
v1.0 safety claim.
