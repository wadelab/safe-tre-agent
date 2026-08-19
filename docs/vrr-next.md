# Next phase: Verifiable Research Records

This is the entry point for the next major research increment.

The aim is to make an AI-assisted protected-data analysis something a researcher
can publish and a reviewer can inspect **without seeing the protected data and
without trusting the AI's narrative**.

Before building, read these in this order:

1. **Decision:** [D9 — a published result is a verifiable research record](decisions/D9-verifiable-research-record.md)
2. **Critical review:** [VRR critical review](vrr-critical-review.md)
3. **Access/composition decision:** [D10 — authenticated release domains before DP](decisions/D10-authenticated-release-domains.md)
4. **Architecture:** [Verifiable Research Records](verifiable-research-record.md)
5. **Build order:** [VRR build plan](verifiable-research-record-build-plan.md)
   — milestones 0-8 are now implemented; see
   [what is built](verifiable-research-record-implementation.md)
6. **Answer-level privacy motivation:** [From query access to answer access](answer-level-release.md)
7. **Existing analyst architecture:** [The inside analyst](inside-analyst.md)
8. **New attack mnemonics:** [VRR bestiary additions](bestiary-vrr-additions.md)

Where older planning language conflicts with D9, D10 or the critical review,
the newer decision/review documents win until the implementation stabilises.

## First target

**Status: this slice is built.** `uv run python scripts/run_vrr_demo.py` runs it
end to end and `docs/verifiable-research-record-implementation.md` says what is
and is not done. What follows is the target it was built against; keep it here,
because a target is how the next reader judges whether the thing that was built
was the thing that was wanted.

Do not begin with DP, semantic question canonicalisation, global memoisation, a
web UI, or a generic workflow engine.

Build one vertical slice:

```text
authenticated synthetic project/release-domain context
  -> fixed or TRE-precommitted NIGHTPLAY question
  -> existing registered analysis
  -> released evidence
  -> PrivateExecutionTrace
  -> PublicProvenance
  -> offline deterministic TRE replay under matching semantics
  -> ReplayCertificate
  -> deterministic reviewer-facing ResearchVerificationBundle
```

The first meaningful success is **one result that genuinely replays from a
custodian-attested snapshot and whose public record remains unchanged when
irrelevant private trace details are perturbed**.

The command, which now exists:

```sh
uv run python scripts/run_vrr_demo.py --question headline-association \
    --out artifacts/vrr-demo
```

## Non-negotiable boundaries

- The LLM is not the verifier.
- The trace is actions/artifacts, not chain-of-thought.
- Private trace and public provenance are different types.
- Public provenance is itself a disclosure surface.
- A raw hash is not a hiding commitment for low-entropy private values.
- HMAC/private MACs are internal binding tools, not advertised as publicly
  verifiable commitments.
- `TRE_PRECOMMITTED` is derived from audit event order. It is not the same claim
  as external scientific preregistration.
- A replay certificate binds to the exact record/manifests/results and replay
  semantics it verified.
- Replay uses the recorded/frozen implementation semantics; there is no silent
  replay under newer code.
- Machine verification does not claim scientific validity.
- Identity and authorisation reduce probing and make abuse attributable, but
  authorised users remain inside the adversary model.
- Cross-user safety keys off custodian-defined release domains and executed
  release semantics, not an LLM deciding that two English questions are the
  same.

## What comes later

Once the deterministic vertical slice is working and red-teamed:

- `AccessContext` / shared `ReleaseDomain` implementation and collusion tests;
- asymmetric custodian signing;
- Lean proofs of the public/private type boundary;
- Alloy checks for plan order, evidence lineage, release-domain persistence and
  provenance noninterference;
- integration with Chimp / adaptive inside analysis;
- private-data-driven evidence selection only when its utility is demonstrated
  and its channel is controlled;
- DP only for measured residuals or modes that genuinely benefit from a
  quantitative privacy guarantee;
- reviewer-facing web rendering if useful.

Until those pieces exist, this work is a research plan rather than part of the
v1.0 safety claim. That remains true of the built slice: it is a research
increment with its own tests and red-team cases, and nothing in the v1.0
disclosure argument depends on it.
