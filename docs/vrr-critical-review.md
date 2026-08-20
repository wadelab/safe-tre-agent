# Critical review of the VRR and answer-level design

*Last-pass design review before implementation. This document records places
where the current planning notes could overclaim, become security-theatre, or
accidentally make a weak property load-bearing. It is intentionally sharper than
the architecture notes.*

## Executive conclusion

The direction is sound if the system keeps one discipline:

> **The intelligent analyst may become more capable, but every public claim,
> release and verification statement must terminate in deterministic authority
> outside the model.**

The design is strongest when it treats the AI as an untrusted proposer and the
TRE as a restricted, authenticated research environment. It weakens whenever it
tries to infer security from natural-language intent, semantic similarity, a
single `verified` badge, or a public hash of something private.

The following corrections are required before implementation claims begin.

---

## 1. Do not call local plan ordering scientific preregistration

### Problem

The current notes use roughly:

```text
plan_commit < first_private_observation_for_stage
```

as the definition of `PRESPECIFIED`.

That proves something useful but narrower: **this execution was committed before
this execution path observed protected results**. It does not prove that the
researcher had not previously inspected the data, run another analysis, learned
the result elsewhere, or chosen the plan after informal exploration.

Calling that full scientific "pre-registration" would overclaim.

### Correction

Use separate terms:

- `TRE_PRECOMMITTED` — mechanically proved by event order inside this TRE
  execution;
- `EXTERNAL_PREREGISTRATION_ATTESTED` — optional reference to an externally
  timestamped registration supplied by the researcher/custodian;
- `PUBLIC_ADAPTIVE`;
- `PRIVATE_ADAPTIVE_ACCOUNTED`;
- `EXPLORATORY_POSTHOC`.

A reviewer may treat `TRE_PRECOMMITTED` as strong evidence about machine-speed
forking paths during the recorded execution. It is not evidence that no prior
human exploration occurred.

### Test implication

The Time Traveller attack remains valid, but the certificate should never imply
more than the event-order property can prove.

---

## 2. HMAC is an internal opaque identifier, not a publicly verifiable commitment

### Problem

A keyed HMAC avoids dictionary attacks by outsiders and fits the current audit
trust model. But an external reviewer without the key cannot independently test
what object it commits to, and the custodian holding the key could compute an
HMAC for a different object later.

So `HMAC(private_artifact)` is useful for **internal binding and opaque public
reference**, but it should not be described as a cryptographic commitment with
strong public binding semantics.

### Correction

Use explicit vocabulary:

- `public_digest` — ordinary content hash for public/high-entropy artifacts;
- `internal_artifact_mac` — keyed integrity/binding identifier inside the TRE;
- `opaque_artifact_id` — public reference to a private object;
- `custodian_attestation` — externally signed statement binding the public VRR
  to the internal record/snapshot.

If later work genuinely needs a public hiding-and-binding commitment, choose and
state a commitment scheme separately. Do not smuggle that claim in through HMAC.

---

## 3. The dataset snapshot is only as trustworthy as the custodian

### Problem

Replay can establish:

> given the dataset object the TRE resolved as snapshot S, code C reproduced R.

It cannot establish that S was the correct source dataset, was collected
properly, or was not replaced by a malicious custodian before attestation.

### Correction

The VRR must say **DATA_SNAPSHOT_ATTESTED**, not `DATA_VERIFIED`.

The custodian attestation should bind:

```text
record_id
internal snapshot identifier
schema/catalogue identity
software/policy identities
replay certificate root
public bundle digest
```

The trust root remains the data custodian/operator. This is acceptable for a
TRE, but it must remain visible.

---

## 4. Replay must run under the recorded semantics, not merely current code

### Problem

A record from commit X cannot be faithfully replayed by commit Y simply because
Y understands the old schema. Dependencies, numerical libraries, catalogue
semantics and policy code may have changed.

A verifier that silently says "current implementation differs, but result still
looks close" becomes a Method Actor/Peacock failure.

### Correction

For research v0 either:

1. replay only records produced by the current exact software/environment
   identity; or
2. provide an archived execution environment/container for the recorded
   software state.

Longer term, a replay service may support versioned procedure implementations,
but it must select them by manifest identity.

Never silently migrate old records before verification. Migration creates a new
record with explicit provenance.

---

## 5. Exact replay is not automatically the right scientific reproducibility claim

### Problem

Bit-for-bit equality is excellent for deterministic infrastructure, but some
scientific procedures may have legitimate platform-level floating-point
variation. Conversely, introducing a generous tolerance can hide a real semantic
change.

### Correction

Replay semantics belong to the registered procedure contract. A tolerance must
be:

- fixed before replay;
- justified by the procedure/numerical backend;
- tight enough that it cannot cross a release/reporting boundary unnoticed;
- tested against perturbations that should fail.

Where possible, preserve bit-exact replay by using the same frozen runtime.
Tolerance is not a recovery mode for failed exact replay.

---

## 6. Public provenance compilation is itself part of the disclosure boundary

### Problem

The current release gateway vets statistical artifacts. The VRR introduces a
second class of outputs: procedure names, branch topology, stage count,
classification, errors, timestamps, software choices and attestations.

It is possible for all numeric evidence to be safe while `PublicProvenance`
leaks the hidden fact.

### Correction

Treat:

```text
compile_public_provenance(private_trace)
```

as a release procedure with its own specification, red team and formal
noninterference property.

Public provenance cannot simply be "metadata" exempt from disclosure review.
Unknown fields default private. New stage types must state what public shape they
induce before the serializer permits them.

---

## 7. Do not make semantic question canonicalisation a security root

### Problem

Two natural-language questions can look equivalent while requesting different
estimands, populations, precision, adjustment sets or sensitivity analyses.
False merge harms scientific integrity; false split harms privacy.

An LLM canonicaliser is especially unsuitable as the deciding security
primitive.

### Correction

Use question canonicalisation only for UX and candidate memoisation.

Load-bearing shared disclosure accounting keys off **executed release
semantics**, such as:

```text
release_domain
population/cohort lineage
quantity / estimand identity
registered procedure and release class
material public parameterisation
```

This follows D10. A `QuestionSpec` may help construct those objects, but free
text or an LLM-derived equivalence judgement never overrides them.

---

## 8. Memoisation has dataset/version semantics

### Problem

"Same question -> same answer" is only safe/correct if the underlying dataset,
policy, software and intended estimand are the same. Reusing an answer after the
data snapshot updates may silently return stale science; recomputing may create a
new release opportunity.

### Correction

A reusable release identity includes at least:

```text
executed release semantics
dataset snapshot identity
policy epoch
reporting precision/release class
```

A new snapshot creates a new candidate release and is accounted accordingly.
The public VRR makes this visible.

---

## 9. Authenticated users help, but authorised insiders remain adversaries

### Problem

Restricting the TRE to verified users materially reduces anonymous/Sybil probing
and supports governance. But it is easy to slide from that fact to "collusion is
mostly a policy problem".

That would weaken the security model.

### Correction

Keep the research core safe against an **authorised adversarial researcher**.
Identity and project approval add controls:

- access restriction;
- attribution;
- rate/quota limits;
- revocation;
- governance consequences.

They do not replace shared statistical accounting. Two approved users can still
subtract their releases.

D10's `ReleaseDomain` must therefore span actors/sessions where releases can
compose.

---

## 10. Release-domain scope is a policy decision and a DoS surface

### Problem

A very broad shared ledger reduces collusion but can allow one project to exhaust
analysis for unrelated users. A narrow scope preserves utility but may miss
cross-project composition.

There is no universally correct tuple such as `(project, population, quantity)`.

### Correction

Make `ReleaseDomain` a custodian-declared object with explicit policy version and
reasoning. Evaluate at least:

- per-project;
- shared-population across projects;
- population + commensurable quantity;
- deliberately adversarial cross-project cases.

The system should expose false-refusal and missed-composition measurements, not
claim the scope is solved by implementation.

---

## 11. Evidence minimisation must not turn into unverifiable summary flags

### Problem

A Boolean such as:

```text
direction_stable: true
```

looks less informative than publishing five sensitivity estimates, but it is
still a statistic selected/computed from protected results. It can be a covert
channel or be scientifically too opaque to audit.

### Correction

Every derived `RobustnessFlag`, `Supported`, `NullResult`, etc. is itself a
registered evidence/release class with:

- deterministic semantics;
- defined inputs;
- disclosure rule;
- provenance;
- replay contract.

"Fewer numbers" is not the security property. **Approved information flow** is.

---

## 12. Evidence selection is more dangerous than evidence computation

### Problem

An agent can compute many individually safe candidate results internally and
choose which one to reveal based on a private fact. The final selected result may
pass ordinary SDC while the choice leaks.

### Correction

For v0, avoid private-data-driven evidence selection entirely. Use a fixed or
TRE-precommitted evidence contract.

Later permit only explicit classes:

1. selection from already public information;
2. selection under a deterministic precommitted rule;
3. privately adaptive selection through a measured/accounted channel.

DP may be useful for class (3), but it is not required for (1) or (2).

---

## 13. Timestamps and ordering can themselves leak

### Problem

VRR provenance will naturally contain execution time, retry timing, issue time
and perhaps stage durations. Fine-grained timestamps can reveal workload,
branching or cohort-dependent computation—the same White Rabbit in provenance
form.

### Correction

Public timestamps have explicit granularity and purpose. Internal event order can
be exact without publishing wall-clock precision. For preregistration/precommit
claims, publish only the minimum externally meaningful ordering/attestation.

Never publish private stage durations by default.

---

## 14. Record identity must not depend on secrets in a way that leaks them

### Problem

Content-addressing the whole private record makes the public record ID another
hash oracle over private topology/values. Random IDs, on the other hand, do not
bind content.

### Correction

Use a random/opaque public `record_id`. Binding comes from the signed canonical
public bundle plus the internal audit record and custodian attestation, not from
making the public identifier a digest of private bytes.

Public artifacts may be content-addressed normally.

---

## 15. Verification should be independently implementable where possible

### Problem

If only the same codebase that produced a result can verify it, replay can share
the producer's bug. The first implementation will necessarily do this, but the
claim should not stop there.

### Correction

Separate two levels:

- **implementation replay** — the recorded software environment deterministically
  reproduces its result;
- **independent recomputation** — for PUBLIC_REPLAYABLE artifacts, a small
  separate verifier/reference implementation reproduces the statistic from
  released ingredients.

Cells-first model releases are a good candidate for the second level. Long term,
keep the VRR schema open enough that another implementation can validate
signatures, manifests and public computations without importing the service.

---

## 16. The verifier is privileged code and needs its own attack surface review

### Problem

A TRE-side replay verifier necessarily resolves private snapshots and may read
private trace/artifacts. A bug in a reviewer-facing replay endpoint could become
a new oracle or egress route.

### Correction

The verifier should initially be an offline/operator-side tool, not a public
interactive endpoint. Its outward result is a fixed-schema `ReplayCertificate`
that itself passes public-provenance compilation.

If remote replay requests are later exposed, they need authentication, quotas,
canonical responses and disclosure review just like analytical queries.

---

## 17. The VRR must capture negative/failed execution without leaking why

### Problem

Scientific provenance benefits from knowing that planned analyses failed or
were refused. But publicising exact exception types, suppressed-stage counts or
which private contingency fired can leak protected facts.

### Correction

Private trace records complete failure detail. Public VRR exposes only
release-approved reason classes, for example:

```text
NOT_ANSWERABLE_DISCLOSURE_POLICY
NOT_ANSWERABLE_UNSUPPORTED_PROCEDURE
ANALYSIS_FAILED_PUBLIC_REASON
```

Data-dependent internal failure distinctions collapse unless they have an
explicit safe public contract.

---

## 18. "Every public number is traced" is necessary but not sufficient

### Problem

Narrative leakage is not limited to numbers. A narrator could disclose category
membership, comparative direction, existence, ordinal position or a rare-event
fact without printing a numeral.

### Correction

The long-term narrative verifier should operate over **typed claims**, not just
number matching. A public sentence must be generated from/linked to an evidence
claim object whose semantics are already approved.

For v0, prefer deterministic rendering over an LLM narrator in the demonstration
bundle. The LLM narrator remains a convenience layer after the public evidence
boundary.

---

## 19. DP should not be assumed to be the destination

### Problem

Earlier answer-level notes make the DP accountant sound like the natural final
solution to global composition. That is too strong for this application and can
push the system toward noisy scientific outputs where deterministic TRE controls
would be more usable.

### Correction

Follow D10:

1. authenticated/authorised access;
2. project and actor operational limits;
3. shared release-domain lineage and deterministic SDC;
4. exact-repeat/release-semantic memoisation where valid;
5. private-selection constraints;
6. DP only for measured residuals or modes that genuinely benefit from a formal
   quantitative privacy bound.

Evaluation should compare these layers rather than treating DP as the expected
winner.

---

## 20. Formal methods should prove authority boundaries, not branding

### Problem

It will be tempting to expand the formal model until the system can say the VRR
is "formally verified". That invites Peacock failure and model/code drift.

### Correction

Keep formal claims narrow and executable:

**Lean**

- public serializers cannot carry private payload types;
- public answer/render functions depend only on public typed objects;
- evidence classes require registered release provenance;
- procedure contracts constrain replay/public outputs.

**Alloy/temporal**

- plan/precommit event ordering;
- release-domain state persists across actor/session changes;
- component binding/certificate freshness;
- public topology noninterference under modeled conditions.

**Tests/red team**

- real serializers, trace compiler, replay and collusion attacks.

Do not claim formal verification of scientific validity, the Python runtime, the
custodian, or all information leakage.

---

## Revised implementation order

The build plan is still basically right, with four changes:

1. Build record + deterministic replay first.
2. Add evidence lineage and private/public provenance separation.
3. Add **AccessContext / ReleaseDomain semantics before global memoisation or
   cross-user claims**.
4. Keep DP, private-data-driven evidence selection and a public replay service
   out of research v0.

The first demonstrator should therefore be:

```text
authenticated synthetic project context
  -> fixed/TRE-precommitted NIGHTPLAY analysis
  -> deterministic registered procedures
  -> ordinary existing disclosure controls
  -> EvidenceItems
  -> PrivateExecutionTrace
  -> disclosure-compiled PublicProvenance
  -> offline TRE replay
  -> narrowly worded ReplayCertificate
  -> deterministic reviewer report
```

Then attack that before adding the safe analysis engine.

## Remaining genuinely open questions

These should remain questions rather than implementation assumptions:

1. **Release-domain scope:** what state should be shared across projects/users
   for realistic TRE policy without unacceptable false refusal?
2. **Evidence granularity:** what minimum public evidence is enough for
   scientific scrutiny without recreating the interactive query surface?
3. **Private adaptivity:** which real research tasks genuinely require the
   agent to condition choices on unvetted information?
4. **Independent verification:** how much of the statistical stack can be
   recomputed from released artifacts by a small independent implementation?
5. **External preregistration:** should a VRR optionally bind to OSF/registry or
   another externally timestamped plan, rather than using TRE precommit alone?
6. **Custodian trust:** whether a later deployment needs stronger transparency
   or multi-party attestation around snapshot identity.

None blocks the first deterministic VRR slice.

## Bottom line

The architecture remains compelling after the critical pass, but the strongest
version is a little less grandiose and more precise:

> **The Safe TRE can make an AI-assisted protected-data analysis unusually
> inspectable: it can attest the protected input context, preserve typed
> computational provenance, mechanically distinguish TRE-precommitted from
> adaptive work, replay registered computations under frozen semantics, bind
> every outward claim to approved evidence, and issue an externally verifiable
> record — while still treating scientific validity and custodian trust as
> explicit human/institutional assumptions.**

That is a strong claim. We do not need to stretch it further.
