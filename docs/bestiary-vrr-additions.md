# Bestiary additions for Verifiable Research Records

*Candidate cards for the next phase. These are planning mnemonics, not yet part
of the normative bestiary. Promote individual specimens into
[bestiary.md](bestiary.md) only after the corresponding control and keeper
exist in code/tests.*

The VRR phase creates a new attack surface: not just **what result leaves**, but
**what story about the computation leaves with it**. A fabricated or leaky
provenance record can be as dangerous as a bad statistical release.

---

## 🦚 The Peacock — provenance that looks more impressive than it is

**Family proposal:** scientific/provenance integrity.

**Field marks:** beautiful feathers: "verified", "reproducible", "pre-registered",
"formally checked". On inspection, each word refers to a different and weaker
thing than the reader assumes.

**What it wants:** collapse several assurance dimensions into one badge so a
researcher or reviewer over-trusts the result.

Examples:

- `VERIFIED` means only that a JSON file parsed;
- `REPRODUCIBLE` means the public table can be re-read, not that the protected
  computation replayed;
- `PRE-REGISTERED` is a user-supplied Boolean;
- `FORMALLY VERIFIED` describes `QuerySpec` syntax while the paper implies the
  scientific inference was proved correct.

**Cage:** typed verification statuses with narrow semantics:

```text
COMPUTATION_REPRODUCED
DATA_SNAPSHOT_ATTESTED
DISCLOSURE_POLICY_VERIFIED
PLAN_ORDER_VERIFIED
SIGNATURE_VALID
```

Scientific validity has no machine-generated `true` field.

**Keepers:** schema tests that reject generic status labels; reviewer report
snapshot tests; documentation lint for claims that exceed the certificate
semantics.

**Rule:** every green tick must answer one explicit question.

---

## 🕰️ The Time Traveller — pre-registration after seeing the result

**Family:** Ghost/Mirror hybrid; provenance laundering.

**Field marks:** the analysis plan is immaculate, timestamped, and exactly
predicts the result — because it was committed after the private analysis ran.

**What it wants:** turn exploratory/data-adaptive work into apparently
confirmatory work.

**Attack shape:**

```text
observe private result
choose attractive analysis
write plan
commit plan
export record with preregistered=true
```

**Cage:** `PRESPECIFIED` is derived from append-only event order:

```text
plan_commit < first_private_observation_for_stage
```

No researcher/model-supplied Boolean exists.

**Keepers:** executable reversed-order attack; Alloy temporal model; audit-chain
order tests.

**Scientific analogue:** p-hacking with a forged clock.

---

## 🗺️ The Cartographer — the map leaks the territory

**Family:** Imp/Nixie hybrid; provenance side channel.

**Field marks:** every value is hidden, but the public DAG reveals exactly which
private branch ran.

Example:

```text
primary model
   |
   +-- fallback_for_sparse_group  <-- public node exists only if sparse group exists
```

The reviewer learns that the private condition was true from the graph shape.

**What it wants:** encode private values in topology, stage count, retry count,
procedure choice or omission.

**Cage:** deterministic `PrivateExecutionTrace -> PublicProvenance` compiler;
collapse/private subgraphs; fixed public skeletons where required; explicit
release classes for topology.

**Keepers:** metamorphic paired traces with different hidden branches but equal
public evidence must compile to byte-identical public provenance; Alloy model of
branch noninterference.

**Rule:** metadata is output.

---

## 🔐 The Glass Safe — a hash that does not hide the secret

**Family:** Nixie/Imp hybrid; commitment disclosure.

**Field marks:** a private value is "protected" by SHA-256, but the value has
only ten plausible possibilities.

Example:

```text
sha256("7") = ...
```

An attacker hashes `0..20` and learns the protected count.

**What it wants:** make a commitment look like encryption.

**Cage:** never publish raw content hashes for low-entropy private artifacts.
Use keyed/hiding commitments or an internal audit reference plus custodian
attestation. Ordinary hashes are safe for public/high-entropy artifacts such as
software files.

**Keepers:** dictionary-attack tests over planted counts/categories/Booleans;
commitment API type separation between public artifact digest and private
commitment.

**Rule:** collision resistance is not hiding.

---

## 🧵 The Seamstress — stitches a real result to the wrong provenance

**Family:** Doppelgänger/Ghost hybrid; substitution attack.

**Field marks:** every component is individually valid, but they did not belong
together.

Examples:

- result from dataset snapshot B + certificate for snapshot A;
- coefficient from software commit X + manifest from commit Y;
- successful old replay certificate attached after editing the result;
- evidence item linked to a different release record with the same shape.

**What it wants:** exploit weak binding between record components.

**Cage:** canonical record ID and signed root digest covering manifests,
evidence, replay certificate and public provenance; IDs derived/validated from
content where appropriate; replay checks same manifest identities as record.

**Keepers:** component-swap tests; stale-certificate attack; signature tamper
tests.

**Rule:** provenance is a graph of bindings, not a folder of plausible files.

---

## 🧟 The Zombie Certificate — a verification that outlives its object

**Family:** Ghost.

**Field marks:** `COMPUTATION_REPRODUCED` was true yesterday, then someone edits
the result or manifest and keeps the successful certificate.

**What it wants:** separate verification state from the exact bytes it verified.

**Cage:** certificate covers the canonical record/root digest; any public record
change invalidates it. Signing covers certificate + record identities.

**Keepers:** mutate-one-byte tests for result, policy manifest, provenance,
classification and evidence.

---

## 🎣 The Citation Fisher — a claim hooks the wrong evidence

**Family:** Mirror.

**Field marks:** the paper's prose contains a real number and the VRR contains
that number somewhere, so the system declares it supported even though it came
from the wrong model/cohort/analysis.

**What it wants:** replace semantic lineage with number matching.

**Cage:** manuscript claims reference stable `EvidenceItem` IDs, not searched
numbers. Each item carries source stage, estimand/procedure identity and release
record. Narrative checking may use number matching only as a diagnostic, never
as authoritative provenance.

**Keepers:** two evidence items with the same numeric value but different
estimands; claim linked to the wrong one must fail semantic validation.

---

## 🎭 The Method Actor — replay reenacts the model instead of the computation

**Family:** Mirror/Sphinx hybrid.

**Field marks:** verification reruns the LLM and declares failure because it
chooses different words/actions, or success because the model says it remembers
what it did.

**What it wants:** make model stochasticity part of the computational trust root.

**Cage:** replay begins from the typed action/plan that actually executed.
Registered statistical computation is replayed deterministically; model text and
chain-of-thought are not.

Where model identity matters, record it as provenance, not as an object that
must regenerate the same token sequence.

**Keepers:** replace planner/model during replay and show that deterministic
registered computation still verifies from recorded typed actions.

---

## 🎰 The Loaded Dice — stochastic output with fake deterministic replay

**Family:** Imp.

**Field marks:** a DP/noisy stage is rerun with fresh randomness and compared for
bit equality; failure is ignored, or the system fixes a public seed and destroys
the intended privacy semantics.

**What it wants:** exploit ambiguity about what reproducibility means for
randomised mechanisms.

**Cage:** explicit `STOCHASTIC_VERIFIABLE` replay class. Record mechanism,
parameters, accountant event and protected randomness provenance. Either replay
inside the TRE with the same protected seed or verify the mechanism/accounting
contract; never pretend fresh draws should match.

**Keepers:** stochastic replay tests; seed-publication attack; accounting
correspondence tests.

---

## 🗣️ The Court Reporter — publishes everything because "transparency"

**Family:** Parrot.

**Field marks:** private model reasoning, withheld diagnostics or sensitive
intermediate values are copied into the provenance bundle to make the workflow
look transparent.

**What it wants:** turn reproducibility into a new egress channel.

**Cage:** trace of actions/artifacts, not chain-of-thought. Public provenance is
a separately typed/compiled object. Unknown trace fields default private.

**Keepers:** plant hostile/private strings in internal notes and assert none reach
the public bundle; schema allowlist tests.

**Rule:** transparency about computation does not require publication of private
state.

---

## 🧪 The Alchemist — a perfectly reproduced bad analysis

**Family proposal:** scientific-validity anti-pattern; not a security defect.

**Field marks:** every hash matches, replay is exact, the signature is valid —
and the model adjusted for a collider or estimated the wrong causal quantity.

**What it wants:** exploit the human tendency to equate reproducibility with
scientific correctness.

**Cage:** there is no deterministic cage. The VRR exposes the `QuestionSpec`,
estimand, adjustment set, model family and analysis classification so reviewers
can judge them. Machine reports never say `SCIENTIFICALLY_VALID`.

**Keepers:** documentation and reviewer-facing separation of assurance
dimensions; test fixture with an intentionally reproducible but scientifically
wrong analysis to ensure the report does not award it a correctness badge.

**Rule:** reproducible nonsense is still nonsense.

---

## Suggested families to add to the main grammar later

If these cards survive implementation, the existing bestiary may want two new
families rather than forcing everything into the security-only taxonomy:

| Family | Totem | What it wants | Class |
|---|---|---|---|
| **The Peacock** | 🦚 a magnificent badge-covered bird | To make an assurance claim sound broader than it is | provenance/attestation overclaim |
| **The Cartographer** | 🗺️ a map with secret roads drawn in invisible ink | To leak protected facts through provenance structure or commitments | provenance side channels |

The Time Traveller, Seamstress and Zombie can remain specimens within these
families or existing Ghost/Doppelgänger families once their actual findings
exist.

Do not assign finding numbers yet. A beast enters the main reserve only after it
has been reproduced, caged and given a keeper.
