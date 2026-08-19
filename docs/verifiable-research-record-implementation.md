# Verifiable research records: what is built

*The state of the [build plan](verifiable-research-record-build-plan.md) in
code. Milestones 0–8 are implemented and pinned by tests; 9–11 are not started,
and the record says so about itself rather than leaving a reader to assume.*

Run the whole thing:

```sh
uv run python scripts/run_vrr_demo.py --question headline-association \
    --out artifacts/vrr-demo
```

That command commits a plan, runs a scripted NIGHTPLAY analysis through the
unchanged gateway, records what happened, compiles the public half, replays the
computation from the attested snapshot, exports a signed bundle, runs a
deliberate post-hoc follow-up and watches it get labelled exploratory, then
tampers with the export and watches verification fail. No language model is
involved at any point, so a failure is a provenance failure.

## The modules

| Module | Milestone | What it is |
|---|---|---|
| `safetre/research_record.py` | 0, 6 | the five record types, disclosure classes, commitments, manifests |
| `safetre/recorder.py` | 1, 5, 6 | a plan run + the audit chain → a private execution trace |
| `safetre/evidence.py` | 3 | released numbers → evidence items with lineage |
| `safetre/provenance.py` | 4 | private trace → public provenance |
| `safetre/replay.py` | 2 | re-run the committed plan → replay certificate |
| `safetre/attestation.py` | 8 | asymmetric signature over the bundle |
| `safetre/vrr_bundle.py` | 7 | export, deterministic report, offline check |

Nothing in the release path changed. `plan.py`, `service.py` and
`disclosure.py` are untouched; the recorder reads the seams they already had —
the `PlanRun` the executor returns and the rows the audit log wrote. The one
addition to existing code is `AuditLog.rows_since`, a read-only accessor that
returns each row's chain position and MAC so a record can *refer* to a row
rather than copy it. That matters: if building the record had required a new
execution path, the record would be evidence about a path that only exists when
somebody is recording.

## The two boundaries

**Disclosure is a construction-time obligation.** Every field of every record
type is classified `PUBLIC`, `OPAQUE_ATTESTATION` or `PRIVATE_ONLY`, and the
check runs when the class is created, not when it is serialized — a record type
with an unclassified field raises at import. The failure this guards against is
mundane and certain: somebody adds a field, and the next exporter publishes it
because publishing was the default.

**A raw hash is not a hiding commitment.** Released artifacts get a plain
SHA-256 a reviewer can recompute from the values in the bundle. Everything else
gets a keyed HMAC under a key that never leaves the safepod, and surfaces as an
`OPAQUE_ATTESTATION` — an internal binding tool, never advertised as publicly
verifiable. The distinction is the point: the private artifacts a record needs
to bind are the low-entropy ones (a suppressed count, a branch outcome, a
category name), and an unkeyed hash of any of those is a lookup table.

## Public provenance is compiled, not filtered

A public provenance node exists because a released number needs explaining,
never because a stage ran. Walk the stage list instead and the shape of the
public graph starts answering questions about the cohort — how many stages the
gateway denied, whether a data-sighted contingency fired, how many retries a fit
needed — which is what the gateway's single canonical refusal exists to refuse
one layer down.

`tests/test_vrr_provenance.py` pins this as a release-equality property. Paired
traces differ in exactly one private thing at a time — suppressed cell count,
rejected candidate model, private branch decision, retry count, sparse category,
private diagnostic — and the canonical public bytes must not move. A control
test changes something public and requires that they do, so the file cannot pass
by comparing two constants.

## Pre-specification is derived, and narrower than it sounds

A stage is `TRE_PRECOMMITTED` only if the row committing its governing plan sits
earlier in the audit chain than the row the stage itself wrote. Run the analysis
first and commit the plan afterwards — the laundering attack — and it comes out
`EXPLORATORY_POSTHOC`. So does a stage the chain never witnessed, which is the
fail-closed reading: a stage the audit history cannot see is not one it can
vouch for.

**The chain has to be authentic first, and the first version of this did not
check.** `TRE_PRECOMMITTED` is a claim about the order of audit rows, and
`recorder.trace_from_plan_run` originally took a list of rows and trusted it.
Measured: run the laundering flow so the chain honestly reads
`EXPLORATORY_POSTHOC`, then reorder the rows in the database so the plan
commitment comes first, and the label became `TRE_PRECOMMITTED` while
`verify()` returned `False` to nobody. That is hardening #59's shape one layer
up, and `AuditLog.since` states the rule it broke: any caller that rebuilds a
control from those rows owes the same gate `SessionStore.rehydrate` pays.

The fix removes the footgun rather than documenting it. The recorder takes the
audit *log*, not a list of rows, and verifies it — there is no parameter for
pre-read rows and no flag to assert the chain is fine. An unverified chain does
not refuse to build a record, because the evidence lineage and the replay stand
on the released artifacts and are worth having; it refuses the one claim that
rests on chain order. Every stage comes out `EXPLORATORY_POSTHOC`, the audit
citations and the plan reference are dropped, and `audit_chain_verified: false`
is published in the provenance and stated in the report, so the record says what
happened instead of quietly reading as exploratory work.

One related weakness went with it. A request is untrusted content, so an analyst
can submit an ordinary query whose text is a plan stage's sub-question verbatim;
correlating stages to rows on text alone would cite the decoy. Both the text and
the gateway's verdict now have to agree, and a mismatch resolves to unwitnessed.

The label is deliberately not called pre-registration.
[D9](decisions/D9-verifiable-research-record.md) and the
[critical review](vrr-critical-review.md) are explicit that event order inside
one TRE execution shows this execution did not choose its plan after seeing its
own protected intermediates, and shows nothing about what the researcher had
seen before the session opened. The generated report says so in those words.

## The bundle

```text
artifacts/vrr/<record_id>/
  record.json  provenance.json  evidence.json  replay_certificate.json
  software_manifest.json  dataset_manifest.json  disclosure_manifest.json
  attestation.json  README.md
```

Two files beyond the build plan's seven. The dataset manifest carries the
population declaration — the denominator no number in the bundle states for
itself — and the attestation travels with the thing it signs rather than beside
it.

`README.md` is a pure function of the JSON, so `verify_bundle_dir` re-renders it
and compares bytes. A Markdown file a reviewer reads but cannot re-derive is
prose asserting things about data they cannot see, which is the thing being
replaced.

Signing is Ed25519 over a payload that names what it covers: the record id and
schema version, the public bundle digest, the replay certificate digest and the
three manifest digests. `cryptography` is used when installed; otherwise the
fallback is the RFC 8032 reference implementation in `safetre/attestation.py`,
pinned against the RFC's own vectors. **The fallback is for research v0 and test
keys** — it is readable and correct, not constant-time — and the bundle records
which backend signed it.

## The bestiary's keepers

`docs/bestiary-vrr-additions.md` names eleven beasts and, for each, the
executable checks that cage it. Nine now have keepers; the doc's own rule is that
a beast enters the main reserve only once it has been reproduced, caged and given
one, so those nine are ready to promote and be numbered.

| Beast | Keeper |
|---|---|
| 🦚 Peacock | closed status vocabularies (`ReplayOutcome`, `EvidenceKind`, `ArtifactRole`), a per-dimension assurance table in the report, schema tests rejecting eight generic labels |
| 🕰️ Time Traveller | reversed-order laundering attack; audit-chain reordering attack; decoy-row attack |
| 🗺️ Cartographer | six paired-trace perturbations, all six at once, and a control |
| 🔐 Glass Safe | a real dictionary attack: recovers the value from an unkeyed hash, fails against the keyed commitment |
| 🧵 Seamstress | component-swap, stale-certificate and signature-tamper tests |
| 🧟 Zombie Certificate | five one-change tamper tests plus report-edit detection |
| 🎣 Citation Fisher | identity covers procedure, stage and keys, so same-value-different-estimand items stay distinct; collision raises |
| 🗣️ Court Reporter | six planted canaries across every private field, with a control proving the sweep can fail |
| 🧪 Alchemist | NIGHTPLAY's planted confounder (T2) as a record that replays exactly, verifies, and is wrong by a third — asserted to earn no correctness badge |

Two are deferred with reason. 🎭 **Method Actor** needs a model in the path
(milestone 10); there is none, so the keeper would be vacuous. 🎰 **Loaded Dice**
needs a stochastic release (milestone 11); `NOT_REPLAYABLE` exists so a future
one cannot be filed as exact, and nothing in v0 releases under it.

### What the Peacock cost

Its cage is "typed verification statuses with narrow semantics", and the first
version used free strings: `ReplayCertificate(outcome="VERIFIED")` and
`EvidenceItem(kind="ScientificallyValid")` were both accepted. The test that
looked like the keeper checked the value `replay()` returns, not the value the
type permits — a weaker claim, and the wrong one when the certificate is the part
that gets quoted.

The second half of the cage was missing too. The bestiary lists five assurance
dimensions precisely because collapsing them is the trick, and section 9 of the
report now gives each its own row, its own status and its own basis. That
surfaced something the prose had buried: **`DATA_SNAPSHOT_ATTESTED` is not
established in v0.** The snapshot commitment is a keyed HMAC the custodian holds,
not a signature a reader can check, so "the computation reproduced" carries no
claim that the data were what the manifest says. The table says so in the row
next to the green ticks rather than in a caveat further down.

## Research v0 against its own definition of done

| Criterion | State |
|---|---|
| the private trace is richer than the public trace | met — the probe, the excluded level, the rewritten filter and the gateway's findings are all private |
| public provenance survives private-trace perturbation | met — six perturbations, plus all six at once |
| every public number has evidence lineage | met — coefficients, design cells and the fit block |
| plan-order classification is mechanically correct | met, including the laundering attack |
| deterministic replay reproduces the result | met — `COMPUTATION_REPRODUCED`, and one test isolates the execution leg by perturbing the snapshot with a matching manifest, so a replay that only compared recorded commitments to themselves would fail it |
| changing dataset/code/policy/result fails verification | met — six failure tests |
| the bundle is externally signature-verifiable with a test key | met |
| an exploratory follow-up is labelled as such | met — demo step 9 |
| red-team cases for trace topology, weak commitments, plan laundering and stale certificates fail | met — plus chain reordering and a decoy audit row |
| the existing query/disclosure red team passes unchanged | met — 29/29, unchanged |

## Milestone 9: the Alloy slice

`formal/vrr_record.als`, wired into `formal/run_checks.py` and
`formal/correspondence.yaml`, five solver-checked properties and eight runs.
Five Alloy models now, twenty-five checks.

The other models are about a release; this one is about the RECORD of one. Its
value is not the five checks — a compiler entails its own properties — but the
five satisfiable runs, each dropping exactly one clause of the compiler and
exhibiting a real disclosure:

| Run | One clause dropped | What a reader recovers |
|---|---|---|
| `F109PlanBodyPublished` | the plan body is published beside the node list | the refused stages, by set difference |
| `F110NotAnswerablePublished` | published evidence may cite a stage that released nothing | the refused stages, by `source_stage` |
| `F108ReorderedChainBuysTheLabel` | the chain's authenticity is not checked | `TRE_PRECOMMITTED` on a reordered chain |
| `StaleCertificateAcceptedWithoutTheRule` | the verifier's equality rule | a certificate over evidence it never covered |
| `BranchVisibleWithoutTheRule` | the topology is a function of evidence alone | a node that exists because of a private decision |

Every one has an executable twin in `formal/correspondence.yaml`, which the
correspondence test enforces in both directions: an attack run with no twin is
a model claiming an attack nobody has reproduced, and a renamed twin breaks the
build rather than orphaning the instance. Three guard runs keep the checks
non-vacuous, and one of them — `someRefusedStage` — is the one that matters:
without it every check would be about records with nothing to hide.

The properties are stated over what a READER can recover, not over which field
the compiler wrote. That framing is the lesson of round 14: #109 and #110 were
both fields correctly omitted from one place and recoverable from another, and a
model asserting "the compiler dropped it" would have held throughout.

**Milestone 9's Lean half is drafted, not done.** `formal/lean/draft/Record.lean`
covers all four targets — the noninterference theorem
(`compile_ignores_private_state`), the release-lineage obligation, the renderer's
type, and the `nameable`-stages theorem that is the Lean twin of the Alloy
model's `PublicRecordNamesOnlyReleasingStages`, with #109 and #110 as named
corollaries.

It sits in `draft/` rather than `SafeTre/` because **it has never been compiled**:
CI runs `lake build` on every push and the sync test requires every module under
`SafeTre/` to be imported by the root, so filing an unchecked file there would
turn the formal job red and claim a proof nobody has replayed. Promote it with

```sh
git mv formal/lean/draft/Record.lean formal/lean/SafeTre/Record.lean
# add `import SafeTre.Record` to formal/lean/SafeTre.lean
cd formal/lean && lake build
```

and expect to fix the list lemmas: the project has no Mathlib, so only Lean 4
core is available, and the three proofs marked `(?)` in the file are where core's
names and shapes are most likely to bite. The Alloy half stands on its own and is
solver-checked in CI.

## Merging this to main: what the off switch is

There is no feature flag, and that is deliberate — the layer is off in a stronger
sense than a flag provides.

**The dependency arrow points one way.** The record modules import the gateway's
types; no module the gateway uses imports a record module. Building a record is
not a thing the release path can do, so it cannot be slowed, broken or influenced
by one. `tests/test_vrr_isolation.py` pins it both statically (an AST walk over
every module in `safetre` and `safetre_web`) and at runtime (a subprocess that
imports the gateway and asserts no record module reached `sys.modules`). Without
that check the property would be true today and quietly false after the first
convenient import.

**And it must be configured, not merely called.** `internal_commitment_key()` has
no default and raises: a record cannot be built until an operator sets
`SAFETRE_VRR_COMMIT_KEY`, because the fallback would be an unkeyed hash of
low-entropy private values.

So a deployment that wants none of this gets none of it by doing nothing, and a
deployment that wants it turns it on by calling it with a key. What merging does
NOT do is make the VRR part of the v1.0 safety claim — that is a separate
decision, and [the entry guide](vrr-next.md) still says the answer is not yet.

The one thing to weigh before merging: the required-checks list in `AGENTS.md`
grows a third red-team corpus (`redteam/run_vrr_redteam.py`, about a minute), and
CI's formal job grows a fifth Alloy model.

## What is deliberately not done

Milestone 9's Lean targets, and milestones 10 and 11: the connection to the
inside analyst, and DP/global accounting. The
[`AccessContext`/`ReleaseDomain`](decisions/D10-authenticated-release-domains.md)
implementation is also outstanding — `release_domain` is recorded as a string
placeholder so the field exists before the machinery that enforces it.

Until those exist this remains a research increment rather than part of the
v1.0 safety claim, exactly as [the entry guide](vrr-next.md) says.
