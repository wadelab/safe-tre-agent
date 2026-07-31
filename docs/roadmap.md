# Roadmap

The forward plan, in priority order. The record of past work lives in the
[hardening log](hardening-log.md) and the
[changelog](https://github.com/wadelab/safe-tre-agent/blob/main/CHANGELOG.md);
this page only says what comes next and why in this order.

One principle drives the ordering: **effort goes to the research core
(`safetre/`), not the demo shell (`safetre_web/`, `deploy/`).** Three hardening
rounds have gone into the shell — identity, channel, sessions, rate limiting —
but a real TRE supplies its own identity and network boundary, so shell work
does not advance the research questions. The shell is frozen: it gets fixes,
not new controls.

## 0. Security follow-ups from round 11

Not a new workstream — the residuals the [round-11 audit](hardening-log.md)
left behind, ordered by what they buy. The first two are cheap and change how
every later round is run, which is why they sit above the fellowship work.

**0.1 — Make the adversarial dataset a first-class artifact.** Three of round
11's findings (#92, #93, #94) are arithmetic that is wrong in general and
correct on the demo data: no measure column holds a NULL, no contribution is
negative, no correlation has one donor carrying all the variance. Each was
found by *constructing* the data that would show it, not by scanning the data
to hand — and a synthetic corpus chosen to be realistic is chosen to be
unexceptional, which is the wrong sampling for finding disclosure defects.
Round 8 added adversarial payloads to `redteam/attacks.yaml` for this reason;
the next step is a generator (`redteam/adversarial_data.py`) whose tables carry
item non-response, cancelling contributions, single-donor variance, extreme
skew and near-zero cell totals, and an `exhaustive` CI job that runs the whole
enumerated skeleton against it. The property is the one the release-equality
tests already state — nothing high-severity leaves — asserted over data chosen
to break it.

**0.2 — Audit the previous round's fixes as new code.** Rounds 10 and 11 both
found their predecessor's work (#82 was round 10's own truncation check; #90
and #91 were round 10's #79 and #76, one week old). In every case the new code
carried a comment asserting the property it was meant to have, true of the
intention and false of the code. A fix that introduces a new key, a new bound
or a new sentinel should enter the next round's scope explicitly rather than
being treated as closed because the finding it answers is closed.

**0.3 — Automate the off-box anchor.** #75 made the chain head readable and
#82 made truncation detectable, but the control that actually survives a host
compromise is still an operator remembering to record a value. A timer that
appends `GET /api/audit/verify`'s `head` to an append-only store off the box —
and alerts when it stops changing, or changes in a way the chain cannot
explain — is a small piece of work that converts a documented control into a
running one. Until it exists, `SAFETRE_AUDIT_HEAD_ANCHOR` is advice.

**0.4 — Give the audit key an epoch.** There is no key rotation story at all:
rotating `SAFETRE_AUDIT_KEY` makes every existing row unverifiable, so the
only rotation available is "start a new chain", which loses the history the
chain exists to protect. A `key_id` column, inside the MAC, with `verify()`
selecting the key per row, makes rotation an ordinary operation. This matters
more now that #81 refuses to start on an unverifiable chain — a well-meant
rotation currently bricks the service.

**0.5 — Declare the population explicitly.** #95's fix treats every dataset in
a definition as one population, on the conservative reading that they share a
`person_key`. That is right for the demo catalogue and over-denies for a
definition holding genuinely disjoint populations (a donors study and a staff
study in one file). An explicit `population:` field per dataset, defaulting to
the person key, would state it rather than infer it — and the Alloy model
should gain the atom, since `disclosure_policy.als` has no notion of a dataset
at all and therefore could not have expressed #95.

**0.6 — Bring the last three dials inside the policy loader.**
`SAFETRE_RATE_LIMIT`, `SAFETRE_AUDIT_VERIFY_RATE_LIMIT` and
`SAFETRE_MAX_BODY_BYTES` are read as bare `int(os.environ.get(...))` straight
into the controls #47 and #64 installed. None has a floor, none is a
`PolicyConfig` field, so none appears in `_cfg.digest()` — which is both the
startup line and the body of the `status=config` audit record #55 added *so
that a release is attributable to the thresholds that allowed it*. Moving them
onto `PolicyConfig` gets them the catalogue, the digest, the audit record and
the floors for free.

**0.7 — Bound how long a request body may take to arrive.** A stalled body
holds a slot in the abandoned-task pool at zero cost to the sender and without
holding a thread, which is a resource the response-time boundary was never
meant to lend out. #91 removed the ability to aim it at a named victim;
bounding arrival in `RequestSizeLimit.counted_receive` — which already wraps
`receive` — removes the resource. Related: anything Starlette's
`ServerErrorMiddleware` answers goes out without the four security headers,
because it sits outside even the raw-ASGI layers. No attacker-reachable
unhandled exception is known on any shipped route, so this is an enumeration
gap rather than a finding, but it is the one response class #77 did not cover.

**0.8 — Lock the npm dependency rather than pinning it.** #101 pinned `pa11y`
by version; a committed `package-lock.json` and `npm ci` would pin the
transitive tree, which is what the rest of the toolchain already gets from
`uv.lock` and the sha256-checked Alloy and Lean downloads.

**Where the timing channel really ends.** Several round-10 and round-11
findings (#76, #91, and the pool residual in 0.7 above) are all consequences of
answering a query on the same call that asked it. The structural answer is the
**asynchronous submit-and-collect** model already recorded under *Parked* below
and in [D5](decisions/D5-timing-channel.md): if a result is collected on a
schedule rather than returned on the call, delivery time has nothing to do with
compute time, there is no pool to hold, and no ceiling to probe. It stays parked
because it is an architectural change to a frozen shell and the interactive demo
is what reviewers use — but every round that touches the response-time boundary
adds to the case for it, and it should be unparked before this is ever pointed
at real data.

## 1. ACRO integration (fellowship WP3)

The disclosure gateway is a stand-in, and it says so. The SDC community will
judge the whole claim on whether the output checking is real, so wrapping
[ACRO](https://github.com/AI-SDC/ACRO) comes before everything else. It brings
the community's production rules — frequency threshold, p% and NK dominance,
missing/negative checks — in the community's own implementation. It does NOT
bring optimal secondary suppression: ACRO's `suppress` masks the failing
cells only (verified against the 0.4.x source), and LP-based complementary
suppression remains τ-Argus/sdcTable territory — so the stand-in's
`_secondary_suppress` stays in force on top. The agent-specific layer —
session auditor, lineage, budget — stays ours and sits on top too.

The cells-first procedure framework composes with it cleanly: ACRO slots in
*underneath* the GLM layer (it vets cells; models consume vetted cells),
rather than needing its own regression checking on day one. Non-gaussian
models with continuous predictors stay parked until ACRO lands (see
[verifiable-extensions §5](verifiable-extensions.md)).

Deliverables: ~~integration design~~ *delivered 2026-07-25
([ACRO integration](acro-integration.md)): the seam sits inside the gateway's
vetting step, the three rule sets compose as a union because none subsumes
another, the checker runs out of process and fails closed, and the
second-moment cell's parameters become a stated policy rather than an
accident*; ~~a comparison of ACRO's decisions against
the stand-in's over the red-team corpus~~ *delivered 2026-07-17, extended
2026-07-25 with planted dominance anchors ([ACRO comparison](acro-comparison.md)):
over 337 comparable cells the two rule sets disagree in both directions —
ACRO's NK-rule suppresses concentrated pairs the stand-in's 50% bound
releases, and that bound catches single dominant donors ACRO's defaults
release — so neither is a superset and the integration keeps both*;
compatibility notes for TRE operators (started, same page); an updated
gateway section in the preprint.

**Rollout, as it stands (2026-07-26).** The seam, the rules and the boundary
are built, and **a configured checker is now used by default**
([D6](decisions/D6-checker-default.md)). `CellVetter` is where rules enter, so
ACRO decides *only* which cells release and never how a release is rounded,
ordered or shaped. ACRO's own implementations run through it, and out of
process behind a versioned contract where every failure denies, because it
cannot be imported into the service environment at all (C3). "Default" cannot
mean "required" for a library a TRE embeds, so it means used whenever
`SAFETRE_CHECKER_CMD` is set; naming the vetter explicitly requires one, and
either way the release records which rules decided it. Measured cost of the
composition: 23 more suppressed cells out of 4684, and 5 of 102 gaussian
models (`artifacts/composite_cost.json`). What is left is the preprint's
gateway section, which still describes the stand-in alone.

## 2. Formal executable specification (fellowship WP2)

The `QuerySpec` space is finite and small, which is what makes it provable.
Encode the catalogue and the `QuerySpec → SQL plan → disclosure` path as a
machine-checkable model (Alloy or TLA+ first; Lean if the invariants warrant
it), discharging the P-clauses of the [specification](specification.md).

A first slice is delivered (spec R16): the registries export their finite
request space (`formal/skeleton.json`), a bounded **Alloy model** generated
from that export checks P19/P21 over every vetting outcome and
P4-admissibility over the exact catalogue atoms, and a CI `formal` job runs
the solver next to pytest.

A second slice followed: the query boundary itself is now proved in
**Lean 4** (`formal/lean/`) — no valid QuerySpec references an identifier
(P3), internal-only columns never reach a group-by or a release (P4),
compiled SQL is a single declared-view read-only SELECT with every value a
bound parameter (P9), and disclosure-role labels are consistent — pinned to
the code by generated artifacts, a 414-case render-equality check against
the live engine, and sync tests. A second Alloy model
(`formal/disclosure_policy.als`) checks the session auditor's simulatable
differencing rule and machine-exhibits its documented residuals.

A third slice delivered the auditor's *temporal* model
(`formal/temporal_session.als`): the `observe → apply → record` event order
over the auditor's mutable state, checking the budget invariant and
exhaustion short-circuit (P17), the fail-closed gate (P7 — the clause the
July round of property-testing showed real bugs land on), and
differencing-pair serialisation under the per-Session lock (P16), with the
hardening #18 race machine-exhibited once the lock assumption is dropped.
A fourth slice delivered the tractable half of *value-level*
noninterference on the query path: a release-equality test
(`tests/test_release_equality.py`) requiring a released frame to be
recomputable, bit for bit, from the gateway-finalized table and the spec, and
to be unchanged when the engine's frame is perturbed in ways finalization
erases. It found two places where released output was still a function of
pre-rounding counts (hardening #27 and #28). What remains on this item is the
quantitative step — replacing "insensitive up to the controls" with a bound —
which is item 3 below, not more of item 2.

This ranks above DP because it hardens the claim we already make, rather than
adding a claim we do not yet make.

## 3. Differential-privacy accountant

The simulatable-auditing argument has one documented residual: the bound
misses differencing that isolates a small group through the interaction of a
common category with a narrow cohort, and catching rare-category isolation
uses one bit of private information (see the
[security model](security.md#side-channels-and-residual-oracles)). A DP
accountant closes both, at the cost of noisy outputs and a harder
explainability story — which is why it ships as an opt-in release mode, not a
replacement for the deterministic gateway.

## 4. Cross-session and cross-user lineage (fellowship WP1 extension)

Persist released-cohort signatures beyond a session so colluding users and
serial sessions are inside the differencing control. Ordered after ACRO and DP
because both change what gets released, and the lineage store should record
the final semantics, not the stand-in's.

## Delivered

Former roadmap items that have shipped; each has a maintained record
elsewhere.

- **Planner-quality evaluation harness** — a scored corpus
  (`evals/corpus.yaml`) and runner (`evals/run_planner_eval.py`) measure
  per-planner spec quality and refusal behaviour; first numbers, method and
  observations in the [planner evaluation](planner-eval.md).
- **CI hardening** — the strict docs build, the red-team harness (exits
  nonzero on any failure), pa11y against the four demo states, and the
  `formal` job (all three Alloy model checks plus the Lean proof replay,
  toolchains sha256-pinned) all run in `ci.yml` next to pytest, bandit and
  pip-audit.
- **Preprint** — `paper/preprint.tex` consolidates the write-up, the
  specification, the red-team results and the planner evaluation into one
  external-facing technical report; builds with `make`, distributed via
  releases. Its gateway section describes the stand-in and is rewritten when
  item 1 lands.

## Parked

- **Asynchronous result delivery (submit-and-collect)** — the structural
  answer to the response-time channel, recorded in
  [D5](decisions/D5-timing-channel.md). If a result is collected on a schedule
  rather than returned on the call, delivery time has nothing to do with
  compute time and there is no channel to narrow; it also matches how output
  checking really works, a queue and a human rather than a request and a
  response, and blunts the wider release-decision oracle of which timing is
  one face. Parked because it is an architectural change to the frozen shell
  and the interactive demo is what reviewers use. Quantisation (spec R18) is
  what makes the interactive version defensible meanwhile; unpark this if the
  system is ever pointed at real data.
- **FHE fixed-analysis backend** — a research experiment combining this
  project with a homomorphic-encryption toolbox: a fixed, manifest-validated
  encrypted statistic (correlation, linear regression) whose decrypted
  aggregate still passes the gateway, session audit and human review. If it
  enters at all, it enters as a fixed tool behind the manifest — no LLM access
  to encryption primitives, no arbitrary encrypted SQL, no bypass of
  validation or release checks — and makes no production cryptographic claim
  until backed by a real FHE scheme (CKKS/BFV/BGV).
- **Container-isolated escalation path** (gVisor/Firecracker) — only if the
  legacy code path is ever promoted; today it exists for the red-team
  narrative.
- **Signed commits and required PR review** — branch protection landed with
  go-public (2026-07-17: green status checks required, no force-push or
  deletion of `main`). Required code-owner review and commit signing stay
  parked while the workflow is a single maintainer committing directly to
  `main`.
- **Git history rewrite to drop old deck binaries** — the full generated decks
  are untracked going forward (the three small plain-language `.ppt` explainers
  are committed deliberately); rewriting history is a separate, destructive
  decision.
