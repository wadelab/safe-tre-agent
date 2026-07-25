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

Deliverables: integration design; ~~a comparison of ACRO's decisions against
the stand-in's over the red-team corpus~~ *delivered 2026-07-17, extended
2026-07-25 with planted dominance anchors ([ACRO comparison](acro-comparison.md)):
over 337 comparable cells the two rule sets disagree in both directions —
ACRO's NK-rule suppresses concentrated pairs the stand-in's 50% bound
releases, and that bound catches single dominant donors ACRO's defaults
release — so neither is a superset and the integration keeps both*;
compatibility notes for TRE operators (started, same page); an updated
gateway section in the preprint.

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
