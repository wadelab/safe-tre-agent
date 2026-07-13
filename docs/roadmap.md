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
[ACRO](https://github.com/AI-SDC/ACRO) comes before everything else. It also
subsumes work the stand-in only approximates: full multi-dimensional secondary
suppression (an LP problem), class disclosure, and production p%-dominance.
The agent-specific layer — session auditor, lineage, budget — stays ours and
sits on top.

The cells-first procedure framework composes with it cleanly: ACRO slots in
*underneath* the GLM layer (it vets cells; models consume vetted cells),
rather than needing its own regression checking on day one. Non-gaussian
models with continuous predictors stay parked until ACRO lands (see
[verifiable-extensions §5](verifiable-extensions.md)).

Deliverables: integration design; a comparison of ACRO's decisions against the
stand-in's over the red-team corpus; compatibility notes for TRE operators;
an updated gateway section in the preprint.

## 2. Formal executable specification (fellowship WP2)

The `QuerySpec` space is finite and small, which is what makes it provable.
Encode the catalogue and the `QuerySpec → SQL plan → disclosure` path as a
machine-checkable model (Alloy or TLA+ first; Lean if the invariants warrant
it), discharging the P-clauses of the [specification](specification.md).

A first slice is delivered (spec R16): the registries export their finite
request space (`formal/skeleton.json`), a bounded **Alloy model** generated
from that export checks P19/P21 over every vetting outcome and
P4-admissibility over the exact catalogue atoms, and a CI `formal` job runs
the solver next to pytest. What remains is the original core: the P1–P9
query-boundary model — starting with P7 (fail-closed), the clause the July
round of property-testing showed real bugs land on — and the auditor's
temporal model (`observe → apply → record`).

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
  nonzero on any failure), pa11y against the four demo states, and the Alloy
  model check all run in `ci.yml` next to pytest, bandit and pip-audit.
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
- **Branch protection + signed commits** — at go-public: require PR review
  from code owners and green status checks, no force-push to `main`,
  optionally signed commits. Deliberately deferred because it slows the
  current solo straight-to-`main` workflow.
- **Git history rewrite to drop old deck binaries** — the decks are untracked
  going forward; rewriting history is a separate, destructive decision.
