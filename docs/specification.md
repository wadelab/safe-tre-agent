# Specification

This is the normative specification for `safe-tre-agent`: what the system must
do, and what it must never do. It is the source of truth the code and tests are
written against, and the list of properties the
[formal-methods work](FORMAL_METHODS_ANALYSIS.md) aims to prove. The prose
[security model](security.md) explains *why* each control exists; this page
states the requirements as testable clauses.

The requirements cover the **secure path** — the QuerySpec gateway that the web
interface uses and that carries the whole security claim. The legacy
"LLM-writes-pandas" path is out of scope here except where a prohibition names
it (see [N3](#non-goals-what-it-does-not-claim)).

## Conventions

**MUST** / **MUST NOT** are absolute requirements; a build that violates one is
non-conformant. **SHOULD** marks a strong recommendation an operator may
knowingly override (in the sense of RFC 2119). Each clause has a stable
identifier — `A` for assumptions, `R` for requirements, `P` for prohibitions,
`N` for non-goals — so tests, commits, and reviews can cite it. The
[traceability table](#traceability) maps every clause to the module that
implements it, the test that checks it, and its status.

## Definitions

- **Planner / model** — the language model that turns a natural-language request
  into a proposed query. Untrusted.
- **QuerySpec** — a typed, declarative aggregate query over an allowlisted
  catalogue. The only thing the model produces that reaches execution.
- **Gateway** — the safe-outputs stage: minimum cell size, dominance,
  influence, suppression, count rounding.
- **Cohort** — the set of individuals a query's filters select, identified by
  its normalized filter predicate.
- **Cell** — one row of an aggregate result (one combination of group-by
  values).
- **Donor** — a synthetic study participant; the unit the disclosure rules
  protect. On real data, a person.
- **Marginals** — the per-value distinct-donor counts the differencing auditor
  decides from.
- **Safepod** — the physical/logical enclave: the app and data on one host,
  reached only over a restricted channel.

## Assumptions (the trust model)

The requirements hold only under these assumptions. They are the boundary of the
claim.

- **A1** — The planner is untrusted. It may be prompt-injected by the data,
  buggy, or adversarial. No requirement depends on the planner behaving.
- **A2** — The data may be hostile. Any string field may carry an injection,
  SQL/DDL, tool-call spoof, or spreadsheet-formula payload.
- **A3** — The operator supplies the network boundary and an upstream identity
  proxy. The app enforces the restricted channel and reads the proxy's identity
  header; it does not itself authenticate users.
- **A4** — The audit HMAC key and the off-box chain anchor live outside the app
  host.
- **A5** — A real deployment runs a **local** model inside the safepod. A remote
  model endpoint is an egress channel and is permitted for synthetic data only,
  behind an explicit opt-in.
- **A6** — The data in this repository is synthetic.

## Requirements — what it MUST do

**R1** — The system MUST accept a natural-language request and obtain a proposed
QuerySpec from the planner, treating the result as untrusted input.

**R2** — The system MUST validate every QuerySpec against the typed allowlist
before any execution, and MUST reject a non-conforming spec with a reason,
running nothing.

**R3** — The system MUST compile a validated QuerySpec to parameterised,
read-only SQL over public views, and execute it under fixed resource caps
(memory, threads, row cap).

**R4** — The system MUST support exactly the aggregate measures registered in
the procedure registry: `count`, `mean`, `sum`, `sum_sq`, and Pearson `corr`.
A correlation result MUST carry its two-sided p-value and its `n`. *(Amended
with the procedure framework: the registry, not this sentence, is the
enumerated source of truth — see R14.)*

**R5** — The gateway MUST apply, to every result: a minimum distinct-donor
threshold, contributor dominance (the p%-rule) for `sum`/`mean`, single-donor
influence for `corr`, count rounding, and primary plus complementary
suppression.

**R6** — The system MUST keep per-session lineage: record each released cohort,
flag a new cohort within the differencing threshold of a prior one, and enforce
a per-session query budget.

**R7** — The system MUST route any residual (non-suppressable) finding to a
human-in-the-loop decision that either escalates for review or denies.

**R8** — The system MUST append every request — released, redacted, or denied —
to the HMAC-chained audit log, and MUST expose a verification endpoint that
checks the chain against an off-box anchor.

**R9** — The system MUST publish its disclosure-safe metadata contracts: the
capability **manifest**, the schema **codebook**, and the **marginals**
(safe donor frequencies).

**R10** — The system MUST enforce the restricted channel and the Safe People
allowlist on every request path, query and metadata alike.

**R11** — Every release decision MUST be inspectable: the validated QuerySpec,
the compiled SQL plan, the findings, and the ordered pipeline trace MUST all be
available for the request.

**R12** — The project MUST provide a red-team harness that replays the attack
suite with the gateway off and on and reports what leaked in each case.

**R13** — When a real model is configured but missing or unreachable, the system
MUST fail loudly; it MUST NOT silently fall back to the deterministic mock
planner (which would quietly degrade result quality). The mock is opt-in for
tests and CI.

**R14** — Every statistical procedure MUST be implemented as a registered
procedure object that declares and discharges its obligations — admissibility,
compilation safety, an influence control or cell-vetting inheritance, lineage
identity, an **output contract** (released columns with their disclosure
classes), and a **finite skeleton export** — before it is reachable from any
request. The registry MUST be the sole dispatch point for validation,
compilation, execution, and disclosure classification; an unregistered function
MUST fail loudly, never fall through to another procedure's behaviour.

**R15** — The system MUST support generalized linear models (`gaussian`,
`binomial`, `poisson` families; canonical links only; categorical terms only)
fitted **exclusively from gateway-finalized design-cell aggregates**. A model
release MUST carry the coefficient table (term, level, estimate, std_error,
statistic, p_value), the model summary block (family, link, rounded n,
df_resid, deviance), and the vetted cell table it was fitted from, so the
analyst can reproduce the fit from released data alone.

**R16** — Every registered procedure MUST export its finite request skeleton as
data, and CI MUST both check the committed formal model against that export
(generation drift fails the build) and run the bounded model check.

**R17** — The system MUST accept a literal spec — a request that is a single
JSON object — in place of a natural-language request, bypassing the planner.
A literal spec is subject to every downstream control unchanged: typed
allowlist validation, the session budget, engine caps, the gateway, lineage,
and audit. Only the natural-language gates — intent vetting and the
request↔spec fidelity checks — are inapplicable, because the analyst authored
the spec and there is no translation to be unfaithful to (under A1 the planner
is untrusted, so an analyst-authored spec introduces no new trust). A request
that begins as a JSON object but does not parse MUST be rejected loudly; it
MUST NOT be handed to the planner as text.

## Prohibitions — what it MUST NOT do

These are the safety invariants. They hold for every request, whatever the
planner proposes and whatever the data contains.

**P1** — MUST NOT execute model-authored code or SQL. The only model output that
reaches execution is a validated QuerySpec.

**P2** — MUST NOT return row-level records. Only aggregates leave the gateway.

**P3** — MUST NOT expose direct identifiers (`donor_id`), free text, or raw
timestamps. These are absent from every allowlist and every public view.

**P4** — MUST NOT let an internal analysis variable (for example raw
`age_years`) be grouped, returned, or otherwise leave. It may only feed a fixed
internal tool.

**P5** — MUST NOT release a cell whose distinct-**donor** count is below the
threshold. The threshold protects individuals, so it counts donors, not rows.

**P6** — MUST NOT release a `sum`/`mean` cell one contributor dominates beyond
the p% share, nor a `corr` cell where removing a single donor moves *r* beyond
the influence threshold.

**P7** — MUST NOT release on an unresolved safety check. An unknown dominance or
influence fails **closed** — filled with `+inf` and suppressed — never defaulted
to safe.

**P8** — MUST NOT accept a QuerySpec with unknown fields, an off-catalogue
dataset, column, or measure, or an operator invalid for a column's type.

**P9** — MUST NOT interpolate filter values into SQL. Values are always bound
parameters; column and view identifiers are regex-checked against a strict
pattern before quoting.

**P10** — MUST NOT put the quantity a differencing attack seeks (a total delta
or symmetric-difference size) into any caller-visible message or the audit
trail. Refusals are non-numeric.

**P11** — MUST NOT decide a differencing denial from the live donor sets. The
decision MUST be a function of the published, simulatable marginals only, so a
refusal discloses nothing an analyst could not already compute. *(One residual
bit — isolating a sub-threshold category — is the documented deviation a DP
accountant closes; see [N1](#non-goals-what-it-does-not-claim).)*

**P12** — MUST NOT publish, in the marginals, a sub-threshold donor count or any
value outside a column's declared domain. An undeclared value (a hostile string
smuggled into a field) is disclosive by its name, so it is dropped entirely, not
count-nulled.

**P13** — MUST NOT trust the identity header on a channel wider than loopback
without an explicit operator opt-in (and, if configured, a proxy shared secret).
Otherwise identity fails closed.

**P14** — MUST NOT serve any request — query or metadata — that arrives outside
the restricted channel or from an identity not on the allowlist.

**P15** — MUST NOT let the audit log be silently rewritten. Verification uses a
keyed (HMAC) chain, so an attacker who can edit the database but not the off-box
key cannot forge a valid chain.

**P16** — MUST NOT let concurrent requests from one identity bypass the session
controls. The `observe → apply → record` critical section is serialised per
session.

**P17** — MUST NOT do planner or engine work once the session budget is spent; an
exhausted budget denies first.

**P18** — MUST NOT render any data table on a denial.

**P19** — MUST NOT fit or release a model over an incomplete vetted cell table.
If any design cell of any underlying aggregate is suppressed by the gateway, or
absent from the full grid of observed levels, the whole model MUST be denied —
loudly, with no category merging and no cell dropping. *(A level with no data
anywhere is omitted from the design and is visibly absent from the released
cell table; that is an omission the release itself shows, not a silent repair.)*

**P20** — MUST NOT release per-observation model outputs: residuals, fitted
values, leverage, influence scores, or per-donor predictions. Only the fixed
coefficient table, the model summary block, and the vetted cell table leave the
gateway. *(Extends P2 to model procedures.)*

**P21** — Model outputs MUST be a deterministic function of the finalized
(post-rounding, post-suppression) vetted cell tables alone. The fitter MUST NOT
read row-level data, internal views, or unfinalized aggregates. *(Machine-checked:
refitting from the released artifacts reproduces the released coefficients
exactly.)*

**P22** — A model refusal MUST be decidable from the vetted cell decisions and
released-equivalent quantities alone — the same information the equivalent
aggregate queries would reveal — and refusal messages MUST stay non-numeric
about any private quantity. *(P10/P11-style: a model denial discloses nothing an
analyst could not already learn from permitted queries. Estimability refusals
may name the aliased or separated term, because rank and separation are
computable from the released cell table itself.)*

## Non-goals — what it does NOT claim

Stated so the claim is not over-read. Several are roadmap items, not permanent
exclusions.

- **N1** — Not a differential-privacy system. The controls are statistical
  disclosure controls; there is no epsilon budget or calibrated noise. DP is a
  [roadmap](roadmap.md) item.
- **N2** — Does not defend across sessions or colluding users. Lineage is
  per-session; global accounting needs DP.
- **N3** — The legacy analyst sandbox is defence-in-depth illustration, **not** a
  secure jail. A production code path would need container isolation
  (gVisor/Firecracker).
- **N4** — Not a production SDC engine. `safetre/disclosure.py` is a lightweight
  stand-in; integrating ACRO is the target ([roadmap](roadmap.md)).
- **N5** — Does not authenticate users itself. It trusts a specific upstream
  identity proxy under [A3](#assumptions-the-trust-model) and
  [P13](#prohibitions-what-it-must-not-do).
- **N6** — Makes no cryptographic-confidentiality claim for computation or
  storage beyond the audit chain — no encryption at rest by the app, no FHE.

## Traceability

Each safety prohibition maps to the module that enforces it and the test that
checks it. *Implemented* means the clause holds today; *Partial* means it holds
with a documented limitation.

| Clause | Enforced in | Checked by | Status |
|---|---|---|---|
| P1 no code/SQL execution | `query.py`, `service.py` | `test_secure.py` | Implemented |
| P2 no row-level output | `engine.py` (aggregate-only views) | `test_secure.py`, `test_invariants.py` | Implemented |
| P3 no identifiers/free-text/timestamps | `query.py`, `engine.py` `_VIEWS` | `test_invariants.py`, `test_web.py`, Lean `P3` | Implemented |
| P4 internal variables never leave | `query.py`, `engine.py` | `test_secure.py`, Lean `P4` | Implemented |
| P5 minimum donor count | `disclosure.py`, `engine.py` (`n_donors`) | `test_secure.py`, `test_disclosure.py` | Implemented |
| P6 dominance / influence | `disclosure.py`, `engine.py` | `test_secure.py`, `test_disclosure.py` | Implemented |
| P7 fail closed on unresolved check | `engine.py`, `disclosure.py` | `test_hardening.py` | Implemented |
| P8 strict allowlist validation | `query.py` (`extra="forbid"`) | `test_secure.py`, `test_query_properties.py` | Implemented |
| P9 parameterised SQL only | `engine.py` (`_ident`, bound params) | `test_secure.py`, `test_query_properties.py`, Lean `P9` | Implemented |
| P10 non-numeric refusals | `disclosure.py` (`SessionAuditor`) | `test_hardening.py` | Implemented |
| P11 simulatable differencing | `disclosure.py`, `service.py` | `test_secure.py`, `test_hardening.py`, Alloy `disclosure_policy` | Partial (one-bit residual, N1) |
| P12 safe marginals & schema | `engine.py`, `manifest.py`, `schema.py` | `test_schema.py`, `test_hardening.py` | Implemented |
| P13 identity/channel coupling | `identity.py`, `channel.py` | `test_hardening.py`, `test_web.py` | Implemented |
| P14 channel + allowlist gate | `channel.py`, `identity.py`, `app.py` | `test_web.py`, `test_schema.py` | Implemented |
| P15 tamper-evident audit | `audit.py` (HMAC chain) | `test_secure.py` | Implemented |
| P16 concurrency serialisation | `session.py`, `app.py` | `test_hardening.py` | Implemented |
| P17 budget short-circuit | `service.py`, `disclosure.py` | `test_hardening.py` | Implemented |
| P18 no table on denial | `_result.html`, `service.py` | `test_web.py` | Implemented |
| P19 deny on incomplete cell table | `service.py` (`_handle_model`) | `test_glm.py`, `test_glm_properties.py`, red-team, Alloy `P19` | Implemented |
| P20 no per-observation model output | `glm.py` (output contract), `analyst.py` (intent) | `test_glm.py`, `test_procedure_conformance.py` | Implemented |
| P21 fitter noninterference | `stats.py`, `glm.py` (pure fit) | reproducibility meta-test (`test_glm_properties.py`), `test_glm_noninterference.py`, Alloy `P21` | Implemented |
| P22 refusals from released-equivalent data | `glm.py` (`preconditions`), `service.py` | `test_glm.py` (non-numeric, term-naming refusals) | Implemented |
| R5 complementary suppression | `disclosure.py` (`_secondary_suppress`) | `test_disclosure.py` | Partial (single-dim exact, multi-dim conservative) |
| R14 procedure registry | `procedures.py` | `test_procedure_conformance.py` | Implemented |
| R15 GLM from vetted cells | `glm.py`, `stats.py`, `service.py` | `test_glm.py`, `test_formal_glm_enumeration.py`, `test_glm_oracle.py` | Implemented |
| R16 skeleton export + model check | `procedures.py`, `formal/` | `test_skeleton_sync.py`, `test_formal_alloy_sync.py`, `test_formal_lean_sync.py`, CI `formal` job | Implemented |
| R17 literal spec entry | `service.py` (`_literal_spec`) | `test_literal_spec.py` | Implemented |

The red-team suite (`redteam/run_redteam.py`, R12) exercises P1–P6, P10–P11,
and P19–P22 end to end, off gateway versus on. The bounded formal model
(`formal/glm_gateway.als`, R16) discharges P19/P21 over every vetting outcome
and P4-admissibility over the exact catalogue atoms, pinned to the code by the
skeleton sync tests. A Lean 4 layer (`formal/lean/`, R16) proves the
query-boundary core over the whole spec space: no valid QuerySpec references
an identifier, free-text, or timestamp column (P3); internal-only columns
never reach a group-by or a release (P4); compiled SQL is one read-only
SELECT over the spec's declared view with every filter value a bound
parameter (P9) — pinned to the engine by generated render-equality cases and
`test_formal_lean_sync.py`. `formal/disclosure_policy.als` model-checks the
session auditor's simulatable differencing decision (P11): the marginal
bound is sound, rare-category isolation is blocked, and the rule's two
documented residuals are machine-exhibited rather than asserted.
