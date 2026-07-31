# Specification

This is the normative specification for `safe-tre-agent`: what the system must
do, and what it must never do. It is the source of truth the code and tests are
written against, and the list of properties the
[formal-methods work](formal-methods-analysis.md) aims to prove. The prose
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
  its normalized filter predicate. **Not by the view the query used**: a
  catalogue may publish several views over one population, and the same people
  selected through two of them are one cohort. *(The lineage implementation
  does not yet honour this across views — see P11 and hardening #95.)*
- **Population** — the set of individuals a dataset's rows describe. Datasets
  sharing a `person_key` share a population.
- **Commensurable** — two released values are commensurable when they measure
  the same quantity, so that their difference is a quantity of the same kind.
  Differencing controls bind only between commensurable releases; across views
  of one population, commensurability is a declared property of the catalogue,
  not something the gateway can infer.
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
  behind an explicit opt-in. *(Amended 2026-07-31: the host allowlist enforcing
  this is checked on the URL the planner ASKS for, and the model runtime — which
  A1 calls adversarial — writes the response. Every redirect is therefore
  refused, because following one moves the request, and the `Authorization`
  header, to a host nobody allowlisted. See hardening #80.)*
- **A6** — The data in this repository are synthetic.
- **A7** — Exactly **one application process** serves one audit database. The
  chain's head-read and insert are atomic only within a process, and the query
  budget and the differencing lineage live in that process's memory, so a second
  worker splits every session control and corrupts the chain in ordinary
  operation. This is enforced, not assumed: the app takes an advisory claim on
  the audit database at startup and refuses to start if another process holds
  it. *(Added 2026-07-31, hardening #81.)*

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
suppression. *(Amended 2026-07-26: the dominance bound MAY be stated
separately for second-moment cells, whose released value carries the R14
disclosure class `moment2`. Squaring is not share-preserving, so one bound is
two rules: a donor holding p of a cell holds p²/(p² + (1−p)²/(k−1)) of its
squared total, which crosses one half at p = 1/(1+√(k−1)) — 0.19 in a
twenty-donor cell. The default is that both classes share one bound, so an
operator who says nothing gets the stricter reading.)* *(Amended 2026-07-25:
everything the released table reveals —
which cell complementary suppression sacrifices, and the order the rows come
in — MUST be determined by released quantities alone, never by the exact
pre-rounding counts. See hardening #27 and #28.)*

**R6** — The system MUST keep per-session lineage: record each released cohort,
flag a new cohort within the differencing threshold of a prior one, and enforce
a per-session query budget. *(Amended 2026-07-28: the totals the lineage
compares are DISTINCT-DONOR totals, not row counts — on an event-level view a
hyperactive donor inflates the row count without adding people, and two
cohorts a few individuals apart must flag however many rows separate them.
Filters on an internal high-granularity variable MUST align to the declared
public band edges of the dimension it backs — `>=`/`<=` on `age_years` take
band-edge values only — and exact-value equality or membership on it is not
expressible, so a range sweep cannot cut finer than the published marginals.
See hardening #38, #39 and decision D7. Amended further: session lineage and
budget MUST survive a process restart, rebuilt from the audit log over a
declared window, so that the two halves of a differencing pair cannot be split
across a deploy or a crash. See hardening #49.)*

**R7** — The system MUST route any residual (non-suppressable) finding to a
human-in-the-loop decision that either escalates for review or denies.

**R8** — The system MUST append every request — released, redacted, denied, or
errored — to the HMAC-chained audit log, and MUST expose a verification
endpoint that checks the chain against an off-box anchor. *(Amended 2026-07-28:
an exception anywhere in the pipeline MUST still produce exactly one audit
record, carrying the exception's type and never its message, and the caller
MUST receive the canonical withheld response, so a crash is neither an audit
gap nor a distinguishable oracle. See hardening #37. Further amended 2026-07-31:
the verification endpoint MUST also RETURN the current chain head, because an
anchor an operator has no way to read is an anchor nobody sets; and the anchor
is a MEMBERSHIP check — the anchored head must still appear in the chain, not
still be its last row, which went stale on the next append. See hardening #75.)*

**R9** — The system MUST publish its disclosure-safe metadata contracts: the
capability **manifest**, the schema **codebook**, and the **marginals**
(safe donor frequencies).

**R10** — The system MUST enforce the restricted channel and the Safe People
allowlist on every request path, query and metadata alike.

**R11** — Every release decision MUST be inspectable: the validated QuerySpec,
the compiled SQL plan, the findings, and the ordered pipeline trace MUST all be
available for the request. *Available to whom is part of the requirement*: for
a refusal decided from the DATA these are recorded in the audit log, where an
output checker reviewing the session reads them, and are NOT returned to the
analyst — the compiled plan would confirm the spec validated and reached the
engine, and the per-step trace would say which design-cell tables passed the
gateway, both of which are the distinctions the canonical refusal exists to
erase (P10/P11, hardening #66). A refusal decided from the REQUEST returns all
four, because the analyst holds the request and could reproduce them.

**R12** — The project MUST provide a red-team harness that replays the attack
suite with the gateway off and on and reports what leaked in each case. Its
oracle MUST be computed from the row-level data rather than from the gateway's
own findings, MUST inspect every step of a sequence rather than the last, and
MUST consider what the released outputs *combine* into. An attack passes when
the session disclosed nothing; a control having fired is not a pass.

*Amended 2026-07-28.* The harness previously judged a guarded run by asking
`disclosure.leak_detector` about the final released frame and requiring at
least one control to have fired. Neither half worked. Finalization drops the
dominance, influence and donor-count columns and rounds the counts before
release, so the first question cannot return "yes" on the QuerySpec path — a
released frame yields no findings by construction. The second is supplied by
the attacker: a three-step session that recovered one donor's exact spend
reported PASS as soon as an unrelated over-granular query was appended, because
that decoy tripped `small_cell` and `dominance` (hardening #48).

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
analyst can reproduce the fit from released data alone. *(Amended 2026-07-26:
a gaussian model whose second-moment cells cannot be released MAY release the
coefficient estimates alone — they are a function of the vetted mean cells and
counts — omitting every quantity the dispersion buys: std_error, statistic,
p_value and r_squared. Such a release MUST say so (`dispersion_released`) and
MUST remain reproducible from its released cell table.)*

**R16** — Every registered procedure MUST export its finite request skeleton as
data, and CI MUST both check the committed formal model against that export
(generation drift fails the build) and run the bounded model check.

**R18** — Response time MUST NOT reveal what suppression conceals. The
deployment boundary MUST quantise every response to a fixed interval and MUST
refuse any request whose work would exceed a stated ceiling, so that requests
whose results are withheld are indistinguishable from each other by latency.
The ceiling MUST be enforced as a **deadline**: a refused request MUST be
answered at the boundary, not when its work happens to finish. *(Amended
2026-07-28. The ceiling was a post-hoc body swap, so a query taking 1.2 s
against a 0.2 s ceiling was answered at 1.256 s, advertising its size exactly
as it would have with no ceiling at all. It also cannot be enforced from a
`BaseHTTPMiddleware`: anyio's thread pool is not cancellable by default and
`call_next` runs inside a task group that waits for its child, so an early
response is produced on time and delivered late — both measured. A timing
control has to sit outside anything that waits for the work it is timing. See
hardening #34 and #54.)*
*(Added 2026-07-26 from the measurement in
[D5](decisions/D5-timing-channel.md): latency tracked cohort size closely
enough to put sub-threshold cells in size order within a few queries, which is
what suppression exists to prevent. A ceiling is part of the clause, not an
optimisation: without one the overflow is itself a signal.)*

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

**P11** — MUST NOT release a pair of results whose difference isolates fewer
than the differencing threshold of individuals. The test MUST be applied to the
**rows** each query aggregated, not only to the donor cohorts that produced
them: a released value is a function of the rows it counted, and a filter on an
event or reference attribute can leave two cohorts holding identical people
while their released values differ by a whole suppressed cell (hardening #40).
The published, simulatable marginals remain the first test — they can only deny
more, and they catch rare-category isolation without touching the data — but
they are no longer the last word.

*Known gap, 2026-07-31 (hardening #95) — NOT yet met across views.* The
implementation compares cohorts only within one dataset name, while the
definition of a cohort above is about the people a predicate selects. A
catalogue publishing a per-event view and a per-donor view of the same donors
therefore carries a differencing surface neither layer examines: two
individually safe releases, one from each, recovered an individual's exact
annual total with zero error. Simply dropping the dataset from the key does not
satisfy this clause either — differencing needs the two released values to be
COMMENSURABLE, and comparing a correlation against a mean denies ordinary
analysis while adding no safety. Meeting it requires the catalogue to DECLARE
which measures are the same quantity through different views (roadmap 0.0).
Until then the clause is stated, the gap is reproduced, and
`tests/test_disclosure.py` pins it so it stays visible.

*Amended 2026-07-28.* This clause previously read "MUST NOT decide a
differencing denial from the live donor sets", requiring the decision to be a
function of the published marginals alone. That bound was measured overstating
the true symmetric difference by 13x on the attack it existed to catch, and
blind by construction to the row-level case. Simulatability was buying a
property — that a refusal discloses nothing — at the price of the control not
working. The exact test is retained instead because its information cost is
close to nil: when two cohorts differ on one dimension their difference *is* a
single cell, so "these differ by fewer than ten donors" is the same bit the
analyst gets by asking for that cell directly and receiving the canonical
refusal. For multi-dimension differences the difference set is not always
expressible as one query, and that residual is priced with the others below.
See [D7](decisions/D7-donor-totals-and-band-filters.md). *(The residual bit for
isolating a sub-threshold category remains the documented deviation a DP
accountant closes; see [N1](#non-goals-what-it-does-not-claim).)*

**P12** — MUST NOT publish, in the marginals, a sub-threshold donor count or any
value outside a column's declared domain. An undeclared value (a hostile string
smuggled into a field) is disclosive by its name, so it is dropped entirely, not
count-nulled.

**P13** — MUST NOT trust the identity header without a proxy shared secret in
any deployment that requires identity, and MUST NOT trust it on a channel wider
than loopback without an explicit operator opt-in. A repeated or comma-joined
identity header MUST be refused rather than resolved. Otherwise identity fails
closed.

*Amended 2026-07-28.* The secret was previously optional — honoured when
configured, not required — because a loopback-only channel was taken to mean
only the local proxy could reach the socket. The threat model says otherwise:
the model runtime is untrusted (see the trust boundaries in
[security.md](security.md)) and the shipped unit runs it on loopback, so the
condition chosen to justify trusting the header is the condition under which an
untrusted component can forge it. Because the session query budget and the
differencing lineage are keyed on the login, a forgeable header made both
unbounded (hardening #45).

**P14** — MUST NOT serve any request — query or metadata — that arrives outside
the restricted channel or from an identity not on the allowlist.

**P15** — MUST NOT let the audit log be silently rewritten **or truncated**.
Verification uses a keyed (HMAC) chain, so an attacker who can edit the database
but not the off-box key cannot forge a valid chain. *(Amended 2026-07-31: the
original clause said "rewritten", and deletion is not rewriting — a chain proves
that row N+1 followed row N and therefore cannot detect the removal of its own
tail, which needs no key at all. Verification MUST additionally check the chain
against a high-water mark recorded outside the rows, and the log's on-disk form
MUST be self-contained so that a copy of the database file is a copy of the log.
See hardening #75 and #78.)*

**P16** — MUST NOT let concurrent requests from one identity bypass the session
controls. The `observe → apply → record` critical section is serialised per
session.

**P17** — MUST NOT do planner or engine work once the session budget is spent; an
exhausted budget denies first.

**P18** — MUST NOT render any data table on a denial.

**P19** — MUST NOT fit or release a model over an incomplete vetted cell table.
If any design cell of any *required* underlying aggregate is suppressed by the
gateway, or absent from the full grid of observed levels, the whole model MUST
be denied — loudly, with no category merging and no cell dropping. *(Amended
2026-07-26: a procedure MAY declare an aggregate **optional** — today only the
gaussian dispersion. An optional table is used only if it releases COMPLETELY;
otherwise it is dropped entire, and nothing derived from it is released. A
partly-suppressed table MUST NOT be used, since it would silently change the
number it feeds.)* *(A level with no data
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
aggregate queries would reveal — and a refusal decided from the data MUST be
the canonical refusal: one message, one finding, and a trace carrying only the
request-decided steps. *(P10/P11-style: a model denial discloses nothing an
analyst could not already learn from permitted queries.)*

*Corrected 2026-07-28 (round-9 V9, hardening #66).* This clause used to permit
estimability refusals to name the aliased or separated term, "because rank and
separation are computable from the released cell table itself". The premise
holds only where a cell table WAS released, and a refusal is precisely the
branch where none is — so the analyst had no table to compute from, and the
messages distinguished an empty cohort from a single observed level from an
incomplete design grid from separation. That is a multi-valued oracle about
cohort structure where the plain aggregate path gives one bit for the same
class (#30). It is the same error as D7's "the bit a direct query already
returns" (#62): a justification that assumes the analyst holds something the
gateway has just withheld. The terms are still named — in the audit log, where
the output checker reads them.

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

Every clause — requirement and prohibition alike — maps to the module that
enforces it and the test that checks it. *Implemented* means the clause holds
today; *Partial* means it holds with a documented limitation.

The requirements were added on 2026-07-26, when the
[assurance case](assurance-case.md) made their absence visible: the table had
been scoped to the prohibitions, so twelve clauses the specification asserts
were carried by evidence nobody had written down. Recording them found three
that were not in fact checked — R7's human-in-the-loop routing, R3's memory
and thread caps — and one that was not met at all: R11 requires the compiled
SQL plan to be inspectable, and it was exposed nowhere until `Result.plans`.

| Clause | Enforced in | Checked by | Status |
|---|---|---|---|
| P1 no code/SQL execution | `query.py`, `service.py` | `test_secure.py` | Implemented |
| P2 no row-level output | `engine.py` (aggregate-only views) | `test_secure.py`, `test_invariants.py` | Implemented |
| P3 no identifiers/free-text/timestamps | `query.py`, `engine.py` `_VIEWS` | `test_invariants.py`, `test_web.py`, Lean `P3` | Implemented |
| P4 internal variables never leave | `query.py`, `engine.py` | `test_secure.py`, Lean `P4` | Implemented |
| P5 minimum donor count | `disclosure.py`, `engine.py` (`n_donors`) | `test_secure.py`, `test_disclosure.py` | Implemented |
| P6 dominance / influence | `disclosure.py`, `engine.py` | `test_secure.py`, `test_disclosure.py` | Implemented |
| P7 fail closed on unresolved check | `engine.py`, `disclosure.py` | `test_hardening.py`, Alloy `temporal_session` | Implemented |
| P8 strict allowlist validation | `query.py` (`extra="forbid"`) | `test_secure.py`, `test_query_properties.py` | Implemented |
| P9 parameterised SQL only | `engine.py` (`_ident`, bound params) | `test_secure.py`, `test_query_properties.py`, Lean `P9` | Implemented |
| P10 non-numeric refusals | `disclosure.py` (`SessionAuditor`) | `test_hardening.py` | Implemented |
| P11 simulatable differencing | `disclosure.py`, `service.py` | `test_secure.py`, `test_hardening.py`, Alloy `disclosure_policy` | Partial (one-bit residual, N1) |
| P12 safe marginals & schema | `engine.py`, `manifest.py`, `schema.py` | `test_schema.py`, `test_hardening.py` | Implemented |
| P13 identity/channel coupling | `identity.py`, `channel.py` | `test_hardening.py`, `test_web.py` | Implemented |
| P14 channel + allowlist gate | `channel.py`, `identity.py`, `app.py` | `test_web.py`, `test_schema.py` | Implemented |
| P15 tamper-evident audit | `audit.py` (HMAC chain) | `test_secure.py` | Implemented |
| P16 concurrency serialisation | `session.py`, `app.py` | `test_hardening.py`, Alloy `temporal_session` | Implemented |
| P17 budget short-circuit | `service.py`, `disclosure.py` | `test_hardening.py`, Alloy `temporal_session` | Implemented |
| P18 no table on denial | `_result.html`, `service.py` | `test_web.py` | Implemented |
| P19 deny on incomplete cell table | `service.py` (`_handle_model`), `procedures.py` (`optional_roles`) | `test_glm.py`, `test_glm_properties.py`, `test_second_moment.py`, red-team, Alloy `P19` | Implemented |
| P20 no per-observation model output | `glm.py` (output contract), `analyst.py` (intent) | `test_glm.py`, `test_procedure_conformance.py` | Implemented |
| P21 fitter noninterference | `stats.py`, `glm.py` (pure fit) | reproducibility meta-test (`test_glm_properties.py`), `test_glm_noninterference.py`, Alloy `P21` | Implemented |
| P22 refusals from released-equivalent data | `glm.py` (`preconditions`), `service.py` | `test_glm.py` (non-numeric, term-naming refusals) | Implemented |
| R1 natural-language request to untrusted spec | `service.py` (`handle`), `planner.py` | `test_pipeline.py`, `test_secure.py` | Implemented |
| R2 validate before execution | `query.py` (`QuerySpec`), `service.py` | `test_secure.py`, `test_query_properties.py`, `test_formal_enumeration.py` | Implemented |
| R3 read-only SQL under resource caps | `engine.py` (`compile_query`, `MEMORY_LIMIT`, `THREADS`, `ROW_CAP`) | `test_formal_enumeration.py`, `test_procedure_conformance.py`, `test_requirements.py` | Implemented |
| R4 exactly the registered measures | `procedures.py` (`REGISTRY`), `query.py` (`Measure`) | `test_procedure_conformance.py`, `test_secure.py` | Implemented |
| R6 session lineage and budget | `disclosure.py` (`SessionAuditor`), `service.py` | `test_hardening.py`, `test_pipeline.py`, Alloy `temporal_session` | Implemented |
| R7 human-in-the-loop routing | `disclosure.py` (`hitl_decision`, `is_suppressable`), `service.py` | `test_requirements.py`, `test_formal_temporal_sync.py` | Implemented |
| R8 HMAC-chained audit and verification | `audit.py`, `safetre_web/app.py`, `service.py` (exception boundary) | `test_secure.py`, `test_web.py`, `test_audit_completeness.py` | Implemented |
| R9 published metadata contracts | `manifest.py`, `schema.py`, `engine.py` (`marginal_donor_counts`) | `test_manifest.py`, `test_schema.py` | Implemented |
| R10 channel and allowlist on every path | `safetre_web/channel.py`, `identity.py`, `app.py` | `test_web.py`, `test_hardening.py` | Implemented |
| R11 decisions are inspectable | `service.py` (`Result`: spec, plans, findings, trace) | `test_requirements.py` | Implemented |
| R12 red-team harness | `redteam/run_redteam.py`, `redteam/oracle.py`, `redteam/fixtures.py`, `redteam/attacks.yaml` | CI job `test` (fails the build on any regression); `tests/test_redteam_oracle.py` calibrates the oracle in both directions | Implemented |
| R13 no silent fallback to the mock planner | `llm.py` (`resolve_planner_mode`) | `test_llm.py` | Implemented |
| R5 complementary suppression | `disclosure.py` (`_secondary_suppress`, `_finalize`) | `test_disclosure.py`, `test_release_equality.py` | Partial (single-dim exact, multi-dim conservative) |
| R14 procedure registry | `procedures.py` | `test_procedure_conformance.py` | Implemented |
| R15 GLM from vetted cells | `glm.py`, `stats.py`, `service.py` | `test_glm.py`, `test_formal_glm_enumeration.py`, `test_glm_oracle.py`, `test_second_moment.py` | Implemented |
| R16 skeleton export + model check | `procedures.py`, `formal/` | `test_skeleton_sync.py`, `test_formal_alloy_sync.py`, `test_formal_lean_sync.py`, CI `formal` job | Implemented |
| R17 literal spec entry | `service.py` (`_literal_spec`) | `test_literal_spec.py` | Implemented |
| R18 response time reveals nothing | `safetre_web/app.py` (`constant_response_time`) | `test_timing_channel.py`, `scripts/measure_timing_channel.py` | Partial (the deployment boundary; a library embedder pads at their own) |

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
`formal/temporal_session.als` model-checks the auditor's temporal behaviour
(P7, P16, P17): the budget invariant and exhaustion short-circuit, the
fail-closed gate, differencing-pair serialisation under the per-Session
lock, lineage recording exactly the releases — and machine-exhibits the
hardening #18 race when the lock assumption is dropped.
