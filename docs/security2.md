# Formal-methods hardening recommendations

Status: **F1–F7 and F10 delivered** (2026-07-28/29, post rounds 8 and 9). **F8
is withdrawn as specified** and replaced by something smaller and more direct;
**F9 is parked** until the policy question it depends on has an owner. Both
decisions are recorded below with the reasoning, because a recommendation that
quietly stops being worked on is indistinguishable from one nobody got to. The delivered items landed with the round-9 code fixes they
specify — hardening #58–#67, see the [hardening log](hardening-log.md) and
[formal/README.md](https://github.com/wadelab/safe-tre-agent/blob/main/formal/README.md). Companion to
[security.md](security.md), [FORMAL_METHODS_ANALYSIS.md](FORMAL_METHODS_ANALYSIS.md),
[formal/README.md](https://github.com/wadelab/safe-tre-agent/blob/main/formal/README.md) and
[redteam/round9_report.md](https://github.com/wadelab/safe-tre-agent/blob/main/redteam/round9_report.md). This document
recommends the formal-model work and records which of it has landed.

## Why now

Rounds 8 and 9 are the evidence base. Both were run on the assumption that the
QuerySpec boundary would hold, and it did: nine rounds have produced no SQL
injection, no identifier egress, no schema escape. The formally covered surface
is the one layer that has never broken. The findings land instead in three
bands:

1. **Out of declared scope** — infrastructure, deployment, operations
   (#37, #45–#47, #49–#51, #54, #55; V5, V7, V11, V14, V15, V16). No model
   claimed these.
2. **Value-level content, explicitly deferred** — arithmetic and string content
   the Lean model abstracts away (#41–#44, #53, #56).
3. **Specification errors inside formalised territory** — #38, #39, #40, and
   now V1–V4, V8, V13. These are the ones worth building against.

## What round 9 changes about the diagnosis

Round 8's lesson was that verification pushes failures up a level, from
implementation bugs to abstraction and scope bugs. Round 9 sharpens that into
two specific, actionable patterns.

### Pattern 1 — the models assume 1:1 where the code is 1:N

Every headline finding in both rounds is an *arity* mismatch between a model's
universe and the code's:

| Finding | The model's universe | What the code actually does |
|---|---|---|
| #40 | a release is a function of a **donor set** | a release is a function of a **row set**; identical donors, differing rows |
| V2 | `LineageIsExactlyReleases` — one released request records **one cohort** | a binomial GLM releases over **two** cohorts (trials, and successes with the procedure-added `response == True` filter) |
| V1 | one audit record = **one** unit of spend on replay | a model charges **once per planned aggregate** live (`Request.cost` ∈ {1,2}) |
| V13 | per-cell donor counts **sum** to a donor total | a donor spanning several cells is counted once per cell |

This is worth stating plainly because it is checkable. `temporal_session.als`
*already* models `Request.cost` as 1 or 2 (`CostShape`) — it has the vocabulary
for V1 and does not use it on a replay path, because there is no replay path.
And its `LineageIsExactlyReleases` assertion encodes the one-cohort-per-request
assumption that hides V2 as a *fact of the model* rather than a checked
property of the code. A model that assumes the arity it should be checking
cannot see this class at all.

**Recommendation running through F1–F3 below:** audit every model for
assumed cardinality — request:cost, request:cohort, release:donor,
release:row, donor:cell — and make each an explicitly checked relation with a
satisfiable attack run when the constraint is dropped, in the style of
`Hardening18RaceWithoutLock`.

### Pattern 2 — the audit log changed role, and no model followed it

Before hardening #49 the audit log was an **output**: a tamper-evident record
of what happened, read by humans and by `verify()`. After #49 it is also an
**input** — the authoritative source from which the budget and the differencing
lineage are rebuilt at startup. A component that was downstream of every
security control became upstream of two of them, and no model, test, or
threat-model document tracked the change of role.

V3 is the direct consequence: `rehydrate` rebuilds the controls from whatever
`audit_log.since()` returns and never calls `verify()`, so *deleting* a row —
which needs write access, not a forged MAC — makes the reconstruction forget a
cohort and lets the second half of a differencing pair through. The chain
detects the tampering (`verify()` returns False) and nothing consults it at the
point where it matters. The `since()` docstring's safety claim — that tampering
can only make the rebuilt session more restrictive or drop a cohort — is a
claim whose second clause *is* the unsafe direction.

V1, V2 and V4 are the same role change seen from the other side: two
independent implementations of one cost model (live `observe`, replayed
`rehydrate`) that disagree in opposite directions, which is what always happens
when a spec is written twice and never stated once.

**Recommendation:** treat the log as a security-critical *input* in the models —
with an attacker who may delete rows — and state replay-equivalence as a
property rather than a hope (F3).

### The honest tally

Of round 9's sixteen findings, the work below would plausibly have caught nine
(V1, V2, V3, V4, V8, V9, V10, V12, V13), would have caught V6 if F8 existed,
and would not have caught six: V5 (unbounded request body), V7 (shared checker
pipe), V11 (abandoned tasks), V14 (unbounded `_cohorts`), V15 (CSRF posture),
V16 (tainted audit `request` field). Those six are resource-exhaustion,
availability, and deployment-hygiene findings; they are the standing argument
for why the red-team rounds continue regardless of how good the models get.

## Recommendations, in priority order

| # | Recommendation | Closes / generalises | Effort | Where |
|---|---|---|---|---|
| F3 | **Done.** Restart, replay-equivalence and log-as-input in the temporal model | V1–V4, #37, #49, #55 | Medium | `formal/temporal_session.als` |
| F1 | **Done.** Rows, simulatability and donor arity in the disclosure model | #40 lag, V8, V13 | Small–medium | `formal/disclosure_policy.als` |
| F2 | **Done.** Band-alignment theorem in Lean | #39, class-wide | Small | `formal/lean/SafeTre/` |
| F10 | **Done.** Denial-channel indistinguishability | V9, V10, generalises #30 | Small–medium | Lean or Alloy + tests |
| F4 | **Done.** Vetting arithmetic in Lean (exact integers, not ℚ) | #41, #42 class | Medium | `SafeTre/Arith.lean` |
| F5 | **Done.** Declared surfaces (#61) and models parametrised over the dials | #46, V12 | Medium | both toolchains + `manifest.py` |
| F7 | **Done.** Counterexample ↔ attack pipeline | the #40/V2 failure mode itself | Process + small tooling | `formal/correspondence.yaml` |
| F8 | **Withdrawn.** Replaced by a shipped-unit conformance test | #45, #50, V6 | Small | `tests/` + `deploy/safetre-web.service` |
| F6 | **Done** at the column/cell level; the value level is F9's | #41–#44 structurally | Large | `SafeTre/Release.lean` |
| F9 | **Parked.** Needs a policy owner before any code | value-level guarantee as a theorem | Large (roadmap item 3) | new |

**Recommended first slice: F3, then F1 + F2.** F3 moves to the front because
round 9's three HIGHs live there, and because of a sequencing point that matters
more than the ordering: **F3 should be authored alongside the V1–V4 remediation,
not after it.** Round 9's meta-recommendation is to make the audit row the
authoritative record of what a request cost and which cohorts it touched. That
is a specification, and writing it as a model first gives the fix a statement to
satisfy — which is also the answer to the #40 lag, where the model trailed the
code and drifted. F1 and F2 remain small, sit in files with existing sync
discipline, and formalise the findings that fell inside territory the models
nominally owned.

---

### F3. Restart, replay-equivalence, and the log as an input — **delivered**

*Delivered 2026-07-28.* All of the below landed, plus one thing the plan did not
anticipate: restating `P17_ExhaustionShortCircuits` over the enlarged model
produced nine counterexamples, because without authoritative accounting a
restart refunds enough spend to reopen an exhausted budget. That is V1 arriving
by a second route, found by the model rather than by the red team, and it is
now guarded by the `Shipped` assumption with the attack kept as a satisfiable
run. Fifteen commands, all nine checks holding and all six runs satisfiable, in
17 seconds — after the first attempt at 3 requests and a per-request integer
field took 226 seconds for a single check.


`formal/temporal_session.als` models a single process lifetime. Hardening #49
added a second lifetime and a reconstruction between them, and nothing models
the join.

**Do:**

- **Add a `Restart` event** and a `replay` relation over the recorded log, so a
  trace is `live steps → restart → replayed state → more live steps`.
- **Replay equivalence (V1, V2, V4):** check that the auditor's state after a
  restart equals its state in the uninterrupted trace — both components, spend
  and lineage. The model already carries `Request.cost` ∈ {1,2}; the check is
  that replayed spend uses the *same* cost function, not a per-record constant.
  Exhibit the V1 attack (spend the budget on multi-aggregate models, restart,
  observe the refund) as a satisfiable run when replayed cost is forced to 1.
- **Request:cohort arity (V2):** relax `LineageIsExactlyReleases` from a
  one-cohort-per-request assumption to a checked relation over a set of
  cohorts per request, including procedure-derived ones the analyst never
  wrote. Exhibit the lost successes cohort when replay derives cohorts from the
  request spec alone.
- **Error cost (V4):** make the exception path an explicit transition and check
  that live and replayed accounting agree on it. The current disagreement —
  live treats an error as free, replay charges it — is exactly what the model
  should refuse to admit. Whichever policy the remediation picks, the property
  is *one* cost function used twice.
- **Log integrity as a dropped assumption (V3):** give the attacker the power
  to delete records, and check that a reconstruction from a chain that does not
  verify is refused (fail closed). Then exhibit the V3 attack as a satisfiable
  run when the verify gate is removed — the `Hardening18RaceWithoutLock`
  pattern applied to the newest assumption in the system.
- **Audit completeness (#37):** every request entering the service emits
  exactly one record on every path including exceptions.
- **Policy record (#55):** the `status=config` record is the chain's first
  event, so every release is attributable to a resolved policy by position.

**Acceptance:** new commands wired into `formal/run_checks.py`;
`tests/test_formal_temporal_sync.py` extended so the live service's event order
and the *cost function* still match the enlarged model; each dropped-assumption
run asserted satisfiable.

### F1. Rows, simulatability and donor arity in the disclosure model — **delivered**

*Delivered 2026-07-28.* All of the below landed. Note one correction the model
forced: the first statement of the pre-#40 rule made the attack run
**unsatisfiable**, because the old rule failed on two counts at once and only
one had been modelled — the universe was donors *and* the guard was `0 < d`, so
a difference of exactly zero passed. A model that cannot exhibit the attack it
defends against is not evidence, which is why the run is a CI requirement.


`formal/disclosure_policy.als` still models only the simulatable marginal
donor-cohort bound. Since #40 the code's strongest differencing control is
`QueryEngine.row_symdiff_donors` ([engine.py:604](https://github.com/wadelab/safe-tre-agent/blob/main/safetre/engine.py#L604)),
with `service._difference_bound` ([service.py:101](https://github.com/wadelab/safe-tre-agent/blob/main/safetre/service.py#L101))
taking the smaller of the row-level count and the marginal bound. The model
describes the weaker of two live bounds.

**Do:**

- **Rows as first-class atoms** distinct from donors: a release aggregates a
  set of rows, each carried by one donor; attributes may be row-level or
  donor-level, so two cohorts can hold identical donor sets over differing row
  sets. Model both bounds and the min rule; check the guard is `d < threshold`,
  not `0 < d`. Check the subsumption claim the fix rests on — on donor-level
  filters the row-level count equals `cohort_symdiff` exactly.
- **Residual discipline:** the #40 attack must be a **satisfiable run when the
  row layer is dropped**. If the model stops exhibiting the attack it defends
  against, it has drifted.
- **Simulatability of the exact leg (V8):** with rows in the model this becomes
  a formal question rather than a comment. The marginal bound is computable
  from published marginals; the exact leg is not, so its denial is a bit about
  live data. State simulatability explicitly — does there exist a second
  dataset, consistent with everything published, on which the decision differs?
  — and check which leg has it. Round 9 is right that the code comment
  ("the bit a direct query for the difference cell already returns") is wrong,
  because that direct query is suppressed. The model should say so, and the bit
  should be priced like the optional-role channel (#53) rather than justified
  away.
- **Donor:cell arity (V13):** model donors spanning several cells and check the
  first-pass total-delta layer's claimed property. Expect it to be unsound as
  stated: either the docstring narrows or the counterexample becomes a
  satisfiable run recording that the weak layer is best-effort and the lineage
  layer is what holds.

**Acceptance:** new `check`s pass under `formal/run_checks.py`; every
dropped-layer attack run stays satisfiable; `tests/test_formal_alloy_sync.py`
still pins any generated block; `formal/README.md` updated in the same change.

### F2. Band-alignment theorem in Lean — **delivered**

*Delivered 2026-07-28* as `internal_range_cuts_no_finer_than_bands` and four
`decide`-checked facts about the generated rule table, `sorry`-free on standard
axioms with no `native_decide`. Two notes. First, `Filter` had to gain an
integer value: band alignment is a statement *about* the value, so the
value-free model could not express it — and the guarantee that used to rest on
having nowhere to put a value is now the theorem
`compile_ignores_filter_values`, which is stronger than the silence it
replaced. Second, `edge_never_splits_a_band` was **false** as first written and
`decide` said so immediately: a `<=` edge is the top of its own band, so the
`>=` form of the claim does not hold for it. The two operator families need
separate lemmas.


The #39 fix (`INTERNAL_RANGE_RULES`,
[query.py:88](https://github.com/wadelab/safe-tre-agent/blob/main/safetre/query.py#L88)) snaps range filters on internal
variables to declared band edges. That rule is a finite, decidable structure
sitting beside machinery already formalised, and it has no formal statement —
only tests on the patched instance.

**Do:** generate the range rules into the Lean catalogue
(`scripts/gen_lean_catalogue.py`) and prove:

> every expressible filter predicate over an internal range variable denotes a
> union of whole declared bands — equivalently, the expressible filter algebra
> on that dimension is no finer than the public dimension algebra, so every
> expressible cohort's marginal on that dimension is a sum of public band
> marginals.

Prove the negative half too: equality and membership on the raw variable are
not expressible (no constructor reaches them for internal range columns).

**Why it matters:** this generalises #39 from a patched instance to a proven
class. A new internal numeric variable added without band rules, or a new
operator that cuts inside a band, becomes a build failure rather than a
round-10 finding. #39 and #40 both came from the filter algebra, which the Lean
model currently treats only syntactically — this is the highest-value new
theorem available.

**Acceptance:** `sorry`-free, standard axioms only (`#print axioms`);
`tests/test_formal_lean_sync.py` extended to pin the generated rules to
`INTERNAL_RANGE_RULES`; `lake build` green in the `formal` CI job.

### F10. Denial-channel indistinguishability — **delivered**

*Delivered 2026-07-28 as hardening #66*, as an executable property rather than
a Lean theorem: `tests/test_refusal_equality.py` now defines the
analyst-observable projection (status, message, findings, trace, row count and
`plans`) and asserts that two data-derived refusals differing only in the data
behind them are identical, on the model path as well as the aggregate one.

Two things the plan did not anticipate. The projection has to *exclude* the
request-decided trace steps rather than compare whole traces — `validation: ok
(gaussian(y~a+b))` legitimately differs between two different requests, and the
property is about everything below those steps. And the leak was not only the
message: the per-role trace lines said which design-cell tables had passed the
gateway before the model was refused, which is "your cells cleared the
threshold" in words. Both P22 and R11 were corrected in the specification,
because both had licensed the behaviour in writing.

### F10. Denial-channel indistinguishability — original plan

New in this revision, prompted by V9 and V10. Hardening #30 canonicalised
data-derived refusals so that a denial carries one bit rather than a
description. That is a property about the *denial* channel, and it has never
been stated formally — so it holds where someone remembered it (the plain
aggregate path) and not where they did not (model estimability messages, V9;
the `plans` field returned on withheld responses, V10).

**Do:** define the analyst-observable projection of a response — status,
message class, trace events, which fields are present — and state:

> for any two data-derived denials, the observable projection is identical;
> the only responses that may vary with data are releases, through the
> declared output-contract channels.

This is the mirror image of F6: F6 constrains what a *release* may depend on,
F10 constrains what a *refusal* may reveal. It is small because the response
shapes are few and enumerable, and it is exactly the kind of property that
decays silently as new paths (models, ANOVA, the external checker) are added,
which is the argument for making it a checked property rather than a
convention.

Pair the theorem with a generated conformance test over every refusal-producing
path, in the style of `tests/test_procedure_conformance.py`, so a new procedure
inherits the obligation instead of re-deciding it.

### F4. Vetting arithmetic — **delivered**

*Delivered 2026-07-29.* One deviation from the plan, and it made the result
stronger: **not ℚ**. Lean's core `Rat` has no kernel-reducible decidability
without Mathlib, and this package deliberately has no dependencies — but every
rule here is a *comparison* against a rational threshold, and integer
cross-multiplication expresses a comparison exactly. So the decisions are
modelled without any rational arithmetic at all, `omega` proves most of them,
and the one nonlinear step (transitivity of `≤` on ratios) is three
multiplications and a cancellation by hand.

Two things worth recording. The monotonicity theorem was stated with the
implication **the wrong way round** on the first attempt and typechecked as far
as its final step, which is a good argument for the generated pin: 864 cells
the live `StandinVetter` was asked about, re-decided by the model, boundary
values included. They all agree — so the exact-versus-float gap is not, on
these rules, a real one.

### F4. Vetting arithmetic over ℚ — original plan

#41 (signed dominance inversion) and #42 (non-finite payloads releasing) were
arithmetic bugs in formulas for which no property had ever been stated. The
Lean model deliberately carries values only as bound-parameter counts, so this
band was invisible. The arithmetic is a few dozen lines and entirely
formalisable.

**Do:** a small `SafeTre/Arith.lean` modelling rounding, the cell threshold and
dominance as magnitude share, with theorems such as:

- the dominance witness lies in `[0,1]` for any contribution vector with
  nonzero magnitude sum;
- the witness is invariant under a global sign flip, and equals the naive share
  on non-negative data (the property the #41 fix pinned by test);
- rounding to base *b* perturbs a count by strictly less than *b*;
- the decisions are monotone in the direction the policy intends (raising the
  threshold never releases more);
- a non-finite payload never satisfies the release predicate.

This does not duplicate the gateway's tests — it states the properties the
formulas must have, which is precisely what was missing when `MAX(c)/SUM(c)`
was written down. Pin to the code with a generated-cases hop in the style of
`cases_pin_engine`.

### F5. Parametrise models and declared surfaces over the policy dials — **delivered**

*Delivered 2026-07-29.* The Alloy threshold and budget are now parameters
ranging over every value the bounded scope admits, rather than the literal 3 —
so a counterexample at ANY admissible setting fails CI, and "these properties
are threshold-generic" is checked instead of asserted. On the Lean side the
arithmetic theorems already quantified over policies, so what was missing was
the floors themselves: `SatisfiesFloors` mirrors `policy_floor_problems`, and
three theorems say what it buys — most usefully that under any admissible
configuration a released cell's largest contributor holds at most half its
magnitude, which is the p%-rule actually bounding something.

### F5, original plan

#46 showed the shipped controls could be silently disabled by configuration.
V12 shows the other half: `manifest.py` hardcodes `minimum_cell_size: 10` and
`counts_rounded_to_nearest: 5` as literals, so an operator who raises the
threshold ships a manifest — served to outside planners and shown in the UI —
that states a policy the system is not running.

**Do:** two related things.

- **Models:** restate the Alloy checks and, where feasible, the Lean theorems
  over *any* policy satisfying the floors that `policy_floor_problems`
  enforces, rather than over one constant assignment. Where full
  parametrisation is awkward in Alloy's bounded setting, check at the floor
  values and one interior point, and say so in the model's comments.
- **Declared surfaces:** any surface that *states* a policy value — the
  manifest, the UI, the docs tables — should be rendered from the resolved
  `PolicyConfig` and pinned by a sync test, exactly as the generated Alloy and
  Lean artifacts are. A number that describes a control belongs in the same
  regime as a model that describes one.

### F7. Counterexample ↔ attack pipeline — **delivered**

*Delivered 2026-07-29* as `formal/correspondence.yaml` plus
`tests/test_formal_correspondence.py`. Every `run` in every model is classified
as a vacuity **guard**, an **attack** that must name an executable twin, or a
**residual** that must name a twin or the record pricing it. Both directions
are enforced, and I checked they have teeth: adding an unclassified run to a
model fails, and renaming a reproducer out from under the table fails.

The classification is the part that earns its keep. Writing it forced a
decision on each run about *what it is for*, and one — `InteractionResidualExists` —
turned out to have no executable twin and could not have one, because since #40
the exact leg denies precisely that pair, so there is no released output to
reproduce. That is now stated in the table with the reason, rather than being
an absence nobody had noticed.

### F7. Counterexample ↔ attack pipeline — original plan

The models and the red-team harness currently validate each other only by hand,
which is how the #40 lag happened and how V2 stayed invisible behind an
assertion that assumed it away. Make the correspondence mechanical in both
directions:

- **Model → harness:** every satisfiable attack or residual run in a model gets
  an executable twin in `redteam/attacks.yaml`, generated or at least indexed
  by a table mapping run name → attack id, so the row-level oracle from #48
  exercises every instance the models exhibit.
- **Harness → model:** every finding whose subject lies in formalised territory
  gets a model run that exhibits it, and a sync test fails if a finding tagged
  `formal-scope` in the hardening log names no model command. #18 and — after
  F1 and F3 — #40, V1, V2 and V3 become the pattern rather than exceptions.

Process plus small tooling rather than proof, but it targets the actual failure
mode of both rounds: models that verify yesterday's code.

### F8. Trust-zone model — **withdrawn, and replaced**

*Decided 2026-07-29.* The model is the wrong tool for this, and the reason is
the same one that motivates the rest of this document.

Every failure F8 was meant to catch is either an assumption in
[security.md](security.md) that was not enforced, or the shipped unit not
setting something — and the enforcement half is now done, as fail-closed
startup checks that refuse to run (#45, #65). A trust-zone model would prove
things about a configuration the code already declines to start under.

Worse, it would have no correspondence hop. Every model here is pinned to
running code — `skeleton.json`, `Catalogue.lean`, the temporal event order —
so it fails when it stops describing reality. A trust-zone model would be a
restatement of the zone table with nothing tying it to the actual deployment,
and it would therefore pass forever regardless of what `deploy/safetre-web.service`
said. That is precisely the #40 failure mode, rebuilt on purpose.

**What replaces it.** Nothing currently tests the shipped unit at all —
verified, not assumed. A conformance test that parses
`deploy/safetre-web.service` and asserts every production-required setting is
present and mutually consistent would have caught **#45 and #65 directly**, in
about thirty lines, with no Alloy and no Java. Unlike the model, the artifact
under test *is* the thing that ships.

The original reasoning, kept because the finding it responds to is real:

Raised in priority by V6. #45 (loopback treated as a trust boundary), #50 (a
link writing into the chain under whoever opened it) and V6 (the shipped
systemd unit leaves the audit HMAC key on the same host as the log, so a host
compromise holds both and can re-MAC a chain that `verify()` accepts) are all
violations of assumptions stated in [security.md](security.md)'s zone table.

A small Alloy model of principals, channels, headers, secrets and *storage
locations* can check two properties: no untrusted principal can be attributed
as another, and the integrity of the audit chain requires the key and the log
to sit in different zones. Both would have flagged the shipped unit. Worth
doing once F3 and F1 are in, as a machine-checked restatement of the zone table
that the unit file must then satisfy.

### F6. Release-function theorem — **delivered at the column/cell level**

*Delivered 2026-07-29* as `SafeTre/Release.lean`, and the scope needs saying
plainly. Proved: a released cell is a function of its key, its payload, the
vetting verdict and the rounded count, so the witnesses, the donor count and
the exact count reach the analyst only through those — any perturbation
leaving them fixed leaves the release identical. That is the theorem behind
the perturbation half of `test_release_equality.py`, the half that found #27
and #28, and it is the channel that has actually bitten: released output still
a function of a quantity the gateway believed it had erased.

**Not** proved, and not provable here: value-level noninterference — that a
released aggregate is insensitive to any one donor's data. An aggregate must
depend on the values it aggregates. That is the quantitative claim, it belongs
to F9, and proving the structural half while calling it the whole would be
exactly the overclaim this document exists to stop.

### F6, original plan

Designed in FORMAL_METHODS_ANALYSIS.md §C; its prerequisite (release =
postprocess ∘ finalize ∘ vet, hardening #26) has landed, and
`tests/test_release_equality.py` is the executable half in both directions.

**Do:** a Lean model of the service composition — labelled tables flowing
validation → engine → witnesses → gateway → finalize — proving every value that
reaches release passed through a declared output-contract channel (`cell_key` /
`count` / `magnitude` / `statistic` / `p_value`) with that channel's control
applied. This is conditional declassification, not classical noninterference:
aggregates must depend on sensitive values; the theorem is that they depend on
them *only* through the approved channels.

The largest single piece, and the one that subsumes the #41–#44 class
structurally rather than case by case. F4 is a natural stepping stone and
becomes its lemma library; F10 is its counterpart on the refusal channel.

### F9. DP accountant — **parked, pending an owner**

*Decided 2026-07-29.* Not deferred for effort: deferred because the hard part
is not code. OpenDP integration is a sprint. The decisions it needs are ones no
repository can make — what counts as neighbouring datasets, what the per-donor
contribution bound is, whether ε is spent per query, per session or per
project, and above all **who owns the number**. In Five Safes terms ε is a Safe
Outputs parameter an information-governance committee sets, not a developer.

It also changes what the product is. Released values become randomised, which
breaks the bit-for-bit reproducibility this system currently *proves* — a
released model is reconstructible from its released artifacts alone (P21,
machine-checked) — and means an analyst can no longer replicate their own
result exactly. Somebody has to agree that trade is acceptable before any of
the code is worth writing.

So F9 stays the honest name for the gap F6 does not close, and stays unstarted
until there is a person or committee attached to the ε question.

The original sketch:

### F9. DP accountant, original sketch

Roadmap item 3, unchanged in position: the only route to value-level
insensitivity to any one donor as a theorem rather than a control description.
Everything above hardens the deterministic pathway; this replaces "insensitive
up to the controls" with an ε. Prefer a vetted library (OpenDP or equivalent)
over a bespoke mechanism proof, per FORMAL_METHODS_ANALYSIS.md §E —
deterministic rounding is not DP and should never be described as such.

## What is actually next, now that F1–F7 and F10 are in

Ranked, and none of it is a model:

1. ~~**The shipped-unit conformance test** (F8's replacement, above).~~
   **Done 2026-07-29** as `tests/test_deploy_unit.py` (hardening #73). The
   required-variable list is read out of `identity.configuration_problems()`
   rather than restated, so a new production requirement in the code fails the
   test until the unit answers it — verified by adding one and watching it
   fail.
2. ~~**The "they could get it anyway" audit.**~~ **Done 2026-07-29**
   (hardening #72): three more claims of that form found and corrected, and
   what was cleared is recorded in the hardening log so the next pass starts
   from a list. Original reasoning: Three findings — #62, #66, and
   D7's original text — turned out to be the same mistake: a justification of
   the form *the analyst could obtain this anyway*, written on the branch where
   they could not. It is a bounded, greppable review of the specification and
   the code comments, and a form that has produced three findings will probably
   produce a fourth.
3. **Round 10.** The red-team rounds have found essentially everything, and
   round 9's own tally — six of sixteen findings outside any model's scope — is
   the argument that the models push failures up a level rather than replacing
   the rounds.
4. **The last restart residual.** Hardening #49's cheap total-delta layer still
   restarts empty, because the audit row records an output *shape* rather than
   the donor total. Narrow, since every pair it catches is also seen by the
   lineage layer, but it is the one thing in the restart path that still does
   not survive a restart.

## What this list deliberately leaves alone

Resource exhaustion and availability (V5, V7, V11, V14) — bounded by the rate
limiter, the response ceiling and operational limits, measured rather than
proved. Timing and other side channels (`redteam/timing_attacker.py` and spec
R18 own them; the bucket-index residual is priced under D5). Web-session
hygiene (V15). Taint in stored audit text (V16) — worth a note wherever the log
is read back, but a property of a viewer that does not exist yet. The untrusted
planner, architecturally handled: its output is unvalidated input to a typed
boundary. Physical and organisational controls. And the legacy code-writing
sandbox, a labelled counter-example since #52 rather than a control —
formalising it would imply the opposite.

## Acceptance discipline for every item

The correspondence rules from `formal/README.md` apply unchanged: generated
artifacts regenerate byte-identical (`gen_alloy_catalogue.py`,
`gen_lean_catalogue.py`), every new command is declared to `run_checks.py`'s
verdict, every residual and attack run is asserted satisfiable, Lean stays
`sorry`-free on standard axioms with any `native_decide` use called out, and
each item lands with its `formal/README.md` and hardening-log entries in the
same change.

Two additions prompted by round 9:

1. **No assumption without a dropped-assumption run.** If a model states a
   constraint the code does not enforce (the lock, log integrity, one cohort
   per request), the model must also exhibit what happens without it. An
   assumption that is only a `fact` is a place where the model cannot see the
   bug.
2. **Declare the arity.** Every relation between model concepts —
   request:cost, request:cohort, release:row, donor:cell — gets an explicit
   cardinality and a comment naming the code that determines it. All four
   headline findings of the last two rounds were an arity the model got wrong
   and never checked.

A model whose drift CI cannot see is a liability dressed as assurance. That is
the one sentence this document exists to enforce.
