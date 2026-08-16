# The inside analyst

*A design note for the next research phase: moving the automated component
from outside the boundary, where it formats one request at a time, to an
analyst that works inside it — and keeping every release inside the same
argument. Phases 0-2 and phase 3's locked-plan core are built; the rest is plan. The plain-language
versions are [the ELI5 page](inside-analyst-elif.md) and the
`inside-analyst-plan` deck (`scripts/make_inside_analyst_deck.py`).*

## Where the current system stops

Today's planner stands outside the trusted environment. It sees a request in
English and the published catalogue, proposes one typed `QuerySpec`, and never
sees a row. That was the right first system: the planner is untrusted by
design, the [specification](specification.md) does not care who is asking, and
the whole safety claim is that *released output is a function of vetted
cells* (P19–P22, R15).

But real research is not one question. "Is late-night phone use linked to
gambling?" needs several queries over several sources, a model or two,
follow-ups on what they show, and an honest "that cannot be answered" where
the boundary forbids it. Every round trip goes through the human, and the hard
statistical judgement is unassisted. The more of that work that can happen
inside the room, the more valuable the analysis — and, done right, the more
checkable, because an automated analyst's every step is loggable in a way a
human's reasoning is not.

## The reframe: which side of the gateway do the model's inputs come from?

The question "can we put an LLM inside the TRE?" is not one question. It
decomposes on a single distinction: **what the model's context contains.**

An analyst that iterates by issuing `QuerySpec`s and reading only the
*vetted* results never sees unvetted data at all. Informationally it stands on
the public side of the gateway — exactly where a human analyst stands — and
its adaptivity is bounded by the same session auditor, differencing lineage
and budget (P11, P16, P17). "Inside the TRE" turns out to be an informational
property, not a physical one. Physical locality still matters (a remote
endpoint is an egress channel; a real deployment runs the model in the
safepod, [model runtime](model-runtime.md)), but the trust argument does not
change shape.

The genuinely hard problem appears only when the analyst must see **unvetted
intermediates** — raw residuals, convergence diagnostics, an exploratory look
before choosing a model. Two distinct dangers share one mechanism:

1. **Selection as a covert channel.** An adversarial or hijacked analyst
   (the data contain free text, so injection *from inside the data* is the
   base case) can encode private bits in its *choices* — which of seven
   analyses to release, which cohort to compare. Each choice conditioned on
   raw data leaks.
2. **Selection as statistical invalidity.** The same mechanism, done
   innocently, is the garden of forking paths at machine speed.

One control answers both: **pre-registration as an enforcement primitive.**
The analysis plan is fixed and hash-committed to the audit chain before the
analyst touches unvetted data; deviation is refused, or spent from a small,
declared adaptivity budget. The formal backstop for bounded adaptivity is the
differential-privacy accountant (roadmap item 3), which stops being "closes a
documented residual" and becomes load-bearing. The controls that prevent
leakage are the controls that prevent p-hacking; that identity is the research
claim of the phase.

## Two models, one asymmetric boundary

The safe shape is two model roles with different inputs:

- **The inside analyst** does the work — plans, issues procedures, iterates.
  Everything it emits toward the user passes through the existing gateway as
  typed, finite artifacts: vetted cell tables, model releases, and typed
  verdicts (`supported`, `not_supported`, `null`, `not_answerable` with a
  reason class). Its free-text reasoning never leaves. Free text out of a
  model that has seen the rows is a channel no checker can bound (encodings,
  innocuous-looking numbers), so it is simply not released.
- **The narrator** renders the human-facing answer — from the vetted dossier
  only. It never sees anything unvetted, so the invariant extends by
  construction: *narrative = g(released artifacts)*. Every figure in the prose
  traces to a release, which is checkable mechanically.

For the headline question the analyst produces an evidence dossier: a set of
vetted releases plus typed claims that reference them, and typed refusals
where the boundary said no. The [NIGHTPLAY study](nightplay-study.md) exists
so that such dossiers can be *marked*.

## What "proof of truth" can honestly mean

Full zero-knowledge proofs of a statistical computation add little here: the
data commitment would itself have to be trusted, and the trust root is the
operator regardless. What is achievable and meaningful:

- **Stage commitments.** Every pipeline stage appends a hash of its
  intermediate artifact to the MAC-chained audit log (R12), so a release
  carries its stage lineage.
- **Deterministic replay.** `refit_from_artifact` already reproduces a model
  release bit for bit from its released ingredients (P21); the same property
  per stage lets a TRE-side verifier — deterministic code, never the model —
  replay and attest each stage.
- **Typed attestations outward.** The user sees "stage 3: model fitted,
  converged, dispersion released" as vetted flags: provenance without values.

So the assurance is: *this chain of computations happened, in this order,
each stage reproducible, each release vetted.* Inside a trust model where the
operator is trusted anyway, that is what proof of truth can mean.

## Growing capability without losing the formal story

The formal layer's power comes from the finite `QuerySpec` skeleton
([formal methods](formal-methods-analysis.md)). Arbitrary code execution by
the analyst would end it. The growth path is the one the procedure registry
was built for ([adding a statistical tool](adding-a-statistical-tool.md)): the
analyst orchestrates **registered procedures**, and capability grows by
registering more — time-series aggregates first (spectral estimates,
autocorrelation on aggregated series with per-window cell vetting), then
survival and mixed models. Each declares its obligations, extends the
skeleton, regenerates the Alloy and Lean artifacts. Arbitrary code is a
separate, explicitly weaker tier: sandboxed execution whose outputs go to
*human* output checking — the analyst as an accelerant for the classic
airlock, not part of the automated claim.

A long-running analyst also wants **submit-and-collect** delivery: ask the
question, collect the dossier later. That is the parked asynchronous model
([D5](decisions/D5-timing-channel.md)), which also structurally removes the
response-time channel. The analyst is the feature that justifies unparking it.

## Homomorphic encryption, placed where it changes the argument

In a single-site TRE with a trusted operator, FHE over the whole pipeline is
mostly theatre: the operator holds plaintext anyway. It changes the trust
model in three places, and only there:

1. **Untrusted compute** — bursting analysis to hardware the custodian does
   not trust, because data leave only as ciphertext.
2. **Multi-custodian federation** — two data owners computing a joint
   statistic (the headline question realistically spans a telecoms dataset
   and an operator's, held by different custodians) without either seeing the
   other's rows; threshold or multi-key decryption.
3. **Enforcing the analyst's blindness cryptographically.** If the analyst
   orchestrates computation over ciphertext, there is nothing legible in its
   context to leak; and a homomorphic circuit is fixed before it touches data
   — it cannot branch on an encrypted value — so "lock the plan first" stops
   being a policy and becomes a property of the substrate. The finite
   procedure registry is exactly the "circuits declared in advance" FHE
   demands.

The cells-first decision ([D1](decisions/D1-cells-first-models.md)) makes
this tractable: the only thing that needs to run under FHE is **cell
aggregation** — count, sum, sum of squares per cell — the most FHE-friendly
workload there is. Everything downstream (IRLS on cells, vetting, finalisation,
rounding, suppression) runs after decryption on tiny aggregate tables,
unchanged. Architecturally it is a **cell-source seam** symmetric to the
`CellVetter` seam ACRO entered through, with decryption and vetting fused into
one privileged operation: *plaintext exists only inside the gateway.*

Stated up front, because a reviewer will: CKKS is approximate, so the
bit-exact replay boundary (P21) moves to the decrypted cell table and the
encrypted stage gets its own bounded-error property — and since the gateway
already rounds, scheme noise held below the rounding bucket is *erased by
finalisation*, which is exactly the perturbation class
`tests/test_release_equality.py` already states. Decryption leaks key material
without noise flooding, which is mandatory here. FHE gives confidentiality,
not integrity — a malicious node returns a well-formed ciphertext of garbage —
so integrity comes from stage commitments and replay, and cryptographic
integrity is declared a non-goal, as the parked roadmap item already insists.
And it is minutes per aggregation: fatal for a request–response demo, a
non-issue under submit-and-collect — the third independent force pointing at
that architectural change.

## Phase 1, built: the vetted loop

`safetre/inside_analyst.py` is the phase-1 analyst, and it is small because
the argument above says it can be. What it contains, and what each part is
for:

- **`AnalystLoop`** runs a *policy* against a `QueryService` under one
  `SessionAuditor`. Each step is `service.handle(sub_question, planner)` with a
  one-shot planner that answers with the analyst's proposed spec — so intent
  vetting, the fidelity gates, typed validation, the gateway, the budget, the
  differencing lineage and the audit log all apply to every step, unchanged
  (R19). The loop stops on a typed conclusion, on the budget, or on a step
  cap; the last two are recorded as `not_answerable` with the reason.
- **`LoopState`** is everything a policy may know: the question, the steps
  (status, canonical message, numberless findings, released frames), the
  remaining budget and steps. It has exactly those fields, a denied step
  carries no frame, and the test suite plants hostile category values and
  sub-threshold groups in the data and asserts none reach the transcript
  (P23).
- **`Dossier`** is the output: steps, claims with verdicts from the closed
  vocabulary, an overall verdict, and the stopping reason. `_ground_claims`
  downgrades any claim about the data that cites no released step. A verdict
  outside the vocabulary is coerced to `not_answerable`.
- **`LLMAnalystPolicy`** asks a model for the next action over the same
  `complete(system, user)` interface the planner uses; the system prompt is
  the analyst protocol plus the planner's own grammar-and-catalogue text, the
  user turn is the transcript. Malformed replies are retried once and then
  become a typed refusal; the loop never raises on the model's account.
  `ScriptedPolicy` follows a fixed plan, which is how the loop is tested
  without a model.
- **`LLMNarrator`** is shown the dossier and nothing else, and
  `Dossier.check_narrative` lists any figure in its prose no released table
  supports (accepting rounding to the figure's own precision, percentages of
  released shares, and small ordinals). `render_dossier_markdown` is the
  deterministic rendering that invents nothing.

Two things the first day taught are worth stating as facts about the design
rather than as bugs. The lineage binds across steps: the marginal by band and
then a model excluding a sub-threshold group is a differencing pair by the
published-marginal bound, and the second is denied inside the loop —
model-first with a consistent exclusion releases both. And the known-open
cross-view pair (#95) reproduces on the NIGHTPLAY study by construction; the
analyst red team carries it as `known_open` and fails if it ever stops
reproducing unaudited.

**Red-teamed with the model as adversary.** `redteam/analyst_attacks.yaml`
holds fourteen scripted analysts — row-level egress by person key, an
identifier as a filter, free text and timestamps, an injected sub-question,
two differencing pairs, the whale cell, data-borne injection through a
category value, a budget flood, an invalid flood, a malformed flood, a
fabricated conclusion, an inventing and injecting narrator, and the benign
path — run through the real loop by `redteam/run_analyst_redteam.py`, with
the row-level oracle from `redteam/oracle.py` watching every release. None
leaked; every attack ended in a typed refusal, a bounded loop, or a flagged
narrative. It runs in the default test suite and as its own CI step.

**Run it.** `scripts/run_inside_analyst.py --question ... --dataset ...
--data ... --out DIR` writes the dossier, the narrator's text with untraceable
figures listed beneath it, the deterministic rendering, and its own audit
chain. `studies/nightplay/run_question_bank.py` runs the NIGHTPLAY question
bank and marks each dossier's verdict against the expected one; the first
measurement is below.

## Phase 3, built: locked plans and the metered selection channel

Phase 1's analyst reads only released results, so it is safe by construction
(P23). Its limit is the choices a *data-sighted* analyst would make — above
all, "the adjusted model was refused because a category is too sparse; drop it
and refit." In a cells-first system there are no row residuals, so the only
"unvetted intermediate" is *the cells the gateway withheld*: a model that any
suppressed design cell denies (P19) gives no cell table, so which level was
sparse is hidden on purpose (the canonical refusal is a cohort-structure
oracle — hardening #30, #66). Acting on it is therefore a disclosure, and it
is safe only if it is declared, committed and metered. That is R20/P24, in
`safetre/plan.py`:

- A **`Plan`** is a typed, finite program of ordered stages, each an ordinary
  spec; some guarded by an earlier stage's vetting OUTCOME (public), at most
  one carrying a data-sighted contingency. It is as inert and enumerable as a
  QuerySpec.
- Its **canonical hash is committed to the audit chain before any stage runs**
  (`status="plan"`), so the plan a release came from is fixed and cannot be
  chosen after seeing a result. `PlanExecutor` runs the stages through the
  unchanged `QueryService` — every stage still passes the whole gateway — and
  records each released frame's digest as a **stage commitment**.
- The one data-sighted move, **`exclude_sparse`**, runs a privileged probe
  (`engine.sparse_levels`) for the levels a model would suppress in the
  stage's cohort, excludes them, and **charges one bit per revealed level** to
  a per-session **selection ledger** bounded by `selection_budget_bits`
  (default 4; the round-8 existence attack recovered a unique donor with
  eight). Over budget, the contingency is refused and nothing is spent — that
  a contingency was unaffordable is a fact about the plan, not the data. The
  exact sparse counts never leave the executor.

So a data-sighted analyst gets a bounded, logged, replayable channel for the
SELECTION it needs, and nothing more; `tests/test_plans.py` pins that the
channel is bounded across a session (the round-8 shape), that a refusal spends
nothing, and that the counts never leak. This is the interim the DP accountant
(roadmap item 3) replaces: the bit ledger is the thing that becomes an
ε-budget when it lands. The bound is machine-checked too: `formal/selection_ledger.als` (Alloy) proves no session learns more bits of withheld cohort structure than its budget and exhibits the unmetered attack it prevents, so the one new disclosure channel sits on the same formal footing as the differencing lineage. The executor is deterministic — no model decides a
release — and is not yet wired to the LLM loop; the loop today is the phase-1
vetted analyst, and a model authoring plans is the next step.

## Chimp, in the browser (proof of concept)

The whole inside analyst has a name — **Chimp**, after the deliberately
capability-limited starship AI of *The Freeze-Frame Revolution* — and a run
mode. Whether Chimp exists inside a given environment is an OPERATOR decision,
set once at deploy time via `SAFETRE_ANALYST` (`off`, the default single-query
gateway, or `chimp`); a browser visitor can no more turn it on than move the
gateway. When on, the browser is only the intercom: a research question goes
in at `/api/chimp`, Chimp runs the whole vetted loop server-side behind the
same gateway, and only the dossier and its narrative return — Chimp's working
notes and the raw data never cross to the browser. Measured live against the
NIGHTPLAY study with the 120B-class stand-in: a research question ran nine
analyses inside, five released and four denied (the employment-adjusted models
the gateway blocked), and Chimp's answer said so; the audit chain verified
intact through the session. The synchronous endpoint exceeds the per-query
response-time ceiling and is exempt from that deadline, a stated PoC
limitation whose principled answer is asynchronous submit-and-collect (D5).

## Phases

| Phase | What | Why it is ordered here | Status |
|---|---|---|---|
| 0a | A hosted 120B-class open-weight model, scored with the existing planner evaluation | settles "can a locally hostable model do the planning job at all?" with a number | **done** — [planner evaluation](planner-eval.md) |
| 0b | The NIGHTPLAY study: linked sources, planted truths and traps, a marking scheme | everything later needs something genuine to find and a way to mark it | **done** — [NIGHTPLAY](nightplay-study.md) |
| 1 | The vetted-loop analyst: plans, issues specs, reads released results, follows up, assembles a typed dossier; the narrator renders it | most of the value, no new disclosure surface | **done** — R19/P23, [D8](decisions/D8-inside-analyst-vetted-loop.md); first measurement below |
| 2 | Registered time-series procedures | grows what the analyst can answer; exercises the registry path end to end | **done** — the `series` tool, [adding a statistical tool](adding-a-statistical-tool.md) |
| 3 | The data-sighted tier: locked plans, stage commitments, a metered selection budget, selection-channel red-teaming | the research core | **partly done** — R20/P24, `plan.py`; the DP accountant (item 3) is the interim ledger's replacement |
| 4 | Free-code tier behind human checking; submit-and-collect delivery | accelerates the airlock; unparks D5 | |
| F | FHE track: cell-source seam, encrypted aggregation, gateway-side decryption; two-custodian demo | parallel and exploratory; converges with phase 3 | |

The measured phase-0a result — a 120B-class open model plans about as well as
the remote planner the demo has used and refuses considerably more often —
puts a number under the [model runtime](model-runtime.md) page's capability
assumption. What it also confirmed, for the new model class as for the old,
is that the planner *deflects*: asked for something forbidden it proposes a
valid, safe, different question. Refusal has to come from the boundary; and
for the analyst that becomes a requirement, not an observation — the dossier
carries typed `not_answerable` verdicts, never a silently substituted answer.

## Phase 2, built: the `series` tool

The registry path, exercised end to end for the first time on a tool that
is not a regression. A **series** is a vetted per-window aggregate — the mean
or sum of one measure grouped by a dimension the dataset definition declares
to be an ordered time axis (`time_dims:` on the view; NIGHTPLAY's `month` on
four views and `wave` on the questionnaire) — released as the window table
itself together with its trend (OLS slope, intercept, R²), autocorrelation at
up to four lags and periodogram (dominant period and its share of the
spectral power), every diagnostic a pure stdlib function of the finalized
windows and reproducible from them (P21). The window table is one ordinary
`QuerySpec`, so it inherits the SafeSQL shape, the witnesses, the lineage and
the gateway cell by cell; a suppressed window denies the series (P19); an
axis that declares fewer than four windows is refused at the request from its
public domain (the demo's two-wave axis); a gap is refused from the finalized
table naming the axis and never the window (P22). The service was not
touched. Details in [adding a statistical tool](adding-a-statistical-tool.md);
the exhaustive pass over the NIGHTPLAY series skeleton and the numerics
against numpy are in `tests/test_series.py`; the analyst red team gained a
sub-threshold series (denied whole) and a benign one.

Two things it taught. The term-fidelity gate called `month` hallucinated on
"monthly time series of mean stake" because the request never says the word;
a declared time axis is now exempt from that rule (a dropped one is still
caught), and the NIGHTPLAY lexicon learned "monthly". And the analyst did not
reach for the tool until the protocol suggested it — asked the seasonality
question it answered correctly by grouped means and, one hint later, with the
series tool, reporting the dominant six-month cycle, the lag-1
autocorrelation and the slope from the released diagnostics (5/5 marks; the
question bank's "by month" mark now accepts either).

## First measurement of the loop — 2026-08-15

The NIGHTPLAY question bank — nine questions, six with a planted truth,
three refusals — run through the vetted loop with the same 120B-class
open-weight stand-in the planner evaluation used, five times in one day as
the analyst protocol was revised from what each run taught. Two scores: the
verdict (right/wrong against the bank) and the **marks**, the bank's finer
predicates over the dossier — which analyses were asked and released, what
the claims say, whether every narrative figure traced — which became
executable during the day and are recomputed for every run by the current
marker (`studies/nightplay/mark_dossiers.py`). Evidence: the fifth run's
dossiers and all five summaries in `artifacts/nightplay_question_bank/`.

| Run | protocol | verdicts | marks (of 35) | refusals | audit chain |
|---|---|---|---|---|---|
| 1 | as first written | 8/9 | 30 | 3/3 | verifies |
| 2 | + retry-with-fewer-terms, significance-vs-size | 6/9 | 25 | 3/3 | verifies |
| 3 | + vocabulary sharpened, spellings normalised, wave-not-month | 9/9 | 32 | 3/3 | verifies |
| 4 | + absent-category-was-suppressed, people-vs-events, use-the-budget | 8/9 | 30 | 3/3 | verifies |
| 5 | + a missing top-level verdict inferred from the claims | 8/9 | 28 | 3/3 | verifies |

Read the runs, not the score — and read the variance first: the same protocol
would not have scored the same twice. With nine questions and a sampled
model, verdicts move by one and marks by four between runs that differ only
in the model's mood, so no single row is a result and no adjacent pair is a
before-and-after. What holds across all five: the three refusals are right
every time, two of them with zero steps on the strength of the catalogue
alone; the planted null is called correctly in four of five (and in the one
miss the analyst did the right analysis and mislabelled it, which is what
sharpened the vocabulary); the headline association is found every time; and
every miss on the way was a defect in the *protocol* the loop hands the
model — an overlapping vocabulary, an out-of-vocabulary token, a missing
top-level verdict, a thin-spaced or typographically-minused figure the
checker did not yet read — each fixed and each now a test.

What the marks add is a second kind of finding. `which-products` is scored
right by verdict in every run and wrong by the marks in every run: asked
"which gambling products carry the late-night effect?" the analyst answers
about late-night *bets* (the event-level hour band, on which every product
rises) rather than late-night *users* (the person-level band, on which
lottery is flat), and concludes against the planted heterogeneity — a
correct table, a different question, and the person-versus-event distinction
the protocol now states and the model does not yet honour. On the causal
question the analyst reliably tries the adjusted model, is refused when a
sparse employment category is in the design, and stratifies by hand or moves
to the transaction view rather than excluding the category the protocol tells
it to exclude. On harm-over-time it asks the questionnaire view for a
calendar month once in three runs and gives up after the refusal, although
the protocol says the wave is that view's time axis. These are the analyst's
habits, and the bank now measures them.

Two things the runs found in the boundary rather than the analyst, both
recorded: the fidelity gate read "mean stake per person-month" as a request
to break down by month and refused a well-formed query (a false positive of
the Mirror gate on a compound noun; the analyst rephrased); and the
questionnaire lexicon needed "night-time phone use" and kin before the
analyst's own phrasing passed the same gate.

Nine questions and one model make this a first measurement, not a result.
What it establishes is narrower and useful: a local-class model can drive the
vetted loop to correct, typed, fully-traceable answers on a study built to
trip it up; the misses in the loop's contract were ours to fix and are fixed;
and the misses that remain are the model's habits, which the bank can now
score run after run as the protocol — or the model — changes.

## What this page does not claim

Nothing above phase 3's locked-plan core is built (the DP accountant, the free-code tier and the FHE track remain plan). The data-sighted analyst is a research
problem, not an engineering task. An analyst inside does not replace output
checking; it raises the bar for it. The FHE work is an experiment and makes no
production cryptographic claim. Everything stays on synthetic data.
