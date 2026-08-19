# From query access to answer access

*Planning note for a post-v1.0 research phase. This is not part of the current
security claim. It extends [the inside analyst](inside-analyst.md) in a different
direction: not just moving more analysis inside the TRE, but asking whether doing
so lets the TRE release **less intermediate information** to the researcher in
the first place.*

## The hypothesis

The current system makes individual analytical requests safer. A user asks a
question, a planner proposes a typed `QuerySpec`, the gateway vets the result,
and a released aggregate crosses the boundary. Session lineage then tries to
catch unsafe combinations of those releases.

That is necessary, but it inherits the interaction model of a human analyst:

```text
researcher
  -> query 1 -> released statistic 1
  -> query 2 -> released statistic 2
  -> query 3 -> released statistic 3
  -> ...
```

The analyst outside the TRE sees every released intermediate, can choose the
next request from what they learned, and can combine outputs with another
analyst's. Subtraction, differencing and reconstruction attacks live in that
composition.

An automated analyst inside the TRE makes another architecture possible:

```text
researcher
  -> high-level scientific question
        -> private adaptive analysis inside the TRE
        -> disclosure-checked evidence selection
  <- one answer package
```

The user does not need to receive every statistic the analyst used to reach an
answer. The internal analyst may inspect distributions, compare models, test
interactions and run sensitivity analyses while those intermediates remain on
the data side of the boundary. Only the evidence needed to support the final
answer is considered for release.

The research hypothesis is therefore:

> **Moving analytical adaptivity inside the TRE can reduce the information
> surface exposed to users, while preserving or improving their ability to ask
> useful scientific questions.**

This is not a claim that natural language is safer than SQL. An unrestricted
English question can encode the same subtraction attack as an unrestricted
query. The putative advantage comes from changing **what crosses the boundary**:
from a user-directed sequence of intermediate statistics to a constrained,
accounted answer package.

A useful shorthand is:

> **Move the analyst to the data, not merely the code.**

## Why this is a distinct phase

[The inside analyst](inside-analyst.md) asks how an automated component can
iterate safely inside the existing release architecture. Phase 1 already shows
that an analyst can issue ordinary requests under one `SessionAuditor` and
assemble released results into a typed dossier. The locked-plan work then
addresses the harder case where an analyst needs to act on withheld structure.

This phase asks a different question:

> **If the automated analyst can do the iterative work internally, why release
> all of the intermediate statistics at all?**

That turns the AI from only a new threat surface into a possible privacy
primitive. The claim must be demonstrated, not assumed: a badly designed
answer-level interface could simply hide the same unsafe queries behind prose.
The point of the phase is to compare the two architectures experimentally.

## The security intuition

Let an internal analysis trace be

```text
T = (Q1, Y1, Q2, Y2, ..., Qn, Yn)
```

where each `Qi` is an analytical operation and each `Yi` is an internal result.
In the current interactive model, some subset of the `Yi` is released after each
step. The researcher can adapt future requests to those releases.

In the proposed model the trace remains private. The researcher receives only

```text
R = Release(question, T, disclosure_state)
```

where `R` is a typed answer/evidence package and `Release` is deterministic
policy code, not the model.

This buys something even before invoking a stronger privacy definition:

1. the user cannot condition the next external request on intermediates they
   never received;
2. many internal exploratory operations can collapse into one externally
   visible release decision;
3. the release policy can minimise evidence to what the answer actually needs;
4. repeated or colluding requests can be accounted at the **answer boundary**
   rather than only inside one user's session.

It does **not** solve composition by itself. Two users can still ask two
high-level questions whose final answers differ by one person. Cross-user and
cross-session accounting therefore becomes more, not less, important.

## What should cross the boundary?

The next phase needs a sharper distinction than today's single `Dossier`.
Internally there are two different objects:

### 1. Private analysis trace

Never visible to the researcher. It may contain:

- proposed and executed `QuerySpec`s;
- withheld and released intermediate cells;
- model diagnostics;
- convergence state;
- sparse-level information available under a metered contingency;
- rejected candidate models;
- private working notes or model reasoning;
- the complete sequence of analytical choices.

The trace exists for execution, audit and TRE-side review. It is not a release
artifact.

### 2. Public evidence package

The only structured object available to the outside narrator or researcher. It
contains the minimum approved evidence necessary to support the answer, for
example:

- a typed claim (`supported`, `not_supported`, `null`, `not_answerable`);
- one or more approved effect estimates or aggregate tables;
- uncertainty where releasable;
- named sensitivity checks expressed as approved flags or released results;
- provenance pointing to release decisions, never to hidden values;
- a reason class when a question cannot be answered.

The human-facing narrative must remain a function of this public package only:

```text
narrative = g(public_evidence)
```

No model that has seen private intermediates gets an unconstrained prose channel
to the user.

## The question contract

A high-level question cannot remain arbitrary prose all the way to execution.
The system needs an intermediate **question contract**: a typed representation
of what is being asked at the scientific level rather than which low-level
statistics to release.

A first `QuestionSpec` might contain:

```text
population / cohort definition
exposure or predictor
outcome
scientific relation being tested
permitted adjustment variables
requested robustness checks
precision / reporting class
release policy or project context
```

Examples of relation types might be deliberately few at first:

- association between X and Y;
- difference between two declared groups;
- trend over a declared time axis;
- whether an effect persists after declared adjustment;
- whether a pre-specified hypothesis is supported.

The purpose is not to automate scientific ontology. It is to give the system a
stable object that can be canonicalised, audited and used for global accounting.
Two paraphrases of the same scientific request should not automatically become
two independent disclosure opportunities.

The `QuestionSpec` is therefore to the **answer boundary** what `QuerySpec` is to
the **execution boundary**.

## Proposed architecture

```text
outside TRE
---------------------------------------------------------------
researcher
    |
    v
natural-language question
    |
    v
question parser / contract builder
    |
    v
QuestionSpec ---------------------> public question identity
                                      / accounting class
---------------------------------------------------------------
inside TRE
    |
    v
analysis planner
    |
    v
private analysis trace
    |     registered procedures only
    |     existing QueryService / gateway
    |     locked-plan / selection budget where required
    v
TRE-side evidence selector
    |
    v
release compiler  <-------------- global disclosure state
    |
    v
PublicEvidence
---------------------------------------------------------------
outside data boundary
    |
    +--> deterministic renderer
    |
    +--> narrator that sees PublicEvidence only
    |
    v
answer
```

The model may propose the analysis and may propose which evidence is useful. It
does not decide which evidence is releasable. That remains deterministic policy
code over typed artifacts.

## The new hard problem: global composition

The current `SessionAuditor` is intentionally local. That is enough to show that
one analyst cannot perform an obvious differencing pair inside one session, but
it does not solve collusion:

```text
Alice asks A -> release RA
Bob asks B   -> release RB
Alice + Bob compute RA - RB
```

An answer-level service is useful only if its accounting identity is broader
than the chat/session that happened to request the answer.

The next phase should therefore make a **global release ledger** a first-class
research object. "Global" does not necessarily mean one ledger for an entire
TRE; plausible scopes include:

- project;
- approved research purpose;
- study population;
- population + measured quantity;
- dataset family;
- institutional disclosure domain.

The correct scope is an empirical and policy question. The technical requirement
is that changing usernames or sessions must not create a fresh disclosure
budget for the same protected population and quantity.

The ledger needs to recognise at least:

- exact repeat questions;
- semantically equivalent `QuestionSpec`s;
- nested or nearly nested cohorts;
- commensurable answer quantities across different views;
- repeated sensitivity requests whose combination is more informative than any
  one answer;
- parallel requests from different users.

This is where differential privacy is likely to become structurally cleaner than
ever more elaborate deterministic rules. The existing deterministic lineage can
remain the explainable first gate; a DP accountant can bound the residual
composition across the release domain.

## Canonical answers and memoisation

One promising defence against repeated probing is to make equivalent questions
produce the **same release object** rather than a fresh computation/release.

Conceptually:

```text
canonical_question_id = canonicalise(QuestionSpec)

if a current approved answer exists:
    return the same release
else:
    run analysis and account a new release
```

This is useful only where equivalence is defensible. Canonicalisation must not
pretend that scientifically different models are the same. But where two users
ask the same cohort/outcome/effect question in different language, treating the
second request as a fresh privacy event is unnecessary and creates an avoidable
attack surface.

Memoisation also changes the collusion game: repeated paraphrases do not buy
independent noisy draws or slightly different rounded outputs unless the release
policy deliberately permits them.

## Evidence minimisation

The answer boundary should expose fewer primitive statistics than the internal
analysis consumes.

For a question such as:

> Is late-night play associated with poorer wellbeing after adjustment for age,
> sex and region, and is the conclusion robust to the pre-specified sensitivity
> analyses?

an internal analyst might examine dozens of objects. A release need not contain
all of them. A plausible public evidence package might contain:

```text
claim: supported
primary_effect:
  estimate: <released>
  interval: <released if permitted>
adjustment_set: [age_band, sex, region]
sensitivity:
  direction_stable: true
  material_change: false
limitations:
  - one planned subgroup analysis not answerable under disclosure policy
```

The exact form is a research question. The important property is that the
release compiler has a finite menu of typed evidence objects; the data-sighted
analyst does not get to improvise an encoded narrative.

## Research questions

### RQ1 — Does answer-level access reduce disclosure risk?

For matched scientific tasks, compare reconstruction/differencing success under:

1. current interactive query-level access;
2. an answer-level analyst with only per-session accounting;
3. an answer-level analyst with shared/global accounting;
4. the same with a DP accountant when available.

The main outcome is attacker success, not whether a control fired.

### RQ2 — What utility is lost by evidence minimisation?

Measure whether researchers can obtain the intended scientific conclusion and
sufficient supporting evidence without receiving the full intermediate trace.
Outcomes should include correctness, `not_answerable` rate, false refusal,
number of follow-up questions and amount of released information.

### RQ3 — Can semantically equivalent questions be canonicalised safely?

Construct paraphrase and near-neighbour corpora. A useful canonicaliser should
merge equivalent disclosure opportunities without merging scientifically
different questions.

### RQ4 — How much does cross-user accounting buy?

Build explicit two-user and multi-user subtraction attacks. Compare a
per-session ledger with a ledger keyed to population/quantity/project semantics.

### RQ5 — How much private adaptivity is actually needed?

Compare fixed/locked plans, vetted-result adaptivity and data-sighted adaptivity.
If most useful scientific tasks can be answered from released-result adaptivity,
there is no reason to create a larger private selection channel.

### RQ6 — Can a public answer be made a mechanically checkable function of
approved evidence?

The narrator must not become the final exfiltration channel. Every quantitative
or categorical data claim in prose should trace to a field in `PublicEvidence`.

## Evaluation design

### Experimental substrate

Use at least the existing synthetic behavioural dataset and NIGHTPLAY. NIGHTPLAY
is particularly valuable because it contains planted truths, sparse groups and
question-bank scoring, so utility and privacy can be measured against known
ground truth rather than judged by inspection.

Add a dedicated **collusion corpus** with planted subtraction targets:

- two large cohorts differing by one protected individual;
- cohorts differing by 2--4 people;
- the same quantity exposed through different views;
- semantically equivalent questions phrased by different users;
- nested sensitivity analyses whose final releases compose;
- a benign pair that looks structurally similar but does not disclose a target.

### Attackers

Test at least three attacker classes:

1. **scripted semantic attacker** — knows the question schema and deliberately
   constructs neighbouring requests;
2. **LLM attacker** — given the public interface and prior answers, tries to
   recover a planted target;
3. **colluding users** — independent identities sharing their released answers.

The LLM attacker is useful as an attack generator, not as the security oracle.
Success is judged against the synthetic ground truth.

### Utility tasks

Use high-level questions with known answers rather than only attacks. Candidate
classes:

- association with adjustment;
- group comparison;
- longitudinal trend;
- robustness across pre-declared sensitivity analyses;
- a deliberately unanswerable question;
- a question whose correct answer requires refusing one intermediate analysis
  but still permits a weaker conclusion.

### Metrics

Privacy/security:

- exact or bounded target reconstruction success;
- number of independent released numerical objects;
- global accounting spend / epsilon where applicable;
- information gained from refusal/release patterns;
- cross-user attack success;
- narrator leakage or untraceable claims.

Utility:

- question-bank correctness;
- claim-level precision/recall against planted truths;
- rate of `not_answerable` outcomes;
- false refusal rate;
- number of user follow-ups required;
- amount of evidence released per correctly answered question.

Systems:

- number of internal analytical steps;
- cost and latency;
- replayability of the final evidence package;
- deterministic equivalence rate for canonical questions.

A useful headline plot would put **scientific task success** against **released
information / attack success** for query-level and answer-level architectures.
The phase is interesting only if the answer-level system moves that frontier.

## Implementation plan

### Phase A — define the answer boundary without giving it private adaptivity

Goal: establish the object model before increasing trust.

Build:

- `QuestionSpec` — typed high-level scientific request;
- `PublicEvidence` — finite release object;
- `AnswerService` — orchestrates an existing scripted or fixed plan;
- deterministic evidence compiler;
- narrator restricted to `PublicEvidence`;
- release-equality tests: two executions with the same public evidence produce
  the same outward answer object.

Initially, every internal step can still pass through the current `QueryService`
and see only released results. The research question is whether withholding the
intermediate releases from the *external* user already improves the attack
surface.

Success criterion: high-level NIGHTPLAY questions can be answered while the
outside transcript contains materially fewer release primitives than the current
interactive route.

### Phase B — private trace, public evidence

Separate the current dossier concept into two explicit types:

```text
PrivateAnalysisTrace
PublicEvidence
```

The internal analyst may retain the full trace; only the evidence compiler may
construct `PublicEvidence`. Add tests that perturb hidden trace fields while
holding approved evidence fixed and require the outward release to remain
identical.

This is the answer-level analogue of the current release-equality property.

### Phase C — collusion benchmark and shared ledger

Implement a ledger whose identity is not the individual session. Begin with a
simple declared scope such as:

```text
(project, population, quantity)
```

and run the collusion corpus against:

- session-only accounting;
- shared deterministic accounting;
- canonical-question memoisation.

Do not claim general collusion resistance yet. The deliverable is the measured
gap between the scopes.

### Phase D — canonical question identity

Add canonicalisation for a deliberately small subset of `QuestionSpec`. The
canonical representation, not free text, defines whether a release is a repeat.

Red-team false merges and false splits explicitly:

- same question, different wording -> should merge;
- same cohort/outcome, materially different estimand -> should not merge;
- same quantity through two database views -> accounting should compose;
- different populations with similar labels -> should not compose by accident.

### Phase E — global privacy accounting

Replace or complement heuristic global budgets with the DP accountant already
planned in [the roadmap](roadmap.md). The answer-level setting gives the
accountant a cleaner unit: the externally released evidence package rather than
every internal exploratory operation.

Internal computations that do not cross the boundary should not consume an
external privacy budget merely because the analyst performed them. Data-sighted
**selection** remains different: if hidden data determine which evidence is
released, that adaptive choice must be accounted, locked in advance, or proved
not to add a channel.

### Phase F — integrate data-sighted adaptation only where it buys utility

Reuse the locked-plan/selection-ledger architecture from
[the inside analyst](inside-analyst.md). The question is now empirical: which
high-level tasks fail without data-sighted contingencies, and is the utility gain
worth the additional information channel?

Do not make data-sighted adaptation the default merely because the machinery
exists.

## Proposed new types and modules

Names are provisional; the important point is the separation of authority.

```text
safetre/question.py
    QuestionSpec
    canonical_question_id(...)

safetre/evidence.py
    EvidenceItem
    PublicEvidence
    compile_evidence(...)

safetre/answer.py
    AnswerService
    AnswerResult

safetre/global_ledger.py
    ReleaseDomain
    GlobalReleaseLedger

safetre/private_trace.py
    PrivateAnalysisTrace
```

Existing components should remain underneath rather than be duplicated:

- `QueryService` remains the execution/release path for registered procedures;
- `SessionAuditor` remains useful as the local first line;
- the procedure registry remains the only analytical capability surface;
- locked plans remain the mechanism for metered data-sighted selection;
- the audit chain records both private execution lineage and public release
  lineage, with access controls preserving the distinction;
- `LLMNarrator` should evolve to accept `PublicEvidence`, never the private
  trace.

## Formal story

The phase is attractive because its core safety statement is a data-flow
property that fits the current assurance style.

### Lean candidates

Represent the outward answer type so it has no constructor for a private trace
field. Candidate properties:

- `PublicEvidence` can contain only registered release classes;
- `PublicAnswer` is a function of `PublicEvidence` and public question metadata;
- changing `PrivateAnalysisTrace` while holding `PublicEvidence` fixed cannot
  change `PublicAnswer`;
- canonical question identity ignores prose wording once a valid `QuestionSpec`
  exists.

### Alloy candidates

Model the stateful/global parts:

- two users sharing one release domain;
- a subtraction attack that succeeds under per-session accounting;
- the same attack blocked under shared lineage/accounting;
- memoised repeat questions do not create independent releases;
- budget is monotone across identities in one release domain;
- known residuals remain explicit satisfiable runs.

The model should include an executable twin for every attack run, following the
existing correspondence discipline.

## Threats and failure modes to keep visible

### Natural-language security theatre

A high-level UI is not a control if the user can specify arbitrary cohorts,
precisions and comparisons. Every question must eventually reduce to a typed
contract with explicit release semantics.

### The answer can still encode the data

A data-sighted LLM must never own the final prose channel. Hidden information
can be encoded in wording, ordering, punctuation, examples or apparently
innocent numbers. The final narrator sees approved evidence only.

### Evidence selection is itself a channel

"Release whichever result is most interesting" leaks through selection even if
each candidate statistic would be safe alone. Evidence choice must either be
pre-specified, made from already public information, or charged to an adaptivity
account.

### Canonicalisation can damage scientific validity

Two questions that sound alike may estimate different quantities. Privacy
memoisation must not silently replace a requested estimand with a previous one.
False merges are an integrity failure; false splits are a privacy failure.

### Global accounting can become unusably conservative

A ledger scoped too broadly can let one project exhaust analysis for everyone.
The scope and replenishment/expiry rules must be measured against real research
workflows rather than chosen only for maximal denial.

### Fewer outputs are not automatically less information

One richly detailed model result can reveal more than several coarse
aggregates. Evaluation must measure attack success or a formal privacy budget,
not count messages.

### Scientific autonomy

An answer-level service can become paternalistic if it hides the analytical
basis needed for scientific scrutiny. `PublicEvidence` must therefore be rich
enough to audit the claim and support legitimate challenge. The goal is not
"trust the AI's conclusion"; it is to release the minimum **checkable evidence**
needed to support or reject it.

## Stop conditions

This phase should be abandoned or substantially reframed if any of the following
hold:

1. answer-level access does not materially reduce reconstruction success once
   matched for scientific utility;
2. useful answers routinely require releasing essentially the full intermediate
   trace;
3. canonical question identity cannot be defined without unacceptable
   scientific ambiguity;
4. shared accounting produces intolerable false refusals before it meaningfully
   reduces collusion risk;
5. data-sighted evidence selection creates a channel that cannot be bounded
   without making the analyst useless.

A negative result would still be valuable: it would show that moving an AI
inside the TRE improves convenience but not the privacy boundary.

## What success would mean

The strongest plausible result is not "the AI understands what is safe". It is:

> A researcher can ask a broad scientific question; an automated analyst can do
> substantially more adaptive work inside the TRE than the researcher could
> safely conduct through an interactive output channel; and the researcher
> receives a smaller, mechanically traceable evidence package whose disclosure
> composes across users and sessions.

That would invert the usual framing of an AI analyst. The agent is indeed a new
attack surface, but placing the analyst on the data side of the boundary may
also let the system expose **less of the analysis itself**.

In that architecture, the scarce object is no longer a query. It is a release.
