# Changelog

All notable changes to safe-tre-agent. The normative record of safety
behaviour is [docs/specification.md](docs/specification.md); security findings
and fixes are in [docs/hardening-log.md](docs/hardening-log.md).

## Unreleased

### Security

- **Red-team round 8 ([hardening log](docs/hardening-log.md)): the filter
  algebra was a differencing channel, and the harness could not see it.**
  Twenty fixes, one residual priced rather than closed, and round 7's two
  open findings closed. A full adversarial review of the query surface
  ([redteam/adver_report.md](redteam/adver_report.md)).
  The QuerySpec boundary held; the leaks ran through the filter algebra nobody
  had attacked with, through data content nobody had made hostile, and through
  failure paths nobody had made fail. #37 to #39 came from the report; #40 to
  #48 came from probing those fixes and working the rest of it, #48 being why
  none of it had been caught before; #49 to #52 close the remaining state,
  concurrency and honesty items; #53 to #56 close out the report, including
  round 7's #34 and #35.
  - **Pipeline exceptions escaped as un-audited 500s** (#37). A planner
    failure, engine error or raising fit produced a 500 with no audit record —
    a hole in the tamper-evident log and a crashability oracle. `service.handle`
    is now an audited, fail-closed wrapper: the exception's TYPE goes to the
    audit log (never its message), and the caller gets the canonical withheld
    response. Spec R8 amended: every request — released, redacted, denied, or
    errored — produces exactly one audit record.
  - **The auditor's total-delta check counted rows, not donors** (#38). On an
    event-level view, two cohorts 1-3 people apart but ~30 events apart passed
    every control — the double-differencing shape that recovers a 1-3 donor
    cell from two large, individually safe releases. The auditor now totals
    distinct donors (completing D4's individuals-not-rows reading), and a
    model's roles are observed under role-qualified keys so a binomial's
    trials/successes tables are not false-flagged as a pair.
  - **Internal range filters cut finer than the public dimensions they back**
    (#39). A sweep `age_years >= v` read each exact-age sub-band total out of
    individually safe releases, and `age_years == 41` released any ≥10-donor
    exact age directly. Range filters on an internal variable must now align
    to the declared band edges (`>=` 13/16/18/25/35/50, `<=`
    15/17/24/34/49/69); exact-age equality/membership is not expressible.
    Decision [D7](docs/decisions/D7-donor-totals-and-band-filters.md); spec R6
    amended; the public manifest states the edges (`MANIFEST_VERSION`
    2026-07-28 v8, the webpage-visible version tag).
  - New red-team entries pin all three: `age_range_sweep_step`,
    `exact_age_probe`, `double_differencing_two_common_dims`,
    `donor_delta_differencing`.
  - **The lineage auditor differenced donor cohorts, but a release is a
    function of rows** (#40). Found by probing #39 rather than by reading the
    report: #39 closed the `age_years` route, not the shape. `age_rating` is an
    attribute of the app rather than the donor, so `{age_rating>=7, ...}` and
    `{age_rating>=8, ...}` hold *exactly the same people* while the rows they
    aggregate differ by a suppressed cell — 20 such cells were still
    recoverable. `QueryEngine.row_symdiff_donors` counts the donors behind the
    rows exactly one of two queries aggregated, and the guard becomes
    `d < threshold` so a difference of zero denies too. On donor-level filters
    the new count equals `cohort_symdiff` exactly. Spec P11 amended.
  - **Dominance was a signed share, so a negative measure inverted it** (#41).
    Over a negative total `MAX(c)/SUM(c)` selects the least negative donor:
    negating one region's spend moved its witness from 0.620 to 0.0027 with the
    concentration unchanged. The witness is now the magnitude share, which is
    identical on non-negative data.
  - **A released payload was never checked for finiteness** (#42). A single
    `-inf` record, and finite magnitudes whose sum overflows, both released.
    Non-finite aggregate payloads now suppress the cell; a fitted model's
    output is out of scope, since an ANOVA `Residual` row has no F or p by
    definition.
  - **Undeclared values were dropped from the marginals and then printed as
    cell keys** (#43). #29's reasoning — a value outside its declared domain is
    disclosive by its name — now applies on the release path, against the
    query's declared group-by keys rather than a dtype guess.
  - **The external checker's returned rule names reached analyst text and the
    audit log** (#44). Poisoned category values travel to the checker as cell
    keys and came back as finding names. A returned name is now projected onto
    a declared identifier shape; the rejected text is recorded nowhere.
  - **Loopback was treated as a trust boundary** (#45). The identity header was
    trusted because the channel was loopback-only — but the model runtime is
    untrusted by the threat model and runs on loopback. 21 forged requests were
    accepted and attributed to a victim, and rotating the header minted a fresh
    query budget and empty differencing lineage, because the session controls
    are keyed on the login. `SAFETRE_PROXY_SHARED_SECRET` is now required
    whenever `SAFETRE_REQUIRE_IDENTITY=1`, an empty allowlist admits nobody in
    production, repeated and comma-joined headers are refused, and the shipped
    systemd unit carries both settings. Spec P13 amended.
  - **Policy floors were checked on the dataclass defaults, not the resolved
    configuration** (#46). Any single relaxed dial passed 737 of 737 tests.
    Floors now apply to the resolved policy, with `SAFETRE_ALLOW_UNSAFE_POLICY=1`
    as an explicit, loudly-logged override; the effective policy is logged at
    startup.
  - **Only `/api/query` was rate-limited** (#47). Twelve concurrent
    `/api/audit/verify` clients moved query median latency from 51 ms to
    1582 ms. A middleware now covers every route, and the full-chain scan has
    its own tighter budget.
  - **The red-team harness could not fail** (#48) — the finding that explains
    the rest of the round. Its oracle asked `leak_detector` about the final released
    frame, which after finalization has no dominance, influence or donor-count
    columns left to test, so it could not return "yes"; and it required a
    control to have fired, which an attacker supplies by appending an unrelated
    over-granular query. A session that recovered one donor's exact spend
    reported PASS. The oracle is now computed from the row-level data, inspects
    every step, and asks what released cells *combine* into; the verdict is its
    findings alone. `redteam/fixtures.py` adds negative, non-finite, NULL,
    undeclared and hyperactive-donor data, and the corpus gains `corr`,
    `sum_sq` and hostile-fixture entries. `tests/test_redteam_oracle.py`
    calibrates the oracle in both directions — it must stay silent on a correct
    system and speak up when a control is removed. Spec R12 amended.
  - **Session state was not durable** (#49). A session lasted exactly as long
    as the process, so a deploy or a crash cleared every analyst's query budget
    and differencing lineage — a pair denied before a restart completed after
    one, recovering a donor's exact spend, with the whole attack sitting unread
    in the audit log. `SessionStore.rehydrate` rebuilds both at startup over a
    declared `session.window_hours` (default 24). Note it tightens behaviour:
    budget spent before a restart is still spent after it. Spec R6 amended.
  - **A prefill link wrote into the audit log under whoever opened it** (#50).
    `/#q=...` auto-ran, so a shared URL planted an attacker-chosen request as
    the victim, recorded as released. The link now fills the box and stops; a
    click is the consent. Auto-run survives only as
    `SAFETRE_ALLOW_PREFILL_AUTORUN`, off by default, for the screenshot scripts
    that drive a browser which cannot click.
  - **One DuckDB connection served every concurrent user** (#51). A frame
    returned to the wrong request would attach one analyst's vetting to
    another's cells. Each thread now gets its own cursor over one shared
    catalogue, which required materialising the input tables rather than
    registering them (a registered frame is connection-scoped and invisible to
    a cursor). Pinned by a 300-query, 12-thread load test.
  - **The legacy code-writing sandbox moved out of the shipped package** (#52).
    `static_check` is a denylist; `np.memmap` and `np.genfromtxt` walk past it
    and release file contents. The path was never reachable from the web app or
    the CLI, but it lived in `safetre/` and the red-team table put guard-OFF
    beside guard-ON for it, which reads as though the guard were what made the
    difference. It is now `redteam/legacy/`, labelled a counter-example, with
    `tests/test_legacy_sandbox.py` pinning the bypass end to end — including
    recovering file contents in order, since the release re-ordering is a side
    effect and not a defence.
  - `_dim_value_set` now models SQL three-valued logic, so the cheap marginal
    bound is an upper bound again and a range predicate no longer raises on a
    NULL-bearing dimension.
  - **The optional-role bit is priced, not closed** (#53). A gaussian model
    whose dispersion cells fail the dominance bound still releases and says so,
    on 30% of released models. It is not closed because it cannot be closed by
    silence: a partial release carries three columns where a complete one
    carries six, so deleting the finding would remove the sentence and leave
    the channel. The two real closures are priced for an operator to choose
    between (`artifacts/optional_role_channel.json`).
  - **The response-time ceiling is now a deadline** (#54, closing round 7's
    #34). An overrunning request used to be answered when its work finished,
    advertising its size exactly as the ceiling exists to prevent. The boundary
    moved to a raw ASGI layer, because inside `BaseHTTPMiddleware` neither
    cancelling nor abandoning the task answers on time — anyio's thread pool is
    not cancellable and `call_next` runs in a task group that waits for its
    child, both measured at 1203 ms against a 200 ms ceiling. Now 400/800/1600/
    3200 ms of work all answer at 252.3-252.5 ms. `redteam/timing_attacker.py`
    attacks the channel adaptively rather than measuring it passively, and the
    straddle vector is gated in CI. Spec R18 amended.
  - **The effective policy is recorded in the audit chain** (#55). A clean
    release under `min_cell=1` was schema-identical to one under the shipped
    policy, so the log could not say which rules approved an output. A
    distinguished `status=config` record at startup puts the resolved policy
    inside the chain, with no schema change and no migration.
  - **`max_output_rows` can fire** (#56, closing round 7's #35). The rule
    required "no aggregation at all", which every compiled query makes
    impossible, so the dial was wired to nothing. It now bounds released cell
    count and escalates to a human checker — judged on what is released rather
    than what was computed, which is 11 of 241 group-by combinations rather
    than 46.
  - **A harness script wrote to the operator's real audit log** (#57). #55 made
    importing `safetre_web.app` append a policy record, which silently turned
    "import the app" into "write to the audit log" — and four harness scripts
    imported it without pinning `SAFETRE_AUDIT_DB`, so `redteam/timing_attacker.py`
    put 578 junk records in the developer's log. #36 recurring by a new route:
    that fix lived in `tests/conftest.py` and never covered the scripts. They
    now pin a throwaway path before the import; the polluted log is archived
    rather than repaired, since it verified and re-MACing is the operation the
    design exists to prevent.
  - `redteam/round8_repro.py` re-runs every load-bearing finding and exits
    nonzero while any is open; `redteam/remediation-plan.md` records the
    verification and the ordering. Nothing from the report is left open; what
    remains is roadmap work — the DP accountant, cross-user lineage, and
    asynchronous delivery.

### Security (round 7, 2026-07-26)

- **Red-team round 7 ([hardening log](docs/hardening-log.md)): five fixes, two
  open.** An adversarial pass over the whole surface on the assumption the code
  is public. The release path held; the leaks ran through the paths nobody had
  treated as outputs.
  - **The published marginals named the ages held by a single donor** (#29).
    The disclosure-safe projection dropped values outside a *declared* domain
    and exempted columns without one — which is `age_years`, the variable the
    catalogue calls internal and never-returnable. Sub-threshold values of a
    domain-less column are now omitted rather than count-nulled, which costs
    the auditor nothing because an absent key and a sub-threshold key give the
    same verdict.
  - **A refusal was a numeric profile of what it had withheld** (#30). Denied
    queries returned the engine's cell count and how many cells each rule had
    caught, and a cohort matching nobody came back *released* with an empty
    table while a cohort matching one person came back *redacted* — so the
    status word alone answered "does anyone match?". Chained with #29, eight
    refusals recovered a unique donor's quasi-identifiers with no cell ever
    released. Refusals decided from the data now give one canonical answer and
    the counts go to the audit log; refusals decided from the request are still
    explained in full, because the analyst holds the request.
  - **Two rare exclusions escaped the differencing rule that one breaks**
    (#31). The bound gave up whenever more than one dimension differed. It now
    sums over the differing dimensions, which was always sound — and closes a
    residual the Alloy model had been exhibiting as a satisfiable run.
  - **One missing value switched off complementary suppression** (#32). Cell
    keys were identified by dtype, so a single unrated app made an integer
    dimension `float64` and stopped it being a key — silently reinstating
    hardening #27 and #28. The query's group-by is now threaded through
    instead of inferred.
  - **The external checker's per-call table lived on the shared vetter** (#33),
    so concurrent users could be answered about each other's tables with a
    matching request id. Reproduced at 2 in 240 under forced preemption.
  - Still open: the response-time ceiling is a post-hoc check rather than a
    deadline, so an overrunning query still advertises its duration (#34); and
    `max_output_rows` cannot fire on the QuerySpec path, making it a live dial
    for a control that never runs (#35).

### Added

- **An external checker is now used by default when one is configured
  ([D6](docs/decisions/D6-checker-default.md)).** "By default" cannot mean
  "required": this is a library a TRE embeds and the checker cannot be
  imported into the service environment, so demanding one would make the
  software fail to start for everyone who has not set it up. Leaving
  `SAFETRE_VETTER` unset now composes with an external checker whenever
  `SAFETRE_CHECKER_CMD` is set; naming the vetter explicitly requires one and
  fails at startup without it. **This is not a silent downgrade, because every
  release records which rules decided it** — `CellVetter.describe()` puts the
  vetter and the checker's version in the trace, so a release reads
  `gateway: redacted by standin+external(0.4.12)`, and one taken without a
  checker says so. The rule held to is not "a checker always ran" but "a
  release never implies checks that did not run". Failure behaviour is
  unchanged and still strict: once configured, every way the checker can fail
  denies.
- **Response time no longer ranks the cohorts suppression hides (spec R18,
  [D5](docs/decisions/D5-timing-channel.md)).** The deployment boundary holds
  every response to the next multiple of `response_quantum_ms` and refuses
  work past `response_ceiling_ms`. Quantising rather than fixing the time is
  the point: cells at or above the threshold have their counts published
  anyway, so only the sub-threshold work needs to be indistinguishable, and
  that varies by a few milliseconds — one 50 ms bucket holds all of it at a
  fraction of the cost of padding to the worst case. Measured at the same
  boundary, sub-threshold pairs orderable within a session's budget fall from
  **7 of 15 to 0 of 15**, closest pair from 6 samples to 26.
  Three details carry the argument: the middleware is outermost, so no
  fast-fail path escapes it; padding runs to the next boundary *from arrival*
  rather than adding a fixed pause, which would shift the distribution without
  collapsing it; and the ceiling refuses, with the refusal padded too, since
  an unpadded refusal is the fast answer meaning "your query was expensive".
  **Narrowed, not closed** — quantisation leaves a bucket-crossing
  probability, so a cross-session attacker can still order pairs at 26–70
  samples. Constant time is one setting away (quantum = ceiling) and was not
  made the default because every query would then pay the ceiling.
  The ceiling defaults to **5 s**, which is deliberately generous: raising it
  costs nothing, since padding runs to the next quantum and never to the
  ceiling, and it does not weaken the hiding, since the sub-threshold work
  that must be indistinguishable lands in the first bucket regardless. Too low
  refuses legitimate analysis; too high widens a tail across cohort sizes that
  are published anyway. The worst query shape measured on the demo data — a
  leave-one-out correlation over three dimensions — is 28 ms steady-state, so
  the default leaves two orders of magnitude, and a deployment should time its
  own rather than inherit that.
  The demo's "Completed in Nms" is measured client-side around the fetch, so
  it reports the padded round-trip and cannot hand an analyst the unpadded
  time — checked, because a UI that printed the real duration would have
  defeated the control entirely.
- **Measured: what composing an external checker actually costs.**
  `scripts/measure_composite_cost.py` → `artifacts/composite_cost.json`. The
  worry was that composing would apply ACRO's dominance rules to second-moment
  cells at ACRO's own parameters — `AcroVetter` ignores `VettingParameters`,
  so the per-class dial governs the stand-in's rules and not the checker's.
  It did not materialise: over 4684 cells the union suppresses **23 more**
  than the stand-in alone, and of 102 available gaussian models **5** stop
  being available. Coefficients-only is unchanged at 42, which says ACRO added
  no new second-moment refusals at all — the five losses are mean cells.
  Flipping the default is therefore a 5% cost in model availability on this
  data, not the cliff it might have been.
- **Measured: the response-time channel, and the security model was wrong
  about it.** `scripts/measure_timing_channel.py` →
  `artifacts/timing_channel_*.json`. The security model called data-dependent
  latency "sub-millisecond and swamped by jitter"; that was an assertion, and
  at the service boundary it is false. Latency tracks cohort size at Spearman
  +0.86, which for published cells reveals nothing — but **9 of 15
  sub-threshold pairs can be put in size order within the 20-query session
  budget, some in 2 queries, at gaps of 2 donors**. Ordering suppressed cells
  by size is what suppression exists to prevent. Two qualifications: the
  measurement has no network in the path, and an external checker does *not*
  make it worse (7 of 15), so the leak is the engine's own work. The security
  model now says so, and [D5](docs/decisions/D5-timing-channel.md) records the
  options — constant time, coarse quantisation, or documented acceptance —
  with the criterion that any defence must take the orderable-pairs count to
  zero rather than merely raising the sample count.
- **The external checker is started once, not once per table (protocol 2).**
  Spawning a process per vetted table cost a second or two of interpreter and
  import time each — which a model pays per design-cell table and a TRE would
  pay on every query, enough that an external checker could not sensibly be
  anyone's default. The contract is now a stream: one request per line in, one
  response per line out, over a process the client starts lazily and
  supervises. Measured end to end on the demo dataset: **0.82s for the first
  query, 0.03s for each after it**, with decisions unchanged.
  A reused pipe brings a failure a fresh process cannot have, and it is the
  dangerous one: if a request times out and its answer arrives late, the next
  request would read it as its own and cells would be vetted against verdicts
  computed for a different table. Two defences — every request carries an id
  the response must echo, and any timeout or protocol error **discards the
  process** rather than reusing it in a state nobody can characterise. A
  checker whose reported version changes mid-session also denies, since a
  release must not claim checks from a version that did not run them, and a
  checker that keeps dying stops being restarted. Each is a test.
- **Every clause now has a traceability row, and a test keeps it that way.**
  The [assurance case](docs/assurance-case.md) had surfaced twelve
  requirements asserted by the specification with no recorded evidence,
  because the table had been scoped to the prohibitions. Writing the rows
  meant finding the evidence rather than assuming it, which turned up three
  clauses that were not in fact checked and one that was not met:
  - **R7** — the human-in-the-loop routing. `hitl_decision` *is* the clause
    and nothing tested it directly, though it is the gate every finding
    passes through and the one this round's `suppressable` work re-routed.
  - **R3** — the memory and thread caps were never asserted; only the row cap
    was, incidentally, by the SafeSQL shape tests.
  - **R11** — requires the validated spec, the compiled SQL plan, the
    findings and the trace to be inspectable. Three of the four were
    available; **the plan was exposed nowhere**, so the clause was not met.
    `Result.plans` now carries it — one entry, or one per design-cell table
    for a model — and it is safe to show because the SafeSQL shape binds
    every value, so the string names allowlisted columns and nothing else.
  `tests/test_requirements.py` covers all three, and
  `test_every_clause_has_a_traceability_row` closes the hole permanently: a
  clause may be *Partial*, but it may not be unaccounted for.

### Changed

- **`config.yaml` shows the response-time dials, and says why three others are
  missing.** An operator reading the shipped policy file saw six dials where
  twelve exist, with no way to tell deliberate omission from oversight. The
  R18 quantum and ceiling are now written there with their defaults; the three
  that stay out — `moment2_dom_threshold`, `vetter`, `checker_cmd` — stay out
  *because unset is a distinct behaviour for each of them*, and the file now
  says so. Pinning `vetter: standin` in a config file would silently switch
  off the checker default that D6 just turned on, which is exactly the kind of
  quiet regression a "let us complete the file" tidy-up would cause.
- **Asynchronous delivery is recorded as the structural answer to the timing
  channel**, in the [roadmap](docs/roadmap.md)'s parked list and the
  [security model](docs/security.md) as well as in D5. Collect a result on a
  schedule rather than return it on the call and delivery time stops being a
  function of compute time, so there is nothing left to narrow; the security
  model previously pointed at the DP accountant here, which is the end state
  for the differencing residual and not for this one.
- The ACRO rollout paragraph in the roadmap still said the default was
  unchanged and the remaining question was whether to flip it. It is flipped;
  what remains there is the preprint's gateway section.

### Fixed

- Four places wrote *data* with a singular verb, one of them the assurance
  case's top-level claim (generated, so fixed at the generator).

## 0.5.0 — 2026-07-26

The checker, and the case for it. An external output checker can now be
switched on end to end — its rules run through a seam that keeps them away
from how a release is rounded, ordered or shaped, and it runs in its own
process where every failure denies. Second moments stopped being checked as
though they were sums, which is what had been quietly deciding whether models
were available at all.

And because the questions this project now poses have grown harder to hold in
one head, three artefacts were added to reason about it with: a catalogue of
every dial and what its number means, a log of what was decided and what would
change our mind, and the safety argument drawn as a structure with its gaps
marked. Each is generated from the code and enforced in CI, and each found a
real defect on its first run.

### Added

- **An assurance case ([assurance-case.md](docs/assurance-case.md)).** The
  safety argument as a structure rather than a narrative: a conditional top
  claim, decomposed by the **Five Safes** — the framework TRE accreditation
  already speaks — with each clause naming what enforces and checks it, the
  trust assumptions carried in as context, and the gaps marked rather than
  omitted. Generated from the specification's traceability table and the
  decision records, so it moves when they do.
  `tests/test_assurance_case.py` enforces the property that makes such a
  document worth trusting instead of merely reassuring: it cannot quietly
  omit anything. Every clause must be assigned a purpose, every clause the
  specification states must be argued, every *Partial* clause must appear as
  a gap, and every open decision must be listed.
  **It found one immediately.** The traceability table is scoped to the
  prohibitions, so twelve requirements — R1–R4, R6–R13, including the audit
  chain and the restricted-channel gate — are claimed by the specification
  with no recorded evidence. They are enforced and tested; what is missing is
  the record saying where, and an argument may not cite evidence it cannot
  point at. They now appear as **unevidenced** rather than being dropped,
  which would have made the case look complete.
- **D4 is parked, not open** — and the decision log gained a status to say so.
  A question nobody has got to and a question that was scoped and deliberately
  declined are different states, and only one of them is waiting for someone.
  The robust-dispersion route would add a second dispersion estimator to the
  trusted computing base, a second thing an output checker must understand, a
  bias correction to defend, and another parameter — against inference on 36
  of 539 gaussian points on synthetic data. That is a poor trade in the
  currency that now binds this project: not engineering effort, but how much
  an operator must hold in their head to reason about a release.
  Coefficients-only stands. The plan survives in the record so unparking is a
  decision rather than a rediscovery, and a parked record must say why it was
  parked.
- **A plan for D4**, the question about inference from a dispersion that
  cannot be released. It reduces architecturally to a new registered
  procedure (a winsorised second moment, whose cell is vetted like any other,
  so P21 needs no new argument) and statistically to an experiment, with
  **acceptance criteria fixed in advance**: coverage of nominal 95% intervals
  at or above 95%, a majority of the 36 affected models recovered, and the
  robust cell passing dominance at the *default* bound. The comparison
  deliberately includes relaxing `moment2_dom_threshold` instead — the two
  buy the same availability, one by losing accuracy and the other by losing
  protection, and choosing between them requires measuring both.
- **A decision log, with the field that usually goes missing
  ([decision-log.md](docs/decision-log.md)).** The hardening log records what
  went wrong; this records what was *chosen* where more than one answer was
  defensible — the question, the evidence, what was rejected, and **what would
  change our mind**. Four records to start: models fitting from vetted cells
  rather than rows (D1), rule sets composing as a union with the checker out
  of process (D2), second moments getting their own bound and their own
  failure mode (D3), and inference from an unreleasable dispersion (D4), which
  is recorded as **open** so the gap in the argument sits beside the answers
  rather than being absent. `tests/test_decision_log.py` fails the build on a
  missing field, a clause not in the specification, evidence that does not
  exist, a `revisit_when` too short to be a condition, a broken cross-record
  link, or a stale index — and on there being no open questions at all, which
  would mean they were being left out rather than answered.
- **A parameter catalogue, generated from the parameters themselves
  ([policy-parameters.md](docs/policy-parameters.md)).** Every dial that
  changes what the gateway releases, on one page: what it controls, what the
  *number* means in terms of donors and cells, how to set it, the clause that
  governs it, the measured cost of changing it where one exists, and the test
  that proves a change to it changes a real decision. The page is rendered
  from metadata declared on each `PolicyConfig` field, so it cannot drift, and
  `tests/test_policy_catalogue.py` makes the declaration mandatory: a
  parameter added without saying what it means, citing a clause that does not
  exist, or pointing at missing evidence fails the build. **Both documented
  ways of setting it are exercised too** — the environment variable and the
  `config.yaml` key must each demonstrably change the loaded policy, which is
  the bug the loader was written to fix and which nothing had been preventing
  from recurring. The `config.yaml` reader is now generic, driven by the
  declared keys rather than a hand-maintained list.
- **Removed two settings that were not settings.** The new check found
  `hitl.default` and `model.backend` in `config.yaml`, neither of which
  anything read — while the file's header told operators that editing it
  changes behaviour. The HITL rule is fixed in code deliberately (a high
  finding denies, a medium one escalates) and the backend comes from
  `SAFETRE_LLM`; both are now said in the file, and a key no parameter reads
  fails the build.

- **The Alloy model follows the code on optional tables.** Making the gaussian
  dispersion optional falsified `P19_noFitOnSuppressedCells`, which asserted
  that no fit coexists with *any* suppressed cell of its spec — a
  machine-checked model that no longer described the system. `Cell` now
  carries a `Required`/`Optional` role, the service rule mirrors
  all-or-nothing consumption, and P19 splits into
  `P19_noFitOnSuppressedRequiredCells` and
  `P19_optionalTablesAreAllOrNothing`. A new satisfiable run
  (`CoefficientsWithoutDispersion`) exhibits a fit alongside a suppressed
  optional cell, so the weakened rule is shown to still permit the case it
  was weakened for rather than being taken on trust. Checking it locally
  found a real counterexample first: the rewritten service rule allowed a fit
  with no inputs at all, since a spec of nothing but optional tables was
  expressible in the model though no procedure can express one.
- **A second moment is no longer checked as though it were a sum
  ([acro-integration §3](docs/acro-integration.md)).** Squaring is not
  share-preserving: a donor holding a fraction `p` of a cell holds
  `p²/(p² + (1−p)²/(k−1))` of its sum of squares, crossing one half at
  `p = 1/(1+√(k−1))` — 0.19 in a twenty-donor cell. So one nominal bound was
  two rules, and the tighter one governed whether models were available at
  all. R14 gained a `moment2` disclosure class (the vocabulary could not
  previously express the distinction), `sum_sq` returns it, and the dominance
  bound is selected by class through `VettingParameters.dominance_for`, with
  `PolicyConfig.moment2_dom_threshold` where an operator states it. **Unset by
  default, so behaviour is unchanged**; stating it makes the choice visible to
  a certifier and settable without touching vetting code. Spec R5 amended.
- **A gaussian model releases its coefficients when its dispersion cannot be
  released.** The estimates are a function of the vetted mean cells and counts
  alone, so `sum_sq` is now declared an *optional* table
  (`ModelProcedure.optional_roles`): if it cannot be released completely it is
  dropped entire — never partly, which would silently change the number it
  feeds — and the release carries estimates with no standard error, t, p or
  R², a `dispersion_released: False` flag, and a finding saying so. Nothing
  derived from the withheld table leaves, the released cell table has no
  `sum_sq` column, and P21 still holds: `refit_from_artifact` reproduces the
  degraded release bit-for-bit. Gaussian skeleton points now split 47 full
  fits / 36 coefficients-only / 456 refused, against 47 / 0 / 492 — exactly
  the 36 the dispersion cell alone had been refusing. Confined to the gaussian
  dispersion: binomial and poisson cannot be fitted without their tables, and
  ANOVA is a variance decomposition. Spec R15 and P19 amended.
- **An external output checker can now be switched on (roadmap item 1,
  rollout steps 3–4).** `PolicyConfig.vetter` selects `standin` (the default)
  or `standin+external`, with `checker_cmd` saying how to start the checker;
  asking for one without a command fails at startup, not at the first query.
  The engine grew `contributions()` and `cell_context()` — procedures now
  declare their own `contribution_expr` and `checker_aggfunc`, so `sum_sq`
  contributes on the squared scale its dominance rule works on — and the
  service builds that context only when a vetter actually reads it. End to
  end on the demo dataset, `sum` by region releases nine regions under the
  stand-in and eight with ACRO composed in; Wales, the NK-rule cell, is the
  difference the comparison predicted. The default is unchanged: what is
  *not* decided is §3 of the design, the second-moment parameters.
- **Two integration defects the end-to-end run caught**, both invisible to
  unit tests of the pieces. A vetter built from configuration has no query in
  it, so an external checker handed only a cell frame vetted every table as a
  single `total` cell and released everything — the cell keys and the
  aggregation now travel with the contributions in a `CellContext`. And
  suppressability was a hard-coded list of the stand-in's own rule names, so
  a new vetter's findings — already resolved by suppressing their cells —
  read as unresolved residuals and denied every query they touched; a
  `Finding` now declares whether suppression resolves it.
- **The external-checker boundary (roadmap item 1, rollout step 2, second
  half).** `redteam/acro_checker.py` is the checker process and
  the versioned JSON contract and client (now `safetre/external_checker.py`,
  moved there when the service gained a switch for it) — which
  imports nothing from ACRO, so it is constructible in the service
  environment where ACRO cannot be installed at all (C3). **Every failure
  denies:** non-zero exit, crash, timeout, unstartable command, malformed or
  non-JSON response, protocol mismatch, a reported error, and a verdict list
  that does not cover the table. There is deliberately no path that falls
  back to the stand-in's rules and releases anyway — a release claims the
  checks that ran, and a checker that is down is not a checker that approved.
  `tests/test_acro_boundary.py` drives each failure with a fake checker, so
  the suite needs neither ACRO nor its environment; the checker's reported
  version is captured for a release to record. Cross-environment operation is
  proved on every comparison run: the harness calls the real checker through
  `uv run --group acro` and fails if the out-of-process verdicts differ from
  the in-process ones.
- **ACRO's rules now run through the seam (roadmap item 1, rollout step 2 —
  the rules).** `redteam/acro_vetter.py` wraps ACRO's own
  check implementations as a `CellVetter`, and the comparison harness drives
  its ACRO side through it instead of a bespoke code path. The regression is
  the published measurement itself: the rewired harness reproduces 337 cells,
  6 `acro_stricter` and 21 `standin_stricter` exactly. It lives in `redteam/`
  deliberately — ACRO cannot be imported into the service environment (C3),
  so production runs this logic behind the out-of-process boundary of §4 of
  [the design](docs/acro-integration.md), which is what remains of the step.
  `tests/test_acro_vetter.py` pins the cell-key mapping, the per-rule finding
  attribution and the fail-closed treatment of a cell ACRO returned no
  verdict for, all without ACRO installed.

- **The cell-vetting seam (roadmap item 1, rollout step 1).** `CellVetter` is
  the interface ACRO will enter through: it decides which cells may be
  released and does nothing else, so complementary suppression, finalization
  and released-value shaping stay the policy's own — which is what keeps
  hardening #27 and #28 and the release-equality property true whatever rules
  run. `StandinVetter` holds today's rules unchanged; `CompositeVetter` runs
  several and suppresses a cell if any of them does, the union being the only
  composition the ACRO comparison supports (neither rule set subsumes the
  other) and a monotone one, so composing cannot regress protection.
  `DisclosurePolicy` gained a `vetter` field and reads its thresholds at call
  time, so a policy built from `config.yaml` cannot vet on stale ones.
  Behaviour preservation was checked directly, not inferred: the pre-seam
  `apply` ran beside the new one over all 2622 skeleton points with identical
  action, released frame and findings on every one.

## 0.4.0 — 2026-07-25

The release-equality round: the query path's released output is now proved to
be a function of the table the gateway approved, and two of this release's
entries are leaks that proof found. The dataset gained the concentration its
dominance rules had never been tested against, which turned the ACRO
comparison from a one-sided result into a two-sided one, and the integration
design was written from those numbers.

### Security

- **Complementary suppression no longer picks its victim by the exact count
  (hardening #27).** `_secondary_suppress` sacrificed the cell with the
  smallest pre-rounding count, so of two cells that both release as `n = 10`
  the analyst learned which was smaller. The victim is now ranked on the
  released (rounded) count and tie-broken on the public cell key.
- **Released rows are no longer ordered by the exact count (hardening #28).**
  The engine hands the gateway cells in `ORDER BY n DESC` on the exact count
  and the gateway preserved that order, so a released table ranked cells more
  finely than its own released counts did. `_finalize` now re-sorts on the
  rounded count, then the cell key — which also makes a release reproducible
  run to run, as `ORDER BY` over tied counts is not. Suppression decisions and
  released numbers are unchanged; only which cell is sacrificed and what order
  rows appear in.

### Added

- **ACRO integration design (roadmap item 1, slice 2 — the design, not the
  code).** [docs/acro-integration.md](docs/acro-integration.md) fixes what to
  build from the first slice's measurements: the seam is a `CellVetter`
  protocol *inside* the gateway's vetting step, so complementary suppression,
  finalization (which owns hardening #27 and #28) and released-value shaping
  stay ours and the release-equality proof survives; the three rule sets
  compose as a union, because the measurements show none subsumes another;
  the checker runs out of process on its own pinned environment (C3) and
  fails closed and loudly on any error, with its version recorded per release
  in the audit chain; and the dominance parameters become a function of the
  output contract's disclosure class, so the second-moment cell's treatment
  is a stated policy rather than an accident. Compatibility shims carry
  explicit removal conditions, and the rollout starts with a
  behaviour-preserving refactor the existing suites regress.
- **CI runs the exhaustive skeleton passes.** A new `exhaustive` job runs the
  `-m slow` suite — every query-skeleton point through the release-equality
  properties and every model-skeleton point through the P21 reproducibility
  meta-test — so "exhaustive, not sampled" is checked rather than asserted.
- **Measured: the dispersion cell, not the frequency threshold, is what
  refuses a cells-first model.** A gaussian model needs group means *and*
  group sums of squares, and P19 denies it if either is suppressed — but
  squaring is not share-preserving, so the same 50% dominance bound is far
  tighter on the second moment (an equal-rest cell of `k` donors crosses it at
  a linear share of `1/(1+√(k−1))` — 0.19 at twenty donors, 0.09 at a
  hundred). `scripts/measure_dispersion_sensitivity.py` →
  `artifacts/dispersion_sensitivity.json` quantifies it at both levels: 355 of
  the 2650 design cells that pass the bound on the linear scale fail once
  squared (none the other way), and 36 gaussian skeleton points are refused by
  the dispersion cell alone against 47 that release — 43% of the
  otherwise-available models. Not a defect, but a ceiling on the extension
  route that nothing stated: written up in
  [verifiable-extensions §5.1](docs/verifiable-extensions.md), with the
  consequence for ACRO integration (whether the second-moment cell is checked
  on the same parameters as the first is now a deliberate decision).
- **Release equality for the query path (roadmap item 2).**
  `tests/test_release_equality.py` discharges, for the aggregate path, what
  the P21 reproducibility meta-test discharges for the model path: over the
  enumerated skeleton (a spread sample by default, all 2622 points under
  `-m slow`), a verifier holding the gateway-finalized table and the spec
  recomputes the released frame bit for bit, and perturbing the engine's frame
  in ways finalization erases — counts moved inside their rounding bucket, the
  internal donor count and the dominance/influence witnesses moved inside
  their verdict, tied rows reordered — leaves the release byte-identical. This
  is the factoring `release = postprocess ∘ finalize ∘ vet` that hardening #26
  established, now pinned; it found hardening #27 and #28.
- **Planted dominance anchors in the synthetic data
  (`synth.DOMINANCE_ANCHORS`).** Sampled spend is heavy-tailed but not
  concentrated — no cell of ten donors or more reached 0.35 single-donor
  share — so both the stand-in's and ACRO's dominance rules were dead code on
  the whole corpus and the comparison measured nothing on that axis. Three
  regions are now concentrated to shapes that separate the two rule sets
  (Scotland 62% in one donor, Wales 46% + 46%, East Midlands 60% + 35%), by
  redistribution within the region and with leaders capped at the largest
  donor total the sampler already produced, so no event, donor or count moves
  and no spend outside the observed range is introduced.
  `tests/test_dataset_anchors.py` pins the shares, the invariants and the
  divergence. The dataset-derived artifacts were regenerated against it:
  `artifacts/rounding_distortion.json` (57 releasable models, down from 61 —
  a few design cells are now concentrated enough to refuse) and the demo
  screenshots.
- **The ACRO comparison now measures dominance divergence in both
  directions.** Six `acro_stricter` cells (the first found): ACRO's NK-rule
  suppresses a cell whose top two donors hold 90%, which the stand-in's
  single-contributor 50% bound releases — a real gap in the stand-in. Ten
  of the 21 `standin_stricter` cells are the converse: one donor over 50%,
  which neither of ACRO's default dominance rules catches. Neither rule set
  subsumes the other, so the integration keeps both; results and the corrected
  reading in [docs/acro-comparison.md](docs/acro-comparison.md). New targeted
  fixtures, and the harness now generates the documented 800-donor dataset
  when `data/` is absent instead of a smaller one, so CI and the published
  numbers describe the same dataset.
- **ACRO decision-comparison harness (roadmap item 1, first slice).**
  `redteam/run_acro_compare.py` replays every plain QuerySpec in the
  service-path red-team corpus (model specs expanded to their planned
  design-cell aggregates) through both the stand-in gateway and ACRO
  0.4.12's own check implementations, feeding ACRO one row per donor per
  cell so its threshold counts donors (P5/D4). Numbers, method and
  compatibility findings in
  [docs/acro-comparison.md](docs/acro-comparison.md); the headline is that
  complementary suppression is a rule ACRO does not have, so
  `_secondary_suppress` stays in force on top of it (the roadmap's contrary
  claim is corrected). New CI job `acro-compare` gates on harness integrity;
  ACRO lives in a separate dependency group because 0.4.x pins `pandas < 3`.
- **Temporal session model (roadmap item 2, third slice).**
  `formal/temporal_session.als` model-checks the auditor's
  `observe → apply → record` event order in Alloy 6 temporal logic: spend is
  monotone and the entry prechecks keep it inside the budget under the
  per-Session lock, exhaustion short-circuits every later request before
  engine work (P17), the fail-closed gate releases only unflagged
  release/redact verdicts (P7), a differencing pair can never fully release
  under the lock (P16), and the cohort history equals the released cohorts
  at every instant. The lock is an explicit assumption, not a fact: a
  mandatory-satisfiable run exhibits the hardening #18 TOCTOU once it is
  dropped. Wired into the CI `formal` job via `run_checks.py`; a new sync
  test pins the live service's trace order and record-only-on-release to
  the model.

## 0.3.0 — 2026-07-17

The formal round: the query boundary proved in Lean 4, the differencing rule
model-checked in Alloy, one-way ANOVA as the worked registry example, and a
p-value side channel closed. Plain-language account in the ELIF-FORMAL deck
(`artifacts/ELIF-FORMAL.ppt`).

### Security

- **Fixed a p-value side channel on `corr` (hardening #26):** released-value
  shaping (`postprocess`) ran in the engine, before gateway finalization, so
  a released correlation's `p_value` was computed from the exact pre-rounding
  cell count — fine-grained information about the `n` that base-5 rounding
  exists to blur. Shaping now runs on the gateway-finalized frame on both the
  plain and the model path: the released `(value, p_value, n)` triple is
  self-consistent, and every released number is recomputable from numbers
  already released.

### Added

- **One-way ANOVA (`anova`), the second registered model procedure.** Fits
  from the same gateway-vetted mean/`sum_sq`/`n` group cells the gaussian GLM
  already plans, so the disclosure machinery (allowlisted design-cell
  queries, fail-closed denial, reproducibility from the released cell table)
  is inherited unchanged. Stdlib-only F-tail (`stats.f_sf`) cross-validated
  against scipy; manifest v5 promotes `anova` to available; 49 new
  model-skeleton points; a worked example of the registry recipe in
  [docs/adding-a-statistical-tool.md](docs/adding-a-statistical-tool.md).
- **Literal spec entry (spec R17).** A request that is a single JSON object
  is taken as the spec itself, bypassing the planner and the
  natural-language gates (intent vetting, fidelity checks) — every
  downstream control (validation, budget, gateway, lineage, audit) applies
  unchanged. Malformed JSON is refused loudly, never handed to the planner
  as text. Red-team: a benign literal baseline plus a literal small-cell
  attack pin the path.
- **Formal round 2 (roadmap item 2, spec R16).** A Lean 4 model of the query
  boundary, generated from and pinned to the live code: no valid QuerySpec
  references an identifier, free-text, or timestamp column (P3);
  internal-only columns never reach a group-by or a release (P4); compiled
  SQL is one read-only SELECT over the declared view with every filter value
  a bound parameter (P9); DI/QI/S/R labels are consistent, with a
  column-level noninterference corollary end to end. Pinned by a 414-case
  byte-exact render-equality check against `compile_query` and a third sync
  hop (`test_formal_lean_sync.py`); the proofs are replayed in the CI
  `formal` job (Lean pinned by sha256). A second Alloy model
  (`formal/disclosure_policy.als`) checks the session auditor's simulatable
  differencing rule (P11) and machine-exhibits its two documented residuals.
- **Public-repo-first demo package.** The repo is the demo surface:
  [docs/public-demo.md](docs/public-demo.md), a five-minute tour, a
  screenshot tour and an evidence checklist, with
  `scripts/make_demo_screenshots.py` regenerating the demo figures against a
  throwaway mock server.
- **Decks and generators.** A maintenance-playbook deck and doc
  ([docs/maintenance.md](docs/maintenance.md)), a component & trust-map
  generator (`scripts/make_component_map.py`), and a plain-language
  explainer deck for the formal layer (`artifacts/ELIF-FORMAL.ppt`, built by
  `build_formal_elif()` in `scripts/make_decks.py`).

### Changed

- **Model/provider identities redacted repo-wide:** tracked files use the
  generic `SAFETRE_LLM_*` endpoint recipe and neutral "automated planner"
  language (decks and web UI regenerated to match).
- **Preprint** brought up to date with the GLM / procedure-framework round.

## 0.2.0 — 2026-07-07

The GLM / statistical-procedure-framework round. Plain-language account in
[docs/elif.md](docs/elif.md).

### Security

- **Fixed a count-rounding bypass (hardening #25):** released count queries
  carried the exact count in `value` beside the rounded `n`, making base-5
  count rounding a no-op. Counts now release `n` alone.

### Added

- **Statistical procedures as registered contracts (spec R14).**
  `safetre/procedures.py` holds the aggregate and model registries; the three
  former `if fn == …` dispatch sites delegate to it and fail loudly on an
  unregistered function. Adding a procedure without declared conformance
  obligations fails the build.
- **A `glm` tool (spec R15), cells-first.** Gaussian / binomial (logit) /
  Poisson models over up to three categorical terms, fitted **exclusively
  from gateway-finalized design-cell aggregates** by a stdlib-only IRLS.
  Any suppressed design cell denies the whole model (P19); per-observation
  outputs are not expressible (P20); a release carries the coefficient table,
  the model block, and the vetted cell table it was fitted from, and
  `safetre.glm.refit_from_artifact` reproduces the release bit-for-bit (P21).
  Estimability refusals are decided from the finalized tables alone and name
  terms, never quantities (P22).
- **`sum_sq`** as a fifth registered aggregate (second-moment cells; the
  gaussian dispersion input and the L2 moment-cell groundwork).
- **Formal layer (spec R16).** The registries export their finite request
  space (`formal/skeleton.json`); a bounded Alloy model generated from it
  checks P19/P21 over every vetting outcome and P4-admissibility over the
  exact catalogue atoms; two pytest sync hops pin code → skeleton → model;
  a CI `formal` job runs the solver (sha256-pinned Alloy 6.2.0).
- **Verification:** exhaustive enumeration of all 718 model skeleton points;
  a reproducibility meta-test (refit-equality, exhaustive at ≤ 2 terms,
  full skeleton under `pytest -m slow`); AST noninterference checks;
  statsmodels as a dev-only oracle (row-level fits match to 1e-8); nine new
  red-team attacks (20 total, all blocked by named controls); GLM items in
  the planner-eval corpus.
- **Measured, not asserted:** `scripts/measure_rounding_distortion.py`
  quantifies the finalized-weights (rounded-count) fitting distortion
  (`artifacts/rounding_distortion.json`).
- `safetre-demo` console script (the packaged face of
  `scripts/demo_query.py`); MIT license; ruff lint baseline.

### Changed

- Manifest v4: `glm` promoted from planned to available; the aggregate tool's
  function list is derived from the registry; planner prompt carries the
  GLMSpec shape and examples. Spec amended: R4 reworded; new clauses R14–R16
  and P19–P22, all Implemented in the traceability table.

## 0.1.0 — 2026-07-06

Initial research prototype: the validated QuerySpec boundary (count / mean /
sum / Pearson corr), read-only DuckDB engine, ACRO-style disclosure gateway
with simulatable session auditing, HMAC-chained audit log, GOV.UK-styled demo
shell, red-team harness, synthetic UK dataset, specification (R1–R13,
P1–P18), and three rounds of hardening.
