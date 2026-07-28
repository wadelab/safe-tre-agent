# A bestiary of caged beasts

*A field guide to the attack classes this system has met, where each one was
found, and the cage it now lives in. It is a map for humans, not a normative
document: the [specification](specification.md), the
[security model](security.md) and the [hardening log](hardening-log.md) are
the record; this page is how to hold the record in your head.*

Map datum: `MANIFEST_VERSION 2026-07-28.aggregate+glm+anova.v8` — the same
version tag shown on the web page. If that tag has moved, check the hardening
log for newer specimens before trusting this map.

---

## Why a bestiary at all?

Security text scales badly. This project has 57 numbered hardening findings,
seven decision records, 18 threats in the security model and 28 red-team
scenarios. That material is complete, precise, and nearly impossible to hold
in working memory at once — which matters, because the failure mode of a
security review is not ignorance, it is *a reviewer who could not keep the
whole shape in their head while reading one diff*.

The human mind does not store lists; it stores **characters and stories**. So
this page does three things:

1. **Compresses attack classes into creatures.** A creature is a mnemonic
   with affordances. "The Subtractor" is easier to reason about than
   "differencing via symmetric-difference-of-cohorts", because you already
   know how subtracting works, what it needs (two nearly-equal things), and
   what stops it (never let the two things be nearly equal).
2. **Keeps the metaphor at the class level, the truth at the specimen
   level.** Every creature below carries its literal finding numbers, code
   habitat, cage (the control) and keepers (the tests). The metaphor is an
   index into the real record, never a substitute for it.
3. **Cages, not kills.** Statistical-disclosure attacks are rarely
   exterminated; the *shape* of the attack is usually still expressible,
   somewhere, under the controls' assumptions. We pen them, name the pen, and
   — most importantly — name the **keeper**: the test, enumeration or formal
   check that must notice if the pen door opens. A cage without a keeper is a
   hope, not a control. Hardening #48 is the story of what happens when the
   keepers themselves fall asleep.

!!! warning "Metaphors lie by omission"
    Every creature is *described as* something simpler than the defect it
    indexes. That is the point of the exercise and its danger: a metaphor
    that silently changes the threat model is worse than none. Rule one of
    this menagerie is that **a specimen account may only restate what the
    hardening log says**, with a pointer to it. Rule two is that cuteness is
    a mnemonic device, not a risk assessment — the Masker is adorable and
    was the most dangerous finding of round 8.

---

## The grammar

Creatures are composed, not invented. A specimen is described by a small set
of orthogonal attributes, so that when a *new* finding appears you can see at
a glance which existing family it belongs to — or notice, usefully, that it
belongs to none. The grammar is the point; the names are decoration.

### Families

| Family | Totem | What it wants | The class it indexes |
|---|---|---|---|
| **The Subtractor** | ➖ A pickpocket carrying two identical-looking baskets | Two releases so close that one minus the other isolates a person | Differencing / triangulation; anything about what outputs *combine* into |
| **The Whale** | 🐋 One donor so large it surfaces through the aggregate | To be personally visible in a statistic | Dominance and influence: p% rules, leave-one-out correlation influence |
| **The Masker** | 🎭 A polite caller at the gate wearing someone else's face | To act under another identity, or from outside the channel | Identity, session and channel forgery |
| **The Nixie** | 🧜 A singer whose *name* is the secret | To make the system print a string that is itself disclosure or payload | Cell-key / identifier / free-text egress; undeclared values |
| **The Sphinx** | 🗿 A sweet-talker at the front desk | To talk the untrusted model — or the intent pre-filter — into asking for the raw thing | Prompt injection, hostile intent, row-level and per-donor requests |
| **The White Rabbit** | 🐇⌚ Always checking its pocket watch | To read secrets in *when* and *whether* an answer arrives, not what it says | Timing channels, refusal oracles, release/withhold bits, crashability |
| **The Ghost** | 👻 Walks through walls, leaves no footprints | To make something happen that the audit log does not record | Audit completeness: unaudited errors, state that resets, restarts |
| **The Hydra** | 🐍 Cut off one head, two heads wear hats | To be fixed in one instance while the *shape* survives elsewhere | Composition of individually-safe steps; multi-dimension variants |
| **The Mirror** | 🪞 Answers every question beautifully — a *different* question | To substitute a valid-looking answer to a question you did not ask | Planner infidelity: swapped/dropped/unsupported terms; silent imputation |
| **The Imp** | 👹 Small, diligent, hides in the margin | To leak fine detail through something nobody treats as an output: row order, tie-breaks, a p-value, a duplicate column | Sub-rounding leaks; formatting as a side channel |
| **The Parrot** | 🦜 Repeats whatever it is fed, verbatim, in public | To carry a hostile string from data to analyst screen to audit log | Reflected injection through tool outputs and checker findings |
| **The Stampede** | 🐂🐂🐂 A thousand queries in a trench coat | To exhaust the shared resource every control serialises on | DoS: rate limits, budget, the audit-chain rescan |
| **The Doppelgänger** | 👥 Two requests that are one request | To make a check-then-act control decide on a world that no longer exists | Concurrency: TOCTOU on session state, shared per-call state |

### Cage and keeper attributes

Every specimen entry names four things:

```
  specimen      ➜ what the field guide calls it (and its finding numbers)
  habitat       ➜ the file(s) it lived in — where to look when probing a diff
  cage          ➜ the control that pens it (and the *kind* of cage, see below)
  keepers       ➜ the tests / enumerations / formal checks that watch the door
```

Cage kinds, weakest to strongest:

| Mark | Cage kind | Meaning |
|---|---|---|
| ⛓️ | **Expressibility** | The attack cannot be *stated*: the QuerySpec allowlist has no word for it |
| 🧮 | **Deterministic gate** | It can be stated, and a deterministic check refuses or reshapes it |
| 🚧 | **Behavioural pen** | It can be stated and run, but session state (lineage, budget, rate) catches the *pattern* |
| 📖 | **Process pen** | Code cannot hold it: review, CODEOWNERS, deployment, physical controls |
| 🌫️ | **Priced residual** | Still in the wild, measured and priced; the map marks these honestly |

### Ecology rules (how to read interactions)

Individual specimens are rarely the whole story; the dangerous entries in the
log are *pack hunts*. Three composition operators cover every interaction
found so far:

- **`A + B` (hunting pair).** Neither creature is worth much alone; together
  they chain. The marginal-support Nixie (#29) finds the target *for free*;
  the refusal-oracle Rabbit (#30) interrogates the target one bit per refused
  query. Eight refused queries, no release, one donor profiled.
- **`A ⇒ B'` (moult).** Fixing A reveals that B was wearing A's shape.
  #39 closed the `age_years` staircase; probing the fix found the **Hollow
  Twin** (#40) running the same attack through `age_rating`, a *public*
  dimension. A fix that closes an instance and not the shape is a Hydra head.
- **`A ⊲ B` (blinding).** A harness whose oracle cannot see B makes every
  control that stops B *look* effective. The gaps and the blind oracle
  "covered for each other" for seven rounds (#48). This is why the keepers
  get their own entry below.

---

## The reserve, mapped

Where the beasts were found, and where their cages stand. Caged specimens are
shown at the control that holds them; priced residuals are marked 🌫️.

```mermaid
flowchart LR
    subgraph OUTSIDE["untrusted"]
        R["researcher"] 
        M["LLM planner<br/>🗿 Sphinx's perch"]
        D[("row-level data<br/>🧜🦜 Nixie & Parrot breeding ground")]
    end

    subgraph POD["safepod (restricted channel)"]
        CH["channel gate<br/>🎭🐂 cage: peer-address check + every-route rate limit<br/><i>channel.py · rate.py</i>"]
        ID["identity desk<br/>🎭 cage: proxy secret + allowlist, ambiguity refused<br/><i>identity.py</i>"]
        SS["session store<br/>👥🚧 cage: per-session lock; lineage rebuilt from log<br/><i>session.py</i>"]
        PL["planner → QuerySpec<br/>🗿🪞 cage: intent vetting (whiskers only)<br/><i>analyst.py · planner.py</i>"]
        QV["validator<br/>⛓️ cage: strict allowlist, band-edge rules<br/><i>query.py</i>"]
        EN["engine (read-only DuckDB)<br/>🧮 cage: bound parameters, caps, witnesses<br/><i>engine.py</i>"]
        GW["safe-outputs gateway<br/>➖🐋🧜👹 cage: donor threshold · dominance · influence ·<br/>suppression · rounding · declared domains<br/><i>disclosure.py</i>"]
        AU["session auditor<br/>➖🚧 cage: row-level symdiff + donor deltas + budget<br/><i>disclosure.py</i>"]
        LG["audit log<br/>👻 cage: HMAC chain + exactly-one-row-per-request<br/><i>audit.py · service.py</i>"]
        RB["White Rabbit's run 🐇🌫️<br/>response-time quantum + ceiling<br/><i>timing at the boundary — narrowed, watched</i>"]
    end

    R --> CH --> ID --> SS --> PL --> QV --> EN --> GW --> AU --> LG
    D -.-> EN
    M -.-> PL
    EN -.-> RB
```

The gateway corridor, zoomed in — this is where most specimens were bagged:

```mermaid
flowchart TB
    F["candidate frame<br/>(aggregate + internal witnesses)"] --> C1{"donors ≥ 10?"}
    C1 -->|"no"| S1["🔒 suppressed"]
    C1 --> C2{"Whale share<br/>MAX abs / SUM abs ≤ p%?"}
    C2 -->|"no"| S1
    C2 --> C3{"Nelson check:<br/>leave-one-donor-out influence?"}
    C3 -->|"too big"| S1
    C3 --> C4{"keys in declared domains?<br/>values finite?"}
    C4 -->|"no"| S1
    C4 --> C5["Imps' laundry:<br/>round counts · re-sort · tie-break on public keys"]
    C5 --> C6{"auditor: row-level symdiff<br/>and donor deltas vs lineage?"}
    C6 -->|"too close"| S2["🔒 denied, canonical refusal"]
    C6 -->|"clear"| R1["✅ released"]
```

---

## The bestiary

Grouped by family. "Bagged" is the hardening finding that caged it; a
creature with no finding number is in the wild (see the last section).

### ➖ The Subtractor — differencing and combination

*Field marks:* never takes anything you didn't hand it. It collects two
releases whose difference is one person. The family's whole being is
**combination**, which is why per-query controls cannot see it: every step is
innocent; only the subtraction is a crime. The most-evolved family in the
reserve — five separate cage rebuilds.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **Two-Basket Pete** | "sum in London" then "…excluding 50+"; shallow total-delta auditor | #4 (r2c) | `disclosure.py` | 🚧 cohort lineage: near-equal cohorts denied | `test_secure.py`; corpus `differencing_attack` |
| **Complement Pete** | one suppressed cell in a margin, recovered from the coarser total | #4b (r2c) | `disclosure.py` | 🧮 complementary suppression to a fixpoint | `test_disclosure.py` |
| **The Staircase** | `age_years >= v` swept v=13…69, reading 57 sub-band totals from individually-safe slices | #39 (r8) | `query.py` | ⛓️ range filters must align to declared band edges; exact-age equality not expressible | `test_hardening.py`; corpus `age_range_sweep_step`, `exact_age_probe`; D7 |
| **Exact-Age Pete** | `age_years == 41` released any ≥10-donor age directly | #39 (r8) | `query.py` | ⛓️ same as above | corpus `exact_age_probe` |
| **The Donor Delta** | two large cohorts 1–3 *people* apart but ~30 *events* apart; the auditor totalled rows | #38 (r8) | `service.py` | 🚧 auditor totals distinct donors, not rows | `test_hardening.py`; corpus `donor_delta_differencing`; D7 |
| **The Hollow Twin** | `{age_rating>=7,…}` vs `{>=8,…}`: *identical donors*, rows differ by a suppressed cell — the auditor compared people; the leak lived in rows | #40 (r8) | `engine.py` | 🚧 `row_symdiff_donors`: difference the donors behind the *rows*, and `d < threshold` so zero denies too | `test_hardening.py`; `round8_repro.py`; spec P11 |
| **Second-Moment Pete** | `sum_sq` pairs difference exactly like sums; with the sum they pin a one-donor cell's magnitude | r8 corpus | `engine.py` | 🧮 same gates + second-moment dominance parameter | corpus `sum_sq_second_moment_differencing`; `test_second_moment.py` |
| **Saturated Golem** | fit a saturated GLM over a redacted grid, hoping the fit imputes suppressed cells | r8 corpus | `glm.py` | ⛓️ the model's own cell table must be fully releasable (P19) — it never touches raw rows | corpus `glm_saturated_recovery_of_suppressed_cell`; `test_glm_noninterference.py` |
| **The Colluder** 🌫️ | two sessions, two people, one subtraction | priced | `disclosure.py` | 🌫️ per-session only, stated plainly; the DP accountant (best-practice deviation D2, roadmap item 4) is the principled cage | documented residual in security model |

### 🐋 The Whale — dominance and influence

*Field marks:* a cell that passes the count threshold while one donor *is*
the cell. Cute as a plush toy; the plush toy is 66% of a released total.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **The Whale** | mean/sum cell where one donor dominates | #2 (r1) | `engine.py`, `disclosure.py` | 🧮 p%-dominance suppression on internal unit views, helper dropped before release | `test_secure.py`; corpus |
| **The Refund Whale** | negative measures inverted the *signed* share: negating a region moved its witness 0.620 → 0.0027 | #41 (r8) | `engine.py` | 🧮 magnitude share `MAX(abs c)/SUM(abs c)` — identical on friendly data, pinned so | `test_hardening.py`; fixture `adversarial_negative_dominance` |
| **The Lever Whale (corr)** | a correlation on an above-threshold group driven by one high-leverage donor | #15 (r2d) | `engine.py` | 🧮 leave-one-donor-out influence witness, suppressed past 0.5 | `test_corr_influence_detects_dominating_donor`; corpus `corr_narrow_cohort_influence` |
| **The Hyperactive Whale** | 900 events from one donor: row counts and donor counts diverge | r8 fixture | `engine.py` | 🧮 thresholds count *donors* (D4), event-level included | fixture `adversarial_hyperactive_donor`; `test_hardening.py` |

### 🎭 The Masker — identity and channel

*Field marks:* arrives politely, on the correct port, holding a header. The
family's recurring lesson: **loopback is a shared room, not a boundary** —
the untrusted model runtime lives in it.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **First Mask** | spoofable login header accepted without a fail-closed mode | #6 (r1) | `identity.py` | 🧮 canonical header only; `REQUIRE_IDENTITY` fails closed | `test_web.py` |
| **Widened-Gate Mask** | widening the channel silently turned the header into an auth bypass | #22 (r3) | `identity.py`, `channel.py` | 🧮 trust requires loopback-only channel or explicit opt-in | `test_hardening.py` |
| **Masker Prime** | any loopback co-tenant (the model runtime!) could forge *any* allowlisted identity — and rotating the header minted fresh budget and empty lineage on demand. 21 forged requests accepted against a real server | #45 (r8) | `identity.py`, `app.py`, `deploy/` | 🧮 proxy shared secret **required** with identity; repeated/comma headers refused; empty allowlist admits nobody in production | `test_hardening.py`; spec P13; startup `configuration_problems()` |
| **The Open Gate** | "bind localhost" documented but not enforced if config drifted | #12 (r2a) | `channel.py` | 🧮 middleware checks the real ASGI peer, ignores forwarded headers | `test_web.py`; spec R10 |

### 🧜 The Nixie — the name that is the secret

*Field marks:* asks you to print a string. The string *is* the disclosure —
a donor's exact age as a key, a typo'd category, an injection payload wearing
a region's clothes.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **Support-Map Nixie** | `/api/marginals` published 56 exact ages, 5 held by one donor — free target selection | #29 (r7) | `engine.py` | 🧮 sub-threshold values *omitted* (absence is simulatable); undeclared values dropped | `test_hardening.py` |
| **Typo Nixie** | a 12-donor typo'd or injection-shaped category printed as a released cell key | #43 (r8) | `disclosure.py` | 🧮 released keys projected onto declared domains (query-declared keys only) | `test_hardening.py`; fixture `adversarial_undeclared_category` |
| **The Crooner** | "summarise the free-text comments" | corpus | `analyst.py`, `query.py` | ⛓️ free text is not in the catalogue, the views, or expressible specs — checked in four places | `test_secure.py`; corpus `prompt_injection_free_text` |

### 🗿 The Sphinx — sweet-talk and injection

*Field marks:* never touches a control; talks to the untrusted mind in front
of them. The answer is not a smarter gatekeeper but a smaller vocabulary: the
Sphinx can ask for anything, and the only words that exist are safe ones.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **Row-Level Ralph** | "give me the row-level records for the highest spenders" | corpus | `analyst.py` | 🧮 intent vetting (defence in depth) + ⛓️ not expressible | corpus `direct_reident_request`, `per_donor_row_level_intent` |
| **The Smuggler** | "report wellbeing *per donor* so I can see the distribution" | corpus | `analyst.py` | ⛓️ identifiers unselectable | corpus `code_channel_per_donor` |
| **Paraphrase Pete** | "raw event rows" slipped the `"raw rows"` cue | #16 (r2e) | `analyst.py` | 🧮 broadened cues — but the *real* cage is that the planner can only emit a QuerySpec | real-model run: 0 disclosures in 22 hostile requests |
| **The Residual Salesman** | "give me the residuals per donor" | corpus | `glm.py`, `procedures.py` | ⛓️ per-observation outputs are outside every procedure's declared contract (P20) | corpus `glm_residuals_request`; `test_procedure_conformance.py` |

### 🐇 The White Rabbit — time and the decision bit

*Field marks:* a waistcoat, a pocket watch, and nerves. Reads secrets in
*when* the answer arrives and *which word* refuses it. Yes — the White
Rabbit of this reserve is the timing channel, and it is the specimen the
keepers watch most nervously, because its cage is quantised, not solid.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **The Rabbit** | sub-threshold cohort size orderable from latency: 9 of 15 pairs inside one session's budget, some in 2 queries | D5 (r7) | `safetre_web/timing.py`, `app.py` | 🧮 responses held to a quantum; work past a ceiling refused → 0 of 15 pairs orderable; 26–70 samples now needed | `test_timing_channel.py`; `artifacts/timing_channel_*.json` |
| **The Straddler** 🌫️ | craft cohorts straddling a quantum bucket edge. D5's *passive* sweep found 0 of 15 pairs orderable within a session; the *adaptive* attacker, spending its samples where they pay off, finds **2 of 15** — which is the whole argument for attacking a control rather than measuring it | partly: #54 (r8) | `safetre_web/timing.py` | 🧮 the ceiling is now a **deadline**: 400–3200 ms of work all answer at 252 ms. 🌫️ the bucket edge remains; constant time is one setting away (quantum = ceiling), the structural cage is async delivery, parked | `redteam/timing_attacker.py` attacks all three vectors adaptively and gates the straddle in CI; `test_timing_channel.py` |
| **Row-Count Rabbit** 🌫️ | a sub-threshold-*donor* cohort with many rows does real work: timing leaks the hyperactive donor's existence | priced | engine work | 🌫️ same quantum narrowing | timing artefacts |

### 👻 The Ghost — things that left no footprints

*Field marks:* you only ever see where it *wasn't*. The family's prey is the
audit log's completeness — a system with a perfect log of *almost* every
request has a hole exactly where an attacker wants one.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **The 500 Ghost** | planner/engine/fit exceptions escaped as 500s with **zero audit rows** — a crashability oracle and a hole in the tamper-evident chain | #37 (r8) | `service.py` | 🧮 audited fail-closed wrapper: exception TYPE recorded, message never; caller sees the canonical refusal; exactly one row per request | `test_audit_completeness.py`; spec R8 |
| **The Amnesiac** | a restart wiped in-memory lineage and budget; a differencing pair split across a restart completed | #49 (r8) | `session.py`, `app.py` | 🚧 sessions rebuild lineage and budget from the audit log at boot (`rehydrate`), over a declared `session.window_hours` | `test_hardening.py`; spec R6. Residual stated: the cheap total-delta layer cannot be rebuilt, because the log records an output *shape*, not a donor total |
| **The Chain Forger** | unkeyed hash chain: rewrite and recompute passes `verify()` | #1 (r1) | `audit.py` | 🧮 HMAC-SHA256 chain; off-box key and head anchor | `test_audit_tamper_with_wrong_key_still_fails` |
| **The Nameless Policy** | a release recorded the request, the spec and the status — but nothing about the *thresholds* that allowed it, so a clean release under `min_cell=1` was byte-schema-identical to one under the shipped policy | #55 (r8) | `app.py`, `config.py` | 🧮 a distinguished `status=config` record puts the resolved policy digest **inside** the chain at the point it takes effect; every later row is attributable by position. No schema change, no migration | `test_hardening.py` |
| **The Keeper's Own Ghost** | #55 turned "import the web app" into "write to the audit log", and four harness scripts imported it unpinned: 578 junk rows in the developer's own log. #36 recurring by a new route — that fix lived in `conftest.py` and never covered the scripts | #57 (r8) | `redteam/`, `scripts/` | 🧮 every harness pins a throwaway `SAFETRE_AUDIT_DB` *before* the import; the polluted log archived, not re-MACed | the habit that caught it: check `audit.db`'s mtime after every run |
| **The Planted Row** | the prefill link *ran on load*, writing an attacker-chosen request into the chain under whoever opened it — and, being answered, recorded as `released` with a shape | #50 (r8) | `static/app.js`, `app.py` | 🧮 the link fills the box and stops; a click is the consent. Auto-run survives only as an off-by-default capture sentinel | `test_web.py`. Still treat `request` as untrusted text in any log viewer: the chain proves authenticity, never authorship |

### 🐍 The Hydra — the shape that survives its instance

*Field marks:* you have met this one before. The Hydra's heads are findings
whose *fix* was verified against the reported attack and passed — while the
attack's shape walked around the fix. Two cages now exist purely to watch
for heads.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **Two-Hat Hydra** | excluding two rare categories passed a sentinel that only fired for one differing dimension — two queries recovered four donors' exact spend | #31 (r7) | `disclosure.py` | 🧮 the bound sums marginals over *every* differing dimension | `test_secure.py`; Alloy `disclosure_policy.als` (the residual was machine-exhibited there first) |
| **The Shape of #39** | `age_rating`: public, coarse, groupable — and a staircase, because it partitions *rows* while the auditor counted *people*. 20 sub-threshold cells recoverable after #39 | #40 (r8) | `engine.py` | 🚧 row-level differencing (see the Hollow Twin) | `round8_repro.py` enumerates rather than hardcodes, because the precondition is data-dependent |
| **The Residual Head** 🌫️ | categorical pairs whose per-dimension marginals are large while the interaction is small — the price of simulatability | priced | `disclosure.py` | 🌫️ stated in D7; the DP accountant is the principled close | roadmap item 4 |

### 🪞 The Mirror — answers to questions you didn't ask

*Field marks:* impeccable manners, plausible output, wrong question. Lives
in the gap between a natural-language request and the spec the untrusted
planner proposes. Its cage is not "make the model honest" (impossible) but
**refuse unless the spec provably answers the request**.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **Swapped-Dimension Mirror** | "by region" → grouped by age band | corpus (service) | `service.py` | 🧮 NL-fidelity gate: grouping must match the request | corpus `grouping_swapped_dimension`, `grouping_dropped_dimension`, `grouping_unsupported_breakdown` |
| **Dropped-Term Mirror** | "on age band and device os" → one term quietly vanished | corpus (service) | `service.py` | 🧮 same gate, over model terms | corpus `glm_dropped_term`, `glm_response_swap` |
| **The Helpful Mirror** 🌫️ | a future model that *silently imputes* — merges a small cell and answers anyway. Refusing loudly is the documented counter; the temptation grows with model capability | design rule | `glm.py` | ⛓️ whole-model refusal if any cell unreleasable (P19); no silent fallback anywhere (R13) | `test_glm.py`; `test_llm.py` |

### 👹 The Imps — the margin of the page

*Field marks:* tiny, numerous, and living in things nobody treats as outputs:
row order, tie-breaks, duplicate columns, a p-value computed from the exact
count, a dtype that flips when a NULL appears. Each Imp leaks an *ordering*
or a *bit* below the granularity the rounding exists to impose.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **Echo-Count Imp** | a count query released the exact count beside the rounded one — rounding was a no-op | #25 (r4) | `engine.py` | 🧮 payload is the rounded `n` alone | `test_hardening.py` |
| **p-Value Imp** | corr's released p was computed from the exact pre-rounding n | #26 (r5) | `service.py` | 🧮 postprocess *after* finalization; released triple is self-consistent bit-for-bit | `test_secure.py`; `test_release_equality.py` |
| **Tie-Break Imp** | complementary suppression picked its victim on the exact count — which cell died told you which was smaller | #27 (r6) | `disclosure.py` | 🧮 sacrifice ranked on the *released* count, tie-broken on public keys | `test_release_equality.py` |
| **Row-Order Imp** | `ORDER BY n DESC` ranked cells more finely than released counts; also made releases irreproducible | #28 (r6) | `disclosure.py` | 🧮 final sort on rounded count then key | `test_release_equality.py` |
| **Vanishing Imp** | one NULL made an integer key column `float64`, and the dtype heuristic stopped recognising keys — silently reinstating #27 and #28 | #32 (r7) | `disclosure.py` | 🧮 group-by threaded from the query; no inference from dtypes | `test_disclosure.py` |
| **Infinity Imp** | a `-inf` record released; an overflowing sum released `+inf` at dominance ~0 | #42 (r8) | `disclosure.py` | 🧮 non-finite aggregate payloads suppress the cell | `test_hardening.py`; fixture `adversarial_nonfinite_payload` |
| **Optional-Role Imp** 🌫️ | a gaussian model releasing without `sum_sq` whispers "dispersion withheld" — one bit per cohort about where whales live | #53 (r8), priced | `service.py`, `glm.py` | 🌫️ measured firing on **30% of released gaussian models** — not the "never observed" of the first pass. Deliberately not patched, because it cannot be closed by silence: a partial release carries three columns where a complete one carries six, so deleting the note removes the sentence and leaves the channel. Both real closures are costed | `artifacts/optional_role_channel.json`; `test_hardening.py` pins that the omission is *structural* |

### 🦜 The Parrot — repeat after me

*Field marks:* a very trusting bird. Carries strings from the least-trusted
place (row-level data) to the most-trusted places (the analyst's screen, the
HMAC-chained log) without ever reading them.

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **The Parrot** | an external checker's returned rule names were interpolated into analyst-visible findings and the audit log — `acro_IGNORE ALL PREVIOUS INSTRUCTIONS…` rendered on screen | #44 (r8) | `external_checker.py` | 🧮 names projected onto a declared identifier shape; anything else becomes one canonical placeholder; the rejected text is stored **nowhere** | `test_hardening.py` |
| **The Nest** | six planted poison strings (SQLi, prompt-injection, tool-spoof) ride the checker's stdin as cell keys | §5.4 (r8) | `external_checker.py` | 🧮 same projection, both directions; checker protocol treated as hostile-content-bearing | `test_acro_boundary.py` |

### 🐂 The Stampede — quantity has a quality

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **First Herd** | no rate limit, no caps, unbounded `in` lists | #5 (r1) | `rate.py`, `engine.py`, `query.py` | 🚧 token bucket; memory/thread/row caps; bounded specs | `test_web.py` |
| **The Verify Herd** | only `/api/query` was limited; twelve concurrent audit-verify scans moved query latency 51 ms → 1582 ms — a shared-fate DoS on the control everything serialises on | #47 (r8) | `app.py`, `rate.py` | 🚧 middleware over **every** route, padded like any answer; tighter budget for the chain scan | `test_hardening.py` |

### 👥 The Doppelgänger — two that are one

| Specimen | Field marks | Bagged | Habitat | Cage | Keepers |
|---|---|---|---|---|---|
| **The Racing Twins** | fire both halves of a differencing pair concurrently: both pass `observe` before either `record`s | #18 (r3) | `session.py`, `app.py` | 🚧 per-session lock across `observe → apply → record_cohort` | `test_concurrent_differencing_serialised_by_session_lock`; Alloy `temporal_session.als` |
| **The Borrowed Table** | the external vetter kept per-call state on the shared instance; a second thread swapped the table mid-flight — verdicts returned matching, about another table (2 in 240 under preemption) | #33 (r7) | `external_checker.py` | 🧮 no per-call state on the instance; lock on the instance not the class | `test_acro_boundary.py` |
| **The Shared Connection** | one DuckDB connection driven concurrently by many users; a wrong frame here attaches one analyst's vetting to another's cells, so an integrity bug is a disclosure bug | #51 (r8) | `engine.py` | 🧮 a cursor per thread over one shared catalogue — which needed the tables *materialised*, because a registered pandas frame is connection-scoped and invisible to a cursor | `test_hardening.py`: 300 queries across 12 threads, every response matched to its own request |

### The sleeping dials — configuration as a habitat

Not creatures so much as unlocked cage doors with labels on them. Bagged in
round 8:

- **The Dead Dial** (#35, caged as #56): `max_output_rows` could not fire on
  the QuerySpec path — the rule wanted "no aggregation at all" and every
  compiled query appends a count, so a live dial in `config.yaml` described a
  control that never ran. It now bounds released **cell** count and escalates
  to a human checker. Judged on what is released rather than what was
  computed: 11 of 241 group-by combinations, not 46. Keeper:
  `test_hardening.py`.
- **The Floorless Dials** (#46, caged): `min_cell_size: 1`, `dom_threshold:
  1.0`, `round_base: 1`, `query_budget: 10**9` all *validated* — and any one
  of them passed **737 of 737 tests**. Semantic floors now apply to the
  resolved policy, the effective policy is digested and logged at startup,
  and the override is an environment variable (`SAFETRE_ALLOW_UNSAFE_POLICY`)
  so it cannot be smuggled in by the file it waives. Keeper:
  `test_hardening.py` policy-floor tests.

---

## Pack hunts: the interactions worth memorising

These are the entries a reviewer should be able to retell from memory,
because each one generalises:

1. **The Nixie and the Rabbit (#29 + #30).** The marginals endpoint said
   *which* age was unique without saying who held it; the refusal oracle
   answered yes/no questions about a cohort without saying which cohort was
   interesting. Separately: two curt notes. Together: 8 queries, every one
   refused, zero cells released, and one unique donor's region, sex, income
   band and device recovered. **Lesson: treat the explanation path — traces,
   finding text, the status word itself — as an output with the same
   disclosure budget as the data path.**
2. **The Subtractor needs two broken links (#38 + #39).** The round-8
   headline attack worked only because row-count totals hid the donor delta
   *and* off-band range values let slices cut anywhere. Either fix alone left
   a working variant. **Lesson: some cages are load-bearing pairs; review
   them as one structure (that is what D7 does).**
3. **The Masker mints the Subtractor's alibi (#45).** Session controls were
   keyed on the login header, so forging identities did not just impersonate
   a victim — rotating the header minted a *fresh differencing lineage and
   budget on demand*. An identity beast and a state beast compounded into a
   clean getaway. **Lesson: session-state keys are part of the identity
   boundary.**
4. **The Amnesiac resets the board (#49).** All lineage was in memory; the
   audit log recorded everything and was never replayed. The differencing
   pair split across a restart completed. **Lesson: a control whose state
   evaporates on deploy is a control with a scheduled outage.**
5. **The Ghost feeds the Rabbit (#37).** An unaudited 500 is also a
   data-dependent crashability bit — one more oracle. **Lesson: failure
   paths are outputs too.**
6. **The Imps are one Imp (#25, #26, #27, #28, #32).** Five findings, one
   shape: *something analyst-visible was computed from something finer than
   what was released*. The release-equality test — perturb inside the
   rounding bucket, demand byte-identical output — is the general trap, and
   it caught #27/#28 without being told what they were. **Lesson: when two
   specimens share a shape, build the trap for the shape.**

And the meta-specimen that explains eleven others:

> **The Blind Zookeeper (#48).** For seven rounds the red-team harness asked
> the gateway's own findings whether the final frame leaked — a question
> vacuously true on the QuerySpec path — and counted any control firing as a
> pass, which a three-step attack could arrange by appending a decoy. The
> gaps and the blind oracle *covered for each other*. The cage: an oracle
> computed from the row-level data, inspecting every step, asking what
> released cells *combine* into, reporting **UNGUARDED** when no control
> engaged — and `test_redteam_oracle.py`, which weakens controls on purpose
> and requires the oracle to notice, in both directions. A silent oracle and
> a safe system look identical from the outside; only calibration tells them
> apart. This is the single most transferable lesson in the reserve.

---

## Still in the wild

Honesty section — creatures seen, measured, priced, not yet caged. Each is
documented where the security model keeps its residuals; the map would be a
lie without them.

| Creature | Shape | Price stated where |
|---|---|---|
| 🐇 The Straddler | the quantum bucket edge: 2 of 15 sub-threshold pairs orderable within a session's budget, and cross-session patience buys more. The *ceiling* half is caged (#54); this half is not | D5; security model side channels; `redteam/timing_attacker.py` measures it every run |
| 🌫️ The Colluder | cross-session / cross-user differencing | security model; the DP accountant (deviation D2) is the principled cage |
| 🌫️ The Residual Head | large marginals, small interaction overlap | D7; roadmap item 4 |
| 🌫️ The One Bit | the simulatability residual: isolating a sub-threshold category uses the true count internally | security model, "simulatable up to one bit" |
| 🌫️ The Optional-Role Imp | 30% of released gaussian models announce a withheld dispersion — and the announcement is not the channel, the missing columns are | security model side channels; `artifacts/optional_role_channel.json` |
| 🌫️ The Paper Tiger | the legacy sandbox's illustrative guard (`np.memmap`, `np.genfromtxt` read files straight through it) — unexposed from shipped faces, and no longer presented as a bar: quarantined under `redteam/legacy/` (#52) with `tests/test_legacy_sandbox.py` pinning the bypass end to end | hardening #52 |
| 🌫️ Audit-lock murmur | every request serialises on the chain write lock: a weak "someone is writing" signal, accepted because chain integrity needs it | security model side channels |

---

## A field guide for future expeditions

Practices this codebase evolved that generalise to any codebase with a
security boundary — the bestiary is the mnemonic; these are the habits:

1. **Name the beast when you cage it.** A finding with a name gets
   remembered in design reviews six months later ("isn't this the Hollow
   Twin again?"). An unnamed fix gets reverted by an innocent refactor. The
   name belongs in the test docstring.
2. **Every cage needs a named keeper, and the keepers need auditing.**
   For each control, ask: which test notices if this door opens? Then ask
   #48's question: how do we know the *test* can fail? Calibration tests
   that weaken the control on purpose are cheap and are the difference
   between evidence and vibes.
3. **Probe the fix, not just the finding.** #39 was verified against the
   reported attack and passed; asking "what else has this shape?" found #40
   the same day. Budget time after every security fix to hunt the shape.
4. **Test on hostile fixtures, not just hostile queries.** #41–#43 needed
   no attacker at all — real refunds, real floating-point overflow and real
   typos supplied them. Controls written against friendly data are tested
   against the fixture, not the threat.
5. **Enumerate the space when it is finite.** The QuerySpec surface is
   enumerable, so the project *enumerates* it (skeleton points, 767 model
   shapes, Alloy runs) instead of sampling it. If your boundary is designed
   to be finite, exhaust it; if it isn't, ask why not.
6. **Price residuals, don't hide them.** Every open creature above has a
   measured price and a named principled close. A priced residual survives
   a design review; an unmentioned one becomes a finding.
7. **Keep a decision log next to the hardening log.** The log says *what*
   happened; the decisions (D1–D7) say *why this trade-off and not another*.
   The bestiary names both, because cages get reviewed by people who weren't
   there.
8. **Treat harness upgrades as security work.** The most important round-8
   fix was not a control; it was the oracle. In any codebase, the
   vulnerability you cannot write a failing test for is the one you ship.
9. **Draw the map.** A one-page diagram of habitats and cages (above) turns
   "where should this new check live?" into a question with a visible answer
   — and makes a missing cage look like a gap on the map rather than an
   absence nobody noticed.

## How to use this page

- **Reviewing a diff?** Find the habitat in the reserve map, check which
  cages are within reach of the change, and re-run their keepers.
- **Adding a feature?** Ask which family it feeds: new filter algebra feeds
  the Subtractor; new outputs feed the Imps and Nixies; new tools feed the
  Mirror; new state feeds the Ghost and the Doppelgänger; new config feeds
  the sleeping dials.
- **Onboarding?** Read [Explained simply](elif.md) for the system, then the
  six pack hunts above, then the hardening log entries they index. You will
  know the shape of the threat model in an afternoon.
- **Found a new beast?** Name it, give it a specimen account with habitat /
  cage / keepers, and append to the hardening log. If it belongs to no
  family, say so loudly — a new family is the most important find there is.

*The reserve is never finished. The keepers are the point.*
