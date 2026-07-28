# Remediation plan — round 8

Response to `redteam/adver_report.md`. Every claim below was re-verified by
running it against the demo data before it was planned for; the numbers are
measured, not quoted. Four claims came back materially different from the
report and are corrected here, and one is refuted outright. Nothing in the plan
rests on a claim that was not reproduced.

`redteam/round8_repro.py` re-runs the load-bearing findings and exits nonzero
while any remains open, so it can gate the work.

## Status — 2026-07-28

**Landed: #37 (audited exception boundary), #38 (donor totals in the auditor),
#39 (band-aligned internal range filters).** Re-verified independently, not
just by their own tests: the reproducer gate reports 0 of 6 applicable checks
vulnerable, `run_redteam.py` is 22/22, and the suite is green. Attacks 2a, 2b
and 2c-on-`age_years` are no longer expressible, the integer-overflow crash is
a request-decided refusal, and a planner failure now writes exactly one audit
row.

**One new finding, from adversarially probing those fixes: #40 below.** #39
closed the `age_years` instance of double-differencing; it did not close the
class. The same attack runs today through `age_rating`, a *public* integer
dimension that keeps unrestricted range operators — 20 sub-threshold cells
recovered on the shipped data. #38 does not catch it either, and the reason
matters more than the instance: the two cohorts have **identical donor sets**.

### Landed since — #40 to #47

All eight are fixed, tested and documented (hardening log round 8). The
reproducer reports **0 of 8 applicable checks vulnerable**, `run_redteam.py` is
22/22, the suite is 794 green, and lint, SAST, dependency audit, the strict docs
build and the formal artifacts are all clean.

| # | What it was | Closed by |
|---|---|---|
| 40 | Row-level differencing through a public integer dimension; the `0 < d` fail-open; the NULL desync | `row_symdiff_donors` + `d < threshold` (§2.1) |
| 41 | Signed dominance inverted by negative measures | magnitude share `MAX(abs c)/SUM(abs c)` (§2.3) |
| 42 | `-inf` and overflow payloads released | non-finite aggregate payloads suppress (§2.3) |
| 43 | Undeclared cell keys printed on release | projection onto declared domains (§2.3) |
| 44 | Checker rule names reaching analyst text and the audit log | identifier-shape projection (§2.3) |
| 45 | Loopback treated as a trust boundary; session controls keyed on a caller-chosen string | proxy secret required, ambiguity refused, allowlist shipped (§2.5) |
| 46 | Policy floors on the defaults, not the resolved config | `policy_floor_problems` + explicit override (§3) |
| 47 | Only `/api/query` rate-limited | middleware over every route + tighter chain-scan budget (§3) |

### Landed since — #48, the harness rebuild (§2.4)

The one that mattered most, because it is why the other eleven survived seven
rounds. The oracle is now computed from the row-level data rather than from the
gateway's own findings, inspects every step rather than the last, and asks what
released cells *combine* into. The verdict is its findings alone; a control
having fired is not a pass, and an `expect_block` entry that leaks nothing while
no control engaged is reported **UNGUARDED** rather than banked as a defence.

Calibrated in both directions, which is the part that makes it evidence:
`tests/test_redteam_oracle.py` requires silence on a correct system and on
hostile data, and requires it to speak when the threshold, the dominance bound
or the differencing auditor is removed — including on the exact three-step
session the old harness passed. `redteam/fixtures.py` supplies negative,
non-finite, NULL, undeclared and hyperactive-donor data, and the corpus gains
`corr`, `sum_sq` and hostile-fixture entries: **28 attacks, 0 disclosures, on
both the shipped CSVs and `synth.generate()`**.

### Landed since — #49 to #52, §6.1 to §6.5

| # | §6 item | Closed by |
|---|---|---|
| 49 | Restart amnesia | `SessionStore.rehydrate` over a declared `session.window_hours` |
| — | `_dim_value_set` NULL semantics | three-valued logic; the marginal bound is an upper bound again |
| 50 | Prefill-link audit injection | the link fills the box and stops; auto-run is an off-by-default capture sentinel |
| 51 | Cross-user engine concurrency | materialised tables and a cursor per thread; 300-query, 12-thread load test |
| 52 | Legacy sandbox presented as a bar | moved to `redteam/legacy/`, labelled a counter-example, bypass pinned by tests |

### Landed since — #53 to #56, §6.6 to §6.9

| # | §6 item | Outcome |
|---|---|---|
| 53 | Optional-role bit (§6.6) | **priced, not closed** — measured at 30% of released gaussian models, and it cannot be closed by silence: the omission is visible in the output shape, so deleting the finding removes the sentence and leaves the channel |
| 54 | #34's post-hoc ceiling (§6.7) | the boundary is a raw ASGI layer and the ceiling is a real deadline: 400–3200 ms of work all answer at 252.3–252.5 ms |
| — | adaptive timing attacker (§6.7) | `redteam/timing_attacker.py` attacks the three named vectors and gates the straddle in CI |
| 55 | Policy digest in the chain (§6.8) | a `status=config` record at startup — no schema change, no migration |
| 56 | #35's dead dial (§6.9) | `max_output_rows` bounds released cell count and escalates; 11 of 241 combinations, measured |

**Nothing from the report is left open.** What remains is roadmap work rather
than findings: the DP accountant (item 3), which closes the residual behind #53
and the one-bit deviation behind P11; cross-user lineage (item 4), where #49
does the single-identity half; and asynchronous delivery (parked), the
structural end state for the timing channel #54 narrows.

The report's own summary — "nothing suggests the allowlist/bound-parameter core
is wrong" — holds. The QuerySpec boundary, the SafeSQL shape and the
cells-first model pipeline all survived. What failed is everything that
reasons *about* those outputs: the differencing controls measure the wrong
quantity, the catalogue's granularity promise is enforced on outputs but not on
inputs, the disclosure rules assume data nobody hostile has touched, and the
red-team harness cannot fail.

---

## 1. What was verified

| # | Attack | Verdict | Measured |
|---|---|---|---|
| 2c | Two-common-dimension double-differencing | **Confirmed** | on the CSVs the app serves: **322** sub-threshold `(region, sex, age)` cells have both enclosing slices releasable, the lineage rule allows **313**, and **158 hold one donor**. On `synth.generate()`: 190 / 165 / 121, of which 157 reconstructed exactly at 0.00 GBP error |
| 2b | Direct `age_years ==` | **Confirmed** | the release bit is exactly `n_donors >= 10`; 29 of 56 ages release with **exact** sums and means |
| 2a | `age_years >=` range sweep | **Confirmed, weaker than reported** | the lineage bound *does* bite when the age marginal is below threshold; the sweep recovers only what 2b already hands over directly |
| 5.1 | Negative values invert dominance | **Confirmed** | negating a cell moves its dominance witness from 0.620 to 0.0027 with identical concentration; a refund cell releases at dominance **−0.081** while one donor holds 66% of the magnitude |
| 5.2 | Non-finite payload released | **Confirmed, amended** | literal `+inf` is caught *incidentally* (`inf/inf` → NaN → fail-closed). **`-inf` releases, and finite inputs that overflow release `+inf` at dominance 0.0** |
| 5.3 | NULL semantics desync | **Confirmed, worse than reported** | `simulatable_cohort_bound` stops being an upper bound; a filter the auditor models as selecting nothing drops one donor, and two queries recover that donor's exact spend **with no findings raised** |
| 5.4 | Undeclared values release as cell keys | **Confirmed** | a typo'd or hostile category with ≥ 10 donors is dropped from the marginals but printed as a cell key |
| 5.5 | Poison strings reach the external checker | **Confirmed, plus a reverse leg** | all six payloads cross into the checker's stdin; and checker-returned rule strings are interpolated into **analyst-visible findings and the audit log** (`external_checker.py:288-293`) |
| 6 | Loopback identity spoof | **Confirmed, and it chains** | see §2.5 — this is the most serious finding in the set. Reproduced against real uvicorn on real loopback, not a test client |
| 6 | Unaudited 500s | **Confirmed, with a better trigger and one refutation** | a schema-valid integer-overflow filter crashes `engine.run()`: **HTTP 500, zero audit rows, zero budget spent, no rate limit**. The report's `df_resid <= 0` example is **refuted** — 6833 model specs reached 220 fits, minimum `df_resid` **23** |
| 4 | Restart amnesia | **Confirmed over HTTP** | a denied differencing pair completes after a restart on the same `audit.db`, recovering one 62-year-old donor's exact spend; all 26 rows were in the log throughout and were never replayed |
| 6 | Prefill-link audit injection | **Confirmed, worse than reported** | the planted row records `status=released` with `output_shape=[6,3]`, so the chain authenticates a log entry that reads as the victim requesting identifiable data **and being granted it** |
| 6 | `/api/audit/verify` unlimited | **Confirmed, with a measured cost** | not rate-limited on any metadata route; 12 concurrent verifiers move `/api/query` median latency from **51 ms to 1582 ms** |
| 7 | Sandbox denylist bypass | **Confirmed, primitive corrected** | the report's `np.fromfile` passes `static_check` but dies in the sandbox (it needs the withheld `open` builtin). **`np.memmap` and `np.genfromtxt` work end to end**: no findings, HITL `auto`, `/etc/passwd` released — and a position-key trick defeats the `_finalize` re-sort, so exact ordered content leaves |
| 10 | Policy config has no floors | **Confirmed, worse than reported** | `min_cell_size=1, dom_threshold=1.0, round_base=1, query_budget=1e9` all validate. **Any single disabled control passes 737 of 737 tests**; all of them off together fails exactly one — and not the floor invariant, which passes in every case |
| 1a | The harness oracle is blind | **Confirmed, worse than reported** | see §2.4 — the verdict is attacker-manufacturable |

Not reproduced as exploitable: the §8 optional-role bit. The code path is real
and analyst-visible (`service.py:367-370`, rendered by `_result.html`), but over
the enumerated gaussian models on `donor_spend` it never fired. It needs pricing
by the skeleton enumeration, not a fix.

---

## 2. Four root causes

Eleven report sections reduce to four defects. Fixing them in this order is
deliberate: each later phase is easier to validate once the earlier one lands.

### 2.1 The differencing controls measure the wrong quantity

Three independent bugs, one theme — the controls count rows, or bound
cohorts loosely, where the threshold they defend counts donors.

- `service.py:194` and `:339` total `df["n"].sum()`, which is `COUNT(*)` —
  **event rows**. The threshold it is compared against, `differencing_delta`,
  is a number of donors. On the 2c pair the check saw 362 versus 327 and
  passed; the donor counts were 19 and 18.
- `simulatable_cohort_bound` sums *whole-population* marginals over differing
  dimensions, ignoring the narrowing effect of the predicates the two cohorts
  share. On the 2c pair it returns 13 against a true symmetric difference of
  **1** — a 13× overstatement, which is exactly the "interaction" residual the
  docstring admits and the roadmap defers to a DP accountant.
- `observe_cohort` tests `0 < d < threshold`. A bound of **zero** therefore
  passes. Two distinct exploits land precisely there: the `age >= 58` /
  `age >= 59` pair, whose release proves nobody in the study is 58; and the
  NULL desync, where a filter naming an absent value gives bound 0 and drops
  one real donor.

**Fix.** Make the lineage test the exact symmetric difference, and state it in
the system's own vocabulary: *a difference you could not have asked for
directly, you may not obtain by subtraction.*

`engine.cohort_symdiff` already computes this exactly and is already used
nowhere. Measured against the shipped rule:

| | vulnerable pairs allowed | benign pairs falsely denied |
|---|---|---|
| shipped simulatable bound | 165 of 190 | 0 of 5 |
| exact symmetric difference | **0 of 190** | 0 of 5 |

(measured on `synth.generate()`; on the shipped CSVs the shipped rule allows
313 of 322, and `redteam/round8_repro.py` re-runs the enumeration on whichever
fixture is present)

#### #40 — the same attack through a public integer dimension

Found by probing #39 rather than by reading the report, and live today. #39
band-aligned `age_years`, but `age_rating` on `spend` is an ordinary public
dimension with the full numeric operator set. Differencing
`age_rating >= v` against `age_rating >= v+1` under two or three common
categorical predicates recovers **20 sub-threshold cells** on the shipped data.
Worked example, `{East Midlands, F, 40-70k}` at `age_rating == 7`:

```
cohort donor sizes      A = 10        B = 10        isolated cell = 9 donors
true |A symdiff B|      0 donors
observe() donor totals  10 vs 10  ->  |delta| = 0, and the guard needs 0 < |d|
lineage bound           786       ->  nowhere near the threshold
both slices             released, no findings
the cell asked directly denied
```

**Why every control missed it.** The two cohorts contain *the same people*.
`age_rating` is an attribute of the app, not of the donor, so the filter
partitions **rows**, not donors — and the released value is a function of the
rows aggregated, not of the cohort. Both differencing layers compare donor
sets, so both correctly see no difference, while the released numbers differ by
a whole suppressed cell. #38 is not wrong; it is answering a question about
people when the disclosure lives in the rows. The `0 <` guard then converts a
symmetric difference of exactly zero into a pass, which is the same fail-open
the `age >= 58` / `age >= 59` pair and the NULL desync both land on.

**Fix — one primitive replaces three patches.** Count the donors who
contribute at least one row to the symmetric difference of the two queries'
**row** sets:

```sql
SELECT COUNT(DISTINCT donor_id) FROM <unit view>
WHERE ((<A>) AND NOT (<B>)) OR ((<B>) AND NOT (<A>))
```

For donor-level filters this is exactly `|A △ B|`, so it subsumes the
donor-cohort test the plan already argued for in §2.1 and loses nothing. For
row-level filters it is the quantity that actually governs the disclosure: on
the worked example it returns 9, and 9 < 10 denies. Pair it with `d < threshold`
rather than `0 < d < threshold` and one change closes #40, the empty-difference
fail-open, and the NULL desync — the last because an exact row difference has
no set model to diverge from.

Keep `simulatable_cohort_bound` as a cheap early-out: it can only deny more,
and it is what catches rare-category isolation without touching the data. It
just stops being the last word. D7 already carries the simulatability argument;
this widens it from donor sets to row sets and the same reasoning applies —
the difference cell is one direct query away, and its answer is the same bit.

Also: change the guard to `d < threshold` (drop `0 <`), since `observe_cohort`
already skips genuinely identical cohorts on the line above; and total donors
rather than rows in `observe` — measured at 0 false positives over 8 ordinary
analysis queries, and it fires on the 2c pair on its own.

**Cost.** Twenty exact symmetric-difference queries take 186 ms on the demo
data against a 5000 ms ceiling. Cache each released cohort's donor set on the
session and it becomes set arithmetic with no SQL at all; do that rather than
pay the queries, because the query cost is a function of cohort size and
therefore its own small timing channel.

**This is a specification change and must be recorded as one.** P11 currently
reads "MUST NOT decide a differencing denial from the live donor sets", and
this fix contradicts it. The argument for making it anyway: simulatability was
bought at the price of the control not working, and the information it was
protecting is available for one query anyway. When two cohorts differ on one
dimension their symmetric difference *is* a single cell, so "these cohorts
differ by fewer than ten donors" is the same bit as the canonical refusal the
analyst gets by asking for that cell directly. For multi-dimension differences
the difference set is not always expressible as one query, so a genuinely new
bit does leak there; it should be priced and documented rather than waved
past. Needs a decision record (D7) and an amendment to P11.

### 2.2 The catalogue's granularity promise is enforced on outputs, not inputs

`query.py` says raw age "cannot be grouped, selected, or returned", and that is
true of every output path. But a filter is an input, and consecutive filters
manufacture the output the promise withholds: `age_years == 41` releases
directly, and `age >= 41` minus `age >= 42` reconstructs the same cell inside a
narrowed cohort. The catalogue withholds a 57-level grouping and the filter
algebra hands it back.

**Fix.** An internal-filter dimension may be filtered only at the cut points of
the public dimension it shadows, and only with range operators. For
`age_years` the grid is the declared `age_band` domain — `{13, 16, 18, 25, 35,
50}` — which is the granularity already public. Verified consequences:

- `==`, `!=` and `in` on an internal filter become inexpressible, so 2b dies at
  validation.
- **No two grid points are adjacent**, so the `>= v` / `>= v+1` construction
  behind 2c is not expressible either.
- 2a collapses to at most six slices, which is exactly `age_band`.

This is a by-construction fix in the boundary the project already trusts, and
it costs nothing analytically: `age >= 18` and `age >= 25` remain legal, which
is what the filter is for. Blast radius is five test sites (`test_glm.py:218`,
`test_refusal_equality.py:76-125`, `test_secure.py:436`,
`test_query_properties.py:260`, and the Hypothesis strategy at
`test_glm_properties.py:82`). Two of those exist only to probe the refusal
oracle on `age_years ==`; under this change those queries become
request-decided rejections, which is a better answer than the one they
currently assert.

### 2.3 The disclosure rules assume friendly data

Every rule in the gateway was written against `synth.generate()`'s
non-negative, finite, non-null floats. Real refund, net-flow and delta measures
are none of those things, and the failures are not subtle.

- **Dominance assumes non-negativity.** `MAX(c)/NULLIF(SUM(c),0)` picks the
  *least negative* contributor over a negative total. Fix: use the magnitude
  share `|c_max| / SUM(|c_i|)`, which is identical on non-negative data and so
  changes no current decision. Assert the assumption per measure rather than
  leaving it implicit.
- **The released payload is never checked for finiteness.** In `disclosure.py`
  the string `"value"` occurs once, and only to classify it as not-a-cell-key.
  Fix: a non-finite payload is a `leak_detector` deny rule, in the same family
  as the fail-closed treatment the safety witnesses already get.
- **The auditor's set model diverges from SQL NULL semantics** in the
  permissive direction. Largely moot once §2.1 lands (the exact symmetric
  difference has no model to diverge from), but `_dim_value_set` should still
  be made NULL-correct so the simulatable bound stays a sound cheap pre-filter.
- **Released cell keys are not projected onto declared domains.** Hardening #29
  established that an undeclared value is disclosive by its name and removed it
  from the marginals; the release path never got the same treatment. Fix:
  suppress cells whose key is outside the declared domain, and pin it.
- **Checker-returned rule names are interpolated into analyst-visible text.**
  `Finding("high", f"acro_{name}", detail=f"cells failed ACRO's {name}")` puts
  checker-controlled content on the analyst's screen and into the HMAC-chained
  audit log. This also violates hardening #30's own rule: `detail` is
  analyst-visible and must not carry data-derived content. Fix: constrain
  returned rule names to a declared vocabulary or a strict charset, and drop
  anything else — the same projection principle as #29, applied to the checker
  boundary.

### 2.4 The red-team harness cannot fail

This is why every attack above survived seven hardening rounds. Two structural
problems, not a coverage gap:

**The oracle cannot fire on the service path.** `leaked()` calls
`leak_detector` on the released frame — but `_finalize` has already dropped
`dominance`, `influence` and `n_donors` and rounded the counts, so none of the
rules have anything left to test. Verified: a released frame returns `[]`
findings by construction.

**The PASS criterion is therefore "a control fired", and the attacker chooses
that.** For `expect_block: true`, `ok = (not leaked(final)) and len(controls) >
0`. Demonstrated: a three-step session that recovers one donor's exact spend
(£168.89) reports **PASS** as soon as an unrelated over-granular query is
appended, because that decoy trips `small_cell` and `dominance`.

Coverage, for completeness: the corpus is 22 entries using one `!=` and one
`in`, on one filter column. No range operator, no `age_years`, no `corr`, no
`sum_sq`, no hostile data, no HTTP, no concurrency, no restart, no crash.

**Fix.** Rebuild the oracle before adding entries, or the entries prove
nothing.

1. **Per-step, not final-step.** Check every released output in the sequence.
2. **A compositional oracle grounded in the data, not in the controls.** For
   each pair of released outputs sharing a measure key, compute the true donor
   symmetric difference of their cohorts from the internal unit views and fail
   if any pairwise difference isolates fewer than `threshold` donors.
   Prototyped: it catches 2c and reports the recovered value, on a session the
   shipped harness passes.
3. **A grammar fuzzer** over QuerySpec/GLMSpec/AnovaSpec covering range
   operators, `in` lists, integer dimensions and internal filters, with the
   metamorphic oracles that already exist (release-equality, refusal-equality,
   no-identifier, threshold).
4. **Adversarial fixtures** beside `POISON_DONORS` and `DOMINANCE_ANCHORS`,
   which are the right precedent: negative and refund values, `-inf` and
   overflow-inducing magnitudes, NULL dimensions, an undeclared category above
   threshold, and one hyperactive donor.
5. **An HTTP-level suite**: identity forgery, concurrency, restart, and the
   assertion that every request yields exactly one audit row.

### 2.5 The deployment posture undoes the session controls

Treated by the report as two items (§6 identity spoof, §4 restart amnesia).
Verified together, they are worse than either.

The trust diagram in `docs/security.md` places the model runtime in the
**untrusted** zone. `deploy/safetre-web.service` runs it at
`http://127.0.0.1:8000/v1` — on loopback. `identity.py` trusts
`Tailscale-User-Login` precisely *because* the channel is loopback-only. The
condition chosen to justify trusting the header is the condition under which an
untrusted component can forge it.

Reproduced under the shipped unit's exact environment (`REQUIRE_IDENTITY=1`,
restricted channel on, loopback nets, and — as shipped — **no
`SAFETRE_ALLOWLIST`, which means every login is allowed**):

- 21 forged requests as `victim@org` were accepted, and the audit log
  attributes all 21 to that person.
- Rotating the header mints a **fresh session with a fresh 20-query budget and
  empty differencing lineage**, on demand.

So the session budget and the differencing lineage — the only defences against
multi-query differencing — are keyed on a string the attacker chooses. Restart
amnesia is a footnote next to this: you do not need a restart, and you do not
need the 4096-entry LRU eviction either. Combined with 2c at two queries per
donor, the practical limit on isolated donors is not ten per session; there
isn't one.

Restart amnesia is the same defect reached a slower way, and it was reproduced
over HTTP: a differencing pair denied before a restart completes after one, on
the same `audit.db`, recovering a single 62-year-old donor's exact spend. All 26
rows of the attack were in the log throughout and were never replayed.

**Fix.**
- **Ship `SAFETRE_PROXY_SHARED_SECRET` in the unit and require it whenever
  `REQUIRE_IDENTITY=1`.** This is the one control measured to work: with the
  secret set, a forged header returns `user=unverified` and HTTP 403. Do not
  reach for the allowlist instead — forging an *allowlisted* identity was
  verified to still succeed, so the allowlist narrows who you may impersonate
  and nothing more. Requiring a non-empty allowlist is still worth doing (an
  open allowlist under a "fail closed in production" flag reads as a control
  and is not one), but it is not the fix.
- **Take the last identity header, not the first, and reject multi-valued or
  comma-joined ones.** `Headers.get` returns the first, which is backwards if
  the upstream proxy appends rather than replaces: the client's forged value
  wins. A comma-joined value is currently accepted verbatim as one login.
- Move the model runtime off loopback, or onto a distinct interface the channel
  check excludes.
- Persist session lineage and budget, keyed on the *authenticated* identity,
  and rebuild from `audit.db` at startup. This is roadmap item 4 arriving
  early, and it is what closes restart amnesia properly.
- Treat `request` as untrusted in any log viewer, and record enough to
  distinguish a typed request from a prefill-link one. The chain proves an
  entry is authentic, not that a human composed it — and the planted entry
  reads as a granted release of identifiable data under the victim's name.

---

## 3. Failure paths, configuration and the legacy path

Smaller, but each is cheap and two of them are spec violations.

**R8 is violated, and there is a free crash primitive.** `record()` is called
only on handled return paths, so any exception is an HTTP 500 with no audit row.
Three reproducible triggers: a planner returning non-JSON, an unreachable model
endpoint (both routine in the shipped `SAFETRE_LLM=real` mode, where they make
*every* natural-language query an unaudited 500), and — the one that matters —
a **schema-valid integer-overflow filter**:

```
{"dataset": "wellbeing", "measure": {"fn": "count"}, "group_by": ["sex"],
 "filters": [{"column": "wave", "op": ">=", "value": -10**40}]}
```

`wave` is an `int` dimension and the value is a Python `int`, so
`_check_filter_value` — which type-checks but never bounds — passes it; DuckDB
then raises at `engine.py:364`. Reproducible on all five integer filter columns
across all three datasets, with the boundary at |v| > 2^127. Because the
exception precedes `auditor.observe`, **50 crashes cost zero session budget**;
and because the rate limiter is keyed per identity while identities are
attacker-minted (§2.5), 300 crashes across 300 logins produced 300 unaudited
500s with no 429. `/api/audit/verify` still answers `chain_intact: true` — the
hole is invisible to the control that exists to detect gaps.

Three fixes, all small: bound integer filter values at the QuerySpec boundary
(int64, or better, the column's declared range) so this is a request-decided
rejection; add an exception boundary in `service.handle` that records a
`denied` row and returns the *canonical* withheld answer, since a crash
reachable from data would otherwise be its own oracle; and assert one audit row
per request in the HTTP suite.

The report's `df_resid <= 0` example did **not** reproduce, and the refutation
is worth keeping: 6833 GLM and ANOVA specs reached 220 real fits with a minimum
observed `df_resid` of 23, and `irls_cells` never raised. Structurally, every
released cell carries `n >= min_cell_size` and a full grid gives
`n_cells >= p`, so `df_resid >= 10·n_cells − p`. That is P19 and
`preconditions` working as designed — pin it with a test rather than leave it
resting on a fuzz run.

**Policy configuration has syntactic floors only.** `min_cell_size=1`,
`dom_threshold=1.0`, `round_base=1`, `response_quantum_ms=0` and
`query_budget=1e9` each validate, and each silently disables a control. **Any
single disabled control passes 737 of 737 tests.** All of them off together
fails exactly one — `test_web.py::test_small_cell_redacted`, an incidental
behavioural assertion — while `test_disclosure_thresholds_have_a_floor` passes
in every case, because it reads the dataclass defaults and the module
constants, never `load_policy_config()`.

Worse, a release carries no record of the policy that allowed it. An audit row
is `(ts, user, request, spec, status, findings, output_shape, prev_mac, mac)`;
threshold numbers appear only inside `audit_detail` strings when a suppression
rule *fires*. A cleanly released row under `min_cell=1, dom=1.0, round=1` is
byte-schema-identical to one under the shipped policy, so the tamper-evident
log cannot answer "what rules approved this?" — the question
`CellVetter.describe` exists to answer.

Fix: semantic floors in `_validate` on the *resolved* config
(`min_cell_size >= 5`, `dom_threshold <= 0.5`, `round_base >= 5`, bounded
budget, `response_quantum_ms > 0` unless explicitly waived); an explicit
`SAFETRE_ALLOW_UNSAFE_POLICY=1` escape hatch for research use that logs loudly;
the effective policy logged at boot; a policy digest recorded on every audit
row; and the invariant test moved off the dataclass defaults onto
`load_policy_config()`.

**The legacy sandbox path should stop being presented as a bar.**
`static_check` is 29 literal substrings matched against lowercased source, and
only `np.save` of the numpy file-IO family is on the list. The report's own
snippet does not work twice over: `import` is itself denylisted, and even
without it `np.fromfile` dies in the sandbox because it needs the `open`
builtin that `SAFE_BUILTINS` withholds. **`np.memmap` and `np.genfromtxt` do
work**, end to end — static check passes, sandbox runs, `leak_detector` returns
nothing, HITL says `auto`, and the file bytes are released. `_finalize`'s
re-sort scrambles a naive dump into a byte multiset, but encoding a zero-padded
position key makes that sort the identity and recovers exact ordered content.

Reachability is as documented: neither `safetre_web/app.py` nor `safetre/cli.py`
imports `Analyst` or `guards`, so the path is genuinely unexposed from both
shipped faces. But the modules ship as importable, and `run_redteam.py` runs
guard-ON as though it measured something. The honest options are to add
sandbox-escape entries to `attacks.yaml` and report the guard as bypassed, or
to stop running the comparison. Do not leave it presented as a meaningful bar.

**Rate-limit the metadata routes.** `limiter.allow` is called on exactly one
route, `/api/query`; `/api/audit/verify`, `/api/marginals`, `/api/schema` and
`/api/manifest` are all unlimited. 400 GETs of `/api/audit/verify` drew zero
429s, and because `verify()` holds the audit lock for an O(N) scan (0.134 s at
20k rows), twelve concurrent verifiers moved `/api/query` median latency from
**51 ms to 1582 ms**. That is not only a shared-fate DoS on the control
everything serialises on — at 31× it walks legitimate queries into the 5000 ms
response ceiling, so the timing control starts refusing real analysis, and the
refusal is observable. Rate-limit every route, and consider taking a chain
snapshot outside the write lock.

---

## 4. Order of work

Phased so each phase is independently verifiable and the riskiest change lands
with the best test coverage behind it.

**Phase 0 — rebuild the oracle first.** §2.4 items 1 and 2, plus the
adversarial fixtures. Nothing else can be validated until the harness can fail.
Add the confirmed attacks as entries and watch them go red.

**Phase 1 — the QuerySpec boundary and the differencing controls.** §2.1 (exact
symmetric difference, `d < threshold`, donor totals), §2.2 (the internal-filter
grid), and the integer bound from §3, which belongs here because it is the same
kind of fix: a value the boundary type-checks but never bounds. Defence in
depth on 2c: the lineage rule and the grid each close it alone, and the grid
also closes 2a and 2b. Write D7 and amend P11 in the same change, because the
simulatability story is what a reviewer will look at hardest.

**Phase 2 — the deployment posture.** §2.5. Cheap, and it is what makes the
Phase 1 budget mean anything: today the budget and the lineage are keyed on a
string the caller picks, so no amount of work on the differencing controls
binds an attacker who can reach loopback.

**Phase 3 — hostile data.** §2.3. Signed dominance, payload finiteness,
declared-domain projection on release, checker rule-name sanitising.

**Phase 4 — failure paths, config floors, legacy path, rate limiting.** §3.

**Phase 5 — the residuals worth pricing rather than fixing.** The optional-role
bit over the skeleton enumeration; adaptive timing against #34, which is
already open; `corr` and `sum_sq` as attack tools; and a number for the
cross-session cost that makes the DP-accountant roadmap item concrete.

---

## 5. Validation gates

A fix is not done until the harness would have caught the original attack.

- The compositional oracle reports FAIL on the recorded 2c session before the
  fix and PASS after it, with the 190-cell enumeration at zero.
- Benign regression: the eight-query ordinary analysis session, the planner
  eval corpus and the skeleton enumeration show no new refusals. The exact
  symmetric difference was measured at 0 false denials over 5 benign cohort
  pairs and the donor-total change at 0 over 8 ordinary queries — widen both.
- The hostile fixture releases nothing with a non-finite payload, nothing
  dominated in magnitude, and no undeclared cell key.
- The integer-overflow filter is a request-decided rejection, not a 500. Every
  HTTP request yields exactly one audit row, including on planner failure and
  on every fuzzed spec.
- A forged identity header without the shared secret returns 403 on bare
  loopback; duplicate and comma-joined headers are rejected rather than
  resolved to a login.
- A restart replays lineage and budget from `audit.db`: the pair denied before
  the restart is still denied after it.
- Any single relaxed policy parameter fails the build, not 0 tests in 737, and
  a released audit row records the policy that allowed it.
- Every route is rate-limited; concurrent `/api/audit/verify` no longer moves
  `/api/query` latency by 31×.
- Latency: the symmetric-difference caching keeps the added work off the
  response-time channel measured in D5.

Findings get numbered #37 onward in `docs/hardening-log.md` as round 8, with
the measured exploit recorded for each, per the method note in round 7.

---

## 6. Remaining work — proposed remediation

Written after the harness rebuild (#48), because the ordering changed once the
oracle could fail: several of these are now *watched* even though they are not
fixed, which is a different risk position from before. Each entry gives the
mechanism rather than the intention, since the intention was already in §2.

### 6.1 Restart amnesia — session state is not durable (High)

`SessionStore` holds every auditor in memory and `audit.db` is never replayed,
so a deploy or a crash clears both the query budget and the differencing
lineage. Reproduced over HTTP: a pair denied before a restart completes after
one, recovering a 62-year-old donor's exact spend, with all 26 rows of the
attack sitting in the log throughout.

**Fix.** Rehydrate at startup. Every audit row already carries `user`, `status`
and the validated `spec`, which is everything a `SessionAuditor` needs: `_spent`
is the count of released aggregates, and `_cohorts` is their normalized filter
sets. Add `SessionStore.rehydrate(audit_log, window)` and call it once at
import, alongside the existing policy log.

The design question this forces, and it should be answered explicitly rather
than by default: **what is a session?** Today it is "the lifetime of the
process", which is neither a security property nor a usability one. Propose a
rolling window per identity — 24 hours is the obvious candidate — declared as a
`PolicyConfig` dial with the same `_dial` metadata as the rest, so it appears in
the parameter catalogue and can be argued about. Note that this *tightens*
behaviour: an analyst who used their budget before a restart stays out of budget
after it, which is the correct answer and will surprise people.

Cost: O(rows in window) at startup. Effort: moderate; the store, one dial, a
restart test in the HTTP suite. This is roadmap item 4 arriving early for the
single-user case, and it should be built so the cross-user case is a widening of
the same query rather than a rewrite.

### 6.2 `_dim_value_set` still models `!=` wrongly (Low, but fix it)

SQL `col != v` is NULL for a NULL row, so those rows are excluded; the auditor's
set algebra keeps them. That made `simulatable_cohort_bound` stop being the
upper bound its docstring proves. #40 makes this safe in practice — the exact
row-level difference has no set model to diverge from — but the cheap bound is
still consulted first, and a bound that is wrong in the *permissive* direction
is worth nothing as an early-out.

**Fix.** Model three-valued logic: every comparison operator drops the NULL
sentinel from the selected set; only the absence of a predicate on a dimension
retains it. Six lines and a test. Do it because a comment that says "sound upper
bound" should be true.

### 6.3 Prefill-link audit injection (Medium)

`/#q=<anything>` auto-runs on load, so a link writes an attacker-chosen string
into the HMAC-chained log under the victim's identity — and the planted row
records `status=released` with a shape, so it reads as the victim requesting
identifiable data and being granted it. The chain proves the entry is
authentic; it was never able to prove a human composed it.

**Fix, in order of preference.** Stop auto-running: prefill the input and let
the analyst press the button. That is one line in `static/app.js`, costs a click
on a convenience feature, and removes the attack entirely because the victim
must consent. Do *not* try to fix it by recording a "came from a link" flag —
that flag is client-supplied and therefore forgeable, which would put a false
assurance into the tamper-evident log, the worst of both.

Then document the residual that remains for any log: `request` is untrusted
text. Any future viewer must render it as data, and an investigator reading a
session must know the field records what was submitted, not what was meant.

### 6.4 Cross-user engine concurrency (Medium, integrity)

`QueryEngine.con` is a single DuckDB connection driven from FastAPI's threadpool
by concurrent users. DuckDB's Python client does not guarantee concurrent
`execute().df()` on one connection, and in this system a wrong frame is not
merely a correctness bug — it is a disclosure bug, because the vetting that
approved one user's cells would be attached to another's.

**Fix.** Give each thread its own cursor over the same database:
`self.con.cursor()` is DuckDB's documented pattern for exactly this, and 1.5.4
supports it. Hold it in a `threading.local()` and route every `execute` through
it. The one thing to verify first is that registered pandas frames are visible
to a cursor as well as to its parent — views are, registration may not be — and
if they are not, materialise the tables at construction instead of registering
them.

This needs the cross-user load test the report asks for: N threads, distinct
cohorts, assert every response matches its own request. Without that test the
fix is unfalsifiable, which is the position #48 was about.

### 6.5 The legacy sandbox should stop being presented as a bar (Medium, honesty)

`np.memmap` and `np.genfromtxt` pass `static_check` — a denylist of 29
substrings — and release file contents through the gateway with no findings and
HITL `auto`. The path is genuinely unexposed: neither `safetre_web.app` nor
`safetre.cli` imports `Analyst` or `guards`. But the modules ship as importable
and `run_redteam.py` still runs a guard-OFF/guard-ON comparison over it, which
presents the guard as a measured defence.

**Fix.** Move `analyst.py`'s sandbox half and `guards.py` under `redteam/legacy/`
and label them what they are: an illustration of why the QuerySpec design
exists, with a named, reproducible bypass. Keep the guard-OFF/ON comparison only
if the corpus also carries the bypass entries, so the table shows the guard
failing rather than implying it holds. The alternative — deleting it — loses the
comparison the write-up uses, so moving and labelling is the better trade. The
intent-vetting functions `service.py` imports (`vet_request`,
`check_grouping_coherence`, `check_term_coherence`) stay where they are; they
are part of the secure path.

### 6.6 Model composition oracles (Low — price before fixing)

Three related residuals, none demonstrated as exploitable on the demo data:

- **The optional-role bit.** A gaussian GLM whose `sum_sq` table is withheld
  still releases and tells the analyst so, naming the role. That is one bit per
  cohort about second-moment dominance, and repeated over cohorts it maps where
  the whales are. Over the enumerated gaussian models on `donor_spend` it never
  fired, so the signal rate is unmeasured rather than zero.
- **Within-cell variance.** A released `n`, `mean` and `sum_sq` give the
  per-cell variance directly. That is deliberate and declared, but variance
  differencing across nested cohorts is unexplored.
- **`sum_sq` as an attack tool** is now covered by #40 — it is an ordinary
  measure with ordinary cohorts — and the corpus carries an entry.

**Proposal: measure first.** Run the skeleton enumeration and report how often
the optional-role message fires and whether it correlates with a whale being
present. If the rate is material, the fix is to deny the model rather than
release a partial one, which costs availability and needs D3/D4's evidence
style to justify. Changing it before measuring would be tuning a dial by
anecdote.

### 6.7 Timing: close #34, then attack it (Medium)

Two distinct pieces of work that keep being described as one.

**#34 — the ceiling is a post-hoc check, not a deadline.** The handler runs to
completion and only then is the body replaced, so an overrunning query is
answered late and advertises its size exactly as it would with no ceiling. Fix:
race `call_next` against the deadline with `asyncio.wait_for` so every overrun
answers at the same boundary. State the limit honestly in the code: `call_next`
runs the sync handler in a threadpool, so a cancelled await does not unwind the
work — the clock stops talking, the resource cost stays, and the ceiling remains
a disclosure control rather than a compute cap.

**§9 — nothing attacks the channel.** `measure_timing_channel.py` measures a
defence; the report asks for an attacker. Extend it into an adaptive one that
picks cohorts straddling a bucket edge and reports how many samples order two
sub-threshold cohorts, then run it in CI as a number that must not improve.
There is also the one-setting answer — quantum = ceiling gives constant time —
which D5 declined on measured exposure; the adaptive attacker is what would
justify revisiting that.

### 6.8 Bind the policy digest into the audit chain (Low)

#46 logs the effective policy at startup, so an operator can see it. A released
row still records nothing about the thresholds that allowed it: a clean release
under `min_cell=1` is schema-identical to one under the shipped policy.

**Fix, cheaply.** Append a distinguished record at startup — `user=system`,
`status=config`, the digest in `spec` — so the policy lands *inside* the chain
at the point it takes effect, and every subsequent row is attributable to it by
position. No schema change, no migration, and it composes with the existing
verification.

The alternative, a `policy` column included in the MAC, is better data modelling
and worse operationally: it changes the MAC input, so every existing chain fails
verification and needs an archive-and-restart with a genesis row referencing the
old head. Not worth it for this.

### 6.9 #35 — `max_output_rows` describes a control that cannot run (Low)

The `too_granular` rule requires no count column and `compile_query` always
appends one, so the dial is live in `config.yaml` and never fires. Either make
it bite on released *cell* count — which needs measuring first, since a
three-dimension cross-tab routinely exceeds 100 cells and the default would
start denying ordinary work — or scope the dial to the analyst path and say so
in the parameter catalogue. Leaving a documented dial wired to nothing is the
defect the config loader was rewritten to prevent.

### Status

All of §6 is done — see the status section at the top of this document, and
hardening #49 to #56. 6.6 landed as a priced residual rather than a change,
which is what the measurement called for. What each turned into in practice is worth recording:
6.1 forced "what is a session?" to become a declared dial rather than an
accident of process lifetime; 6.4 required materialising the input tables,
because a registered pandas frame turns out to be connection-scoped and
invisible to a cursor; and 6.5 came down to what a two-column table is *read*
to mean rather than to any new defect.

Two of these turned out differently from the proposal, and both times because
something was measured before it was changed. 6.6 proposed denying partial
models if the rate was material; the rate *is* material (30%), and the fix is
still wrong, because the channel is the missing column rather than the message
— which only measuring the released shapes shows. 6.7 proposed racing the
handler against a deadline; that provably does not work inside Starlette's
`BaseHTTPMiddleware`, for two independent framework reasons, and the control
had to move out of it entirely.
