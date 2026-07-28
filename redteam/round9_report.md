# Round-9 security review: the restart/state path and the shipped boundary

Status: **findings reported, not yet remediated** (2026-07-28, post round 8).
Companion to [adver_report.md](adver_report.md) (the round-8 gap analysis) and
[remediation-plan.md](remediation-plan.md). This review read the whole boundary
again on the assumption that the code is public — `query.py`, `engine.py`,
`disclosure.py`, `service.py`, the session/audit layer, the web app, the
external checker, GLM/ANOVA, the red-team harness, the tests, and the systemd
unit — after hardening #1–#57.

The QuerySpec boundary held again. Eight rounds have produced no SQL injection,
no identifier egress, no schema escape, and round 9 adds none. Everything below
is in the **state-accounting and restart paths that #49 introduced**, in the
**shipped deployment configuration**, or in **oracles that survived** the
canonical-refusal work. Each finding names the file and the line, the attack,
and the fix direction.

**The four headline findings are confirmed by executable reproducers, not only
by reading** (the project's own methodology — see `round8_repro.py`). Measured
on synthetic data against a throwaway audit database:

```
[VULNERABLE] V1  GLM released: live _spent=2, rehydrated _spent=1
[VULNERABLE] V2  binomial released: live cohorts=2, rehydrated=1
                 (successes cohort ('contains_lootboxes'==True) lost on restart)
[VULNERABLE] V3  records 3->2 after deleting one row; verify()=False (chain
                 broken) yet rehydrate proceeded WITHOUT verifying, forgot the
                 cohort, and the follow-up differencing query was 'released'
[VULNERABLE] V4  5 planner-failure queries -> _spent=0 (exceptions are free)
```

---

## 1. Headline: the #49 rehydration reopens the differencing residual across a restart

Hardening #49 made session state durable by rebuilding each identity's budget
and differencing lineage from the audit log at startup. It is the right idea —
but the reconstruction uses the **wrong cost model**, an **incomplete cohort
model**, and it **trusts the log without verifying it**. Together these reopen,
across a restart, exactly the accumulation/differencing class round 8 closed
within a session. A fourth finding (V4) is the same cost-model defect on the
*live* path rather than the reconstructed one.

### V1 (HIGH) — Query budget is not restart-faithful for models

- **Where:** `safetre_web/session.py:83–136` (`SessionStore.rehydrate`, the
  `_spent += 1` at line 129) against `safetre/service.py:405–460`
  (`_handle_model`).
- **Defect:** a model charges the budget **once per planned aggregate** in a
  live session — each aggregate's `auditor.observe(...)` increments `_spent`
  (2 units for a gaussian/binomial GLM, 2 for ANOVA). But the service writes
  **one** audit record per model (`record("released", spec_dict, notes, output)`
  at `service.py:490`). `rehydrate` rebuilds spend as **`_spent += 1` per
  qualifying record** (`session.py:124–129`).
- **Measured:** a released gaussian GLM leaves the live auditor at `_spent=2`;
  after `rehydrate`, the restored auditor shows `_spent=1`.
- **Effect:** after a restart, every model a user ran refunds roughly half its
  cost. The query budget is a differencing/accumulation control; this silently
  ~doubles it across a restart boundary — the exact gap #49 exists to close,
  closed only for plain (single-aggregate) queries.
- **Attack:** spend the full 20-unit budget on 10 gaussian GLMs; wait for (or
  induce) a deploy/restart; the restored budget shows ~10 spent instead of 20;
  repeat. Each cycle roughly doubles the intended per-window accumulation.
- **Fix:** the audit record already carries `spec["aggregates"]` (a list of
  measure keys, `service.py:488–489`). Rehydrate should add
  `max(1, len(aggregates))` for released/redacted model records — or, more
  robustly, record the exact `_spent` delta in the audit row so reconstruction
  is authoritative rather than inferred. (The error path has the mirror-image
  defect — see V4 — which an authoritative per-record cost would also fix.)
- **Pin:** a test that runs a GLM, serialises the log, rehydrates, and asserts
  the restored `_spent` equals the live `_spent`.

### V2 (HIGH) — Restart loses the binomial "successes" cohort lineage

- **Where:** `safetre_web/session.py:139–156` (`_cohort_of`) against
  `safetre/service.py:405–487` (`_handle_model`) and
  `safetre/glm.py:67–82` (`plan_aggregates`).
- **Defect:** live, a binomial GLM records **two distinct cohorts** — the
  trials cohort (base filters) and the successes cohort (base filters +
  `response == True`, appended at `glm.py:76–77`). `_handle_model` records each
  aggregate's normalized filters (`service.py:418–421`, `486–487`).
  `rehydrate` → `_cohort_of` re-validates the **model** spec and restores
  **one** cohort — the model's own base filters (`session.py:150–155`). The
  successes cohort is never restored.
- **Measured:** a released binomial GLM (`contains_lootboxes ~ price_tier`)
  leaves the live auditor holding two cohorts — `('spend', ())` and
  `('spend', (('contains_lootboxes', '==', True),))`. After `rehydrate`, only
  `('spend', ())` remains; the successes cohort is gone.
- **Effect:** after a restart, a query that differences against the forgotten
  successes cohort passes the lineage check. Narrow (needs a prior binomial fit
  plus a restart) but real, and it is the same class #40 closed.
- **Fix:** record each planned aggregate's normalized filters in the audit row
  (not only the model's), and restore all of them. The model spec alone does
  not determine the aggregates' cohorts (the successes filter is added by the
  procedure, not the analyst), so this cannot be re-derived from the model spec.
- **Pin:** a binomial fit, serialise + rehydrate, then assert the successes
  cohort is present in the restored auditor.

### V3 (HIGH) — Rehydration trusts unverified audit rows; row *deletion* defeats lineage

- **Where:** `safetre_web/session.py:113–135` (`rehydrate` calls
  `audit_log.since`) and `safetre/audit.py:105–128` (`since` reads rows with no
  `verify()`).
- **Defect:** `rehydrate` rebuilds the security controls from whatever rows
  `since()` returns, and **never calls `verify()` first**. An attacker with
  write access to `audit.db` who **deletes** (not forges) the record of the
  first half of a differencing pair causes rehydration to skip it — the second
  half is then allowed after the restart.
- **Measured:** three records (benign, cohort A released, benign); delete only
  cohort A's row. `verify()` returns **False** — the chain is broken, so the
  tampering is detectable — yet `rehydrate` proceeds without verifying, forgets
  cohort A, and a follow-up differencing query against A comes back
  **`released`**.
- **Why the documented safety net doesn't hold:** the `since()` docstring says
  "a tampered row can only ever make the rebuilt session more restrictive or
  drop a cohort." But **dropping a cohort is the unsafe direction** — it is
  precisely the differencing-lineage gap. Deletion does not require forging
  MACs, only write access. `verify()` *would* detect it (the chain breaks), but
  nothing gates rehydration on verification, so the tamper-evidence is never
  consulted where it matters.
- **Fix:** `verify()` the chain before rehydrating; on failure, **fail closed**
  (refuse to rehydrate and alert / deny) rather than silently trust a broken
  chain. Document the residual that an off-box anchor is still required for
  full tamper-resistance.
- **Pin:** delete a mid-chain row, rehydrate, assert the app refuses to rebuild
  from it.

### V4 (MEDIUM) — Exceptions before `observe` are free: the budget does not bound error cost

- **Where:** `safetre/service.py:146–159` (`handle`'s exception boundary) against
  `safetre/service.py:266–267` (`auditor.observe` is only reached *after* a
  successful `engine.run`).
- **Defect:** the query budget's stated purpose is to bound **cost** as well as
  accumulation (`SessionAuditor.over_budget` docstring: "bounds both cost and
  the per-session state a flood can accumulate"). But `_spent` is only
  incremented inside `observe`, which runs *after* a successful engine call. A
  query that raises anywhere before that point — a planner failure, an engine
  error, a raising fit — is caught by `handle`'s audited boundary and returned
  as a denial **without spending any budget**.
- **Measured:** five planner-failure queries leave the session auditor at
  `_spent=0`. An attacker can repeat expensive, failing queries indefinitely;
  only the per-route rate limiter (120/min) bounds them — the budget never
  engages. In real-LLM mode the failing call is itself the costly one (model
  inference), so this is a cost-amplification channel the budget was meant to
  close.
- **Nuance / consistency note:** `rehydrate` *does* charge error records
  (`session.py:124–128`: "an `error` row is charged, because the log cannot say
  whether the exception preceded the engine"). So live treats an error as free
  while the reconstruction treats it as spent — the two cost models disagree in
  opposite directions, which is the strongest evidence that the per-record cost
  must be recorded authoritatively rather than inferred on both sides (see V1's
  fix).
- **Fix:** decide the policy — if the budget bounds cost, charge every request
  that enters the pipeline (including errored ones) or a separate error budget;
  if it is purely a privacy/accumulation budget, narrow the docstring and rely
  explicitly on the rate limiter for cost. Either way, make live and rehydrated
  accounting agree.

---

## 2. Shipped deployment configuration

### V5 (MEDIUM) — Unbounded HTTP request body before validation (memory-exhaustion DoS)

- **Where:** `safetre_web/app.py:128–129` (`QueryRequest.q` capped at 500) and
  `:213` (`/api/query`).
- **Defect:** `q` is length-capped by Pydantic, but the JSON body is fully read
  into memory **before** validation. `{"q":"ok","pad":"…2GB…"}` is buffered by
  the transport. One request is enough; the rate limiter does not help, and
  uvicorn imposes no default body limit. (Flagged in round 8's report §6 as
  "pin body limits at uvicorn/tailscale"; still unfixed in code.)
- **Fix:** a small middleware rejecting `Content-Length` above a few KB and
  capping body reads; or pin it at the gateway and say so in the unit.
- **Pin:** a multi-MB body returns 413 without being read in full.

### V6 (MEDIUM) — Shipped systemd unit keeps the audit HMAC key on the same host as the log

- **Where:** `deploy/safetre-web.service:24` (sets `SAFETRE_AUDIT_DB` but not
  `SAFETRE_AUDIT_KEY` / `SAFETRE_AUDIT_HEAD_ANCHOR`) and
  `safetre/audit.py:34–57` (`_load_key` dev fallback).
- **Defect:** with no env key, `_load_key` generates `audit.db.key` (0600)
  **on the same box** as the log. The threat the HMAC chain exists to address —
  a host compromise rewriting the log — then has both key and log and can
  re-MAC a forged chain that `verify()` accepts. The docs say the key must be
  off-box (`audit.py:8–12`, `docs/security.md`); the shipped unit does not do
  that, does not require it, and startup only logs a warning. The one deployment
  the project ships should fail closed without the env key rather than silently
  downgrade to host-resident keys.
- **Fix:** in production mode (e.g. when `SAFETRE_REQUIRE_IDENTITY=1`), refuse
  to start without `SAFETRE_AUDIT_KEY`; document `LoadCredential=` anchoring and
  `SAFETRE_AUDIT_HEAD_ANCHOR` in the unit.

### V7 (MEDIUM) — Cross-user DoS via the single shared external-checker pipe

- **Where:** `safetre_web/app.py:51–56` (one shared `CompositeVetter`) and
  `safetre/external_checker.py:60` (`DEFAULT_TIMEOUT = 120.0`), `:232–274`
  (`_ask` under a per-instance `_lock`).
- **Defect:** the app builds **one** vetter — and therefore one checker process
  and one `_lock` — shared by all users. A contribution frame that makes the
  checker hang (it receives poisoned, untrusted cell-key strings) stalls `_ask`
  for up to **120 s**, holding the shared lock and blocking **every** user's
  external check for the duration. Repeated poisoned queries sustain a
  cross-user denial of the vetting path. The 120 s timeout is also far too
  generous for a boundary already governed by a 5 s response ceiling.
- **Fix:** bound the checker timeout to well under the response ceiling; add a
  circuit breaker so repeated checker hangs stop the vetter from being offered;
  consider per-request isolation if the checker is not fully trusted.

### V8 (MEDIUM) — The exact `row_symdiff_donors` leg is a non-simulatable bit (justification overstated)

- **Where:** `safetre/service.py:101–125` (`_difference_bound`),
  `safetre/engine.py:604–639` (`row_symdiff_donors`), `docs/decisions/D7`.
- **Defect:** when the cheap marginal bound does not deny, the auditor runs the
  **exact** row-level symmetric difference against live data and denies if
  `< threshold`. That denial leaks one bit about live data that the published
  marginals cannot reproduce — by construction not simulatable. The code comment
  justifies it as "the bit a direct query for the difference cell already
  returns," but that direct query is **suppressed** (small cell), so the analyst
  does **not** otherwise get it.
- **Assessment:** an accepted, documented residual — but the stated equivalence
  is wrong, and the bit deserves the same honest pricing the optional-role
  channel got (#53, `artifacts/optional_role_channel.json`), not a rationale
  that overstates its safety.
- **Fix:** correct the comment; measure and price the bit; confirm the exact
  leg's denial message is byte-identical to the cheap leg's (it already is) and
  pin that with a test so the two are indistinguishable.

---

## 3. Oracles that survived canonical refusal

### V9 (LOW) — Model estimability refusals leak cohort-structure facts the aggregate path hides

- **Where:** `safetre/glm.py:104–159` and `safetre/anova.py:66–94`
  (`preconditions`), surfaced by `safetre/service.py:462–466`.
- **Defect:** messages like `"term 'sex' has a single observed level"` and
  `"design grid is incomplete over the observed levels of …"` reveal structural
  facts about the cohort's composition. The plain aggregate path returns one
  canonical refusal ("nothing released") for exactly this class of
  existence/count fact (#30). The model path distinguishes *empty cohort* from
  *aliased terms* from *separation* — a multi-valued oracle where the aggregate
  path gives one bit. P22 permits naming terms, but "single observed level" is
  a count-class fact about the cohort.
- **Fix:** canonical public messages for estimability refusals; keep the
  term-naming detail in the audit log only.

### V10 (LOW) — `plans` (compiled SQL) returned on data-derived denials

- **Where:** `safetre/service.py:288–294` (withheld path returns `plans=plans`).
- **Defect:** the plans are placeholder-only and allowlisted (round 8 §3 called
  to pin this), but on a **data-derived** denial they confirm the spec validated
  and reached the engine — mild confirmation beyond the canonical refusal. The
  trace already says "engine: aggregate computed," so the marginal leak is
  small, but it is non-zero and unpriced.
- **Fix:** omit `plans` on data-derived (withheld) denials; keep them for
  request-derived rejections where the analyst holds the request.

---

## 4. Hardening / hygiene

### V11 (LOW) — Abandoned ceiling-exceeded tasks keep consuming compute

- **Where:** `safetre_web/timing.py:111–128`.
- **Defect:** the response-time ceiling refuses at 5 s but the abandoned task
  keeps its thread and runs to natural completion. An attacker can hold many
  expensive abandoned tasks concurrently (bounded only by the 120/min rate
  limit and DuckDB's own caps). The ceiling stops the clock talking, not the
  meter running — the docstring admits this. Worth a hard cap on concurrent
  abandoned work.

### V12 (LOW) — `manifest` hardcodes disclosure thresholds instead of reading the resolved policy

- **Where:** `safetre/manifest.py:119–125`
  (`"release": {"minimum_cell_size": 10, "counts_rounded_to_nearest": 5, ...}`).
- **Defect:** these are literals. An operator who raises `min_cell_size` to 25
  gets a manifest (served to outside planners, shown in the UI) still claiming
  10 — a config-drift honesty bug in a security-relevant metadata surface, in
  the spirit of #46 (controls that read as set but are not).
- **Fix:** render the manifest from the resolved `PolicyConfig`.

### V13 (LOW) — `_donor_total` over-counts when a donor spans cells

- **Where:** `safetre/service.py:46–57` (`_donor_total`).
- **Defect:** it sums per-cell `n_donors` across all cells. For group-bys where
  one donor appears in several cells (e.g. `event_type`), the total is inflated
  by the number of cells a donor touches, so the cheap total-delta check can
  **miss** a true few-donor difference on such groupings. The strong lineage
  layer (`row_symdiff_donors`) still catches it, so this is defence-in-depth
  noise — but the first-pass layer is weaker than its docstring implies for
  multi-cell donors.

### V14 (LOW) — `SessionAuditor._cohorts` is unbounded (O(n²) at high budgets)

- **Where:** `safetre/disclosure.py:815` (`_cohorts`), `:872–880`
  (`observe_cohort` is O(n) per query).
- **Defect:** `_history` is capped (`MAX_HISTORY`) but `_cohorts` is not. With
  an operator-raised budget (floors allow 10 000), sessions degrade
  quadratically. Cap or index it.

### V15 (LOW) — CSRF posture relies on JSON content-type only

- **Where:** `safetre_web/app.py:213` (`/api/query`).
- **Defect:** not currently exploitable for data — a form POST sends
  `application/x-www-form-urlencoded` → 422, and a cross-origin fetch is blocked
  by the same-origin default (no CORS headers). But there is no explicit CSRF
  token, so any future form-post endpoint is exposed, and content-type confusion
  could let a same-channel page burn a victim's budget. Defence in depth: add a
  SameSite/CSRF token.

### V16 (LOW) — Audit `request` is a tainted-content store for any future log viewer

- **Where:** `safetre/audit.py:86–103` (raw `request` stored verbatim),
  `safetre_web/templates/` (current templates autoescape).
- **Defect:** the raw 500-char query string is stored verbatim. Current
  templates autoescape, but any future audit-log viewer that renders `request`
  as HTML/Markdown is an XSS sink (extends the #50 note: the chain proves an
  entry is authentic, not that a human typed it). Worth an explicit "treat as
  untrusted" note anywhere the log is read back.

---

## 5. Novel / imaginative attack avenues investigated (incl. timing)

The task asked specifically for novel, undocumented and imaginative attacks —
including timing. These are the non-obvious avenues worked through, and where
each landed. (The four *new* live vulnerabilities it produced are V1–V4; the
rest were found to be sound or already documented, and saying so is part of the
audit rather than an omission.)

**Restart / state reconstruction (the new surface #49 added).** The differencing
and budget controls were re-attacked across a *process restart*, which no prior
round did. This yielded the headline trio: the cost model is wrong for models
(V1), the cohort model is incomplete for multi-cohort models (V2), and the
reconstruction trusts a log it never verifies — so *deleting* a row (not
forging one) defeats the lineage the HMAC chain was built to protect (V3).

**Timing.** The R18 boundary (raw-ASGI deadline + quantum padding, #54) was
re-read as an attacker, not measured as a defender:
- The **bucket index** (`ceil(latency/quantum)`) still orders sub-threshold
  cohorts, but only across sessions at 26–70 samples — the documented, priced
  D5 residual, not a new hole. Within a 20-query session there is not enough
  averaging to beat it.
- The **ceiling straddle** (a query finishing just under vs just over the
  ceiling lands a quantum apart) is the vector `redteam/timing_attacker.py`
  already gates in CI.
- The **over-budget short-circuit** returns near-instantly, but budget state is
  public and self-countable, so the latency drop reveals nothing new.
- **New:** the ceiling's *abandoned* tasks keep their thread and run to
  completion, so the control that stops the clock talking does not stop the
  meter running — a compute-amplification angle the docstring admits but does
  not bound (V11).
- **New:** exception responses are *fast*, and fast failing queries spend no
  budget (V4), so an attacker can hold the pipeline in cheap-error mode
  indefinitely under the rate limiter.

**Differencing / composition.** Cross-measure and model↔plain cohort
interactions were probed: `observe_cohort` compares filter cohorts regardless
of measure, so a model's aggregate on a near-duplicate cohort of a prior plain
query is still caught by the row-symdiff lineage. The role-qualified totals
keys (#38) only affect the weak total-delta layer; the strong layer holds. The
first-pass layer's `_donor_total` over-counts for donors spanning cells (V13).

**Data content.** Round 8's hostile fixtures (negative, non-finite, NULL,
undeclared, poison strings) were re-checked against the fail-closed witnesses:
`-inf` contributions and int-overflow sums collapse the dominance witness to
NaN→+inf→suppressed; zero-variance `corr` → NULL value → suppressed; every
groupable dimension has a declared domain, so #43's cell-key projection covers
the whole group-by surface. No new content-driven leak.

**Architectural / imaginative.** One shared external-checker process serialises
all users behind one lock with a 120 s timeout → cross-user DoS via a poisoned
cell key (V7). The audit log's verbatim `request` field is a stored-XSS sink
for any future log viewer (V16). Session eviction (4096 LRU) is unreachable in
both identity modes (forging is blocked by #45 in production; a single shared
identity in dev gives no per-attacker advantage).

**What was deliberately not chased:** cross-session/cross-user accumulation and
the optional-role dispersion bit are documented, priced residuals with roadmap
owners (DP accountant, #53); re-reporting them adds nothing. Micro-architectural
/cache timing is out of scope by design — the untrusted model runs no
attacker-controlled code in-process, and the one secret comparison (audit MAC,
proxy secret) is constant-time.

---

## 6. What was checked and found SOUND

- **QuerySpec / GLM / ANOVA validation boundary** — allowlists, `extra="forbid"`,
  per-type value checks, band-edge rules (#39). No escape found.
- **SQL layer** — every identifier regex-checked via `_ident`, every value a
  bound parameter. No injection path, including in `row_symdiff_donors` and the
  dominance/influence/contribution compilers.
- **Fail-closed witnesses** — dominance (magnitude share), influence, non-finite
  payload, undeclared cell key (#41–#43) all fail closed.
- **Audit verify** — `verify()` fails closed on malformed rows and never raises
  (P15); the chain logic itself is sound. (The gap is V3: it is not *called*
  before rehydration.)
- **Identity / channel** — #45 is correctly implemented: proxy secret required
  in production, repeated/comma-joined headers refused, loopback not treated as
  a boundary, wide-channel trust gated behind an explicit opt-in.
- **Timing boundary** — raw-ASGI deadline plus quantum padding (#54) correctly
  makes the ceiling a real deadline.
- **Session concurrency** — the per-session lock over
  observe → apply → record_cohort is correct (#18); `SessionStore.get` is
  guarded.
- **Refusal canonicalisation** (#30) and **release equality** (#26–#28) —
  correctly implemented; the withheld response is uniform across data-derived
  denials.
- **External checker protocol** — request-id matching, fail-closed on every
  error, rule-name sanitising (#44), per-instance lock, version pinning. The
  residual is operational (V7), not protocol.

---

## Priority

| # | Finding | Class | Confirmed | Effort to demo |
|---|---------|-------|-----------|----------------|
| V1 | Budget not restart-faithful for models | accumulation / differencing | **measured** (2→1) | spend 10 GLMs, restart, re-spend |
| V2 | Binomial successes cohort lost on restart | lineage gap | **measured** (2→1) | fit binomial, restart, difference |
| V3 | Rehydration trusts unverified rows (row deletion) | lineage defeat across restart | **measured** (verify=False, still trusts) | delete 1 row, restart |
| V4 | Exceptions before observe are free | cost-budget gap | **measured** (_spent=0) | 5 failing queries |
| V5 | Unbounded request body | DoS | by inspection | 1 large POST |
| V6 | Audit key on same host in shipped unit | tamper-resistance gap | by inspection | read the unit |
| V7 | Shared checker pipe stalls all users | cross-user DoS | by inspection | poisoned cell key + hang |
| V8 | Exact row-symdiff bit not simulatable | oracle (accepted, mis-justified) | documented | engineered pair |
| V9–V16 | hardening / hygiene | assorted | — | — |

**Meta-recommendation:** the three restart findings (V1–V3) plus the error-path
gap (V4) are one coherent change — make the audit row the authoritative record
of *what a request cost and which cohorts it touched*, verify the chain before
replaying it, and reconstruct budget and lineage from that authoritative record
rather than from a per-record heuristic applied on both sides. That closes the
class #49 opened rather than its instances. V5 and V6 are the two deployment
fixes worth landing first because they are small and independent.

*Reproducers for V1–V4 were run standalone against synthetic data with a
throwaway audit database (the `round8_repro.py` pattern); they can be promoted
to `redteam/round9_repro.py` and gated in CI alongside the round-8 checks once
the fixes land.*
