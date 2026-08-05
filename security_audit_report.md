# Security Audit Report: safe-tre-agent

## Round 2 — 2026-08-05 (final pass, post-hardening-log)

**Scope:** Re-verification of all 15 findings from the 2026-08-04 audit against the current tree, plus a fresh adversarial pass over the recent refactors (complexity pass #102/#103, `_suppression_hits`, `_hitl` extraction, checker env allowlist) and the imaginative/composite surface.
**Baseline:** 946 tests green, bandit clean, pip-audit clean, red-team 28/28. No security code changed since the 2026-08-04 audit (only docs/artifact commits).

### Status of previous findings

| # | Finding | Status (2026-08-05) |
|---|---|---|
| V-1 | Cross-view differencing (#95) | **OPEN** — documented; dedicated keeper test added (`tests/test_disclosure.py`, commit `ed97542`). `disclosure.py:987-988` skip; `service.py:234-240` UNREACHABLE. Roadmap 0.0. |
| V-2 | Checker env inheritance | **FIXED** — allowlist (`external_checker.py:174-189`); only OS/runtime names cross, no `SAFETRE_*`, no generic secret carriers. Residual: `PYTHONPATH`/`PYTHONHOME`/`VIRTUAL_ENV` allowed (operator's own env, not a secret leak). |
| V-3 | Session eviction window | **OPEN (documented)** — `session.py:102-128,141-150`; #90 prevents newcomer eviction; stateful-victim eviction logged loudly. |
| V-4 | Timing distinguishability | **OPEN (documented, D5)** — `over_budget` short-circuit vs full-pipeline denial. |
| V-5 | Literal spec bypass | **BY DESIGN (R17)** — `service.py:145-159,377-381`. |
| V-6 | Greedy JSON regex | **NOT MITIGATED (fail-closed)** — `planner.py:108`. |
| V-7 | Planner prompt operator content | **OPERATOR-TRUST** — unchanged. |
| V-8 | Marginal cache race | **BENIGN (GIL)** — unchanged. |
| V-9 | `.env.local` key | **PRESENT** — gitignored, on disk. |
| V-10 | Chain truncation | **MITIGATED** — high-water mark + off-box anchor. |
| V-11 | `SAFETRE_ALLOW_UNSAFE_POLICY` | **BY DESIGN** — logged loudly. |
| V-12 | WAL external readers | **OPERATIONAL** — unchanged. |
| V-13 | Bucket-boundary timing | **DOCUMENTED** — unchanged. |
| V-14 | Audit-log growth | **DOCUMENTED** — unchanged; see R2-5 note on user-string amplification. |
| V-15 | NULL semantics | **DOCUMENTED** — exact leg catches the direction. |

### New findings

**R2-1. The webpage version tag has not been bumped since round 8 (Low).**
The page renders `v{{ version }}` from `safetre.__version__` (importlib.metadata → pyproject 0.5.0), and `MANIFEST_VERSION = "2026-07-28.aggregate+glm+anova.v8"` (`manifest.py:24`) is embedded in the planner system prompt. Rounds 9, 10, 11 and the complexity pass (through 2026-08-03) shipped security changes without bumping either. AGENTS.md requires "On each new build, update a version tag visible in the webpage so that we can see which version of the code produced the interface." The tag is a manual literal that has gone stale — the exact drift class #61/#89 hunt. A planner reading the manifest believes it is talking to the v8 surface. **Fixed (#104):** `MANIFEST_VERSION` bumped to `2026-08-05...v12`, package to 0.5.1, and the bestiary's map datum moved with them; `project_counts.py` now reads finding numbers from the log's own table rows so the drift test cannot stall on prose. Deriving the tag from the git commit remains a future option.

**R2-2. `_suppression_hits` is executed twice per vet call, while its docstring says "computed ONCE" (Low).**
`StandinVetter.vet` (`disclosure.py:484-507`) calls `_suppression_hits` once inside `leak_detector` (line 492) and once directly (line 504). The function is deterministic and pure, so the two executions cannot disagree — the single-definition refactor is sound. But the docstring overclaims, and a reviewer reading "computed once" could believe there is a single call site. This is the #91/#103 shape: a docstring asserting a property the code does not have. **Fixed (#105):** reworded — the docstring's summary line and the `vet` comment now both say one definition with two readers, each executing it afresh.

**R2-3. `_evictable` reads the private `_cohorts` attribute (Low, house-style).**
`session.py:126` reads `sess.auditor._cohorts` directly. The complexity pass fixed the identical pattern in app.py (`getattr(auditor, "_spent", 0)` → `.spent`), on the rule that "reaching past a public property to a private attribute" is a wrong number waiting to happen. No public property exists for cohorts; a rename would silently change eviction behavior. **Fixed (#106):** `SessionAuditor.cohort_count` added, and all three private reads in `session.py` (the eviction predicate and both eviction log lines) now go through it.

**R2-4. DP-switch composition hazards (roadmap note, not a finding).**
Before the differential-privacy accountant (roadmap item 3) is switched on, these current design decisions will conflict with a DP guarantee:
1. **Per-identity budget vs global privacy.** Budget=20/window is per-identity; DP needs a global budget across colluding analysts (roadmap item 4 is the same gap).
2. **Deterministic rounding is not noise.** Base-5 rounding is a deterministic function with bounded distortion, not a privacy mechanism. A DP accountant must either add noise or prove a deterministic mechanism's DP guarantee.
3. **The exact-leg denial leaks a bit DP must budget.** #62's non-simulatable denial is a query on the data; a DP accountant must account for refusals as queries.
4. **Cross-view #95 breaks a per-dataset ledger.** If the DP accountant budgets per dataset, the same donors in two views get two budgets.
5. **Published marginals are queries.** `/api/marginals` publishes donor-frequency tables — these consume privacy budget and must be accounted for.
6. **The 24h window is a privacy-period question.** DP budgets typically accumulate; `session_window_hours` resets lineage at restart. Decide whether the window is a privacy period.
7. **The lineage/totals layers are deterministic checks.** They must either be replaced by the DP accountant or their refusals accounted for as queries.

**R2-5. User-string length asymmetry (Low, note).**
`rate_limit_key` and `timing._caller` bound the login to 200 chars, but `current_user`/`_presented_login` do not — the session key and the audit `user` field are bounded only by the HTTP header limit. The session store is bounded by `MAX_SESSIONS` (count, not bytes: 4096 × ~16KB ≈ 64MB worst case, within `MemoryMax=1G`), and the audit log stores the user per row, so a long login amplifies V-14's log-growth rate. Not a disclosure; a consistency nit worth folding into the V-14 closure.

### What this round did NOT find

- No SQL injection, no identifier egress, no schema escape — the twelfth round, and the QuerySpec boundary remains the only layer that has never broken.
- The `_suppression_hits` single-definition refactor is sound (deterministic; two readers cannot disagree).
- The `_hitl` extraction is behavior-preserving on both paths; #96 holds (`notes.extend(findings)` on the model path).
- The checker env allowlist (V-2) is sound: no secret and no `SAFETRE_*` config crosses; the direction that fails is a checker that will not start.
- The middleware-order assertion runs at import and checks the live stack.
- The docs/security.md timing claims (26–70 samples, 0/15 orderable) match the current config defaults (quantum 50ms, ceiling 5000ms).
- The `_caller` vs `rate_limit_key` divergence (`timing.py:163-170`) is documented honestly: the abandoned-pool key trusts a header the identity layer refuses for rate limiting, but the secret requirement makes it unforgeable, and the docstring says not to copy the shape.
- The audit-log-as-injection-vector thread: no consumer renders the request field as HTML/markdown/terminal; rehydrate parses `accounting` with isinstance checks and fail-closed casts (a forged huge `cost` only over-budgets the session).
- The time-as-a-channel thread: the 24h window applies only at rehydrate (restart); the live auditor never ages out records, so a pair cannot be split across a window boundary without an operator-controlled restart.
- The chained-residual campaign composes documented residuals but adds no new disclosure capability beyond #95; the marginal-absence bit and eviction reset make targeting more efficient, not more powerful.

---

## Round 1 — 2026-08-04 (original audit)

**Date:** 2026-08-04
**Scope:** Full codebase security review (no code changes)
**Methodology:** Manual review of all security-critical modules, redteam corpus, formal verification layer, and documentation; automated subagent analysis of web layer, LLM integration, and redteam artifacts.

---

## Executive Summary

This is an exceptionally well-hardened Trusted Research Environment agent with 99+ iterative hardening fixes, formal verification (Lean 4, Alloy), and comprehensive red-teaming (28/28 attacks neutralised). The developers have honestly documented every accepted residual. Nevertheless, **15 findings** were identified, the most critical being an active, unmitigated cross-view differencing attack (Gap #95).

---

## CRITICAL / HIGH — Active Open Gaps

### V-1. Cross-View Differencing Attack (Confirmed Open — Gap #95)

- **Files:** `safetre/disclosure.py:987-988`, `safetre/service.py:237-241`
- **Status:** DOCUMENTED as open, cross-view comparison code explicitly UNREACHABLE
- **Severity:** HIGH

`SessionAuditor.observe_cohort` skips cross-dataset comparisons:

```python
if prev_dataset != dataset:  # line 988 of disclosure.py
    continue
```

The codebase publishes multiple views of the same people (`donor_spend`, `wellbeing`, `spend`). An attacker can issue two queries on **different views** with slightly different filters to isolate a single individual. The cross-view bound machinery exists in `service.py:242-246` (`cohort_symdiff` with `dataset_b`), but the comment at lines 234-240 explicitly states: **"UNREACHABLE TODAY, and deliberately kept."**

**Attack scenario:**
1. Query A on `donor_spend`: `{region: "Northern Ireland", sex: "M"}` → count/mean released
2. Query B on `wellbeing`: `{region: "Northern Ireland", sex: "M", income_band: "!= >150k"}` → count/mean released
3. The differencing auditor sees two different datasets and skips the comparison entirely
4. Subtracting the two released aggregates recovers a single donor's values

**Mitigation planned:** Declared-measure equivalence (roadmap item 0.0). Currently no code defends against this.

---

### V-2. Checker Process Inherits Most Environment Secrets

- **File:** `safetre/external_checker.py:166-171`
- **Status:** PARTIALLY mitigated (#97), only 2 variables withheld
- **Severity:** MEDIUM-HIGH

`_checker_env()` passes the **entire parent environment** to the checker subprocess except `SAFETRE_AUDIT_KEY` and `SAFETRE_PROXY_SHARED_SECRET`:

```python
_WITHHELD_FROM_CHECKER = ("SAFETRE_AUDIT_KEY", "SAFETRE_PROXY_SHARED_SECRET")

def _checker_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items()
            if k not in _WITHHELD_FROM_CHECKER}
```

Any other secret in the environment — `SAFETRE_LLM_API_KEY`, `OPENAI_API_KEY`, database credentials, cloud provider tokens — is inherited by the checker. The checker receives **poisoned, untrusted cell-key strings** from the data (documented at lines 83-87) and is treated as a process that could be exploited through those strings. If the checker is compromised (buffer overflow in ACRO's C extensions, supply-chain attack), it holds every secret in the environment.

**Fix:** Build an explicit allowlist of environment variables the checker needs, rather than a denylist of what it doesn't.

---

### V-3. Session Eviction Creates Differencing Window

- **File:** `safetre_web/session.py:102-128, 141-150`
- **Status:** DOCUMENTED (#59, #69, #90) but mitigation is logging only
- **Severity:** MEDIUM-HIGH

When the session cache reaches `MAX_SESSIONS` (4096) and all sessions hold state, the LRU session is **forcibly evicted**, dropping its differencing lineage and query budget. The `rehydrate` mechanism restores from the audit log at startup, but between eviction and the next restart, that identity operates with a fresh, empty session.

**Attack scenario (non-production mode):**
1. Attacker creates 4096 sessions with distinct forged login headers (trivial when allowlist is empty)
2. Victim's session is evicted
3. Attacker issues the second half of a differencing pair targeting the victim's released cohorts
4. The fresh session has no memory of the first half

The code explicitly acknowledges this at line 107: "forgetting a cohort is the unsafe direction." The `#90` fix prevents the newly-created session from being evicted, but doesn't prevent the victim's session from being evicted.

---

## MEDIUM — Design-Level Concerns

### V-4. Timing Distinguishability Between Fast and Slow Denial Paths

- **Files:** `safetre_web/timing.py`, `safetre/service.py:386-392`
- **Status:** KNOWN residual (D5), quantized but not closed
- **Severity:** MEDIUM

The `over_budget()` check (service.py:386) short-circuits **before** the planner and engine, returning in ~1-5ms. A differencing denial (service.py:477) runs the full pipeline before denying, taking ~30-100ms+. Both produce the same canonical refused message, but the timing boundary quantizes them to different quantum buckets: a 5ms response pads to quantum 1 (50ms), while an 80ms response pads to quantum 2 (100ms).

An attacker who deliberately triggers denials can distinguish budget-exhaustion from differencing-detection by latency. This leaks one bit per request: "is this query too similar to a prior release?"

**Closure paths:** Constant-time (quantum = ceiling, all queries pay 5s) or asynchronous delivery (collect result on schedule, not on call).

---

### V-5. Literal Spec Path Bypasses All Natural-Language Defence-in-Depth

- **File:** `safetre/service.py:362-382, 424-425`
- **Status:** BY DESIGN (R17) but removes defence in depth
- **Severity:** MEDIUM

When a request starts with `{`, it is treated as a literal JSON QuerySpec. This bypasses:
- Intent vetting (`vet_request` — catches "give me row-level records")
- Grouping coherence checks (`check_grouping_coherence`)
- Term coherence checks (`check_term_coherence`)

The only validation remaining is Pydantic QuerySpec/GLMSpec/AnovaSpec validation. While the typed validation IS the strong gate, an analyst who knows the schema can submit maximally aggressive queries directly without any natural-language gate. Defence drops from 4 layers to 1.

---

### V-6. Greedy Regex in Planner JSON Extraction

- **File:** `safetre/planner.py:108`
- **Status:** NOT mitigated (fail-closed due to downstream validation)
- **Severity:** LOW-MEDIUM

```python
def _extract_json(text: str) -> str:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return m.group(0) if m else text
```

Uses a **greedy** match from the first `{` to the last `}` in the LLM response. A hostile model could output text containing two JSON objects; the regex would capture everything between the first `{` and last `}`, producing invalid JSON. This is fail-closed (planner error → denied request), but a targeted attack could embed a valid malicious JSON object that the greedy regex captures.

---

### V-7. Planner Prompt Includes Operator-Supplied Content

- **File:** `safetre/planner.py:54-103`
- **Status:** Operator-trust boundary, not formally validated
- **Severity:** LOW-MEDIUM

The planner system prompt includes:
- Dataset descriptions from the definition
- Planner hints (operator-supplied strings)
- Few-shot examples

If any of these contain text interpretable as instructions by the LLM planner, it could influence the planner's behavior. While operator-controlled, a compromised or poorly-written dataset definition YAML could inject instructions into the planner prompt.

---

### V-8. Race Condition in Marginal Cache Population

- **File:** `safetre/engine.py:499-527`
- **Status:** Benign under CPython GIL
- **Severity:** LOW

`marginal_donor_counts()` checks `self._marginals is not None` without a lock and then populates it. Two concurrent threads could both compute marginals simultaneously. Correct under CPython's GIL (deterministic read-only computation) but the pattern is fragile — a DuckDB backend replacement without GIL protection could expose this.

---

## LOW — Configuration and Deployment Risks

### V-9. `.env.local` Contains a Live API Key

- **File:** `.env.local`
- **Status:** Gitignored but present on disk in plaintext
- **Severity:** LOW

A live API key for `api.cline.bot` exists on disk. While gitignored, it persists in plaintext. If the machine is shared, backed up, or compromised, the key is exposed. Standard practice: rotate immediately and use a secret manager.

---

### V-10. HMAC Chain Cannot Detect Its Own Truncation

- **File:** `safetre/audit.py:14-31`
- **Status:** KNOWN, partially mitigated by high-water mark and off-box anchor
- **Severity:** LOW with off-box anchor, MEDIUM without

The HMAC chain proves rows present are consistent but cannot prove no rows are missing. The high-water mark (`.head` file) and off-box anchor partially address this, but an attacker with write access to both the database directory and the `.head` file can truncate the chain and forge a new mark. Only the off-box anchor survives a full host compromise.

---

### V-11. Single Env Var Disables All Safety Floors

- **File:** `safetre/config.py:342-344, 482-490`
- **Status:** BY DESIGN, logged loudly
- **Severity:** LOW

`SAFETRE_ALLOW_UNSAFE_POLICY=1` disables all safety floors including `min_cell_size >= 5`, `dom_threshold <= 0.5`, `round_base >= 5`, and `response_quantum_ms >= 10`. An operator could inadvertently set this alongside development flags and deploy with effectively no disclosure controls.

---

### V-12. SQLite WAL Mode Allows External Readers

- **File:** `safetre/audit.py:189`
- **Status:** Operational risk, not a code bug
- **Severity:** LOW

`PRAGMA journal_mode=WAL` allows concurrent readers. An operator or attacker with filesystem access can open the audit database with `sqlite3` and read all records (including request strings, user identities, and findings). The `claim_exclusive` flock prevents another server process but not a manual connection.

---

## Novel / Imaginative Attack Vectors

### V-13. Cross-Session Timing Oracle via Quantization Bucket Boundaries

- **Status:** NOT previously documented
- **Severity:** LOW-MEDIUM

An attacker who makes many requests can determine the quantum size (observable from response time clusters). Once the quantum is known, they can time requests to land exactly on bucket boundaries, where a small difference in computation time crosses from one bucket to the next. By issuing the same query many times and measuring which bucket the response lands in, they can extract sub-quantum timing information through statistical analysis. This could accelerate the documented 26-70 sample estimate for ordering sub-threshold cohorts.

---

### V-14. Denial-of-Service via Audit Log Growth

- **Status:** NOT previously documented
- **Severity:** LOW-MEDIUM

Every request — including denied ones — appends to the audit log. The `verify()` method reads ALL rows under the lock. An attacker sending requests (within the rate limit) can grow the log indefinitely:
- 120 requests/hour × 365 days ≈ 1M rows/year
- `verify()` performance degrades linearly with log size
- Startup (`rehydrate`) replays the entire `session_window_hours` window

A sufficiently large log could make verification and startup impractical.

---

### V-15. `_dim_value_set` NULL Semantics Interaction

- **File:** `safetre/disclosure.py:745-782`
- **Status:** Previously buggy (#40), current behavior documented
- **Severity:** LOW

The `simulatable_cohort_bound` function computes an upper bound on |A △ B| using published marginals. The `_dim_value_set` function implements SQL-like three-valued logic. The interaction between `!=` filters and NULL values means that `sex != 'Other'` excludes both 'Other' AND NULL rows. This is correct SQL behavior but creates an edge case where the simulatable bound could differ from the exact bound when NULLs are involved. The exact leg (#40) catches this direction, but the simulatable bound is not a true bound in the NULL case.

---

## Documented Residuals (Not New Findings)

These are well-documented in the codebase and represent accepted trade-offs:

| # | Residual | Status | Closure Path |
|---|----------|--------|-------------|
| 95 | Cross-view differencing | **OPEN** | Declared-measure equivalence (roadmap 0.0) |
| 62 | Exact-leg not simulatable | Accepted, measured | DP accountant |
| D5 | Timing quantization residual | Narrowed to 0/15 orderable | Constant-time or async delivery |
| — | Secondary suppression heuristic | Conservative for ≥2 dims | ACRO proper (LP problem) |
| — | Differencing across sessions/users | Not addressed | DP accountant (round 3) |
| — | Optional-role channel | Accepted, 30% of gaussian models | DP accountant |
| — | Human-in-the-loop is a policy stub | Acceptable for Phase 1 | Reviewer queue (Phase 3) |

---

## Testing Coverage Gaps

1. **No fuzz testing** of the QuerySpec validation boundary — Pydantic is robust but edge cases in nested models, deeply nested filters, or extreme string lengths could reveal issues.
2. **No regression tests for cross-view differencing** (#95) — the gap is documented but not regression-tested.
3. **No timing-attack scenarios in the redteam corpus** — `timing_attacker.py` exists separately but isn't in `attacks.yaml`.
4. **No adversarial prompt content tests for the planner** — LLM response parsing is tested but not adversarial prompt construction.
5. **Partial-output checker hang behavior under-tested** — the `ExternalCheckerVetter` timeout path is tested, but a checker that returns 9 of 10 verdicts then hangs is a more subtle failure mode.

---

## Overall Assessment

This is one of the most thoroughly hardened open-source security systems reviewed. The developers have:
- Iteratively red-teamed and fixed 99+ hardening issues
- Documented every accepted residual honestly with measurements
- Built formal verification layers (Lean 4, Alloy)
- Implemented defence-in-depth at every boundary
- Failed closed by default throughout

**Priority recommendations:**
1. **V-1 (cross-view differencing)** — most actionable; implement declared-measure equivalence
2. **V-2 (checker env inheritance)** — switch from denylist to allowlist for subprocess environment
3. **V-3 (session eviction)** — bound session eviction to only truly idle sessions, or increase MAX_SESSIONS
4. **V-4 (timing channel)** — consider async delivery architecture for the principled long-term fix