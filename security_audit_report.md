# Security Audit Report: safe-tre-agent

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