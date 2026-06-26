# Round 2 hardening — plan

**Status: started.** Follow-on to [hardening round 1](hardening-log.md).
Round 2 covers the remaining "Open" items from that log plus the safepod /
restricted-channel hardening added after the first review. It touches boundary
files, so substantive changes should ship as a reviewed PR (see item D).

## Scope

| # | Item | Type | Size | Priority |
|---|---|---|---|---|
| A0 | Safepod restricted-channel enforcement | code + docs + deploy | small | done |
| A | Remote-LLM egress / SSRF lockdown | code + deploy | small | first (quick win) |
| B | Differencing via query lineage | code | medium | core security win |
| C | Complementary (secondary) suppression | code | medium | partial; pairs with B |
| D | Branch protection + signed commits | ops/GitHub | small | at go-public |

---

## A0. Safepod restricted-channel enforcement — done

**Threat.** The deployment relied on "bind localhost" and operator discipline.
If uvicorn or firewall configuration drifted, a direct LAN/public path could
reach the app and bypass the intended safepod channel.

**Shipped.**

- `safetre_web/channel.py` — checks the real ASGI peer address against
  `SAFETRE_CHANNEL_ALLOW_NETS` and ignores forwarded headers.
- `safetre_web/app.py` — denies off-channel requests before identity, planning,
  or query execution.
- `deploy/safetre-web.service` — enables restricted-channel mode, requires
  identity, and denies arbitrary network access from the service process.
- `docs/safepod.md` — defines the physical safepod model, failure modes, and
  operational controls.

**Tests.** Direct client outside the allowlist is denied even with a spoofed
`X-Forwarded-For`; a configured channel CIDR is allowed.

---

## A. Remote-LLM egress / SSRF lockdown

**Threat.** With `SAFETRE_LLM=real` to a non-local endpoint, the *research
questions* egress to a third party, and a tampered `OPENAI_BASE_URL` makes the
app an SSRF pivot to internal services.

**Approach.** Validate-and-allowlist the endpoint; enforce local-only in prod;
firewall egress.

- `safetre/llm.py` — in `LLMClient.__init__`, parse `OPENAI_BASE_URL`; require
  host ∈ `SAFETRE_ALLOWED_LLM_HOSTS` (default `localhost,127.0.0.1,::1`); raise
  on violation (fail fast → no SSRF).
- Startup assertion: if `SAFETRE_LLM=real` and `SAFETRE_REQUIRE_LOCAL_LLM=1`,
  reject a non-loopback base URL at boot.
- `deploy/safetre-web.service` — add `IPAddressDeny=any` +
  `IPAddressAllow=127.0.0.1 ::1 <model-host>`.
- Update `.env.example` and `docs/deployment.md`.

**Tests.** `LLMClient` rejects a disallowed host, accepts localhost; boot
assertion fires under the prod flag.

**Trade-off.** None meaningful — remote mode stays available for dev by widening
the allowlist. **Effort:** ~1 sitting.

---

## B. Differencing via query lineage (core)

**Threat.** `SessionAuditor` compares only count totals for the same
`measure_key` and ignores filters — so sum-differencing across overlapping
cohorts (e.g. "sum spend in Vaud", then "…excluding 50+") evades it.

**Approach (deterministic, explainable).** Track each released query's **cohort**
(its normalized filter predicate) and flag when a new cohort is a near sub/
superset of a prior one — i.e. the **symmetric difference is a small set of
individuals**.

- `safetre/engine.py` — add `cohort_symdiff(dataset, filters_a, filters_b) -> int`
  (distinct-`donor_id` count of A△B, on the internal unit views; donor_id stays
  internal) and `cohort_size(filters)`.
- `safetre/disclosure.py::SessionAuditor` — store prior
  `(dataset, normalized_filters, measure_key)`; add `observe_cohort(...)` that
  flags `differencing` when `|A △ prior_i| < threshold` for any prior same-dataset
  query. Keep the cheap total-delta check as a first pass.
- `safetre/service.py` — pass the engine + spec filters into the auditor;
  normalize filters (sort/dedupe; reconcile `in` vs `==`).

**Tests.** Two cohorts differing by a small donor set → 2nd denied
(`differencing`); well-separated cohorts → allowed; cost bounded (≤ budget
queries/request).

**Why not DP now.** Differential privacy is the eventual gold standard but makes
outputs noisy, needs per-query sensitivity analysis, and breaks the
"every number is explainable/auditable" property. Lineage-auditing is
deterministic and can tell the user *why* a query was blocked. **DP is round 3
(or an opt-in mode).**

**Limits to state honestly.** Conservative → some false positives (tune
threshold); does **not** defend across sessions or colluding users (needs global
accounting → DP). **Effort:** ~1–2 sittings.

---

## C. Complementary (secondary) suppression

**Threat.** Suppressing only the primary small/dominated cell can leak it via
margins; the margin is obtainable as a coarser query, so this overlaps with B.

**Approach (partial now, full via ACRO later).**

- Within a released table: `_secondary_suppress(original_df, released_df,
  group_cols)` — if a margin has exactly one primary-suppressed cell, suppress
  the next-smallest cell too. Implement cleanly for **1 group-by dim**; for ≥2
  dims, conservatively suppress the smallest remaining cell in the affected
  margin.
- Cross-**granularity** margin attacks (a coarser query reconstructs a finer
  suppressed cell) are caught by **B's lineage auditor**, not here.

**Be explicit.** Complete multi-dimensional suppression is an LP/network-flow
problem; its proper home is **ACRO integration (round 3)**. Round 2 ships the
single-dim heuristic and relies on B for the cross-query case.

**Trade-off.** Over-suppression (releases less). **Effort:** ~1 sitting.

---

## D. Branch protection + signed commits (ops — your decision)

Makes round-1 CODEOWNERS + CI actually enforce:

- Require PR + **review from Code Owners** + CI status checks green + no
  force-push to `main`.
- Optionally require **signed commits** (SSH/gitsign) — everything is currently
  unsigned and impersonable.

**Decision.** This slows the current straight-to-`main` solo workflow.
Recommendation: enable **just before the repo goes public**, not now. Scriptable
via `gh api` on request.

---

## Explicitly NOT round 2 (round 3+ backlog)

DP accountant · **ACRO proper** (subsumes full secondary suppression + class
disclosure + dominance) · container-isolated escalation path (gVisor/Firecracker)
· off-box audit-log mirroring + off-box HMAC key.

---

## Sequence & open decisions

**Sequence:** A (quick, self-contained) → B (core) → C-light → D (at go-public).

Decisions to confirm before execution:

1. **Differencing:** deterministic lineage-auditing now, DP later? *(rec: yes)*
2. **Secondary suppression:** single-dim heuristic now, full coverage via ACRO? *(rec: yes)*
3. **Lineage threshold:** start conservative (more false-positives, safer)? *(rec: yes)*
4. **Branch protection:** now, or at go-public? *(rec: go-public)*
