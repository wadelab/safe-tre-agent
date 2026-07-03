# Hardening log

A dated record of self-red-team findings and the fixes applied. New findings get
appended; the table is the quick index, the notes below give detail.

## 2026-07-03 — round 2c (query lineage + secondary suppression)

| # | Finding | Sev | Status | Fix | Where |
|---|---|---|---|---|---|
| 4 | Differencing auditor was shallow: it compared only released totals per measure, so sum/mean differencing across overlapping cohorts (e.g. "sum spend in Vaud", then "…excluding 50+") evaded it | Med | **Fixed** | query lineage: each released query's normalized filter predicate (its *cohort*) is remembered per session; a new cohort whose symmetric difference with a prior released cohort is fewer than `threshold` individuals is denied. The symdiff is computed on the internal unit views (`cohort_symdiff`) and never released | `safetre/engine.py`, `safetre/disclosure.py`, `safetre/service.py`, `safetre/query.py` |
| 4b | Only primary suppression: a margin with exactly one suppressed cell lets an attacker recover it by subtraction (the margin total is obtainable as a coarser query) | Med | **Fixed (single-dim exact; multi-dim conservative)** | complementary suppression: if a margin has exactly one suppressed cell, the smallest remaining cell in that margin is suppressed too, iterated to a fixpoint. Exact for one group-by dimension; conservative per-dimension for ≥2 (minimal patterns are an LP problem → ACRO, round 3) | `safetre/disclosure.py` |

### Notes

**#4 lineage.** Deterministic and explainable by design: the auditor can say
*which* prior cohort a denied query nearly duplicates. Identical cohorts are not
flagged (a repeated query reveals nothing new) and denied queries are not
recorded (nothing was released). Limits stated honestly: conservative → some
false positives; per-session only — it does **not** defend across sessions or
colluding users (that needs global accounting → the DP accountant, round 3).

**#4b suppression.** Over-suppresses rather than risk a recoverable cell: in a
2×2 table with one sensitive cell, everything goes (any three released cells
plus margins solve for the fourth). Cross-*query* margin attacks — a coarser
query reconstructing a finer suppressed cell — are #4's job, not this one's.

## 2026-06-26 — round 2a (safepod / restricted channel)

| # | Finding | Sev | Status | Fix | Where |
|---|---|---|---|---|---|
| 12 | Safepod ingress was documented as "bind localhost", but the app did not independently enforce the restricted-channel assumption if uvicorn or firewall config drifted | High | **Fixed** | restricted-channel middleware checks the real ASGI peer address against `SAFETRE_CHANNEL_ALLOW_NETS`, ignores forwarded headers, and denies before request handling | `safetre_web/channel.py`, `safetre_web/app.py` |
| 13 | Physical boundary was implicit; deployment docs did not state the safepod controls needed to make "no raw data leaves" true operationally | Med | **Fixed in docs** | new safepod model covering physical controls, restricted-channel properties, failure modes, and production env defaults | `docs/safepod.md`, `docs/security.md`, `docs/deployment.md` |

### Notes

**#12 restricted channel.** The intended production path is
`tailscale serve -> localhost uvicorn`. The app now enforces that topology at
runtime by default (`SAFETRE_RESTRICTED_CHANNEL=1`,
`SAFETRE_CHANNEL_ALLOW_NETS=127.0.0.1/32,::1/128`). This is defence in depth for
an accidental public bind or firewall mistake; it is not a substitute for the
host firewall and systemd `IPAddressDeny=any`.

**#13 safepod.** The safepod is a physical/operational boundary around the data
host, not a Python feature. The repo can enforce channel assumptions and document
the controls, but a real deployment still needs site work: locked/tamper-evident
housing, disk encryption, disabled unused ports/radios, maintenance logging,
off-pod audit anchoring, and network policy outside the process.

## 2026-06-26 — round 2b (model runtime agnosticism)

| # | Finding | Sev | Status | Fix | Where |
|---|---|---|---|---|---|
| 10 | Real-model config defaulted to a hosted OpenRouter-style endpoint and used a provider SDK, making the local-model production posture weaker than the docs implied | Med | **Fixed** | local-first `SAFETRE_LLM_*` config, no SDK dependency, stdlib OpenAI-compatible HTTP adapter, host allowlist, explicit `SAFETRE_ALLOW_REMOTE_LLM=1` for synthetic-data remote use | `safetre/llm.py`, `.env.example`, `docs/model-runtime.md` |

### Notes

**#10 model runtime.** The repo now assumes a capable local planner model,
roughly 120B-class, while still treating the model as adversarial. Production
uses a local `/v1/chat/completions` endpoint on loopback or a fixed safepod host.
Remote endpoints remain possible only with an explicit synthetic-data flag and
must not be enabled for real safepod data.

## 2026-06-26 — round 1 (self red-team)

| # | Finding | Sev | Status | Fix | Where |
|---|---|---|---|---|---|
| 1 | Audit chain was an **unkeyed** hash chain; a host attacker could rewrite and recompute it, and `verify()` would still pass | High | **Fixed** | keyed **HMAC-SHA256** chain; `verify(expected_head)` for an off-box anchor; key from `SAFETRE_AUDIT_KEY` | `safetre/audit.py` |
| 2 | No **p%-dominance** rule: `mean`/`sum` over a group where one donor dominates leaks that individual | High | **Fixed** | engine computes top-contributor share via internal unit views (never exposed); gateway suppresses dominated cells | `safetre/engine.py`, `disclosure.py` |
| 3 | Exact counts released → aided differencing | Med | **Fixed** | released counts rounded to nearest 5 | `safetre/disclosure.py` |
| 5 | No rate limit / query timeout / unbounded `in` list → DoS + LLM cost amplification | High | **Fixed** | per-user token-bucket (429); DuckDB memory/thread caps + row cap; `in` list capped at 50 | `safetre_web/rate.py`, `engine.py`, `query.py` |
| 6 | Identity accepted spoofable `X-Tailscale-User-Login`; no fail-closed | High | **Fixed** | trust only canonical header; `SAFETRE_REQUIRE_IDENTITY` fails closed in prod | `safetre_web/identity.py` |
| 7 | Boundary files had no integrity controls (no CODEOWNERS / required review / invariant tests) | High | **Fixed** | CODEOWNERS on the 4 boundary files; invariant tests; CI gate | `.github/CODEOWNERS`, `tests/test_invariants.py`, `.github/workflows/ci.yml` |
| 8 | CI could become an RCE/secret-exfil surface | Med | **Fixed (preventively)** | `pull_request` (not `_target`), `permissions: contents: read`, actions pinned by SHA | `.github/workflows/ci.yml` |
| 9 | Supply chain: known-CVE detection only | Med | **Partial** | `pip-audit` + `bandit` in CI; deps pinned/hashed in `uv.lock` | CI |
| 4 | Differencing auditor is shallow (tracks count totals, not measure/lineage) | Med | **Fixed in round 2c** | query-lineage cohort tracking (see 2026-07-03 entry); DP accountant remains round 3 | `safetre/disclosure.py`, `engine.py` |
| 4b | Only primary suppression — margins can reconstruct a suppressed cell | Med | **Fixed in round 2c** | complementary suppression (see 2026-07-03 entry); full multi-dim via ACRO remains round 3 | `safetre/disclosure.py` |
| 10 | SSRF / research-question egress in `SAFETRE_LLM=real` remote mode | Med | **Fixed** | local-first `SAFETRE_LLM_BASE_URL`, host allowlist, explicit remote opt-in, no provider SDK dependency | `safetre/llm.py` |
| 11 | Prompt-injection against the maintainer's AI coding agent | Low/novel | **Mitigated by process** | CODEOWNERS + human review of any boundary diff regardless of origin | process |

### Notes

**#1 audit crypto.** A plain hash chain is only tamper-*evident* against an
adversary who cannot rewrite the whole tail. The chain is now an HMAC chain: an
attacker who rewrites the store but lacks the key cannot forge it
(`test_audit_tamper_with_wrong_key_still_fails`). Two operational requirements
remain and are documented: the key must live **off-box** (systemd
`LoadCredential`), and the head should be **anchored off-box** and checked via
`verify(expected_head=...)`.

**#2/#3 disclosure.** Dominance is computed at the **donor** level inside the
engine using `_spend_u` / `_wellbeing_u` views that include `donor_id`; those
views are not in the QuerySpec `dataset` literal, so they are unqueryable, and
`donor_id` is never returned. The `dominance` helper column is dropped before
release. Counts are rounded only at release; suppression decisions use true `n`.

**#5 DoS.** Defence in depth: a per-user request budget (rate limiter), a bounded
query (engine memory/threads + `LIMIT`), and a bounded spec (`in` ≤ 50,
group-by ≤ 3, filters ≤ 5). systemd `MemoryMax` is the final backstop.

**Still open (roadmap):** the DP accountant and ACRO-proper integration that
subsume #4/#4b (both got deterministic fixes in round 2c). Tracked in
[security.md](security.md#limitations-and-roadmap).
