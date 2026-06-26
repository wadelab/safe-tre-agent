# Hardening log

A dated record of self-red-team findings and the fixes applied. New findings get
appended; the table is the quick index, the notes below give detail.

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
| 4 | Differencing auditor is shallow (tracks count totals, not measure/lineage) | Med | **Open** | needs query-lineage tracking / DP accountant | roadmap |
| 4b | Only primary suppression — margins can reconstruct a suppressed cell | Med | **Open** | needs complementary (secondary) suppression | roadmap |
| 10 | SSRF / research-question egress in `SAFETRE_LLM=real` remote mode | Med | **Open** | pin/validate `OPENAI_BASE_URL` to localhost; egress firewall; enforce local-in-prod | roadmap |
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

**Still open (roadmap):** #4/#4b (a proper SDC differencing model — lineage +
secondary suppression, ultimately a DP accountant), #10 (lock down remote-LLM
egress). These are tracked in [security.md](security.md#limitations-and-roadmap).
