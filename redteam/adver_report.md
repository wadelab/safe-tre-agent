# Pentest gap analysis: what `redteam/` doesn't cover

I read the whole boundary — `query.py`, `engine.py`, `disclosure.py`, `service.py`, the web layer, GLM/ANOVA, audit, the existing suite (`attacks.yaml` + `run_redteam.py`), and the hardening history through round 7 (#29–#35, incl. the new canonical-refusal work). The QuerySpec boundary itself is in good shape; every load-bearing claim below was re-verified against the code. The gaps are almost all *around* the boundary: in the filter algebra nobody attacks, in the harness's own oracle, in state that resets, and in failure paths nobody makes fail.

---

## 1. Harness-level blind spots (why whole attack classes are invisible today)

**1a. The oracle only inspects the final step's output.** `leaked(final_on)` looks at the last frame of a sequence. An attack that succeeds at step 3 of 5 then issues innocent queries reads "PASS". Multi-step attacks need a per-step oracle plus a *compositional* one: "no subset of the released outputs, taken together, isolates < k donors." Nothing composes released outputs.

**1b. The hostile planner is a static script of ~20 specs — all equality filters on categorical dims.** No redteam entry uses `<, <=, >, >=`, `in`-lists, `!=`, integer dims (`wave`, `age_rating`), or `age_years` at all. The range-filter algebra — the most dangerous part of the catalogue — is entirely unredteamed.

**1c. No adversarial data fixtures.** Everything runs on `synth.generate()`'s friendly non-negative floats. Control behavior under negative values, NaN/±inf, NULLs, and hostile strings is unpinned (§5).

**1d. The web path, the legacy sandbox, failure paths, concurrency, and time are not in the suite.** `run_redteam.py` never sends an HTTP request, never fires two requests concurrently, never makes the engine/planner raise, never measures latency, and — as the hardening log itself admits — never exercises `corr`.

---

## 2. The headline gap: filter-semantics differencing

The lineage auditor (`simulatable_cohort_bound`) and the total-delta check (`SessionAuditor.observe`) are the two anti-differencing controls, and both are blind to the same trick.

**Attack 2a — range-sweep granularity escalation.**
1. For v = 13..69: `{"dataset":"spend","measure":{"fn":"sum","column":"amount_gbp"},"filters":[{"column":"age_years","op":">=","value":v}]}` (literal spec; planner not needed).
2. Each slice {age ≥ v} has ≥ 25 donors for most v → released at 2dp.
3. Lineage: A={age≥v} vs B={age≥v+1} differ on one dim; bound = whole-population marginal of age v (≈14–25) ≥ threshold → **allowed**. The bound certifies |A△B| ≥ 10 donors — but the attack doesn't need a small difference, it needs the *sum over the difference at 2dp*, which no released query was supposed to give (age_years is deliberately ungroupable).
4. Total-delta: `observe()` compares **`df["n"].sum()` — row counts, not measure totals** (service.py:194). Adjacent slices differ by ~14 donors × ~13 events ≈ 180 rows ≫ 10 → never fires.
5. `sum(age≥v) − sum(age≥v+1)` = total spend of exact-age-v donors ±£0.005. 57 benign queries reconstruct a 57-point age histogram the catalogue was built to withhold (post-#29 age_years is also absent from `/api/marginals` — this is the way back in).

**Attack 2b — direct exact-age querying.** `age_years == 41` is a legal filter. Any age with ≥ 10 donors returns its mean/sum/count **directly**, one query per value — no differencing at all. Singleton ages are withheld (threshold works), but this is a granularity escalation from 6 bands to ~57 values with zero effort. It forces a policy question — should `==` be allowed on `age_years` at all? — that the suite should make visible.

**Attack 2c — two-common-dimension double-differencing: a genuine threshold bypass.**
1. Target a donor known (external knowledge or §3) to be {London, F, age≈41}.
2. Query A: `sum(amount_gbp)` over `{age_years>=41, region=="London", sex=="F"}` — cohort ≈ 30 donors → released.
3. Query B: same with `age_years>=42` → released.
4. A − B = Σ spend over {London, F, age 41} ≈ **1–3 donors** — a cell the gateway suppresses instantly if asked directly.
5. Every control fails: lineage sees one differing dim, bound = marginal(41) ≈ 14 ≥ 10 → allowed (#31's multi-dim sum never engages). Total-delta compares **rows**: the isolated donors have ~13–40 events; whenever ≥ 10 the check passes (D4 moved the *cell threshold* onto donors, but `observe()` still totals **rows** — that asymmetry is the crack). Dominance is per-slice. Post-#30 the occasional withheld B is indistinguishable from any other refusal — skip and move on.
6. Cost: 2 queries/cell, budget 20/session → ~10 cells/session; a targeted individual costs one session. Add `sum_sq` on the same pair → Σx²; for a 1-donor cell, x and x² pin exact |x|.

This works *today*, is absent from `attacks.yaml`, and the documented residual ("interaction of a common category with an otherwise-narrow cohort… largely covered by the per-cell donor threshold") undersells it: that coverage holds only when the *slices* are narrow; with two common narrowing dims the slices stay large while the difference is tiny. Fix directions: count donor totals in `observe()`, bound the symdiff on the interaction, or restrict range ops on internal filter dims when combined with other filters.

---

## 3. Refusal-oracle mapping (the post-#30 residual, made concrete)

#30 canonicalized data-derived refusals. What remains distinguishable — never redteamed — is **released vs withheld vs redacted**:

- `age_years == v` (count): released ⟺ ≥ 10 donors have age v. 57 queries → the age support map; with the rounded counts, a near-exact histogram. This is the support-discovery preamble for §2.
- `redacted` on a 2-cell group-by, read against a coarser release, localizes the unsafe cell to one of two buckets. No adaptive attack in the suite uses a release at one granularity to interpret a redaction at another.
- `plans` is returned on withheld results (placeholder-only SQL). Probably benign; pin with a test that plans never contain values.
- The release/withhold bit on **domain-less internal filters** (age_years — unpublished marginals post-#29) is NOT simulatable: it's new information, one bit per query about cohort size ≥ k. Currently the largest unpriced oracle; deserves an explicit threat-model line.

## 4. State, sessions, restarts

- **Restart amnesia.** `SessionAuditor` lineage/budget is in-memory; `audit.db` records every spec and cohort but is never replayed. A restart (deploy, crash — see §6's unguarded exception paths) wipes differencing history. Redteam: differencing pair split across a restart → the second half must still be denied, or the gap must be documented and priced.
- **Cross-session/collusion** is documented-open but unquantified — e.g., the §2a sweep costs 3 sessions at budget 20; a number makes the DP-accountant roadmap concrete.
- **Session eviction** (4096 LRU): safe with `REQUIRE_IDENTITY=1` + allowlist; with shared/absent identity, one user can starve everyone's budget or evict lineage. One test per deployment mode.
- **`/api/audit/verify` is allowlist-gated but not rate-limited** — it rescans the whole HMAC chain under the audit write lock; spamming it starves audit appends (shared-fate DoS on the control everything serializes on).

## 5. Adversarial data content (controls are only tested on friendly floats)

- **Negative values invert dominance.** `MAX(c)/NULLIF(SUM(c),0)`: with a negative signed cell total, the largest-magnitude debtor produces a small/negative ratio → cell releases; a narrower follow-up isolates them. The p%-rule silently assumes non-negativity (synth measures happen to comply; real refund/net-flow/delta data won't). Nothing validates the assumption per measure.
- **NaN/±inf in a measure**: `SUM` propagates inf → `value.round(2)` stays inf → `leak_detector` checks counts/dominance/influence for finiteness but **never the payload `value`** → a released inf leaks "an extreme/invalid record exists".
- **NULL semantics desync the auditor**: `_dim_value_set` treats `!=` as set difference over the marginal universe (which includes a NULL group); SQL `col != v` excludes NULL rows. The auditor's cohort model and the engine's cohort diverge, in the permissive direction. Synth data has no NULL dims — real data will.
- **Poison strings cross to the external checker**: the 6 `POISON_DONORS` payloads (SQLi/prompt-injection/tool-spoof in `region`/`sex`/`income_band`) flow as contribution records into the checker's stdin JSON. The checker protocol is redteamed for transport failure, never for hostile *content*; a checker that builds rule output from cell keys is one bug from evaluating a planted string.
- **Undeclared observed values still release as cell keys**: #29 drops them from marginals, but a 12-donor typo'd category would *release* in a grouped table, printing a string #29 itself called "disclosive by its name". Pin: release path should project cell keys onto declared domains or suppress undeclared ones.

## 6. Web / HTTP layer (zero redteam scenarios)

- **Loopback co-tenant impersonation.** `Tailscale-User-Login` is trusted on a loopback-only channel — but the threat model's own premise is that the *local model runtime is untrusted*, and it shares loopback. Any local process (model server, checker, cron) can `curl -H 'Tailscale-User-Login: victim@org' …/api/query` and act **as any allowlisted user**, with the audit log attributing it to the victim. `SAFETRE_PROXY_SHARED_SECRET` exists but is optional and **unset in `deploy/safetre-web.service`**. Either ship the secret or state plainly that loopback is one trust domain. Test: forged header on bare loopback without the secret must be 403.
- **Duplicate/case-variant identity headers** (first-wins vs tailscale append/strip behavior): untested; pin it.
- **Crash oracle + unaudited requests.** `service.handle()` has no exception boundary around `planner.plan()` (non-JSON LLM output raises), `engine.run()`, or `proc.fit()` (e.g. gaussian `df_resid ≤ 0` raises). Any of these → 500 **with no audit row** — `record()` sits on handled paths only. Two consequences: a data-dependent crashability bit, and an audit-completeness hole in the tamper-evident log. Redteam: fuzz valid specs hunting exceptions; assert every HTTP request yields exactly one audit row.
- **Shared DuckDB connection across users.** `QueryEngine.con` is one connection driven from FastAPI's threadpool by concurrent users; DuckDB's Python client doesn't guarantee concurrent `execute().df()` on one connection. A cross-user load test hunting wrong-frame/exception is missing — a confusion here is an integrity bug, which in this system is also a disclosure bug.
- **Audit-content injection via the prefill link.** `/#q=<anything>` auto-runs on load and writes an attacker-chosen 500-char string into the HMAC-chained log **under the victim's identity**. The chain proves the entry is authentic; not that the human typed it. Any future log viewer must treat `request` as untrusted; investigators should know entries can be planted by link.
- **Body size**: `q` ≤ 500 chars but the JSON body is unbounded before pydantic — pin body limits at uvicorn/tailscale.

## 7. Legacy sandbox path — never attacked, and it's made of substring matching

`run_redteam.py` runs the Analyst path guard-OFF/ON but never attacks the guard. `static_check` is a denylist; `np.fromfile('/etc/passwd', dtype=np.uint8)` (only `np.save` is listed) wrapped as `pd.DataFrame({'x': …})` yields ≤100 rows, innocent names, no count column → `leak_detector` finds nothing high (`raw_sensitive` needs sensitive *names*; `too_granular` needs >100 rows) → HITL auto → **file contents released**. `np.memmap` likewise. This path is documented as illustration-only and unexposed, but it ships and the redteam presents guard-ON as a meaningful bar. Either redteam it honestly (sandbox-escape entries in `attacks.yaml`) or stop presenting it as one.

## 8. Models (GLM/ANOVA) — composition and failure modes

- **Second-moment differencing**: `sum_sq` over the §2 slices recovers Σx² per isolated cell; combined with the sum, a 1-donor cell is fully pinned. `sum_sq` is untested as an attack *tool*.
- **ANOVA within-cell SS** (`sum_sq − n·mean²` from three released numbers) is a per-cell variance release; variance-differencing across nested cohorts is unexplored.
- **The optional-roles bit**: a gaussian model releasing without `sum_sq` reveals "dispersion withheld" — one bit per cohort about second-moment dominance; repeated over cohorts it maps where whales live. Documented as deliberate, untested as an oracle.
- **Fit-time exceptions** (`IRLS did not converge`, singular design, `df_resid ≤ 0`) → 500 with no audit row and data-dependent conditions — a crashability oracle over model space. The skeleton enumeration covers release decisions, not "fit never raises on releasable input".
- **`corr` is absent from `attacks.yaml`** (admitted in round 2e). Missing end-to-end: hunt a cohort whose whale influence is just under 0.5, pair it with a second cohort, and difference — the influence witness is per-cell, not per-difference.

## 9. Timing (#34 is open — attack it adaptively, don't just measure the defense)

`measure_timing_channel.py` measures; nothing attacks. (a) **Bucket-index readout**: the quantum makes `ceil(work/50ms)` observable; craft cohorts straddling a bucket edge to size-order sub-threshold cohorts across sessions (D5's own 26–70 samples). (b) **Ceiling straddle** (#34): the 503 arrives at its true time; tune cohorts against the ceiling as a size gauge. (c) **Row-count-via-work**: sub-threshold-donor cohorts with many rows (one hyperactive donor) do real work — timing leaks *row counts* of cohorts whose *donor counts* are suppressed, and n ≥ n_donors, so a large timing signature on a suppressed cohort reveals a hyperactive donor exists — the fact D4's donor-threshold exists to hide. Constant-time is documented as one setting away; the redteam should price that decision with an adaptive attacker, not a passive measurement.

## 10. Configuration as an attack surface

`_validate` enforces only syntactic floors: `min_cell_size=1`, `dom_threshold=1.0`, `round_base=1`, `response_quantum_ms=0`, `query_budget=10**9` all validate — each silently disables a control. `test_invariants.py::test_disclosure_thresholds_have_a_floor` checks the **dataclass defaults**, not `load_policy_config()`'s resolved values, so a dangerous `config.yaml` (which ships in the repo) passes CI. The effective policy also isn't logged/asserted at boot: a release records the vetter but not the thresholds that decided it. Add resolved-policy floors (min_cell ≥ 5, dom ≤ 0.5, round ≥ 5, bounded budget, quantum > 0 in prod) pinned invariant-style.

---

## Priority

| # | Attack | Status vs. controls | Effort to demo |
|---|---|---|---|
| 2c | Two-common-dim double-differencing (1–3 donor cells) | **Works today**; lineage + total-delta both blind | ~4 queries |
| 2a/2b | Range-sweep / direct `age_years==` granularity escalation | Works today; "sound" per the bound's own definition | 1–57 queries |
| 6 | Loopback co-tenant identity spoof (secret unset in shipped unit) | Works in the shipped deploy config | 1 curl |
| 6 | Unaudited 500s (planner/engine/fit exceptions bypass `record()`) | Works today; audit-completeness hole too | fuzz valid specs |
| 4 | Restart wipes lineage/budget; never rebuilt from audit.db | Works today | pair across restart |
| 5 | Negative-value dominance inversion; inf/NaN payload release | Untested; assumption unenforced | 1 hostile fixture |
| 7 | Sandbox denylist bypass (`np.fromfile`) → release | Works on the legacy path | 1 attack entry |
| 9 | Adaptive timing (bucket index, ceiling straddle, row-count-via-work) | Narrowed, not closed; no attacker in the loop | extend timing script |
| 10 | Policy-config floors | Unenforced | 1 config + 1 test |
| 8 | corr end-to-end; sum_sq/variance differencing; optional-role bit | Untested | new YAML entries |
| 3 | Release/withhold bits on domain-less internal filters | Priced nowhere | support-mapping run |

**Meta-recommendation for `redteam/` v2:** (1) a per-step *and* compositional oracle ("do any k released outputs jointly isolate < threshold donors") — the dangerous attacks are about what outputs *combine* into; (2) a grammar-based hostile-planner fuzzer over QuerySpec/GLMSpec/AnovaSpec, including range ops and `age_years`, with metamorphic oracles (release-equality, refusal-equality, no-identifier, threshold); (3) adversarial data fixtures (negative, NaN/inf, poison strings, hyperactive single donor); (4) an HTTP-level suite (identity spoofing, concurrency, restart, crash auditability); (5) an adaptive timing attacker in CI rather than a passive measurement. Nothing found suggests the allowlist/bound-parameter core is wrong — every gap is in the filter algebra's semantics, in state and failure handling around the pipeline, or in the fact that the redteam's oracle can't see composition.