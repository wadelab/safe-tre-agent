# Complexity & opacity review

Status: **Tiers 1 and 2 landed; Tier 3 proposed** (2026-08-03). Items 1–10 below are
implemented — see the 2026-08-03 clarification pass in
[hardening-log.md](hardening-log.md) for what each one changed, including the
two that tighten behaviour (#102 band alignment, #103 the pool key). Tier 2
changed no behaviour at all. Companion to
[security.md](security.md), [hardening-log.md](hardening-log.md) and the formal
artifacts. Guiding principle: *secure code is understandable code.* Eight-plus
rounds of self-red-teaming layered subtle logic into the decision path; this
review finds where that logic is now **unnecessarily** hard to follow — for a
reviewer trying to confirm a control holds — and proposes clarifications that
change no behaviour.

Every item below is a clarification, not a relaxation: no control is removed or
weakened. Three of the five Tier 1 items changed no behaviour at all; two
(#102, #103) deliberately TIGHTEN it and landed with tests pinning the new
refusal. Each must land with the test suite and
the `test_formal_*_sync` checks still green; the rule-name set and the
Alloy/red-team corpus refer to rules *by name*, so any rename stays in step with
them.

## How the findings were reached

Three read-only reviewers swept the security-relevant modules (`safetre/`
decision core, the request boundary/config, and `safetre_web/`), and the three
highest-severity structural claims were then verified by hand against the code.

## Tier 1 — a reviewer could plausibly misjudge whether a control holds

1. **[DONE] Disclosure gateway computed its five suppression rules twice.**
   `StandinVetter.vet` calls `leak_detector` for the *findings*, then
   independently recomputes the *suppress mask* for the same five rules
   (`disclosure.py`). "A finding fires ⟺ the cell is withheld" rests on those
   two hand-written copies staying identical — and they already differ in
   numeric coercion. **Fixed:** `_suppression_hits(df, ...)` builds the
   per-rule masks once; findings and the mask are two readers of it, with
   `test_findings_and_suppression_mask_cannot_disagree` pinning the equivalence.

2. **[DONE, #103] `timing._caller` applied a weaker rule than the one it claimed to share.**
   It trusts the login on the proxy secret alone (last-header-wins), while
   `identity.rate_limit_key` also requires `_header_trustworthy` and the
   allowlist and *refuses* repeated headers. The docstring says "the rule is
   identity.py's" — it isn't; in a widened channel this re-opens the #91
   pool-key oracle for the timing control. **Fix:** derive the key through a
   shared helper applying identity's full rule, or replace the comment with the
   three explicit differences and why each is acceptable for a resource bucket.

3. **[DONE, #102] Band-alignment (#39) failed *open* for an internal filter with no range
   rule.** `check_filters` only snaps to band edges when `INTERNAL_RANGE_RULES`
   has an entry; a future internal filter without one falls through to the
   generic numeric branch, reopening exact-age equality. The forward invariant
   (every internal filter has a rule) is enforced nowhere and a test encodes the
   fail-open. **Fix:** internal filter with `rule is None` → refuse.

4. **[DONE] `public_manifest(policy=None)` re-read config on omission**, so an
   announced/hashed cell size can diverge from what is enforced (#61/#89).
   **Fix:** make `policy` required on the request-path manifest functions; add
   one explicitly-named `manifest_for_current_config()` for offline/CLI use.

5. **[DONE] Cross-view differencing branch read as live but is unreachable.**
   `service._difference_bound` handles `prev_dataset != this_dataset`, but the
   only caller skips cross-dataset priors, so the branch never runs. **Fix:**
   make the unreachability explicit at the branch, cross-referencing the skip;
   the scaffolding is intended for the open #95 work and should read as such.

## Tier 2 — materially slows understanding

*All landed. See the hardening log's Tier 2 notes for detail.*

6. **[DONE]** State the middleware order in one place (a comment block or startup
   assertion): six positional controls depend on it. `app.py`.
7. **[DONE]** Factor the three near-duplicate spec validators (QuerySpec/GLMSpec/AnovaSpec)
   into a shared model-allowlist helper, so the load-bearing differences
   (GLM's reserved filter slot, ANOVA gaussian-only) stop hiding in copy-paste.
8. **[DONE, adapted]** `ExternalCheckerVetter`'s stored-table mode. The premise
   was wrong — the ACRO comparison harness and ~15 boundary tests use it, so
   deleting it would have been a functional regression. Instead `shared=True`
   makes the dangerous combination unconstructible and the shared instance's
   fallback fail closed.
9. **[DONE, worst offenders]** Move the hardening archaeology (>5:1 comment:code in places) out of the
   decision path into `hardening-log.md` keyed by `#NN`; leave a one-line
   current invariant + ref at each site.
10. **[DONE]** Smaller: one authority for "suppressable"; `identity_is_verifiable`
    documented as the stronger key-grade check (NOT renamed: hardening #91
    records the fix by that name); annotate each config `_FLOORS`
    entry with its non-waivable hard floor; rewrite `_looks_like_a_measure`'s
    double negative positively; explain or unify the eager-vs-lazy procedure
    registries; split `configuration_problems()` fatal vs advisory; replace
    `getattr(sess.auditor, "_spent", 0)` with the public `.spent`.

## Tier 3 — polish

Dead `getlist` fallback that would weaken the repeat-header refusal if it ran;
duplicated HITL block; the pool-full 503's disguised constant sleep; unused
`sleep_to_boundary` import; the band-snap mock helpers sitting at module top as
if they were controls.

## Do NOT "simplify" these — load-bearing

The min-of-two-bounds differencing guard (cheap simulatable + exact
`row_symdiff_donors`, #40); the two-ratio dominance witness
`GREATEST(mag-share, total-share)` (#41/#93); `simulatable_cohort_bound` summing
over differing dimensions; every fail-closed `+inf`/NaN→suppress path; the
`_secondary_suppress` fixpoint loop; the band-edge snapping arithmetic itself;
the `budget×1.2 ≤ ceiling` cross-dial floor; the procedure `IS NOT NULL` guards
(#92) and `sum_sq` moment2 override; `ResponseTimeBoundary` at raw ASGI; the
per-caller *and* global abandoned-task caps; padding refusals; the required
proxy secret; and `SessionStore.rehydrate`'s chain-verify-fatal replay. Each
looks over-built and each closes a specific, documented attack.

## The through-line

The opacity here is not clever code — it is rationale inlined as essays plus a
few controls whose load-bearing status is only discoverable by tracing. Highest
systemic leverage: #1, #6, #9. Highest correctness risk: #1, #2, #3.
