# Complexity & opacity review

Status: **implemented** (2026-08-03). Companion to [security.md](security.md),
[hardening-log.md](hardening-log.md) and the formal artifacts. Guiding
principle: *secure code is understandable code.* Eight-plus rounds of
self-red-teaming layered subtle logic into the decision path; this review found
where that logic had become **unnecessarily** hard to follow — for a reviewer
trying to confirm a control holds — and the clarifications that fix it without
changing behaviour.

All the accepted changes are behaviour-preserving (the one exception, the
abandoned-task key, moves strictly fail-closed) and shipped in commit
`0e506f5`. The full suite is green (944 passed, 3 slow-deselected) and the
`test_formal_*_sync` hops hold, so the models and docs stayed in step.

## How the findings were reached

Three read-only reviewers swept the security-relevant modules (`safetre/`
decision core, the request boundary/config, and `safetre_web/`). Each finding
was then verified by hand against the code before it was accepted or dropped —
which mattered: several were already fixed in the live tree by the time they
were checked, and three were judged not worth doing.

## Tier 1 — a reviewer could misjudge whether a control holds — DONE

1. **Disclosure rules computed once.** `_suppression_hits` is the single
   definition of the five cell-level rules; `leak_detector`'s findings and
   `StandinVetter.vet`'s suppression mask both read it, instead of two
   hand-kept copies that had drifted on numeric coercion. *Implemented;
   verified mask-equivalence for all five rules; `test_disclosure.py`.*
2. **`timing._caller` applies the full identity rule.** One header, no
   comma-joined pair, the allowlist — not a weaker secret-only rule (#91); the
   one residual difference (`identity_is_verifiable`'s opt-in) is documented
   rather than implied away. *Implemented (strictly fail-closed);
   `test_timing_channel.py`.*
3. **Band-alignment fails closed.** An internal filter with no range rule is
   refused (#39's forward invariant). *Already implemented; property test
   matches.*
4. **`public_manifest` requires the enforced policy.** No silent config
   re-read; `manifest_for_current_config()` is the named escape hatch (#89).
   *Already implemented; `test_manifest.py`.*
5. **Cross-view branch marked unreachable.** The `#95`-open leg no longer reads
   as a live defence. *Implemented (comment).* 

## Tier 2 — materially slows understanding — DONE

- **Middleware order stated once and asserted** — `MIDDLEWARE_ORDER` in
  `app.py`, checked by `middleware_order()`, replacing four scattered comments.
- **Spec validators factored** — `check_model_allowlist` (GLM + ANOVA), the two
  real differences now visible in the callers. Accept/reject sets unchanged.
- **One authority for `suppressable`** — the boolean, read by both
  `is_suppressable` and `deny`; the parallel name-set is gone from the decision.
- **`_looks_like_a_measure` stated positively** (no double negative).
- **`_FLOORS` annotated with each entry's non-waivable hard floor** (`config.py`).
- **Procedure registries** — the eager/lazy asymmetry is explained where it
  lives (`procedures.py`).
- **`configuration_problems()` split** into blocking vs advisory (`identity.py`).
- **`getattr(auditor, "_spent", 0)` → the public `.spent`** (`app.py`).

## Considered and deliberately dropped

- **Relocating the hardening archaeology to the log (the old Tier-2 #9).**
  Dropped. Every function this pass touched *grew* a rich rationale docstring —
  the codebase has a deliberate house style of keeping the "why" inline. Moving
  that narrative out wholesale would fight the maintainers' demonstrated choice
  and churn security-critical files for debatable benefit. The high-*leverage*
  item on paper is the wrong call for *this* code.
- **Dropping `ExternalCheckerVetter`'s stored-table mode (old #8).** Dropped.
  It is exercised by `test_acro_boundary.py`; the live path already uses the
  context path, so removing it is real test churn for a modest surface
  reduction. Not worth it.
- **Renaming `identity_is_verifiable` (old #10 sub-item).** Dropped. Its
  docstring already spells out the key-grade-vs-authorization distinction, and
  it has one call site; a security-module rename earns too little.

## Tier 3 — polish — not pursued

Cosmetic items (a dead `getlist` fallback, a duplicated HITL block, an unused
import, the band-snap mock helpers' placement). Left as-is; none affect
understandability of a control.

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
