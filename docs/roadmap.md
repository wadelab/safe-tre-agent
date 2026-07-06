# Roadmap

The forward plan, in priority order. The record of past work lives in the
[hardening log](hardening-log.md) and the [round 2 plan](round2-plan.md); this
page only says what comes next and why in this order.

One principle drives the ordering: **effort goes to the research core
(`safetre/`), not the demo shell (`safetre_web/`, `deploy/`).** Three hardening
rounds have gone into the shell — identity, channel, sessions, rate limiting —
but a real TRE supplies its own identity and network boundary, so shell work
does not advance the research questions. The shell is now frozen: it gets
fixes, not new controls.

## Status refresh — 2026-07-06

Done since this roadmap was written: the [specification](specification.md)
(the P/R clauses the formal model will discharge), the safe schema-disclosure
endpoint and the marginals value-leak fix, the comprehensive UK synthetic
dataset with pinned disclosure anchors, the GOV.UK restyle of the demo shell
(pa11y-clean, WCAG 2.2 AA), and round-3 hardening of the stateful controls.
The shell is now genuinely finished — items 1–4 below are unchanged in order,
and three new items enter behind them.

## 1. ACRO integration (fellowship WP3)

The disclosure gateway is a stand-in, and it says so. The SDC community will
judge the whole claim on whether the output checking is real, so wrapping
[ACRO](https://github.com/AI-SDC/ACRO) comes before everything else. It also
subsumes work the stand-in only approximates: full multi-dimensional secondary
suppression (an LP problem), class disclosure, and production p%-dominance.
The agent-specific layer — session auditor, lineage, budget — stays ours and
sits on top.

Deliverables: integration design; a comparison of ACRO's decisions against the
stand-in's over the red-team corpus; compatibility notes for TRE operators.

## 2. Formal executable specification (fellowship WP2)

The `QuerySpec` space is finite and small, which is what makes it provable.
Encode the catalogue and the `QuerySpec → SQL plan → disclosure` path as a
machine-checkable model (Alloy or TLA+ first; Lean if the invariants warrant
it). The properties to discharge are now written down: the P-clauses of the
[specification](specification.md), starting with P1–P9 (the query boundary)
and P7 (fail-closed), which the July round of property-testing showed is the
clause real bugs land on. CI runs the model check next to pytest.

This ranks above DP because it hardens the claim we already make, rather than
adding a claim we do not yet make.

## 3. Differential-privacy accountant

The simulatable-auditing argument has one documented residual: the bound
misses differencing that isolates a small group through the interaction of a
common category with a narrow cohort, and catching rare-category isolation
uses one bit of private information (see the
[security model](security.md#side-channels-and-residual-oracles)). A DP
accountant closes both, at the cost of noisy outputs and a harder
explainability story — which is why it ships as an opt-in release mode, not a
replacement for the deterministic gateway.

## 4. Cross-session and cross-user lineage (fellowship WP1 extension)

Persist released-cohort signatures beyond a session so colluding users and
serial sessions are inside the differencing control. Ordered after ACRO and DP
because both change what gets released, and the lineage store should record
the final semantics, not the stand-in's.

## 5. Planner-quality evaluation harness

The gateway makes planner mistakes safe, not invisible: the live
local-model-a planner proposed `mean spend by region` without the
`event_type` filter, releasing a valid but diluted answer (£0 sessions in the
mean). Nothing measures this today. Build a scored corpus of natural-language
requests with reference QuerySpecs, and report per-model: exact-spec match,
semantic match (same cohort and measure), validation-rejection rate, and
denial rate. This turns "local models will become strong enough for planning"
from an assumption into a measurement, and gives the model-runtime docs an
evidence page. Cheap, publishable, and useful before ACRO lands.

## 6. CI hardening

Three checks exist but only run by hand: `mkdocs build --strict` (broken docs
links), the red-team harness (currently 10 attacks, gateway off/on), and
pa11y against the four demo states. Add all three to `ci.yml` next to pytest,
bandit and pip-audit. The red-team run doubles as an executable conformance
check on the specification's P1–P6 and P10–P11.

## 7. Consolidate the write-up into a preprint

The [write-up](writeup.md) is the canonical report and now carries the
simulatable-auditing section; the specification and red-team results are the
evidence. Fold them into one technical report (arXiv-ready) before the
fellowship deadline — the repository docs then reference the preprint rather
than restating it. Best done alongside item 1, so the report describes ACRO
integration rather than the stand-in.

## Parked

- **FHE fixed-analysis backend** — research experiment, entered as a fixed
  tool behind the manifest if at all (see the
  [round 2 plan](round2-plan.md#experimental-fhe-fixed-analysis-backend)).
- **Container-isolated escalation path** (gVisor/Firecracker) — only if the
  legacy code path is ever promoted; today it exists for the red-team
  narrative.
- **Branch protection + signed commits** — at go-public, as decided in the
  round 2 plan.
- **Git history rewrite to drop old deck binaries** — the decks are untracked
  going forward; rewriting history is a separate, destructive decision.
- **Deck regeneration** — the three presentation decks still show the dark
  console UI; refresh from new screenshots when next presenting, and attach
  to a release rather than committing.
