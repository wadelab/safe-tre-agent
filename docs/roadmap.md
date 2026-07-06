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
it), and check the invariants the tests currently sample: no internal column
reaches a public plan, no released cell is below threshold, suppression fails
closed. CI runs the model check next to pytest.

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
