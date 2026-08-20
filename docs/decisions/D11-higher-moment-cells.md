---
id: D11
title: Third and fourth moment cells reuse the signed dominance witness, and tighten by the power
date: 2026-08-20
status: accepted
question: >
  A normality test (Jarque-Bera) is a function of the first four moments, so it
  needs third (sum of cubes) and fourth (sum of fourth powers) moment cells. The
  third moment is SIGNED, where the p%-rule's magnitude share does not apply; the
  fourth is more concentrated than the second, where one outlier holds a larger
  share still. What disclosure control governs these new cells, and does either
  need a new mechanism?
clauses: [R5, R15, P19]
evidence:
  - docs/adding-a-statistical-tool.md
  - docs/decisions/D3-second-moment-parameters.md
revisit_when: >
  Someone sets a `moment4_dom_threshold` (or a third-moment one) in anger — the
  default deliberately changes nothing, so the evidence for a defensible
  relaxation on real rather than synthetic concentration does not exist yet. Also
  revisit if a mean-centred two-pass moment lands (it removes the raw-power-sum
  cancellation the current one-pass computation carries), which would change the
  numerics but not this disclosure argument.
---

Neither needs a new mechanism, and this is the point of the decision.

**The third moment is already handled.** `sum_cube`'s per-donor contribution is
`x³`, which is signed. The dominance witness the gateway reads is not the naive
`MAX(c)/SUM(c)` — that assumes non-negative contributions and inverts on signed
data. It is the magnitude-and-released-total aware
`GREATEST(MAX|c|/SUM|c|, MAX|c|/|SUM c|)` that hardening #41 and #93 built for
exactly the signed case (refunds, net flows, deltas). A third moment is one more
signed donor-additive quantity, so the witness bounds a donor's share of it
correctly with no change. It gets its own disclosure class, `moment3`, so the
contract *says* the cell is a signed higher moment rather than a magnitude.

**The fourth moment tightens itself.** `sum_quad`'s contribution is `x⁴`,
non-negative and more concentrated than the square: a donor holding fraction *p*
of a cell holds a larger share of its fourth power than of its second, so the
*same* nominal dominance bound suppresses more outlier-driven cells. The
protection strengthens with the power, by construction — which is the safe
direction, because a fourth moment (kurtosis) is precisely the statistic a single
extreme value drives. Its class is `moment4`.

**Decision.** Both new classes select the ordinary `dom_threshold` by default
(they fall through the same `_threshold_for` as everything but `moment2`), and
the higher-power contribution — not a tighter dial — does the tightening. As in
[D3](D3-second-moment-parameters.md), an operator dial (`moment4_dom_threshold`,
and a third-moment analogue) is where a defensible relaxation would be *stated*;
unset by default, so the conservative witness governs and the choice is visible.

**What this buys.** The normality tool (`safetre/normality.py`) fits from four
ordinary vetted `QuerySpec`s, so it inherits P5–P7, rounding, lineage, budget and
fail-closed denial (P19) literally rather than by analogy — a whale-dominated
response is *denied*, not leaked, because its fourth-moment cell does not clear
the witness. The formal layer moved only where it should: the measure vocabulary
grew, so `formal/skeleton.json` and the Lean case pins regenerated, while the
Alloy catalogue atoms — datasets, dimensions, responses — did not change, so the
solver-checked correspondence holds unchanged.

**What was rejected.** Inventing a bespoke control for the signed third moment
(the existing signed witness already bounds it) and a tighter *default* threshold
for the fourth (the higher-power contribution already tightens it, and a lower
default would refuse more than anyone has agreed to — the D3 mistake, avoided).
