---
id: D3
title: Second-moment cells get their own bound, and their own failure mode
date: 2026-07-26
status: accepted
question: >
  A dominance bound calibrated for sums is a far tighter rule on sums of
  squares, and the second moment is what decides whether a model may be
  released at all. Should both moments be checked on the same parameters, and
  what should happen when the dispersion cell cannot be released?
clauses: [R5, R15, P19]
evidence:
  - artifacts/dispersion_sensitivity.json
  - docs/verifiable-extensions.md
revisit_when: >
  Someone sets a second-moment bound in anger. The default deliberately
  changes nothing, so the interesting evidence — whether a stated relaxation
  is defensible to an output checker, and what it costs on real rather than
  synthetic concentration — does not exist yet. Also revisit if a robust
  dispersion lands ([D4](D4-robust-dispersion.md)), which would make the
  availability argument for relaxing the bound much weaker.
---

Squaring is not share-preserving. A donor holding a fraction *p* of a cell
holds `p² / (p² + (1-p)²/(k-1))` of its sum of squares, which crosses one half
at `p = 1/(1+√(k-1))` — 0.19 in a twenty-donor cell, 0.09 in a hundred. One
nominal bound was therefore two rules, and the tighter of them silently
governed model availability: 355 of 2650 cells passing on the linear scale
fail once squared, and the dispersion cell alone refused 36 of the 83
otherwise-releasable gaussian models.

**Decision, part one.** The bound is selected by the released value's
disclosure class. R14 gained a `moment2` class because the contract vocabulary
could not previously express the distinction, and
`moment2_dom_threshold` is where an operator states it. Unset by default: the
value is that the choice is visible and settable, not that it is taken.

**Decision, part two.** A gaussian model whose dispersion cannot be released
now returns its coefficients — a function of the vetted mean cells and counts
alone — and withholds everything the dispersion buys. That recovers exactly
the 36 models the ceiling was refusing.

**What was rejected.** Applying a checker's dominance parameters unchanged to
both moments, which would have refused far more than anyone had agreed to;
and releasing significance stars from a withheld dispersion, which is
[D4](D4-robust-dispersion.md).
