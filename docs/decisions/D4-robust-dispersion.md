---
id: D4
title: Inference from a dispersion that cannot be released
date: 2026-07-26
status: open
question: >
  A coefficient without a standard error is rarely publishable. Can inference
  — an interval, or even a significance class — be restored when the
  second-moment cell is too concentrated to release?
clauses: [R15, P21]
evidence:
  - artifacts/dispersion_sensitivity.json
revisit_when: >
  This is open, so what it needs is not a trigger but an answer to two
  questions. First, statistical: is a winsorised or trimmed dispersion
  something a researcher would publish, given it is optimistic unless
  corrected? Second, empirical: how much of the 36-model gap does it actually
  recover, which is measurable with the existing sweep once an estimator is
  chosen.
---

**Status: open.** Recorded so the gap is visible as a gap rather than an
absence.

The naive form — release the coefficients plus significance stars — does not
work, and the reason is worth stating because it will come up again. A star is
a function of the standard error, which is a function of the second moment. So
deriving stars from a suppressed `sum_sq` releases a coarsened function of a
cell that failed its check. That breaks the invariant everything else here
rests on: released values are a function of *vetted* cells (P21,
release-equality). It also leaks, weakly — β and *n* are released, so a star
bounds the standard error, which bounds Σx², which bounds the dominant donor's
value. Coarse in one model, narrower across several.

**The version that could work** is a **robust dispersion**: winsorise or trim
the largest contributor so the cell is not dominated by construction, vet
*that* cell honestly, and derive inference from it. Every released number is
then a function of vetted cells again and the invariant holds.

The obstacle is statistical rather than architectural. Winsorising the extreme
contributor shrinks the dispersion, so the standard error comes out optimistic
unless corrected — the wrong direction for a disclosure tool, which should err
towards saying less than it knows rather than more. Choosing and characterising
that correction is the open work.
