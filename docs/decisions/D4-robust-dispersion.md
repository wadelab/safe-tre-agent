---
id: D4
title: Inference from a dispersion that cannot be released
date: 2026-07-26
status: parked
question: >
  A coefficient without a standard error is rarely publishable. Can inference
  — an interval, or even a significance class — be restored when the
  second-moment cell is too concentrated to release?
clauses: [R15, P21]
evidence:
  - artifacts/dispersion_sensitivity.json
revisit_when: >
  A researcher is actually blocked by it — the availability gap is currently
  36 gaussian points out of 539 on synthetic data, and a real cohort where
  the concentrated case is the common one rather than the rare one would
  change the arithmetic. Or a robust dispersion arrives from outside with its
  bias already characterised, so the correction does not have to be defended
  here. Or the wider question is settled by the DP accountant (roadmap item
  3), which would supply intervals by a route that does not need this one.
  The plan below survives intact, so unparking is cheap.
---

**Status: parked, 2026-07-26.** The technical route below is sound and the
plan stands; the judgement is that it is not worth taking now.

The reason is not difficulty. A robust dispersion would add a second
dispersion estimator to the trusted computing base, a second thing an output
checker must understand and accept, a bias correction that has to be defended
rather than merely chosen, and another parameter to the catalogue. Against
that: inference on 36 of 539 gaussian skeleton points on synthetic data. That
is a poor trade in the currency that now binds this project, which is not
engineering effort but how much an operator has to hold in their head to
reason about a release.

Coefficients-only therefore stands as the answer for a concentrated cohort,
and the honest thing to tell a researcher is that inference needs a less
concentrated one. The plan is kept rather than deleted so that unparking is a
decision rather than a rediscovery.

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

---

## Plan

The question splits cleanly, and only the second part is hard.

**Architecturally it is not a special case at all.** A robust dispersion is a
new registered aggregate — `sum_sq_winsorised`, say — whose per-donor
contribution is the winsorised squared value. It then inherits everything a
procedure inherits: allowlisted admissibility, the proven SafeSQL shape, a
dominance witness computed on *its own* scale, lineage, budget, and the output
contract. Its cell is vetted like any other, so if it releases, every number
derived from it is a function of vetted cells and P21 holds unchanged. No new
disclosure argument is required — which is the whole reason to prefer this
route over releasing a coarsened function of a suppressed cell.

**Statistically it needs an experiment**, because winsorising shrinks the
dispersion and an optimistic standard error is the wrong kind of wrong for a
disclosure tool.

### Candidates

1. **Winsorise the top contributor** to the value of the next largest, on the
   squared scale, per cell. Minimal information loss, and the cell's dominance
   share falls to at most the second contributor's.
2. **Trim the top contributor** and rescale by the remaining donor count.
   Simpler to describe to an output checker; discards more.
3. **Neither — relax the bound instead**, using `moment2_dom_threshold` from
   [D3](D3-second-moment-parameters.md).

Three is not a throwaway. It buys the same availability by a completely
different trade: the robust estimators keep the protection and lose accuracy,
while the relaxed bound keeps accuracy and loses protection. **The experiment
must compare all three on the same axes**, or the decision is being made
between an option that was measured and one that was assumed.

### What to measure

Against the synthetic generator, where the truth is known and the planted
dominance anchors give real concentration to work with:

- **Availability** — how many of the 36 coefficients-only gaussian models each
  option recovers.
- **Validity** — empirical coverage of nominal 95% intervals across the model
  skeleton. This is the criterion that matters: an interval that says 95% and
  covers 88% is worse than no interval.
- **Accuracy cost** — how far the robust standard error sits from the one the
  full dispersion would have given, where both exist.
- **Protection retained** — the dominance share of the robust cell itself, and
  for option 3 the share that is now being released instead.

### Acceptance criteria, fixed in advance

Adopt a robust dispersion only if, across the skeleton:

- empirical coverage of nominal 95% intervals is **at least 95%** — a
  disclosure tool may be conservative and may not be optimistic;
- it recovers a **majority of the 36** models, since a marginal recovery does
  not justify a second dispersion estimator in the trusted computing base;
- the robust cell passes dominance at the **default** bound, not a relaxed
  one, or the option collapses into option 3 wearing a disguise.

If coverage fails and cannot be corrected by a factor that is itself defensible
— a stated inflation, not one tuned until the numbers pass — then the answer to
D4 is *no*, coefficients-only stands, and the honest recommendation to a
researcher is that inference needs a less concentrated cohort.

### Sequence

1. A measurement script alongside `measure_dispersion_sensitivity.py`,
   computing all four quantities for the three options. No release-path code
   changes: this is a study, and it may conclude *no*.
2. Only if the criteria are met: register the procedure, amend R15, and add
   the availability and coverage numbers to the parameter catalogue as the
   evidence for the new dial.
3. Supersede this record either way, with the numbers.
