---
id: D7
title: Auditor totals count donors, and internal range filters are band-aligned
date: 2026-07-28
status: accepted
question: >
  An adversarial review (redteam/adver_report.md §2) showed the filter algebra
  is a differencing channel the auditor cannot see: a range sweep on exact age
  reads sub-band totals from individually safe releases, and two such slices
  with two common narrowing dimensions recover a 1-3 donor cell. Do we count
  donors in the auditor's delta check, restrict internal range filters to the
  public band edges, both, or something structural (DP)?
clauses: [R5, R6]
evidence:
  - redteam/adver_report.md
  - tests/test_hardening.py
  - redteam/attacks.yaml
revisit_when: >
  A differential-privacy accountant (roadmap item 4) would make both rules
  redundant by bounding the answer rather than the query shape; revisit then.
  Also revisit if a new internal high-granularity filter variable is added —
  it needs its own declared edge set in query.INTERNAL_RANGE_RULES, or the
  same analysis repeated — and if analysts complain that band-aligned age
  windows cost real utility, because the alternative (publishing two-
  dimensional marginals so the lineage bound can see interactions) is a
  different disclosure trade, not a free one.
---

**Status: accepted 2026-07-28 — both, together (hardening #38, #39).**

## The attack, stated once

`age_years` is an internal filter variable: it may filter but never group or
return, so the finest age granularity an analyst is supposed to reach is the
six declared bands. The review showed three ways through that wall, all using
nothing but legal filters:

1. **Range sweep.** `sum(amount_gbp) where age_years >= v` for v = 13..69.
   Every slice clears the donor threshold, so every slice releases. Adjacent
   pairs differ by the exact-age-v sub-band total at two decimal places — a
   57-point histogram where the catalogue offers 6 bands.
2. **Direct exact-age equality.** `age_years == 41` releases the mean/sum of
   every age value held by at least ten donors. No differencing at all.
3. **Two-common-dimension double-differencing.** `{age>=41, London, F}` minus
   `{age>=42, London, F}` is the spend of one to three people. The lineage
   auditor allowed the pair (the differing dimension's whole-population
   marginal is >= threshold), the total-delta check allowed the pair (it
   counted **rows**: the isolated donors' ~30 events exceed the threshold),
   and the per-cell threshold never saw the cell because it is computed on
   the slices, which are large.

## Why these two controls, together

**The auditor's totals must be distinct donors, not rows (#38).** The
differencing threshold protects individuals; D4 moved the *cell threshold*
onto donors but left the auditor comparing row totals, and on an event-level
view a hyperactive donor inflates rows without adding people. With donor
totals, the double-differencing pair above flags, because the two cohorts
differ by 1-3 people however many events those people have. This is a
one-line change with a large blast radius — it catches attack 3 and any
variant built on categorical narrowing alone — and it completes D4 rather
than inventing a rule.

**Internal range filters must align to the public band edges (#39).** Donor
totals do nothing for attacks 1 and 2, because the slices there differ by
10-25 donors — legitimately "safe" by every cohort rule, and yet finer than
the data was meant to be read. The honest fix is at validation: a range
filter on an internal variable may only take the declared band-edge values
of the dimension it backs, and equality/membership is not offered. Any
expressible predicate then selects a union of whole bands, whose marginals
are public, so the sweep's resolution collapses to what the codebook already
publishes. The residual — differencing two band-aligned slices — is
simulatable from the published marginals, which is the property the auditor
is built on.

Alternatives considered and set aside: computing the lineage bound on the
*interaction* of dimensions (breaks simulatability unless two-dimensional
marginals are published — a different disclosure trade); restricting range
ops combined with other filters (stops attack 3, leaves 1 and 2); doing
nothing at validation and relying on the auditor (the auditor's own
docstring called the residual "largely covered"; the review showed it is
not).

## What it cost

Utility: "age over 40" is now answered as the 50+ band (the tightest whole-
band subset), and exact-age windows are refused with the edges named in the
error. A binomial model's trials and successes tables stopped being compared
against each other in the delta check — they are one joint release, so the
comparison was a false positive — by qualifying the auditor's measure key
with the aggregate's role. Both are documented in the hardening log and the
spec amendment to R6.

## Amendment, 2026-07-28: the difference is over rows, not cohorts (#40)

Everything above was verified against the attack as reported, and it held. It
did not hold against the *shape*. Probing the band-alignment fix rather than
re-running the report's example found `age_rating`: an ordinary public
dimension, coarse, groupable, published — and an attribute of the **app**
rather than of the donor. Differencing `age_rating >= v` against
`age_rating >= v+1` under two common categorical predicates recovered twenty
sub-threshold cells on the demo data, with both slices individually safe.

The reason none of the controls saw it is worth stating precisely, because it
is not a granularity problem. The two cohorts contain **exactly the same
people** — symmetric difference zero. A filter on an app or event attribute
partitions the *rows* a query aggregates without changing the *donors* who
appear in it. Both differencing layers compared donor sets, and both were
right: there was no difference in the donors. The disclosure was in the rows.

So the alternative this record set aside as breaking simulatability — deciding
from something other than published marginals — is taken after all, in the
form the evidence pointed at:

> A released value is a function of the rows it aggregated, so that is what the
> auditor has to difference.

`QueryEngine.row_symdiff_donors` counts the donors contributing at least one
row to the symmetric difference of two queries' row sets.
`service._difference_bound` takes the smaller of that and the published-marginal
bound, so the cheap simulatable test still runs first and can only deny more.

**Why this does not give up what D7 was protecting.** Where every filter is a
donor attribute the row-level count *equals* `|A △ B|` exactly — a donor outside
both cohorts contributes no rows, one inside both contributes none to the
difference — so the new test subsumes the old rather than replacing it with
something weaker, and that equality is pinned by a test. The information cost
is close to nil for the dominant case: when two cohorts differ on one dimension
their difference **is** a single cell, so "these differ by fewer than ten
donors" is the same bit an analyst obtains by asking for that cell directly and
receiving the canonical refusal. For differences spanning several dimensions the
difference set is not always expressible as one query, and that genuinely is a
new bit; it is priced with the other residuals rather than waved past, and it is
what the DP accountant closes.

**Correction, 2026-07-28 (round-9 V8, hardening #62).** The paragraph above
understates this, and the code comment that repeated it was simply wrong. Two
things are true that it glosses:

1. The bit an analyst "obtains by asking for that cell directly" is not
   obtained. A difference small enough to trip the threshold is a sub-threshold
   cell, so the direct query is **suppressed** and returns the canonical
   refusal — which is the same answer they would get for a cell that is empty,
   or dominated, or undeclared. The denial here is therefore not a bit they
   already hold.
2. It is not the rare case. Measured over the demo catalogue's one- and
   two-filter cohorts (`scripts/measure_exact_leg_channel.py`,
   `artifacts/exact_leg_channel.json`): across 368,511 pairs the cheap
   simulatable leg denies **120** and the exact leg denies **34,163** that the
   cheap leg allowed. So **99.6% of every differencing denial the auditor
   issues is non-simulatable**, and 9.3% of all pairs draw one. The
   differencing control is, in practice, the non-simulatable one — the cheap
   leg is an early-out, not the substance.

The decision does not change: the alternative is the #40 attack, which
recovered twenty sub-threshold cells, and a control that cannot see the attack
is not a control. What changes is the accounting. The bit is accepted and
bounded by the two properties that keep it *one* bit — the refusal carries no
number, and it is byte-identical whichever leg decided, so it does not even
disclose which one did (pinned by `tests/test_hardening.py::
test_the_two_differencing_legs_are_indistinguishable`).
`formal/disclosure_policy.als::V8ExactLegIsNotSimulatable` exhibits the gap as
a model instance, so a future edit that quietly assumed simulatability would
have to delete a satisfiable run to do it.

The guard also changes from `0 < d < threshold` to `d < threshold`. Genuinely
identical cohorts are already skipped a line earlier, so the only pairs that
reached a zero were ones whose predicates *differ* while selecting the same
rows — and that is a sub-threshold existence fact of its own. Two were live:
releasing both halves of `age >= 58` and `age >= 59` proves nobody in the study
is 58, and a filter naming a value no record holds drops precisely the donors
carrying a NULL, which recovered one donor's exact spend in two queries with no
finding raised.

**What it cost.** One SQL count per prior cohort per request, measured at
186 ms for a full twenty-cohort session on the demo data against a 5000 ms
ceiling; caching each released cohort's donor set on the session would make it
set arithmetic if that ever matters. Nought false denials across the benign
regression session and the eight-query analysis replay. And the honest
irritation: two different predicates that happen to select the same rows now
refuse the second, which is the correct call and will occasionally surprise.
