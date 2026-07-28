// disclosure_policy — a bounded model of the session auditor's cohort-lineage
// rule (roadmap item 2, second slice; FORMAL_METHODS_ANALYSIS §2.D).
//
// What is modelled: cohorts as per-dimension value selections, the DONOR and
// the ROW sets they select, and the two bounds the auditor decides from
// (safetre/disclosure.py::simulatable_cohort_bound, SessionAuditor.
// observe_cohort, safetre/engine.py::row_symdiff_donors, and the min-rule in
// service._difference_bound).
//
// ARITY, declared (the round-9 lesson, and the reason this model was rebuilt).
// A release is a function of the ROWS it aggregated, not of the donors behind
// them, and the two are not the same relation:
//
//   donor : row     1..N  — one donor contributes many rows (an event-level
//                           view); this is the arity the first version of this
//                           model did not have, and hardening #40 is exactly
//                           what it could not see
//   dim             donor-level or row-level — `age_band` is an attribute of
//                           the PERSON, `age_rating` is an attribute of the
//                           APP. Two cohorts differing only on a row-level
//                           dimension can hold precisely the same people while
//                           aggregating different rows: symmetric difference
//                           zero, released values differing by a suppressed
//                           cell. Twenty sub-threshold cells were recoverable
//                           that way.
//   donor : cell    1..N  — a donor with rows in several cells is counted once
//                           per cell by service._donor_total, which is why the
//                           cheap total-delta layer over-counts (V13, below).
//
// The threshold is abstracted to 3 (the code's 10): the properties are
// threshold-generic, and a small constant keeps the bounded search exact.
//
// What is checked (counterexample = CI failure):
//   MarginalBoundSound          — the docstring's soundness claim: the summed
//                                 marginal bound really is an upper bound on
//                                 the true symmetric difference, on ANY number
//                                 of differing dimensions;
//   RareCategoryIsolationBlocked — the canonical differencing attack
//                                 (adding/removing globally-rare categories)
//                                 cannot survive the auditor;
//   RowDifferenceAlwaysBounded  — hardening #40: any two releases the auditor
//                                 allows differ over at least T donors AT ROW
//                                 LEVEL, so the #40 attack (identical donor
//                                 sets, differing rows) cannot pass;
//   RowLayerSubsumesDonorLayer  — the claim the #40 fix rests on: where the
//                                 cohorts differ only on donor-level
//                                 dimensions the exact row-level count EQUALS
//                                 the old donor symmetric difference, so the
//                                 new layer strictly extends the old one
//                                 rather than trading it away.
//
// What is SEARCHED FOR and expected to EXIST (unsatisfiable = CI failure,
// because the model would then contradict the code's own documentation):
//   someSession                 — the modelled space is inhabited;
//   InteractionResidualExists   — a pair the MARGINAL layer alone would allow
//                                 whose true difference is small: the
//                                 documented price of simulatability, and now
//                                 also the reason the exact leg exists;
//   Hardening40AttackWithoutRowLayer — drop the row layer and the attack
//                                 returns: two cohorts holding the same people
//                                 over different rows, both released;
//   V13DonorTotalOvercounts     — the cheap total-delta layer sums per-cell
//                                 donor counts, so a donor with rows in
//                                 several cells is counted several times and
//                                 the total exceeds the distinct-donor count.
//                                 Exhibited rather than fixed: the layer is
//                                 best-effort and the lineage layer is what
//                                 holds, which is what the code should say.
//   V8ExactLegIsNotSimulatable  — a denial the published marginals cannot
//                                 justify: the marginal bound is >= T (nothing
//                                 public says these cohorts are close) while
//                                 the exact row-level leg denies. That denial
//                                 is a bit about live data by construction.
//                                 The code comment used to justify it as "the
//                                 bit a direct query for the difference cell
//                                 already returns" — but that query is
//                                 SUPPRESSED, so the analyst does not
//                                 otherwise get it. Priced, not explained away.
//
// A residual used to be exhibited here — MultiDimSentinelResidual, a
// small-difference pair on two dimensions slipping past the never-denying
// sentinel. It is gone because the sentinel is gone: the bound now sums over
// every differing dimension, so RareCategoryIsolationBlocked covers the
// multi-dimension case that run demonstrated. A red-team pass turned that
// documented residual into a two-query bypass, which is the argument for
// closing a gap rather than exhibiting it.

module disclosure_policy

sig Dim {}
// a dimension is an attribute of the PERSON or of the ROW — the distinction
// hardening #40 turned on
sig DonorDim in Dim {}
fun RowDim: set Dim { Dim - DonorDim }

sig Val { dim: one Dim }
sig Donor {}

// the unit of aggregation: one row belongs to one donor and carries a value on
// every dimension
sig Row { donor: one Donor, attr: Dim -> one Val }
fact AttrWellTyped { all r: Row, dm: Dim | r.attr[dm].dim = dm }

// a donor-level dimension is a property of the person, so all of that person's
// rows agree on it; a row-level dimension is free to vary within a donor
fact DonorLevelConstantPerDonor {
  all disj r1, r2: Row, dm: DonorDim |
    r1.donor = r2.donor implies r1.attr[dm] = r2.attr[dm]
}

// every donor has at least one row (a donor with no rows is in no release and
// only inflates the search)
fact EveryDonorHasRows { all d: Donor | some r: Row | r.donor = d }

// a cohort selects, per dimension, the set of admitted values
// (a dimension with every value selected is unconstrained)
sig Cohort { sel: Dim -> set Val }
fact SelWellTyped { all c: Cohort, dm: Dim, v: c.sel[dm] | v.dim = dm }

// the rows a query aggregates, and the people behind them
fun rows [c: Cohort] : set Row {
  { r: Row | all dm: Dim | r.attr[dm] in c.sel[dm] }
}
fun donors [c: Cohort] : set Donor { rows[c].donor }

// the OLD comparison: how many people are in exactly one of the two cohorts
fun donorSymdiff [a, b: Cohort] : Int {
  (#(donors[a] - donors[b])).plus[#(donors[b] - donors[a])]
}

// the EXACT comparison (engine.row_symdiff_donors): the donors behind the rows
// exactly one of the two queries aggregated. A released value is a function of
// those rows, not of the cohort that produced them.
fun rowSymdiffDonors [a, b: Cohort] : Int {
  #(((rows[a] - rows[b]) + (rows[b] - rows[a])).donor)
}

// whole-population donor marginal of one value (engine.marginal_donor_counts)
fun marginal [v: Val] : Int {
  #{ d: Donor | some r: Row | r.donor = d and r.attr[v.dim] = v }
}

// dimensions on which two cohorts' selections differ
fun differing [a, b: Cohort] : set Dim {
  { dm: Dim | a.sel[dm] != b.sel[dm] }
}

// the simulatable bound: the published marginals of the values selected by
// exactly one of the cohorts, summed over every differing dimension
fun dimBound [a, b: Cohort, dm: Dim] : Int {
  sum v: (a.sel[dm] - b.sel[dm]) + (b.sel[dm] - a.sel[dm]) | marginal[v]
}
fun simBound [a, b: Cohort] : Int {
  sum dm: differing[a, b] | dimBound[a, b, dm]
}

// --- the auditor rule as implemented ----------------------------------------

// service._difference_bound: the cheap marginal leg decides where it can, the
// exact row-level leg decides where it cannot, and either denying is a denial —
// so the effective bound is the smaller of the two.
fun effectiveBound [a, b: Cohort] : Int {
  simBound[a, b] < rowSymdiffDonors[a, b] implies simBound[a, b]
                                          else rowSymdiffDonors[a, b]
}

// The guard is `d < threshold`, NOT `0 < d < threshold`. A difference of
// exactly zero denies too: identical cohorts are skipped before this, so the
// only pairs reaching a zero are ones whose predicates DIFFER while selecting
// the same rows — which is a sub-threshold existence fact of its own.
pred auditorAllows [a, b: Cohort] {
  a.sel = b.sel or effectiveBound[a, b] >= 3
}

// The pre-#40 rule, kept so the attack it admitted can be exhibited. TWO
// things were wrong with it and the attack needed both: the universe was
// donors rather than rows, and the guard was `0 < d and d < T`, so a
// difference of exactly ZERO passed. That is where the `age >= 58` / `age >=
// 59` absence proof and the NULL-desync single-donor recovery both landed.
pred donorOnlyAuditorAllows [a, b: Cohort] {
  a.sel = b.sel or
    let d = (simBound[a, b] < donorSymdiff[a, b] implies simBound[a, b]
                                                  else donorSymdiff[a, b]) |
      not (d > 0 and d < 3)
}

// a Release is a query the auditor let through this session
sig Release { cohort: one Cohort }
fact SessionReleasesPassAuditor {
  all disj r1, r2: Release | auditorAllows[r1.cohort, r2.cohort]
}

// --- checked properties -------------------------------------------------------

// A donor in exactly one of two cohorts satisfies one and violates the other,
// so on at least one dimension they hold a value selected by exactly one of
// them, and that value's whole-population marginal counts them. Summing over
// the differing dimensions therefore dominates the true symmetric difference
// (denials are sound); donors failing on several dimensions are counted
// several times, which only makes the bound larger.
assert MarginalBoundSound {
  all a, b: Cohort | donorSymdiff[a, b] <= simBound[a, b]
}
check MarginalBoundSound for 2 Dim, 4 Val, 4 Donor, 5 Row, 2 Cohort, 0 Release, 6 Int

// The canonical attack — isolate globally-rare categories by adding or
// removing predicates — cannot survive: any auditor-passing pair has identical
// member sets or a bound of at least T, on however many dimensions it differs.
// The `one differing` guard is deliberately absent: with it, this held while
// two rare exclusions in one step walked through.
assert RareCategoryIsolationBlocked {
  all disj r1, r2: Release | let a = r1.cohort, b = r2.cohort |
    donorSymdiff[a, b] = 0 or simBound[a, b] >= 3
}
check RareCategoryIsolationBlocked
  for 2 Dim, 4 Val, 4 Donor, 5 Row, 3 Cohort, 3 Release, 6 Int

// hardening #40: whatever the donor sets look like, two releases differ over at
// least T people AT ROW LEVEL. This is the property the donor-only model could
// not even state.
assert RowDifferenceAlwaysBounded {
  all disj r1, r2: Release | let a = r1.cohort, b = r2.cohort |
    a.sel = b.sel or rowSymdiffDonors[a, b] >= 3
}
check RowDifferenceAlwaysBounded
  for 2 Dim, 4 Val, 4 Donor, 5 Row, 3 Cohort, 3 Release, 6 Int

// The new layer SUBSUMES the old one rather than trading it away: on cohorts
// that differ only over donor-level dimensions, the exact row-level count is
// exactly the donor symmetric difference. (A donor whose rows all fail the
// shared row-level selection is in neither donor set, so neither side counts
// them.)
assert RowLayerSubsumesDonorLayer {
  all a, b: Cohort |
    (differing[a, b] in DonorDim) implies
      rowSymdiffDonors[a, b] = donorSymdiff[a, b]
}
check RowLayerSubsumesDonorLayer
  for 2 Dim, 4 Val, 4 Donor, 5 Row, 2 Cohort, 0 Release, 6 Int

// --- documented residuals (expected satisfiable) ------------------------------

pred someSession {
  #Release = 2
  some rows[Release.cohort]
  some disj r1, r2: Release | r1.cohort.sel != r2.cohort.sel
}
run someSession for 2 Dim, 4 Val, 4 Donor, 5 Row, 2 Cohort, 2 Release, 6 Int

// the interaction residual: a large marginal hides a small true difference
// (e.g. the over-50s within one small region). The MARGINAL layer alone would
// allow this pair — which is what made it a residual — and it is now the
// reason the exact leg exists rather than an open gap. Stated over cohorts,
// not releases, precisely because the released pair can no longer occur.
pred InteractionResidualExists {
  some disj a, b: Cohort {
    simBound[a, b] >= 3
    donorSymdiff[a, b] > 0
    donorSymdiff[a, b] < 3
  }
}
run InteractionResidualExists for 2 Dim, 4 Val, 4 Donor, 5 Row, 2 Cohort, 0 Release, 6 Int

// #40, machine-exhibited: drop the row layer and two cohorts holding exactly
// the same PEOPLE over different ROWS are both released. `age_rating >= 7` and
// `age_rating >= 8` over the same region and sex is the live instance.
pred Hardening40AttackWithoutRowLayer {
  some disj a, b: Cohort {
    a.sel != b.sel
    donorSymdiff[a, b] = 0                 // the same people, exactly
    rowSymdiffDonors[a, b] > 0             // over different rows
    rowSymdiffDonors[a, b] < 3             // by fewer than T donors
    donorOnlyAuditorAllows[a, b]           // and the pre-#40 auditor allows it
  }
}
run Hardening40AttackWithoutRowLayer
  for 2 Dim, 4 Val, 4 Donor, 5 Row, 2 Cohort, 0 Release, 6 Int

// V13: `service._donor_total` sums the per-cell donor counts, so a donor with
// rows in several cells of the group-by is counted once per cell. The cheap
// total-delta layer is therefore weaker than its docstring implies for
// multi-cell donors — best-effort, with the lineage layer as the real control.
fun cellDonorSum [c: Cohort, dm: Dim] : Int {
  sum v: dm.~dim | #({ r: rows[c] | r.attr[dm] = v }.donor)
}
pred V13DonorTotalOvercounts {
  some c: Cohort, dm: RowDim | cellDonorSum[c, dm] > #donors[c]
}
run V13DonorTotalOvercounts for 2 Dim, 4 Val, 4 Donor, 5 Row, 1 Cohort, 0 Release, 6 Int

// V8: the exact leg's denial is not simulatable. The published marginals put
// these cohorts at least T apart — nothing public says they are close — and the
// exact row-level count denies anyway. That one bit is about live data by
// construction, and the direct query that would "already return" it is
// suppressed, so the analyst does not otherwise hold it.
pred V8ExactLegIsNotSimulatable {
  some disj a, b: Cohort {
    a.sel != b.sel
    simBound[a, b] >= 3
    rowSymdiffDonors[a, b] < 3
  }
}
run V8ExactLegIsNotSimulatable
  for 2 Dim, 4 Val, 4 Donor, 5 Row, 2 Cohort, 0 Release, 6 Int
