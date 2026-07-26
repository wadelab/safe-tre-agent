// disclosure_policy — a bounded model of the session auditor's cohort-lineage
// rule (roadmap item 2, second slice; FORMAL_METHODS_ANALYSIS §2.D).
//
// What is modelled: cohorts as per-dimension value selections over a donor
// population (the normalized filter predicate of a released QuerySpec), the
// true symmetric difference between two cohorts, and the SIMULATABLE upper
// bound the auditor actually decides from — the whole-population donor
// marginal of the values selected by exactly one cohort, summed over every
// dimension on which the two selections differ
// (safetre/disclosure.py::simulatable_cohort_bound, SessionAuditor.observe_cohort).
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
//                                 (adding/removing globally-rare categories,
//                                 e.g. "exclude sex X", or "exclude sex X AND
//                                 age 50") cannot survive the auditor: a
//                                 surviving pair has identical cohorts or a
//                                 bound >= T, however many dimensions differ.
//
// What is SEARCHED FOR and expected to EXIST (unsatisfiable = CI failure,
// because the model would then contradict the code's own documentation):
//   someSession                 — the modelled space is inhabited;
//   InteractionResidualExists   — a pair the auditor allows (bound >= T)
//                                 whose true symmetric difference is small:
//                                 the documented price of simulatability.
//
// That run is the machine-checked form of the residual-risk paragraph in
// simulatable_cohort_bound's docstring: the gap is real, bounded, and covered
// by the per-cell donor threshold and the DP roadmap item — not silently
// absent from the model.
//
// A second residual used to be exhibited here — MultiDimSentinelResidual, a
// small-difference pair on two dimensions slipping past the never-denying
// sentinel. It is gone because the sentinel is gone: the bound now sums over
// every differing dimension, so RareCategoryIsolationBlocked covers the
// multi-dimension case that run demonstrated. A red-team pass turned that
// documented residual into a two-query bypass, which is the argument for
// closing a gap rather than exhibiting it.

module disclosure_policy

sig Dim {}
sig Val { dim: one Dim }
sig Donor { attr: Dim -> one Val }

// every donor's attribute value lies in its dimension
fact AttrWellTyped { all d: Donor, dm: Dim | d.attr[dm].dim = dm }

// a cohort selects, per dimension, the set of admitted values
// (a dimension with every value selected is unconstrained)
sig Cohort { sel: Dim -> set Val }
fact SelWellTyped { all c: Cohort, dm: Dim, v: c.sel[dm] | v.dim = dm }

fun members [c: Cohort] : set Donor {
  { d: Donor | all dm: Dim | d.attr[dm] in c.sel[dm] }
}

fun symdiff [a, b: Cohort] : Int {
  (#(members[a] - members[b])).plus[#(members[b] - members[a])]
}

// whole-population donor marginal of one value (engine.marginal_donor_counts)
fun marginal [v: Val] : Int { #{ d: Donor | d.attr[v.dim] = v } }

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

// deny iff the simulatable bound is nonzero and below threshold, whatever the
// number of differing dimensions
pred simulatableAuditorAllows [a, b: Cohort] {
  not (simBound[a, b] > 0 and simBound[a, b] < 3)
}

// a Release is a query the auditor let through this session
sig Release { cohort: one Cohort }
fact SessionReleasesPassAuditor {
  all disj r1, r2: Release | simulatableAuditorAllows[r1.cohort, r2.cohort]
}

// --- checked properties -------------------------------------------------------

// A donor in exactly one of two cohorts satisfies one and violates the other,
// so on at least one dimension they hold a value selected by exactly one of
// them, and that value's whole-population marginal counts them. Summing over
// the differing dimensions therefore dominates the true symmetric difference
// (denials are sound); donors failing on several dimensions are counted
// several times, which only makes the bound larger.
assert MarginalBoundSound {
  all a, b: Cohort | symdiff[a, b] <= simBound[a, b]
}
check MarginalBoundSound for 3 Dim, 6 Val, 6 Donor, 2 Cohort, 0 Release, 6 Int

// The canonical attack — isolate globally-rare categories by adding or
// removing predicates — cannot survive: any auditor-passing pair has identical
// member sets or a bound of at least T, on however many dimensions it differs.
// The `one differing` guard is deliberately absent: with it, this held while
// two rare exclusions in one step walked through.
assert RareCategoryIsolationBlocked {
  all disj r1, r2: Release | let a = r1.cohort, b = r2.cohort |
    symdiff[a, b] = 0 or simBound[a, b] >= 3
}
check RareCategoryIsolationBlocked for 3 Dim, 6 Val, 6 Donor, 4 Cohort, 4 Release, 6 Int

// --- documented residuals (expected satisfiable) ------------------------------

pred someSession {
  #Release = 2
  some members[Release.cohort]
  some disj r1, r2: Release | r1.cohort != r2.cohort
}
run someSession for 3 Dim, 6 Val, 6 Donor, 2 Cohort, 2 Release, 6 Int

// the interaction residual: a large marginal hides a small true difference
// (e.g. the over-50s within one small region) — allowed, yet symdiff < T
pred InteractionResidualExists {
  some disj r1, r2: Release | let a = r1.cohort, b = r2.cohort {
    simBound[a, b] >= 3
    symdiff[a, b] > 0 and symdiff[a, b] < 3
  }
}
run InteractionResidualExists for 2 Dim, 4 Val, 6 Donor, 2 Cohort, 2 Release, 6 Int
