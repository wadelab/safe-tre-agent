// disclosure_policy — a bounded model of the session auditor's cohort-lineage
// rule (roadmap item 2, second slice; FORMAL_METHODS_ANALYSIS §2.D).
//
// What is modelled: cohorts as per-dimension value selections over a donor
// population (the normalized filter predicate of a released QuerySpec), the
// true symmetric difference between two cohorts, and the SIMULATABLE upper
// bound the auditor actually decides from — the whole-population donor
// marginal of the differing values when exactly one dimension differs, and
// the never-denying sentinel otherwise
// (safetre/disclosure.py::simulatable_cohort_bound, SessionAuditor.observe_cohort).
//
// The threshold is abstracted to 3 (the code's 10): the properties are
// threshold-generic, and a small constant keeps the bounded search exact.
//
// What is checked (counterexample = CI failure):
//   MarginalBoundSound          — the docstring's soundness claim: on a
//                                 single differing dimension the marginal
//                                 bound really is an upper bound on the true
//                                 symmetric difference;
//   RareCategoryIsolationBlocked — the canonical differencing attack
//                                 (adding/removing a globally-rare category,
//                                 e.g. "exclude sex X") cannot survive the
//                                 auditor: a surviving single-dimension pair
//                                 has identical cohorts or a bound >= T.
//
// What is SEARCHED FOR and expected to EXIST (unsatisfiable = CI failure,
// because the model would then contradict the code's own documentation):
//   someSession                 — the modelled space is inhabited;
//   InteractionResidualExists   — a pair the auditor allows (bound >= T)
//                                 whose true symmetric difference is small:
//                                 the documented price of simulatability;
//   MultiDimSentinelResidual    — a small-difference pair on >= 2 dimensions
//                                 slips past the sentinel: the documented
//                                 reliance on per-cell thresholds and budget.
//
// These two runs are the machine-checked form of the residual-risk paragraph
// in simulatable_cohort_bound's docstring: the gaps are real, bounded, and
// covered by the per-cell donor threshold and the DP roadmap item — not
// silently absent from the model.

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

// the simulatable bound on a single differing dimension: the sum of the
// published marginals of the values selected by exactly one of the cohorts
fun simBound [a, b: Cohort, dm: Dim] : Int {
  sum v: (a.sel[dm] - b.sel[dm]) + (b.sel[dm] - a.sel[dm]) | marginal[v]
}

// --- the auditor rule as implemented ----------------------------------------

// deny iff the cohorts differ on exactly one dimension and the simulatable
// bound is nonzero and below threshold; >1 differing dimension returns the
// ALLOW sentinel (never denies)
pred simulatableAuditorAllows [a, b: Cohort] {
  one differing[a, b] implies
    not (simBound[a, b, differing[a, b]] > 0 and
         simBound[a, b, differing[a, b]] < 3)
}

// a Release is a query the auditor let through this session
sig Release { cohort: one Cohort }
fact SessionReleasesPassAuditor {
  all disj r1, r2: Release | simulatableAuditorAllows[r1.cohort, r2.cohort]
}

// --- checked properties -------------------------------------------------------

// A donor in exactly one of two cohorts that agree on every other dimension
// must hold a differing value on the one differing dimension, so it is
// counted by that value's whole-population marginal: the simulatable bound
// dominates the true symmetric difference (denials are sound).
assert MarginalBoundSound {
  all a, b: Cohort | one differing[a, b] implies
    symdiff[a, b] <= simBound[a, b, differing[a, b]]
}
check MarginalBoundSound for 3 Dim, 6 Val, 6 Donor, 2 Cohort, 0 Release, 6 Int

// The canonical attack — isolate a globally-rare category by adding or
// removing one predicate — cannot survive: any auditor-passing pair on one
// differing dimension has identical member sets or a bound of at least T.
assert RareCategoryIsolationBlocked {
  all disj r1, r2: Release | let a = r1.cohort, b = r2.cohort |
    one differing[a, b] implies
      (symdiff[a, b] = 0 or simBound[a, b, differing[a, b]] >= 3)
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
    one differing[a, b]
    simBound[a, b, differing[a, b]] >= 3
    symdiff[a, b] > 0 and symdiff[a, b] < 3
  }
}
run InteractionResidualExists for 2 Dim, 4 Val, 6 Donor, 2 Cohort, 2 Release, 6 Int

// the sentinel residual: cohorts differing on two dimensions are never
// denied by this rule, whatever their true symmetric difference
pred MultiDimSentinelResidual {
  some disj r1, r2: Release | let a = r1.cohort, b = r2.cohort {
    #differing[a, b] = 2
    symdiff[a, b] = 1
  }
}
run MultiDimSentinelResidual for 2 Dim, 4 Val, 6 Donor, 2 Cohort, 2 Release, 6 Int
