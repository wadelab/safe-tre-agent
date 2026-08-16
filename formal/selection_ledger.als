// selection_ledger — a bounded model of the phase-3 SELECTION CHANNEL
// (spec R20/P24; safetre/plan.py::PlanExecutor._apply_contingency,
// safetre/disclosure.py::SessionAuditor.charge_selection, config
// selection_budget_bits). The differencing lineage already has its model
// (disclosure_policy.als); this puts the one NEW disclosure channel the
// inside analyst's data-sighted tier opens on the same footing.
//
// What is modelled. One `Fact` is one bit of WITHHELD cohort structure: "this
// level of this dimension is below the frequency threshold in this cohort" —
// the thing the gateway hides, because the canonical refusal is a
// cohort-structure oracle (hardening #30, #66). Learning a Fact is the
// data-sighted disclosure a locked plan's `exclude_sparse` contingency makes,
// and the only such disclosure the analyst is allowed. The round-8
// existence-oracle attack recovered a unique donor with EIGHT such bits, which
// is why the budget default is 4.
//
// What is checked (counterexample = CI failure):
//   ChannelBounded  — however a plan is shaped, one session cannot LEARN more
//                     bits of withheld structure than its budget. This is the
//                     P24 guarantee: the interim, counted bound the
//                     differential-privacy accountant later replaces.
//
// What is SEARCHED FOR and must EXIST (unsatisfiable = CI failure):
//   someLedger              — a session where the budget is reached and a later
//                             probe is therefore refused, so the check is not
//                             vacuously true;
//   UnboundedWithoutLedger  — the attack the ledger prevents: WITHOUT it, a
//                             session charges every probe and learns more bits
//                             than the budget allows (test_plans.py::
//                             test_the_selection_channel_is_bounded_across_a_session
//                             is the executable twin);
//   BenignSessionAllowed    — a within-budget session is allowed, so the bound
//                             does not over-deny.

module selection_ledger

open util/ordering[Stage]

sig Fact {}

// The per-session budget (config.selection_budget_bits). A PARAMETER, not a
// constant (recommendation F5): the property is checked for every admissible
// value the bounded search exercises, so it is threshold-generic, not proved
// for one dial setting.
one sig Params { Budget: Int }
fact AdmissibleBudget { Params.Budget >= 0 and Params.Budget <= 4 }
fun Budget: one Int { Params.Budget }

// The stages of a locked plan, in execution order (util/ordering). `probe` is
// the set of Facts a stage's exclude_sparse contingency would reveal — empty
// for a stage that declares no contingency. A stage is either CHARGED — it
// paid |probe| bits and revealed them — or refused, having paid nothing and
// revealed nothing.
sig Stage { probe: set Fact }
sig Charged in Stage {}

// Bits already spent when a stage runs: the sum of |probe| over EARLIER CHARGED
// stages. A refused stage spends nothing — PlanExecutor._apply_contingency
// returns before charging when the ledger cannot afford the probe.
fun spentBefore [x: Stage]: Int { sum e: (Charged & prevs[x]) | #e.probe }

// The ledger discipline the executor enforces: a stage is charged exactly when
// its probe is affordable at its turn. A predicate, not a fact, so the model
// can also exhibit a session WITHOUT it (the attack).
pred Ledger {
  all s: Stage | s in Charged iff spentBefore[s].plus[#s.probe] <= Budget
}

// The facts a session actually LEARNS: the union of probes over charged stages.
// A refused stage's probe is never in it — its levels were not disclosed.
fun learned: set Fact { Charged.probe }

// -- the property (P24) -------------------------------------------------------
// distinct(learned) <= sum over charged of |probe| = the final spend <= Budget,
// by the charging rule; so no plan, however shaped, extracts more bits of
// withheld cohort structure than the budget.
assert ChannelBounded {
  Ledger implies #learned <= Budget
}
check ChannelBounded for 6 Fact, 4 Stage, 6 Int

// -- inhabitation and the attack ----------------------------------------------

pred someLedger {
  Ledger
  some Charged
  some (Stage - Charged)      // a real refusal happened
  #learned = Budget           // and the budget was reached
}
run someLedger for 6 Fact, 4 Stage, 6 Int

pred UnboundedWithoutLedger {
  not Ledger
  Charged = Stage             // an unmetered analyst charges every probe
  #learned > Budget           // and learns more bits than the budget allows
}
run UnboundedWithoutLedger for 6 Fact, 4 Stage, 6 Int

pred BenignSessionAllowed {
  Ledger
  Charged = Stage             // nothing refused
  some learned
  #learned <= Budget          // because the session stayed within budget
}
run BenignSessionAllowed for 6 Fact, 4 Stage, 6 Int
