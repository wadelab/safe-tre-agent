// temporal_session — a bounded temporal model of the session auditor's
// observe → apply → record ordering and the query budget (roadmap item 2,
// third slice; FORMAL_METHODS_ANALYSIS §2.D).
//
// What is modelled: one session, requests as atoms stepping through the
// phases of QueryService.handle / _handle_model
// (safetre/service.py):
//
//   Idle -> Started    the affordability precheck at entry — handle's
//                      over_budget() short-circuit and _handle_model's
//                      spent + len(aggregates) > budget precheck, which for
//                      cost k coincide as spent + k <= Budget; an
//                      unaffordable request is Denied with NO engine work
//   Started -> Observed  engine.run has happened; SessionAuditor.observe
//                      increments spent unconditionally (once per underlying
//                      aggregate, abstracted to one step of size cost) and
//                      flags the request if the increment passes the budget
//   Observed -> Checked  observe_cohort compares the request's cohort with
//                      every cohort recorded so far; a distinct near cohort
//                      flags the request (identical cohorts are skipped,
//                      exactly as prev_filters == filters is)
//   Checked -> Released | Denied   the fail-closed gate: release only a
//                      gateway release/redacted with no auditor flag, and
//                      record_cohort in the same critical section — a denial
//                      records nothing
//
// `near` abstracts observe_cohort's "0 < bound < threshold" on two cohorts'
// symmetric difference (the bound itself is modelled in
// disclosure_policy.als); the budget is abstracted to 3 (the code's 20),
// same discipline as that model's threshold. The per-Session lock the web
// shell holds across the whole critical section (safetre_web/session.py,
// app.py; hardening #18) is NOT a fact here: it is the explicit `Serialized`
// assumption of the properties that need it, so dropping it is expressible.
//
// What is checked (counterexample = CI failure):
//   P17_SpentMonotone            — spent never decreases;
//   P17_BudgetInvariantUnderLock — with the lock held, the two entry
//                                  prechecks keep spent <= Budget forever;
//   P17_ExhaustionShortCircuits  — once spent reaches the budget, no request
//                                  ever starts again (no engine work after
//                                  exhaustion; hardening #24) — with or
//                                  without the lock;
//   P16_DifferencingPairNeverBothReleased — with the lock held, the two
//                                  halves of a differencing pair cannot both
//                                  be released: the first records its
//                                  cohort, so the second is flagged and the
//                                  gate denies it;
//   P7_GateFailsClosed           — under ANY interleaving a flagged request,
//                                  an explicit deny, or an unrecognised
//                                  gateway action never releases;
//   LineageIsExactlyReleases     — at every instant the auditor's cohort
//                                  history is exactly the released cohorts.
//
// What is SEARCHED FOR and expected to EXIST (unsatisfiable = CI failure):
//   someTemporalSession          — a serialized session with a release and a
//                                  denial is reachable (the checks above are
//                                  not vacuous);
//   Hardening18RaceWithoutLock   — drop the lock and the TOCTOU returns:
//                                  both halves of a differencing pair pass
//                                  observe_cohort before either records, and
//                                  both release. The machine-checked reason
//                                  the lock is a security control, not a
//                                  performance choice.

module temporal_session

// a cohort = the normalized filter predicate of a request; `near` holds when
// the simulatable bound on the pair's symmetric difference is positive and
// below the differencing threshold — symmetric, and irreflexive because an
// identical cohort is skipped, not flagged
sig Cohort { near: set Cohort }
fact NearSymmetricIrreflexive { near = ~near and no iden & near }

enum Phase { Idle, Started, Observed, Checked, Released, Denied }

// the gateway's verdict for the request, decided outside the auditor
// (nondeterministic here): release, redacted, deny, or an action the service
// does not recognise
enum Action { ActRelease, ActRedact, ActDeny, ActUnknown }

fun Budget: one Int { 3 }

sig Request {
  cohort: one Cohort,
  cost: one Int,       // 1 = plain aggregate; 2 = model (its planned aggregates)
  action: one Action,
  var phase: one Phase,
}
fact CostShape { all r: Request | r.cost = 1 or r.cost = 2 }

// requests the auditor has flagged (query_budget overrun or differencing);
// the fail-closed gate denies any member
var sig Flagged in Request {}

one sig Auditor {
  var spent: one Int,
  var cohorts: set Cohort,
}

fact Init {
  all r: Request | r.phase = Idle
  Auditor.spent = 0
  no Auditor.cohorts
  no Flagged
}

// --- events -------------------------------------------------------------------

pred framePhases [moved: Request] {
  all q: Request - moved | q.phase' = q.phase
}

// the entry precheck: handle() denies when over_budget() before any planner
// or engine work; _handle_model denies when spent + len(aggregates) > budget
pred affordable [r: Request] { Auditor.spent.plus[r.cost] <= Budget }

pred start [r: Request] {
  r.phase = Idle
  affordable[r] implies r.phase' = Started else r.phase' = Denied
  Auditor.spent' = Auditor.spent
  Auditor.cohorts' = Auditor.cohorts
  Flagged' = Flagged
  framePhases[r]
}

// SessionAuditor.observe: the spend increments unconditionally; an increment
// that passes the budget adds the query_budget finding (spent > budget)
pred observe [r: Request] {
  r.phase = Started
  r.phase' = Observed
  Auditor.spent' = Auditor.spent.plus[r.cost]
  Auditor.spent' > Budget implies Flagged' = Flagged + r else Flagged' = Flagged
  Auditor.cohorts' = Auditor.cohorts
  framePhases[r]
}

// SessionAuditor.observe_cohort: a recorded cohort that is distinct and near
// flags the request; the history consulted is whatever is recorded NOW —
// this timing is the whole point of the model
pred cohortCheck [r: Request] {
  r.phase = Observed
  r.phase' = Checked
  (some Auditor.cohorts & r.cohort.near) implies Flagged' = Flagged + r
                                         else Flagged' = Flagged
  Auditor.spent' = Auditor.spent
  Auditor.cohorts' = Auditor.cohorts
  framePhases[r]
}

// the fail-closed gate and record_cohort, one critical step: "any auditor
// flag, an explicit deny, or an unrecognised action withholds all data";
// only an actual release records its cohort
pred decide [r: Request] {
  r.phase = Checked
  (r.action in ActRelease + ActRedact and r not in Flagged) implies {
    r.phase' = Released
    Auditor.cohorts' = Auditor.cohorts + r.cohort
  } else {
    r.phase' = Denied
    Auditor.cohorts' = Auditor.cohorts
  }
  Auditor.spent' = Auditor.spent
  Flagged' = Flagged
  framePhases[r]
}

pred stutter {
  phase' = phase
  Auditor.spent' = Auditor.spent
  Auditor.cohorts' = Auditor.cohorts
  Flagged' = Flagged
}

fact Traces {
  always (stutter or some r: Request |
    start[r] or observe[r] or cohortCheck[r] or decide[r])
}

// the per-Session lock as an explicit environment assumption: at most one
// request inside the critical section at any instant (the web shell holds it
// across observe -> apply -> record; hardening #18)
pred Serialized { lone r: Request | r.phase in Started + Observed + Checked }

// --- checked properties -------------------------------------------------------

assert P17_SpentMonotone { always Auditor.spent' >= Auditor.spent }
check P17_SpentMonotone for exactly 3 Request, 3 Cohort, 4 Int, 10 steps

assert P17_BudgetInvariantUnderLock {
  (always Serialized) implies always Auditor.spent <= Budget
}
check P17_BudgetInvariantUnderLock for exactly 3 Request, 3 Cohort, 4 Int, 10 steps

// spent never decreases, so exhaustion is absorbing and the entry precheck
// denies every later request before engine work — no lock needed
assert P17_ExhaustionShortCircuits {
  always (Auditor.spent >= Budget implies
    always no r: Request | r.phase = Idle and r.phase' = Started)
}
check P17_ExhaustionShortCircuits for exactly 3 Request, 3 Cohort, 4 Int, 10 steps

assert P16_DifferencingPairNeverBothReleased {
  (always Serialized) implies
    always no disj r1, r2: Request |
      r1.phase = Released and r2.phase = Released and r2.cohort in r1.cohort.near
}
check P16_DifferencingPairNeverBothReleased
  for exactly 3 Request, 3 Cohort, 4 Int, 12 steps

assert P7_GateFailsClosed {
  always all r: Request | r.phase = Released implies
    (r.action in ActRelease + ActRedact and r not in Flagged)
}
check P7_GateFailsClosed for exactly 3 Request, 3 Cohort, 4 Int, 10 steps

assert LineageIsExactlyReleases {
  always Auditor.cohorts = (phase.Released).cohort
}
check LineageIsExactlyReleases for exactly 3 Request, 3 Cohort, 4 Int, 10 steps

// --- inhabitation and the machine-exhibited race ------------------------------

pred someTemporalSession {
  always Serialized
  eventually some r: Request | r.phase = Released
  eventually some r: Request | r.phase = Denied
}
run someTemporalSession for exactly 3 Request, 3 Cohort, 4 Int, 10 steps

pred Hardening18RaceWithoutLock {
  not always Serialized
  eventually some disj r1, r2: Request |
    r1.phase = Released and r2.phase = Released and r2.cohort in r1.cohort.near
}
run Hardening18RaceWithoutLock for exactly 2 Request, 2 Cohort, 4 Int, 12 steps
