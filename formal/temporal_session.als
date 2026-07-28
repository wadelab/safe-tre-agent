// temporal_session — a bounded temporal model of the session auditor's
// observe → apply → record ordering, the query budget, and the RESTART path
// (roadmap item 2, third slice; FORMAL_METHODS_ANALYSIS §2.D).
//
// What is modelled: one identity's session, requests as atoms stepping through
// the phases of QueryService.handle / _handle_model (safetre/service.py), and
// the reconstruction SessionStore.rehydrate performs after a restart
// (safetre_web/session.py):
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
//   Observed -> Checked  observe_cohort compares the request's cohorts with
//                      every cohort recorded so far; a distinct near cohort
//                      flags the request (identical cohorts are skipped,
//                      exactly as prev_filters == filters is)
//   Checked -> Released | Denied   the fail-closed gate: release only a
//                      gateway release/redacted with no auditor flag, and
//                      record_cohort in the same critical section — a denial
//                      records nothing
//   * -> Errored       the audited exception boundary (handle's except): the
//                      request is recorded and, since hardening #60, CHARGED —
//                      it used to be free, so a failing query was the cheapest
//                      way to use the system
//
// ARITY, declared (the round-9 lesson). Every relation between a request and
// what it costs or touches is a checked cardinality, not an assumption:
//
//   request : cost     1..2  — a plain aggregate spends 1; a model spends one
//                              per PLANNED aggregate (glm.plan_aggregates)
//   request : cohorts  1..2  — a model releases over one cohort per aggregate,
//                              and a binomial's successes cohort carries the
//                              `response == True` filter the PROCEDURE adds,
//                              which the analyst never wrote. The earlier
//                              version of this model wrote `cohort: one
//                              Cohort` and so could not express V2 at all: the
//                              assumption sat where the property should have.
//   #cohorts <= cost          — a gaussian GLM plans two aggregates over ONE
//                              cohort (mean and sum-of-squares tables share
//                              the analyst's filters)
//
// THE LOG IS AN INPUT. Before hardening #49 the audit log was an output — a
// tamper-evident record. After it, budget and lineage are rebuilt from it at
// startup, so it is upstream of two controls, and nothing modelled that change
// of role. Here it is explicit: `Recorded` is the log, `Deleted` is an
// attacker with write access (deleting a row needs no key), `Replay.mode`
// selects authoritative accounting (#58) or the per-record heuristic it
// replaced, and `Deployment.gate` is the verify-before-replay gate (#59).
// Each is an assumption that can be DROPPED, and each dropped assumption has a
// satisfiable run exhibiting the attack it prevents — the discipline the lock
// established in `Hardening18RaceWithoutLock`.
//
// `near` abstracts observe_cohort's "bound < threshold" on two cohorts'
// symmetric difference (the bound itself is modelled in
// disclosure_policy.als); the budget is abstracted to 3 (the code's 20), same
// discipline as that model's threshold. The per-Session lock the web shell
// holds across the whole critical section (safetre_web/session.py, app.py;
// hardening #18) is NOT a fact here: it is the explicit `Serialized`
// assumption of the properties that need it, so dropping it is expressible.
//
// What is checked (counterexample = CI failure):
//   P17_SpentMonotone            — spent never decreases WITHIN a process;
//   P17_BudgetInvariantUnderLock — with the lock held, the two entry
//                                  prechecks keep spent <= Budget forever;
//   P17_ExhaustionShortCircuits  — once spent reaches the budget, no request
//                                  ever starts again (no engine work after
//                                  exhaustion; hardening #24);
//   P16_DifferencingPairNeverBothReleased — with the lock held, the two
//                                  halves of a differencing pair cannot both
//                                  be released, ACROSS RESTARTS included;
//   P7_GateFailsClosed           — under ANY interleaving a flagged request,
//                                  an explicit deny, or an unrecognised
//                                  gateway action never releases;
//   LineageIsExactlyReleases     — at every instant the auditor's cohort
//                                  history is exactly the released cohorts
//                                  (now a property over SETS of cohorts, which
//                                  is what made it a check rather than an
//                                  assumption);
//   ReplayEquivalence            — a restart does not change the controls:
//                                  replayed spend and lineage equal live
//                                  spend and lineage (V1, V2, V4);
//   AuditCompleteness            — every request that reaches a terminal
//                                  phase, exceptions included, is in the log
//                                  (hardening #37);
//   PolicyPrecedesEveryRecord    — the config record is in the chain before
//                                  any request row, so a release is
//                                  attributable to a policy (hardening #55).
//
// What is SEARCHED FOR and expected to EXIST (unsatisfiable = CI failure):
//   someTemporalSession          — a serialized session with a release and a
//                                  denial is reachable (the checks above are
//                                  not vacuous);
//   someRestartedSession         — a session that restarts and keeps serving
//                                  is reachable (the restart path is not
//                                  vacuously disabled);
//   Hardening18RaceWithoutLock   — drop the lock and the TOCTOU returns:
//                                  both halves of a differencing pair pass
//                                  observe_cohort before either records, and
//                                  both release;
//   V1BudgetRefundedOnRestart    — drop authoritative accounting and a model's
//                                  spend comes back smaller after a restart:
//                                  the budget refund round 9 measured;
//   V2CohortLostOnRestart        — drop it and a released cohort is missing
//                                  after a restart: the binomial successes
//                                  cohort, which the model spec cannot express;
//   V3DeletionDefeatsLineage     — drop the verify gate and a DELETED row (no
//                                  forged MAC, just write access) removes a
//                                  cohort from the rebuilt lineage.

module temporal_session

// a cohort = the normalized filter predicate of a released aggregate; `near`
// holds when the bound on the pair's symmetric difference is below the
// differencing threshold — symmetric, and irreflexive because an identical
// cohort is skipped, not flagged
sig Cohort { near: set Cohort }
fact NearSymmetricIrreflexive { near = ~near and no iden & near }

enum Phase { Idle, Started, Observed, Checked, Released, Denied, Errored }

// the gateway's verdict for the request, decided outside the auditor
// (nondeterministic here): release, redacted, deny, or an action the service
// does not recognise
enum Action { ActRelease, ActRedact, ActDeny, ActUnknown }

// how a restart rebuilds the session. Authoritative = the audit row carries
// what the request cost and which cohorts it released over (#58); Heuristic =
// the replaced code, which inferred one unit per record and re-derived the
// cohort by re-reading the model spec.
enum Accounting { Authoritative, Heuristic }
one sig Replay { mode: one Accounting }

// whether rehydration verifies the chain before replaying it (#59)
enum Gate { GateOn, GateOff }
one sig Deployment { gate: one Gate }

fun Budget: one Int { 3 }

sig Request {
  cost: one Int,           // planned aggregates: 1 = plain, 2 = model
  cohorts: some Cohort,    // the cohorts a release records — 1:N, not 1:1
  base: one Cohort,        // the cohort re-derivable from the request's SPEC
  action: one Action,
  var phase: one Phase,
}

// What a request has been charged, as SET membership rather than a per-request
// integer field: `Engaged` passed observe and paid `cost`, `ErrCharged` raised
// before observe and paid the flat unit hardening #60 introduced. Membership
// is enormously cheaper for the solver than an Int-valued var relation, and
// the two carry exactly the same information.
var sig Engaged in Request {}
var sig ErrCharged in Request {}

fun spentOf [r: Request]: one Int {
  r in Engaged implies r.cost else (r in ErrCharged implies 1 else 0)
}

fact ArityShape {
  all r: Request {
    r.cost = 1 or r.cost = 2
    #r.cohorts <= r.cost           // two aggregates may share one cohort
    r.base in r.cohorts            // the spec's own filters are one of them
  }
}

// requests the auditor has flagged (query_budget overrun or differencing);
// the fail-closed gate denies any member
var sig Flagged in Request {}

// the audit log: a request lands in `Recorded` when its row is appended, and
// in `Deleted` when an attacker with write access removes that row
var sig Recorded in Request {}
var sig Deleted in Request {}

// the chain carries the startup policy record (#55)
one sig Chain {}
var sig PolicyLogged in Chain {}

one sig Auditor {
  var spent: one Int,
  var cohorts: set Cohort,
}

fact Init {
  all r: Request | r.phase = Idle
  no Engaged
  no ErrCharged
  Auditor.spent = 0
  no Auditor.cohorts
  no Flagged
  no Recorded
  no Deleted
  no PolicyLogged
}

// --- the log, read back -------------------------------------------------------

// rows that survive to be replayed
fun liveRows: set Request { Recorded - Deleted }

// what a row says the request cost. Authoritative: what it was actually
// charged. Heuristic: one unit per row that reached the engine — the replaced
// code, and the reason a two-aggregate model came back charged 1.
fun recCost [r: Request]: one Int {
  Replay.mode = Authoritative implies spentOf[r]
    else (spentOf[r] > 0 implies 1 else 0)
}

// which cohorts a row restores. Authoritative: the ones actually released.
// Heuristic: only the cohort re-derivable from the spec, which loses any
// cohort the PROCEDURE added.
fun recCohorts [r: Request]: set Cohort {
  r.phase = Released implies
    (Replay.mode = Authoritative implies r.cohorts else r.base)
  else none
}

fun replaySpent: one Int { sum r: liveRows | recCost[r] }
fun replayCohorts: set Cohort { { c: Cohort | some r: liveRows | c in recCohorts[r] } }

// the chain verifies exactly when no row has been removed from it
pred chainVerifies { no Deleted }

// --- events -------------------------------------------------------------------

pred framePhases [moved: Request] {
  all q: Request - moved | q.phase' = q.phase
}
pred frameCharges { Engaged' = Engaged and ErrCharged' = ErrCharged }

pred frameLog { Recorded' = Recorded and Deleted' = Deleted }
pred framePolicy { PolicyLogged' = PolicyLogged }

// the startup policy record: appended before any request is served, so every
// later row is attributable to the policy in force at its own position
pred boot {
  PolicyLogged' = Chain
  phase' = phase
  frameCharges
  Auditor.spent' = Auditor.spent
  Auditor.cohorts' = Auditor.cohorts
  Flagged' = Flagged
  frameLog
}

// the entry precheck: handle() denies when over_budget() before any planner
// or engine work; _handle_model denies when spent + len(aggregates) > budget
pred affordable [r: Request] { Auditor.spent.plus[r.cost] <= Budget }

pred start [r: Request] {
  r.phase = Idle
  Chain in PolicyLogged                     // the service is up
  affordable[r] implies r.phase' = Started else r.phase' = Denied
  frameCharges
  // an unaffordable request is refused, and refusing it is still audited
  affordable[r] implies Recorded' = Recorded else Recorded' = Recorded + r
  Deleted' = Deleted
  Auditor.spent' = Auditor.spent
  Auditor.cohorts' = Auditor.cohorts
  Flagged' = Flagged
  framePhases[r]
  framePolicy
}

// SessionAuditor.observe: the spend increments unconditionally; an increment
// that passes the budget adds the query_budget finding (spent > budget)
pred observe [r: Request] {
  r.phase = Started
  r.phase' = Observed
  Engaged' = Engaged + r
  ErrCharged' = ErrCharged
  Auditor.spent' = Auditor.spent.plus[r.cost]
  Auditor.spent' > Budget implies Flagged' = Flagged + r else Flagged' = Flagged
  Auditor.cohorts' = Auditor.cohorts
  framePhases[r]
  frameLog
  framePolicy
}

// SessionAuditor.observe_cohort: a recorded cohort that is distinct and near
// flags the request; the history consulted is whatever is recorded NOW —
// this timing is the whole point of the model
pred cohortCheck [r: Request] {
  r.phase = Observed
  r.phase' = Checked
  (some Auditor.cohorts & r.cohorts.near) implies Flagged' = Flagged + r
                                          else Flagged' = Flagged
  frameCharges
  Auditor.spent' = Auditor.spent
  Auditor.cohorts' = Auditor.cohorts
  framePhases[r]
  frameLog
  framePolicy
}

// the fail-closed gate and record_cohort, one critical step: "any auditor
// flag, an explicit deny, or an unrecognised action withholds all data";
// only an actual release records its cohorts — all of them
pred decide [r: Request] {
  r.phase = Checked
  (r.action in ActRelease + ActRedact and r not in Flagged) implies {
    r.phase' = Released
    Auditor.cohorts' = Auditor.cohorts + r.cohorts
  } else {
    r.phase' = Denied
    Auditor.cohorts' = Auditor.cohorts
  }
  frameCharges
  Auditor.spent' = Auditor.spent
  Flagged' = Flagged
  Recorded' = Recorded + r
  Deleted' = Deleted
  framePhases[r]
  framePolicy
}

// the audited exception boundary. An error is recorded (hardening #37) and
// charged at least one unit (hardening #60): `_spent` only moved inside
// `observe`, so a request that raised earlier was answered for free.
pred fail [r: Request] {
  r.phase in Started + Observed + Checked
  r.phase' = Errored
  spentOf[r] = 0 implies {
    ErrCharged' = ErrCharged + r
    Engaged' = Engaged
    Auditor.spent' = Auditor.spent.plus[1]
  } else {
    frameCharges
    Auditor.spent' = Auditor.spent
  }
  Auditor.cohorts' = Auditor.cohorts
  Flagged' = Flagged
  Recorded' = Recorded + r
  Deleted' = Deleted
  framePhases[r]
  framePolicy
}

// the attacker with write access to the database — no key, no forged MAC,
// just a DELETE. This is the environment, not the system.
pred deleteRow [r: Request] {
  r in Recorded
  r not in Deleted
  Deleted' = Deleted + r
  Recorded' = Recorded
  phase' = phase
  frameCharges
  Auditor.spent' = Auditor.spent
  Auditor.cohorts' = Auditor.cohorts
  Flagged' = Flagged
  framePolicy
}

// SessionStore.rehydrate. The process dies and comes back: in-flight requests
// are gone, and the session controls are rebuilt from the log. The verify gate
// (#59) is what makes replaying a mutilated chain unreachable.
pred restart {
  no r: Request | r.phase in Started + Observed + Checked
  Deployment.gate = GateOn implies chainVerifies
  Auditor.spent' = replaySpent
  Auditor.cohorts' = replayCohorts
  // the new process appends its own policy record before serving
  PolicyLogged' = Chain
  phase' = phase
  frameCharges
  Flagged' = Flagged
  frameLog
}

pred stutter {
  phase' = phase
  frameCharges
  Auditor.spent' = Auditor.spent
  Auditor.cohorts' = Auditor.cohorts
  Flagged' = Flagged
  frameLog
  framePolicy
}

fact Traces {
  always (stutter or boot or restart or some r: Request |
    start[r] or observe[r] or cohortCheck[r] or decide[r] or fail[r]
    or deleteRow[r])
}

// the per-Session lock as an explicit environment assumption: at most one
// request inside the critical section at any instant (the web shell holds it
// across observe -> apply -> record; hardening #18)
pred Serialized { lone r: Request | r.phase in Started + Observed + Checked }

// the shipped configuration: authoritative accounting and the verify gate on
pred Shipped { Replay.mode = Authoritative and Deployment.gate = GateOn }

// --- checked properties -------------------------------------------------------

// within a process spend only grows; a restart REPLAYS it, which is a
// different claim and is ReplayEquivalence's job
assert P17_SpentMonotone {
  always (not restart implies Auditor.spent' >= Auditor.spent)
}
check P17_SpentMonotone for exactly 2 Request, 2 Cohort, 4 Int, 9 steps

assert P17_BudgetInvariantUnderLock {
  (Shipped and always Serialized) implies always Auditor.spent <= Budget
}
check P17_BudgetInvariantUnderLock for exactly 2 Request, 2 Cohort, 4 Int, 9 steps

// Spent never decreases, so exhaustion is absorbing and the entry precheck
// denies every later request before engine work — no lock needed.
//
// `Shipped` is load-bearing and was not, at first: without authoritative
// accounting the model found nine counterexamples in which a restart REFUNDS
// spend far enough to reopen an exhausted budget. That is V1 arriving by a
// second route — the refund does not merely mis-count, it un-exhausts a
// session — and it is what V1BudgetRefundedOnRestart exhibits.
assert P17_ExhaustionShortCircuits {
  Shipped implies always (Auditor.spent >= Budget implies
    always (not restart implies no r: Request | r.phase = Idle and r.phase' = Started))
}
check P17_ExhaustionShortCircuits for exactly 3 Request, 2 Cohort, 4 Int, 9 steps

// the differencing pair stays denied ACROSS a restart: this is the property
// hardening #49 exists to provide and #58/#59 exist to make true
assert P16_DifferencingPairNeverBothReleased {
  (Shipped and always Serialized) implies
    always no disj r1, r2: Request |
      r1.phase = Released and r2.phase = Released and
      some r2.cohorts & r1.cohorts.near
}
check P16_DifferencingPairNeverBothReleased
  for exactly 2 Request, 2 Cohort, 4 Int, 10 steps

assert P7_GateFailsClosed {
  always all r: Request | r.phase = Released implies
    (r.action in ActRelease + ActRedact and r not in Flagged)
}
check P7_GateFailsClosed for exactly 2 Request, 2 Cohort, 4 Int, 9 steps

assert LineageIsExactlyReleases {
  Shipped implies always Auditor.cohorts = (phase.Released).cohorts
}
check LineageIsExactlyReleases for exactly 2 Request, 2 Cohort, 4 Int, 9 steps

// V1/V2/V4: a restart is a no-op on the controls. One cost model, replayed —
// not a second one, inferred.
assert ReplayEquivalence {
  Shipped implies always (restart implies
    (Auditor.spent' = Auditor.spent and Auditor.cohorts' = Auditor.cohorts))
}
check ReplayEquivalence for exactly 2 Request, 2 Cohort, 4 Int, 10 steps

// hardening #37: every terminal request is in the log, exceptions included
assert AuditCompleteness {
  always all r: Request |
    r.phase in Released + Denied + Errored implies r in Recorded
}
check AuditCompleteness for exactly 2 Request, 2 Cohort, 4 Int, 9 steps

// hardening #55: no request row can precede the policy record
assert PolicyPrecedesEveryRecord {
  always (some Recorded implies Chain in PolicyLogged)
}
check PolicyPrecedesEveryRecord for exactly 2 Request, 2 Cohort, 4 Int, 9 steps

// --- inhabitation and the machine-exhibited attacks ----------------------------

pred someTemporalSession {
  Shipped
  always Serialized
  eventually some r: Request | r.phase = Released
  eventually some r: Request | r.phase = Denied
}
run someTemporalSession for exactly 2 Request, 2 Cohort, 4 Int, 9 steps

// the restart path is reachable and keeps serving — without this the restart
// properties above could hold vacuously
pred someRestartedSession {
  Shipped
  always Serialized
  eventually (some r: Request | r.phase = Released) and eventually restart
  eventually (some r: Request | r.phase = Idle and r.phase' = Started
              and once restart)
}
run someRestartedSession for exactly 2 Request, 2 Cohort, 4 Int, 10 steps

pred Hardening18RaceWithoutLock {
  Shipped
  not always Serialized
  eventually some disj r1, r2: Request |
    r1.phase = Released and r2.phase = Released and
    some r2.cohorts & r1.cohorts.near
}
run Hardening18RaceWithoutLock for exactly 2 Request, 2 Cohort, 4 Int, 10 steps

// V1: drop authoritative accounting and a model's budget comes back refunded.
// Round 9 measured exactly this: live _spent=2, rehydrated _spent=1.
pred V1BudgetRefundedOnRestart {
  Replay.mode = Heuristic
  Deployment.gate = GateOn
  always Serialized
  eventually (restart and Auditor.spent' < Auditor.spent)
}
run V1BudgetRefundedOnRestart for exactly 2 Request, 2 Cohort, 4 Int, 10 steps

// V2: drop it and a cohort the PROCEDURE added is lost — the binomial
// successes cohort, which re-reading the model spec cannot recover.
pred V2CohortLostOnRestart {
  Replay.mode = Heuristic
  Deployment.gate = GateOn
  always Serialized
  eventually (restart and some c: Cohort |
    c in Auditor.cohorts and c not in Auditor.cohorts')
}
run V2CohortLostOnRestart for exactly 2 Request, 2 Cohort, 4 Int, 10 steps

// V3: drop the verify gate and a DELETED row — no forged MAC, just write
// access — removes a cohort from the rebuilt lineage. `verify()` detected this
// all along; nothing consulted it where it mattered.
pred V3DeletionDefeatsLineage {
  Replay.mode = Authoritative
  Deployment.gate = GateOff
  always Serialized
  eventually (some r: Request | deleteRow[r])
  eventually (restart and some c: Cohort |
    c in Auditor.cohorts and c not in Auditor.cohorts')
}
run V3DeletionDefeatsLineage for exactly 2 Request, 2 Cohort, 4 Int, 10 steps
