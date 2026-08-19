// vrr_record — a bounded model of the PUBLIC/PRIVATE boundary of a verifiable
// research record (D9; build plan milestone 9; safetre/provenance.py,
// safetre/recorder.py, safetre/research_record.py).
//
// The other models are about a release. This one is about the RECORD of a
// release: the release has already happened and passed the gateway, and what is
// under test is whether the published account of it discloses what the gateway
// withheld. Round 14 found three ways it did, and all three are exhibited below
// as satisfiable runs with one clause of the compiler dropped — which is the
// point of having the model at all, because each was a control firing correctly
// beside a fact that stayed recoverable.
//
// What is modelled. An ordered `Event` sequence is the audit chain: a `Commit`
// is a plan-commitment row, a `Look` is a stage observing protected data. A
// `Stage` released some set of `Artifact`s (none, if the gateway refused it) and
// may have taken a private `Branch`. `Evidence` cites a stage and an artifact.
// The three free sets `Node`, `Published` and `PlanBody` are what the exported
// bundle contains, and `Compiled` is the shipped compiler that fixes them.
//
// What is checked (counterexample = CI failure):
//   PublicRecordNamesOnlyReleasingStages — nothing a reader can name from the
//        bundle is a stage the gateway refused. This is the whole of #109 and
//        #110: not "the compiler dropped the field" but "the fact is not
//        recoverable", which is the difference the two findings turned on.
//   EvidenceHasAuthorisedLineage — every published evidence item cites an
//        artifact its own stage actually released (build plan M9 Alloy target 2).
//   PrecommitmentNeedsOrderAndAuthenticity — a stage is pre-committed only if
//        the chain witnessed it, the chain verifies, and the commitment precedes
//        every observation it made (target 1, and finding #108).
//   StaleCertificateCannotAuthenticate — a certificate is accepted only over the
//        exact evidence set it covered (target 3).
//   PrivateBranchDoesNotEnterPublicTopology — the node set is a function of the
//        published evidence alone, so no private branch can move it (target 4).
//
// What is SEARCHED FOR and must EXIST (unsatisfiable = CI failure):
//   someRecord                    — inhabitation, so the checks are not vacuous;
//   someRefusedStage              — a record where the gateway refused something,
//                                   which is the only interesting case;
//   F109PlanBodyPublished         — the plan body published beside the node list
//                                   names the refused stages;
//   F110NotAnswerablePublished    — evidence citing a stage that released
//                                   nothing names the refused stages;
//   F108ReorderedChainBuysTheLabel — an unverified chain buys TRE_PRECOMMITTED;
//   StaleCertificateAcceptedWithoutTheRule — the staleness rule dropped;
//   BranchVisibleWithoutTheRule   — the topology allowed to consult a branch;
//   BenignRecordPublishes         — a released stage IS published, so the
//                                   boundary does not refuse everything.

module vrr_record

open util/ordering[Event]

// ---- the audit chain --------------------------------------------------------

abstract sig Event {}

// A plan-commitment row (`status="plan"`, PlanExecutor._commit). At most one:
// the model is about one record's governing plan.
sig Commit extends Event {}
fact AtMostOneCommit { #Commit =< 1 }

// A row a stage wrote, which is also the moment it observed protected data.
sig Look extends Event { looker: one Stage }

// The chain's tamper-evidence, consulted or not. `some Verified` is
// AuditLog.verify() returning true.
one sig Chain {}
sig Verified in Chain {}

// ---- the record ------------------------------------------------------------

sig Artifact {}
sig Branch {}

sig Stage {
  released: set Artifact,   // empty for a stage the gateway refused
  branch: lone Branch       // a private decision: a contingency, a retry, a
}                           // rejected candidate model

sig Evidence { source: one Stage, of: one Artifact }

// What the exported bundle contains. Free sets, fixed by `Compiled`.
sig Node in Stage {}          // provenance.json nodes
sig Published in Evidence {}  // evidence.json
sig PlanBody in Stage {}      // stages nameable from a published plan body
sig Precommitted in Stage {}  // the TRE_PRECOMMITTED classification

sig Certificate { covers: set Evidence }
sig Accepted in Certificate {}

fun refused: set Stage { { s: Stage | no s.released } }
fun looks [s: Stage]: set Event { { l: Look | l.looker = s } }

// A stage the chain witnessed, under a commitment that precedes every
// observation it made, on a chain that verifies. All three conjuncts are
// load-bearing and each has its own finding: dropping authenticity is #108,
// and dropping witnessing is the same finding's laundering variant, where an
// analysis run as ordinary queries is fitted with a plan afterwards.
pred committedBefore [s: Stage] {
  some Verified
  some looks[s]
  some c: Commit | looks[s] in nexts[c]
}

// ---- the shipped compiler ---------------------------------------------------

pred Compiled {
  // safetre/provenance.py: a node exists because a released number needs
  // explaining, never because a stage ran
  Node = Published.source

  // safetre/research_record.py::public_evidence — the bundle publishes exactly
  // the evidence the provenance cites, and an item cites an artifact its own
  // stage released (#110 was this clause missing for NotAnswerable items)
  all e: Published | e.of in e.source.released

  // safetre/vrr_bundle.py — the plan's hash is published, its body is not
  // (#109)
  no PlanBody

  // safetre/recorder.py — the label is derived, and needs an authentic chain
  Precommitted = { s: Stage | committedBefore[s] }

  // safetre/vrr_bundle.py::verify_bundle_dir — a certificate is accepted only
  // over the exact evidence set it covered
  Accepted = { k: Certificate | k.covers = Published }
}

// ---- what must hold ---------------------------------------------------------

// Nothing nameable from the bundle is a stage the gateway refused. Stated over
// what a READER can recover rather than over which field the compiler wrote,
// because #109 and #110 were both fields correctly omitted from one place and
// recoverable from another.
assert PublicRecordNamesOnlyReleasingStages {
  Compiled implies no ((Node + Published.source + PlanBody) & refused)
}
check PublicRecordNamesOnlyReleasingStages for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

assert EvidenceHasAuthorisedLineage {
  Compiled implies (all e: Published | e.of in e.source.released)
}
check EvidenceHasAuthorisedLineage for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

assert PrecommitmentNeedsOrderAndAuthenticity {
  Compiled implies (all s: Precommitted |
    some Verified and some looks[s] and (some c: Commit | looks[s] in nexts[c]))
}
check PrecommitmentNeedsOrderAndAuthenticity for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

assert StaleCertificateCannotAuthenticate {
  Compiled implies (all k: Accepted | k.covers = Published)
}
check StaleCertificateCannotAuthenticate for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// The node set is a function of the published evidence and of nothing else, so
// a stage's private branch cannot put it in or out. Two stages that publish the
// same evidence are treated the same however differently they decided.
assert PrivateBranchDoesNotEnterPublicTopology {
  Compiled implies (all s: Stage |
    (s in Node iff some e: Published | e.source = s))
}
check PrivateBranchDoesNotEnterPublicTopology for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// ---- inhabitation -----------------------------------------------------------

pred someRecord {
  Compiled
  some Published
  some Precommitted
  some Accepted
}
run someRecord for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// The only interesting case: the gateway refused something, and the record is
// still published. If this were unsatisfiable every check above would be about
// records with nothing to hide.
pred someRefusedStage {
  Compiled
  some refused
  some Published
  some branch
}
run someRefusedStage for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// A released stage really is published, so the boundary does not achieve safety
// by publishing nothing.
pred BenignRecordPublishes {
  Compiled
  some s: Stage | s in Node and some s.released
}
run BenignRecordPublishes for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// ---- the findings, exhibited -----------------------------------------------

// #109. Drop only the "no PlanBody" clause: every other control fires exactly
// as shipped, and a reader takes the published plan's stage set minus the node
// list and has the gateway's verdict on each stage.
pred F109PlanBodyPublished {
  Node = Published.source
  all e: Published | e.of in e.source.released
  Precommitted = { s: Stage | committedBefore[s] }
  Accepted = { k: Certificate | k.covers = Published }
  some PlanBody & refused          // <- the disclosure
}
run F109PlanBodyPublished for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// #110. Drop only the release-lineage clause: `NotAnswerable` evidence cites a
// stage that released nothing, and publishing the evidence list names it.
pred F110NotAnswerablePublished {
  Node = Published.source
  no PlanBody
  Precommitted = { s: Stage | committedBefore[s] }
  Accepted = { k: Certificate | k.covers = Published }
  some e: Published | no e.source.released     // <- the disclosure
}
run F110NotAnswerablePublished for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// #108. Drop only the authenticity conjunct: the rows say the commitment came
// first, nothing checked that the rows are the rows that were written, and the
// label is issued anyway.
pred F108ReorderedChainBuysTheLabel {
  Node = Published.source
  all e: Published | e.of in e.source.released
  no PlanBody
  Accepted = { k: Certificate | k.covers = Published }
  no Verified                                  // the chain does not verify
  some s: Precommitted | some c: Commit | looks[s] in nexts[c] and some looks[s]
}
run F108ReorderedChainBuysTheLabel for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// A certificate accepted over an evidence set it never covered — the stale and
// swapped certificate, with the verifier's rule dropped.
pred StaleCertificateAcceptedWithoutTheRule {
  Node = Published.source
  all e: Published | e.of in e.source.released
  no PlanBody
  Precommitted = { s: Stage | committedBefore[s] }
  some k: Accepted | k.covers != Published     // <- the stale certificate
}
run StaleCertificateAcceptedWithoutTheRule for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate

// The topology allowed to consult a private branch: a stage with no published
// evidence appears as a node because of a decision it took privately.
pred BranchVisibleWithoutTheRule {
  all e: Published | e.of in e.source.released
  no PlanBody
  Precommitted = { s: Stage | committedBefore[s] }
  Accepted = { k: Certificate | k.covers = Published }
  some s: Node | no e: Published | e.source = s   // <- topology beyond evidence
  some (Node & refused).branch
}
run BranchVisibleWithoutTheRule for 5 Stage, 5 Artifact, 5 Evidence, 5 Event, 3 Branch, 3 Certificate
