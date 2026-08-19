/-
The public/private boundary of a verifiable research record
(D9; build plan milestone 9, the Lean half; safetre/research_record.py and
safetre/provenance.py).

**THIS IS A DRAFT AND HAS NEVER BEEN COMPILED.** It lives in `formal/lean/draft/`
rather than `formal/lean/SafeTre/` on purpose: CI runs `lake build` on every
push, and `tests/test_formal_lean_sync.py` requires every module under
`SafeTre/` to be imported by the root, so putting an unchecked file there would
turn the formal job red and claim a proof nobody has replayed. Promote it with

    git mv formal/lean/draft/Record.lean formal/lean/SafeTre/Record.lean
    # add `import SafeTre.Record` to formal/lean/SafeTre.lean
    cd formal/lean && lake build

and expect to fix things. The proofs marked (?) below are the ones most likely
to need work: this project has no Mathlib, so only Lean 4 core lemmas are
available, and the list lemmas are where core's names and shapes bite.

## What is modelled

`safetre/provenance.py::compile_public_provenance`, and the two things round 14
found out about it the hard way (#109, #110). The Alloy model
`formal/vrr_record.als` covers the same boundary from the other side and is
solver-checked; this is the type-level half, and the two should agree.

The design decision that makes the theorems short is the same one that makes the
Python fail closed: **the compiler reads a projection of a stage, not the stage.**
`provenance._PUBLIC_NODE_KEYS` is an allowlist, so a private field has no route
into a node; here `compilePublic` takes `List PubStage`, so a private field has
no route into a node *because there is no argument to carry it in*. The
noninterference theorem is then a congruence rather than an induction.

## What is claimed, and what is not

Claimed: whatever a stage decided privately, the compiled public record and
anything rendered from it are unchanged. That is the type-level form of the six
paired-trace perturbations in `tests/test_vrr_provenance.py`.

Not claimed: that the released NUMBERS are insensitive to any one person's data.
They are not, and cannot be — an aggregate depends on what it aggregates. That
is the quantitative claim, it belongs to a DP accountant, and proving this
easier statement must not be mistaken for it. `SafeTre/Release.lean` makes the
same disclaimer about the release function and for the same reason.
-/

namespace SafeTre.Record

/-! ## The vocabulary -/

/-- `research_record.Disclosure`. -/
inductive Disclosure
  | «public»
  | opaqueAttestation
  | privateOnly
deriving DecidableEq, Repr

/-- `research_record.ArtifactRef`. It carries its own disclosure class, so a
reference to a withheld table cannot be surfaced by the layer above. -/
structure ArtifactRef where
  artifactId : String
  disclosureClass : Disclosure
  commitment : String
deriving DecidableEq, Repr

def isPublic (a : ArtifactRef) : Bool :=
  match a.disclosureClass with
  | Disclosure.«public» => true
  | _ => false

/-- `research_record.EvidenceItem`, abstracted to what the boundary cares about:
which stage it cites, and whether it is the `NotAnswerable` kind — the one that
may cite a stage that released nothing, and therefore the one that names the
refused stages if it is ever published (#110). -/
structure EvidenceItem where
  evidenceId : String
  sourceStage : String
  notAnswerable : Bool
deriving DecidableEq, Repr

/-- `research_record.StageRecord`. The first four fields are the PUBLIC ones;
everything below `released` is decided by the data. -/
structure Stage where
  stageId : String
  procedure : String
  publicParams : String
  outputs : List ArtifactRef
  released : Bool
  message : String
  excludedLevels : List String
  privateDetail : String
deriving DecidableEq, Repr

/-- The public projection of a stage: everything a node may be built from, and
nothing else. The Lean counterpart of `provenance._PUBLIC_NODE_KEYS`. -/
structure PubStage where
  stageId : String
  procedure : String
  publicParams : String
  artifacts : List ArtifactRef
deriving DecidableEq, Repr

def pubStage (s : Stage) : PubStage :=
  ⟨s.stageId, s.procedure, s.publicParams, s.outputs.filter isPublic⟩

/-- A public provenance node. Definitionally the public projection, and that is
the claim: a node can hold exactly what the projection holds, so there is no
field for a private one to arrive in (milestone 9 Lean target 1). -/
abbrev Node := PubStage

/-- `research_record.PrivateExecutionTrace`. -/
structure Trace where
  question : String
  planRef : Option String
  /-- The plan BODY. Private, and not because of what it contains: published
  beside the node list it names the refused stages by set difference (#109). -/
  committedPlan : Option String
  stages : List Stage
  evidence : List EvidenceItem
  chainVerified : Bool
  user : String
deriving DecidableEq, Repr

/-- `research_record.PublicProvenance`. Note the absent fields: no committed
plan body, no stage statuses, no messages, no excluded levels, no user. -/
structure Public where
  question : String
  planRef : Option String
  nodes : List Node
  evidence : List EvidenceItem
  chainVerified : Bool
deriving DecidableEq, Repr

/-! ## The compiler -/

/-- `research_record.ResearchRecord.public_evidence` — the bundle publishes only
the evidence the provenance cites, which excludes `NotAnswerable` (#110). -/
def publicEvidence (t : Trace) : List EvidenceItem :=
  t.evidence.filter (fun e => !e.notAnswerable)

def cites (es : List EvidenceItem) (id : String) : Bool :=
  es.any (fun e => e.sourceStage == id)

/-- A node exists because a released number needs explaining, never because a
stage ran. -/
def nodeIfCited (es : List EvidenceItem) (s : PubStage) : Option Node :=
  if cites es s.stageId then some s else none

/-- `provenance.compile_public_provenance`.

Takes the stages only through `pubStage`. Everything below is a consequence of
that one choice. -/
def compilePublic (t : Trace) : Public :=
  { question := t.question
    planRef := t.planRef
    nodes := (t.stages.map pubStage).filterMap (nodeIfCited (publicEvidence t))
    evidence := publicEvidence t
    chainVerified := t.chainVerified }

/-- The reviewer-facing renderer (`vrr_bundle.render_report_from_public`).

Its TYPE is the theorem for milestone 9 target 3: it takes `Public`, not
`Trace`, so it cannot consult private state — not because it declines to, but
because it is not given any. The body is deliberately dull; nothing below
depends on what it renders. -/
def renderPublic (p : Public) : String :=
  p.question
    ++ (match p.planRef with | some h => h | none => "")
    ++ String.join (p.nodes.map (fun n => n.stageId ++ n.procedure ++ n.publicParams))
    ++ String.join (p.evidence.map (fun e => e.evidenceId))
    ++ (if p.chainVerified then "verified" else "unverified")

/-! ## Target 1 and 4 — private state does not reach the public record

The Lean form of the six paired-trace perturbations in
`tests/test_vrr_provenance.py`, and of `vrr_record.als`'s
`PrivateBranchDoesNotEnterPublicTopology`.
-/

/-- Two traces agreeing on every public component compile identically, however
far apart their private state is. `hs` is the whole content: the stage lists may
differ in status, message, excluded levels and private detail, and need only
agree after projection. -/
theorem compile_ignores_private_state
    {t t' : Trace}
    (hq : t.question = t'.question)
    (hp : t.planRef = t'.planRef)
    (hc : t.chainVerified = t'.chainVerified)
    (he : t.evidence = t'.evidence)
    (hs : t.stages.map pubStage = t'.stages.map pubStage) :
    compilePublic t = compilePublic t' := by
  -- (?) if `simp only` does not close this, `unfold compilePublic publicEvidence`
  -- then `rw [hq, hp, hc, he, hs]` should
  simp only [compilePublic, publicEvidence, hq, hp, hc, he, hs]

/-- Milestone 9's stated theorem shape. Trivial once the compiler is a function,
and that is the point: everything a reader sees is downstream of
`compilePublic`, so agreement there is agreement everywhere. -/
theorem render_determined_by_compile
    {t t' : Trace} (h : compilePublic t = compilePublic t') :
    renderPublic (compilePublic t) = renderPublic (compilePublic t') := by
  rw [h]

/-- The composite: nothing private reaches the rendered report either. -/
theorem render_ignores_private_state
    {t t' : Trace}
    (hq : t.question = t'.question)
    (hp : t.planRef = t'.planRef)
    (hc : t.chainVerified = t'.chainVerified)
    (he : t.evidence = t'.evidence)
    (hs : t.stages.map pubStage = t'.stages.map pubStage) :
    renderPublic (compilePublic t) = renderPublic (compilePublic t') :=
  render_determined_by_compile (compile_ignores_private_state hq hp hc he hs)

/-! ## Target 2 — published evidence has authorised release lineage -/

/-- Every published evidence item cites a stage that actually released. The
record-level obligation `ResearchRecord.validate_record` enforces. -/
def Wellformed (t : Trace) : Prop :=
  ∀ e ∈ publicEvidence t, ∃ s ∈ t.stages, s.stageId = e.sourceStage ∧ s.released = true

theorem published_evidence_has_release_lineage
    {t : Trace} (h : Wellformed t) :
    ∀ e ∈ (compilePublic t).evidence,
      ∃ s ∈ t.stages, s.stageId = e.sourceStage ∧ s.released = true := by
  intro e he
  -- `(compilePublic t).evidence` is `publicEvidence t` by definition
  exact h e he

/-! ## #110 — `NotAnswerable` is never published

The kind is legitimate internally: it is how a record says "the gateway released
nothing for this sub-question". It carries `sourceStage`, so publishing it names
the refused stages — which is the same disclosure as #109 by a second route, and
the one that survived #109's fix.
-/

theorem not_answerable_is_never_published (t : Trace) :
    ∀ e ∈ (compilePublic t).evidence, e.notAnswerable = false := by
  intro e he
  -- (?) core's `List.mem_filter : a ∈ List.filter p l ↔ a ∈ l ∧ p a = true`
  have hp := (List.mem_filter.mp he).2
  simpa using hp

/-! ## #109 — nothing nameable from the public record is a refused stage

The Lean twin of `vrr_record.als::PublicRecordNamesOnlyReleasingStages`. Stated
over what a READER can recover rather than over which field the compiler wrote,
because #109 and #110 were both fields correctly omitted from one place and
recoverable from another.
-/

/-- Every stage identifier a reader can read off the public record. There is no
`committedPlan` disjunct because `Public` has no such field — which is #109's
fix, expressed as a type rather than as a rule. -/
def nameable (p : Public) : List String :=
  p.nodes.map (fun n => n.stageId) ++ p.evidence.map (fun e => e.sourceStage)

/-- A node is emitted only for a cited stage. -/
theorem node_is_cited
    {es : List EvidenceItem} {xs : List PubStage} {n : Node}
    (h : n ∈ xs.filterMap (nodeIfCited es)) : cites es n.stageId = true := by
  -- (?) core's `List.mem_filterMap : b ∈ filterMap f l ↔ ∃ a ∈ l, f a = some b`
  rcases List.mem_filterMap.mp h with ⟨s, _, hs⟩
  unfold nodeIfCited at hs
  split at hs
  · rename_i hc
    cases hs
    exact hc
  · exact absurd hs (by simp)

/-- **The theorem.** Every stage a reader can name released something.

Both halves reduce to `Wellformed`: an evidence item names its own source, and a
node exists only because some published item cited it. -/
theorem nameable_stages_all_released
    {t : Trace} (h : Wellformed t) :
    ∀ id ∈ nameable (compilePublic t),
      ∃ s ∈ t.stages, s.stageId = id ∧ s.released = true := by
  intro id hid
  -- (?) `List.mem_append` then the two halves
  rcases List.mem_append.mp hid with hn | hev
  · -- a node: cited by some published item, which by `h` has a released source
    rcases List.mem_map.mp hn with ⟨n, hnmem, rfl⟩
    have hc := node_is_cited hnmem
    unfold cites at hc
    rcases List.any_eq_true.mp hc with ⟨e, hemem, heq⟩
    have := h e hemem
    rcases this with ⟨s, hsmem, hsid, hsrel⟩
    exact ⟨s, hsmem, by simp_all, hsrel⟩
  · -- an evidence item: `Wellformed` directly
    rcases List.mem_map.mp hev with ⟨e, hemem, rfl⟩
    exact h e hemem

end SafeTre.Record
