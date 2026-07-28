/-
The release function (FORMAL_METHODS_ANALYSIS §2.C, recommendation F6).

`release = postprocess ∘ finalize ∘ vet` is the factoring hardening #26
established in the code, and `tests/test_release_equality.py` checks it
executably in both directions — recomputing the released frame from the
finalized table, and perturbing the engine's frame in ways finalization erases
and requiring the release to be byte-identical. That perturbation direction is
the one with teeth: it found two further channels where released output was
still a function of exact counts (#27, #28).

This file is the theorem behind that test. It says what reaches a released
value and what cannot:

  A released cell is a function of its cell key, its payload, the VERDICT the
  vetting rules reached, and the ROUNDED count. Everything else the engine
  computed — the dominance and influence witnesses, the distinct-donor count,
  the exact count — reaches the release only through those two, and a change
  that leaves them fixed cannot move the release at all.

**What this is not.** It is not value-level noninterference: it does not say a
released aggregate is insensitive to any one donor's data. It cannot, because
an aggregate must depend on the values it aggregates — that is what makes it an
aggregate. The quantitative claim is the DP accountant's (roadmap item 3), and
conflating the two would be claiming the hard half by proving the easy one.
What this rules out is the channel that actually bit three times: a released
output that is a function of a quantity the gateway believed it had erased.
-/

import SafeTre.Arith

namespace SafeTre

/-- A cell as the engine produces it: the public key and payload, plus the
internal helpers the gateway decides with and then drops. -/
structure RawCell where
  key : String
  payload : Option Int
  /-- the exact row count, before rounding -/
  exactCount : Int
  /-- distinct donors — the quantity the threshold is really about (D4) -/
  nDonors : Int
  dominance : Option (Int × Int)
  influence : Option (Int × Int)
deriving Repr, DecidableEq

/-- A cell as an analyst receives it. Note what is absent: no witnesses, no
donor count, no exact count. -/
structure RelCell where
  key : String
  payload : Int
  count : Int
deriving Repr, DecidableEq

/-- The vetting view of a raw cell. The threshold reads the DONOR count, not
the row count — hardening #38, which is why `n` here is `nDonors`. -/
def toCell (c : RawCell) : Cell :=
  ⟨c.nDonors, c.dominance, c.influence, c.payload⟩

/-- `DisclosurePolicy._finalize`, per cell: a cell that passes every rule is
released with its key, its payload and its ROUNDED count; one that does not is
dropped entirely.

`round` is a parameter, not a definition, so the theorems below hold for any
nearest-multiple rounding — the code uses numpy's half-to-even and nothing here
depends on that choice. -/
def finalizeCell (p : Policy) (round : Int → Int) (c : RawCell) : Option RelCell :=
  if releases p (toCell c) then
    match c.payload with
    | some v => some ⟨c.key, v, round c.exactCount⟩
    | none => none
  else none

def finalize (p : Policy) (round : Int → Int) (cs : List RawCell) : List RelCell :=
  cs.filterMap (finalizeCell p round)

/-- `release = postprocess ∘ finalize`. `post` is an arbitrary function OF THE
FINALIZED TABLE, which is precisely the output contract's "no new data": a
postprocessor that could reach past its argument would not have this type.
Hardening #26 moved `postprocess` after finalization to make that true — before
it, corr's `p_value` was computed from the exact pre-rounding `n`. -/
def release (p : Policy) (round : Int → Int)
    (post : List RelCell → List RelCell) (cs : List RawCell) : List RelCell :=
  post (finalize p round cs)

/-! ## What cannot reach a release -/

/-- A perturbation the release cannot see. -/
def Invisible (p : Policy) (round : Int → Int) (g : RawCell → RawCell) : Prop :=
  ∀ c, finalizeCell p round (g c) = finalizeCell p round c

/-- **The criterion.** Anything that leaves the key, the payload, the verdict
and the rounded count alone is invisible — so those four are the entire
channel from the engine's frame to the analyst's. -/
theorem invisible_of_verdict_and_rounded_count
    {p : Policy} {round : Int → Int} {g : RawCell → RawCell}
    (hkey : ∀ c, (g c).key = c.key)
    (hpay : ∀ c, (g c).payload = c.payload)
    (hver : ∀ c, releases p (toCell (g c)) = releases p (toCell c))
    (hcnt : ∀ c, round (g c).exactCount = round c.exactCount) :
    Invisible p round g := by
  intro c
  simp only [finalizeCell, hver c, hkey c, hpay c, hcnt c]

/-- **The theorem.** An invisible perturbation leaves the release identical —
every cell of it, in order, whatever the postprocessor does. -/
theorem release_invariant_under_invisible_perturbation
    {p : Policy} {round : Int → Int} {post : List RelCell → List RelCell}
    {g : RawCell → RawCell} (h : Invisible p round g) (cs : List RawCell) :
    release p round post (cs.map g) = release p round post cs := by
  simp only [release]
  congr 1
  simp only [finalize]
  induction cs with
  | nil => rfl
  | cons c t ih => simp only [List.map_cons, List.filterMap_cons, h c, ih]

/-- **The factoring.** Two engine frames with the same finalized table release
identically, whatever the postprocessor is. This is the direction
`test_release_equality.py` checks by recomputation. -/
theorem release_factors_through_finalize
    {p : Policy} {round : Int → Int} {post : List RelCell → List RelCell}
    {cs cs' : List RawCell} (h : finalize p round cs = finalize p round cs') :
    release p round post cs = release p round post cs' := by
  simp only [release, h]

/-! ## The three concrete channels, as corollaries

Each is a perturbation the gateway believed it had erased, and two of them were
live before the hardening round that erased them.
-/

/-- The donor count is dropped by finalization and reaches the release only
through the threshold verdict, so moving it without crossing the threshold is
invisible. -/
theorem donor_count_reaches_release_only_through_the_verdict
    {p : Policy} {round : Int → Int} {g : RawCell → RawCell}
    (hkey : ∀ c, (g c).key = c.key) (hpay : ∀ c, (g c).payload = c.payload)
    (hcnt : ∀ c, (g c).exactCount = c.exactCount)
    (hdom : ∀ c, (g c).dominance = c.dominance)
    (hinfl : ∀ c, (g c).influence = c.influence)
    (hver : ∀ c, (p.threshold ≤ (g c).nDonors) = (p.threshold ≤ c.nDonors)) :
    Invisible p round g := by
  refine invisible_of_verdict_and_rounded_count hkey hpay ?_ (fun c => by rw [hcnt])
  intro c
  simp only [releases, passesCount, passesDominance, passesInfluence,
             passesPayload, toCell, hdom c, hinfl c, hpay c, hver c]
  rfl

/-- **Hardening #27/#28.** The exact count reaches the release only through the
rounded one: two frames whose counts round the same way release identically,
so the released table cannot rank cells more finely than the counts it shows.
Both of those hardenings were exactly this property failing — once through the
choice of sacrificed cell, once through row order. -/
theorem exact_count_reaches_release_only_when_rounded
    {p : Policy} {round : Int → Int} {g : RawCell → RawCell}
    (hkey : ∀ c, (g c).key = c.key) (hpay : ∀ c, (g c).payload = c.payload)
    (hsame : ∀ c, toCell (g c) = toCell c)
    (hbucket : ∀ c, round (g c).exactCount = round c.exactCount) :
    Invisible p round g :=
  invisible_of_verdict_and_rounded_count hkey hpay
    (fun c => by rw [hsame c]) hbucket

/-- **Hardening #41/#42, from the release side.** The witnesses are decision
inputs and nothing else: move them anywhere that leaves every verdict standing
and the analyst sees the same table. -/
theorem witnesses_reach_release_only_through_the_verdict
    {p : Policy} {round : Int → Int} {g : RawCell → RawCell}
    (hkey : ∀ c, (g c).key = c.key) (hpay : ∀ c, (g c).payload = c.payload)
    (hcnt : ∀ c, (g c).exactCount = c.exactCount)
    (hver : ∀ c, releases p (toCell (g c)) = releases p (toCell c)) :
    Invisible p round g :=
  invisible_of_verdict_and_rounded_count hkey hpay hver (fun c => by rw [hcnt])

/-- A released cell carries a key, a payload and a count — and nothing a
`RawCell` knows that a `RelCell` does not. The type is the statement, in the
same way `SafeSelect` is the SafeSQL grammar: there is no field for a witness
to occupy, so no refactor can leave one in. -/
theorem released_cells_carry_no_witness
    {p : Policy} {round : Int → Int} (cs : List RawCell) (r : RelCell)
    (h : r ∈ finalize p round cs) :
    ∃ c ∈ cs, r.key = c.key ∧ r.count = round c.exactCount := by
  simp only [finalize, List.mem_filterMap] at h
  obtain ⟨c, hc, hfc⟩ := h
  simp only [finalizeCell] at hfc
  split at hfc
  · split at hfc
    · exact ⟨c, hc, by cases hfc; rfl, by cases hfc; rfl⟩
    · simp at hfc
  · simp at hfc

end SafeTre
