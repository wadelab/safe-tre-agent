/-
The vetting arithmetic (FORMAL_METHODS_ANALYSIS §2, recommendation F4).

Hardening #41 and #42 were arithmetic bugs in formulas for which no property
had ever been stated. The dominance witness was `MAX(c)/SUM(c)` — the largest
contributor's *signed* share, which silently assumes every contribution is
non-negative. Over a negative total `MAX` selects the least-negative donor
while `SUM` is large and negative, so the ratio collapses toward zero:
negating one region's spend moved its witness from 0.620 to 0.0027 with the
concentration unchanged. And the released payload was never checked for
finiteness at all, so a single `-inf` record released.

Neither is subtle once the property is written down. They survived because the
property was never written down: the Lean model carries filter values only as
bound-parameter counts, by design, so this whole band was invisible to it.
This file is the band.

**Why integers rather than ℚ.** Every rule here is a comparison against a
rational threshold, and a comparison is exactly what integer cross-
multiplication expresses: `a/b ≤ p/q` is `a * q ≤ p * b` for positive
denominators. So the decisions are modelled exactly, `omega` proves them, and
no rational arithmetic library is needed (this package deliberately has no
dependencies — see `lakefile.toml`).

**What this does and does not claim about the running code.** These are
theorems about the RULES. The engine evaluates them in double-precision
floating point, so the model is exact where the implementation is approximate,
and `Cases.arithCases` pins the two together on witnesses that are exact in
both (`Proofs.arith_cases_pin_vetter`). A disagreement at a boundary would be a
finding, not a modelling artefact — which is the point of pinning rather than
asserting.
-/

namespace SafeTre

/-! ## Contributions and the dominance witness -/

/-- One donor's signed contribution to a cell. Signed is the whole point: a
refund, a net flow or a delta is negative, and the demo's measures happening to
be non-negative is what let #41 stand. -/
abbrev Contribution := Int

def absInt (x : Int) : Int := if x < 0 then -x else x

/-- `SUM(abs(c))` — the cell's total magnitude. -/
def sumAbs : List Contribution → Int
  | [] => 0
  | c :: cs => absInt c + sumAbs cs

/-- `MAX(abs(c))` — the largest single magnitude. -/
def maxAbs : List Contribution → Int
  | [] => 0
  | c :: cs => let m := maxAbs cs; if absInt c > m then absInt c else m

/-- The naive signed share the code used to compute: `MAX(c) / SUM(c)`. Kept
so the two can be compared, because "identical on non-negative data" is the
property that made #41's fix safe to land. -/
def sumSigned : List Contribution → Int
  | [] => 0
  | c :: cs => c + sumSigned cs

def maxSigned : List Contribution → Int
  | [] => 0
  | c :: cs => let m := maxSigned cs; if c > m then c else m

/-! ## Ratio comparison, exactly -/

/-- `a ≤ b` for ratios given as (numerator, denominator) with positive
denominators — the comparison the vetter makes, without dividing. -/
def leRat (a b : Int × Int) : Bool := a.1 * b.2 ≤ b.1 * a.2

/-! ## The cell rule -/

/-- A witness the engine could not resolve is `none`: NaN or ±inf. In the code
that is a comparison against NaN, which is False, and the mask is its negation
— so an unresolved witness suppresses. Here it is a constructor, so the
fail-closed behaviour is not a consequence of IEEE semantics that a refactor
could lose. -/
structure Cell where
  /-- distinct donors behind the cell -/
  n : Int
  /-- `MAX(abs)/SUM(abs)`, or `none` when unresolved -/
  dominance : Option (Int × Int)
  /-- leave-one-donor-out influence, or `none` when unresolved -/
  influence : Option (Int × Int)
  /-- the released value, or `none` when non-finite -/
  payload : Option Int
deriving Repr

structure Policy where
  threshold : Int
  dom : Int × Int
  infl : Int × Int
deriving Repr

/-- The four rules, one predicate each. `StandinVetter.vet` builds the
suppression mask as the complement of "passes every applicable rule" — its own
docstring says so — and taking that decomposition as the definition is what
makes monotonicity a two-line proof instead of boolean algebra. -/
def passesCount (p : Policy) (c : Cell) : Bool := decide (p.threshold ≤ c.n)

def passesDominance (p : Policy) (c : Cell) : Bool :=
  match c.dominance with
  | none => false                      -- unresolved: fail closed
  | some d => leRat d p.dom

def passesInfluence (p : Policy) (c : Cell) : Bool :=
  match c.influence with
  | none => false
  | some i => leRat i p.infl

def passesPayload (c : Cell) : Bool :=
  match c.payload with
  | none => false                      -- non-finite: not an aggregate at all
  | some _ => true

def releases (p : Policy) (c : Cell) : Bool :=
  passesCount p c && passesDominance p c && passesInfluence p c && passesPayload c

def suppresses (p : Policy) (c : Cell) : Bool := !releases p c

/-! ## Theorems -/

theorem absInt_nonneg (x : Int) : 0 ≤ absInt x := by
  simp only [absInt]; split <;> omega

theorem sumAbs_nonneg (cs : List Contribution) : 0 ≤ sumAbs cs := by
  induction cs with
  | nil => simp [sumAbs]
  | cons c t ih => have := absInt_nonneg c; simp only [sumAbs]; omega

/-- **Fail closed.** An unresolved witness or a non-finite payload always
suppresses, whatever else is true of the cell (hardening #42, A4). -/
theorem unresolved_dominance_suppresses (p : Policy) (c : Cell)
    (h : c.dominance = none) : releases p c = false := by
  simp [releases, passesDominance, h]

theorem unresolved_influence_suppresses (p : Policy) (c : Cell)
    (h : c.influence = none) : releases p c = false := by
  simp [releases, passesInfluence, h]

theorem nonfinite_payload_suppresses (p : Policy) (c : Cell)
    (h : c.payload = none) : releases p c = false := by
  simp [releases, passesPayload, h]

/-- The magnitude witness is a genuine share: `0 ≤ MAX(abs) ≤ SUM(abs)`, so the
ratio lies in `[0,1]` for any contribution vector. The signed version has no
such bound, which is what #41 exploited. -/
theorem maxAbs_nonneg (cs : List Contribution) : 0 ≤ maxAbs cs := by
  induction cs with
  | nil => simp [maxAbs]
  | cons c t ih =>
      simp only [maxAbs]
      split
      · exact absInt_nonneg c
      · exact ih

theorem maxAbs_le_sumAbs (cs : List Contribution) : maxAbs cs ≤ sumAbs cs := by
  induction cs with
  | nil => simp [maxAbs, sumAbs]
  | cons c t ih =>
      have h1 := absInt_nonneg c
      have h2 := sumAbs_nonneg t
      simp only [maxAbs, sumAbs]
      split <;> omega

theorem dominance_witness_is_a_share (cs : List Contribution) :
    0 ≤ maxAbs cs ∧ maxAbs cs ≤ sumAbs cs :=
  ⟨maxAbs_nonneg cs, maxAbs_le_sumAbs cs⟩

/-- **Sign invariance (hardening #41).** Negating every contribution — a
column of refunds rather than payments — leaves the witness identical, so the
decision cannot be inverted by the sign of the measure. -/
theorem absInt_neg (x : Int) : absInt (-x) = absInt x := by
  simp only [absInt]; split <;> split <;> omega

theorem sumAbs_neg (cs : List Contribution) : sumAbs (cs.map (- ·)) = sumAbs cs := by
  induction cs with
  | nil => rfl
  | cons c t ih => simp only [List.map_cons, sumAbs, absInt_neg, ih]

theorem maxAbs_neg (cs : List Contribution) : maxAbs (cs.map (- ·)) = maxAbs cs := by
  induction cs with
  | nil => rfl
  | cons c t ih => simp only [List.map_cons, maxAbs, absInt_neg, ih]

/-- The decision itself is therefore sign-invariant: the witness a negated
cell presents is the one the original presented. -/
theorem dominance_decision_sign_invariant (cs : List Contribution) :
    (maxAbs (cs.map (- ·)), sumAbs (cs.map (- ·))) = (maxAbs cs, sumAbs cs) := by
  simp [maxAbs_neg, sumAbs_neg]

/-- **Agreement on non-negative data.** Where every contribution is
non-negative the magnitude share IS the naive signed share — same MAX, same
SUM. This is why #41's fix changed no existing decision, and it is now a
theorem rather than a test over the demo data. -/
theorem absInt_of_nonneg {x : Int} (h : 0 ≤ x) : absInt x = x := by
  simp only [absInt]; split <;> omega

theorem sumAbs_eq_sumSigned (cs : List Contribution)
    (h : ∀ x ∈ cs, 0 ≤ x) : sumAbs cs = sumSigned cs := by
  induction cs with
  | nil => rfl
  | cons c t ih =>
      rw [sumAbs, sumSigned, absInt_of_nonneg (h c (List.mem_cons_self ..)),
          ih (fun x hx => h x (List.mem_cons_of_mem _ hx))]

theorem maxAbs_eq_maxSigned (cs : List Contribution)
    (h : ∀ x ∈ cs, 0 ≤ x) : maxAbs cs = maxSigned cs := by
  induction cs with
  | nil => rfl
  | cons c t ih =>
      rw [maxAbs, maxSigned, absInt_of_nonneg (h c (List.mem_cons_self ..)),
          ih (fun x hx => h x (List.mem_cons_of_mem _ hx))]

/-! ## Rounding -/

/-- What it means for `r` to be a released count: a multiple of the base, and
one of the nearest such to the true count.

Stated as a PREDICATE rather than a function on purpose. The code rounds with
numpy's half-to-even; half-away-from-zero would be an equally valid choice, and
the disclosure property below holds for either. Pinning the tie-break would
make the theorem a statement about numpy. -/
def IsRounded (base r n : Int) : Prop :=
  (∃ k : Int, r = base * k) ∧ 2 * absInt (r - n) ≤ base

/-- **Rounding blurs by no more than the base.** Two exact counts that release
as the same rounded value differ by at most `base`, which is the entire
disclosure content of rounding: the released number pins the true one only to a
window of that width. -/
theorem rounding_hides_within_the_base {base r n m : Int}
    (hn : IsRounded base r n) (hm : IsRounded base r m) :
    absInt (n - m) ≤ base := by
  obtain ⟨_, hn2⟩ := hn
  obtain ⟨_, hm2⟩ := hm
  simp only [absInt] at hn2 hm2 ⊢
  split at hn2 <;> split at hm2 <;> split <;> omega

/-! ## Monotonicity: a tighter policy never releases more -/

/-- **Raising the threshold never releases more.** The direction an operator
expects when they tighten a dial, and the property #46's floors assume when
they insist a floor is a floor. -/
theorem raising_the_threshold_never_releases_more
    {p q : Policy} (hdom : p.dom = q.dom) (hinfl : p.infl = q.infl)
    (hthr : p.threshold ≤ q.threshold) (c : Cell) :
    releases q c = true → releases p c = true := by
  simp only [releases, passesCount, passesDominance, passesInfluence,
             hdom, hinfl, Bool.and_eq_true, decide_eq_true_eq]
  intro h
  exact ⟨⟨⟨by omega, h.1.1.2⟩, h.1.2⟩, h.2⟩

/-- `x * y * z = x * z * y`. Spelled out because `ring` is a Mathlib tactic and
this package has no dependencies. -/
theorem mul_swap_right (x y z : Int) : x * y * z = x * z * y := by
  rw [Int.mul_assoc, Int.mul_comm y z, ← Int.mul_assoc]

/-- Transitivity of `≤` on ratios written as cross-multiplications. `omega`
cannot do this one: the products are of two variables each, and it decides
LINEAR integer arithmetic. Three multiplications and a cancellation, by hand. -/
theorem leRat_trans {a b c : Int × Int}
    (ha : 0 < a.2) (hb : 0 < b.2) (hc : 0 < c.2)
    (hab : leRat a b = true) (hbc : leRat b c = true) : leRat a c = true := by
  simp only [leRat, decide_eq_true_eq] at *
  -- a.1 * b.2 ≤ b.1 * a.2  and  b.1 * c.2 ≤ c.1 * b.2
  have h1 : a.1 * b.2 * c.2 ≤ b.1 * a.2 * c.2 :=
    Int.mul_le_mul_of_nonneg_right hab (Int.le_of_lt hc)
  have h2 : b.1 * c.2 * a.2 ≤ c.1 * b.2 * a.2 :=
    Int.mul_le_mul_of_nonneg_right hbc (Int.le_of_lt ha)
  -- chain them: a.1 * c.2 * b.2 ≤ c.1 * a.2 * b.2
  have h3 : a.1 * c.2 * b.2 ≤ c.1 * a.2 * b.2 := by
    have e1 := mul_swap_right a.1 b.2 c.2
    have e2 := mul_swap_right b.1 a.2 c.2
    have e3 := mul_swap_right c.1 b.2 a.2
    omega
  -- and cancel the positive b.2
  exact Int.le_of_mul_le_mul_right h3 hb

/-- **Tightening dominance never releases more.** A lower permitted share is a
tighter policy, and anything it releases the looser one releases too — so an
operator who tightens the dial cannot, by tightening it, cause a cell to appear.

This is the direction the config floors (#46) assume when they insist a floor
is a floor, and it is worth stating because the first attempt here had the
implication the wrong way round and typechecked as far as the final step. -/
theorem tightening_dominance_never_releases_more
    {p q : Policy} (hthr : p.threshold = q.threshold) (hinfl : p.infl = q.infl)
    (hp : 0 < p.dom.2) (hq : 0 < q.dom.2)
    (htight : leRat p.dom q.dom = true)                 -- p.dom ≤ q.dom
    (c : Cell) (d : Int × Int) (hd : c.dominance = some d) (hdpos : 0 < d.2) :
    releases p c = true → releases q c = true := by
  simp only [releases, passesCount, passesDominance, passesInfluence,
             passesPayload, hthr, hinfl, hd, Bool.and_eq_true, decide_eq_true_eq]
  intro h
  exact ⟨⟨⟨h.1.1.1, leRat_trans hdpos hp hq h.1.1.2 htight⟩, h.1.2⟩, h.2⟩

end SafeTre
