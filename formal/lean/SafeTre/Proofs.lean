/-
The machine-checked properties (FORMAL_METHODS_ANALYSIS §2 A/B, roadmap
Phases 1–2). Three groups:

1. Catalogue facts, proved by `decide` over the generated data — exhaustive
   over the real catalogue, labels, and live view columns, in the same sense
   as the Alloy model's exact-bounds checks.
2. Structural theorems over *all* specs (an infinite space — filter counts
   and names are unbounded): a valid spec references only allowlisted
   columns, hence never an identifier; compilation mentions only referenced
   columns, reads one declared view, and binds one parameter per filter
   value; the released frame carries only group-by keys and fixed payload
   names.
3. The engine pin: for every generated case, the abstract compiler's
   rendered SQL equals engine.compile_query's actual output byte for byte
   (`native_decide` — evaluated by compiled code; the pytest sync hop
   independently regenerates the same pairs from the live engine).
-/

import SafeTre.Sql
import SafeTre.Cases

-- several `<;>`-joined branches share a simp set; per-branch unused-argument
-- lint noise is expected there
set_option linter.unusedSimpArgs false

namespace SafeTre

/-! ## 1. Catalogue facts (exhaustive over the generated data) -/

/-- Columns that may filter but never appear in any output. -/
def internalColumns (ds : String) : List String :=
  (internalFiltersOf ds).map (·.1) ++ internalMeasuresOf ds

/-- No column any valid spec can reference is an identifier, free-text, or
timestamp column (opportunity A, the set-membership core). -/
theorem allowed_never_forbidden :
    ∀ ds ∈ datasets, ∀ c ∈ allowedColumns ds, c ∉ forbiddenColumns := by
  decide

/-- Public group-by dimensions are disjoint from internal-only columns. -/
theorem dims_disjoint_internal :
    ∀ ds ∈ datasets, ∀ c ∈ (dimsOf ds).map (·.1), c ∉ internalColumns ds := by
  decide

/-- Label totality: every referencable column carries a disclosure role. -/
theorem labels_cover_catalogue :
    ∀ ds ∈ datasets, ∀ c ∈ allowedColumns ds, (roleOf? c).isSome := by
  decide

/-- Label consistency: no referencable column is labelled DI. -/
theorem no_di_referencable :
    ∀ ds ∈ datasets, ∀ c ∈ allowedColumns ds, roleOf? c ≠ some .di := by
  decide

/-- Label consistency: group-by keys are never sensitive or identifying —
cell keys are QI/reference/structural columns only. -/
theorem group_keys_not_sensitive :
    ∀ ds ∈ datasets, ∀ c ∈ (dimsOf ds).map (·.1),
      roleOf? c ≠ some .s ∧ roleOf? c ≠ some .di := by
  decide

/-- Label consistency: every aggregable public measure is sensitive — which
is why measures may only leave as gateway-checked aggregates. -/
theorem measures_are_sensitive :
    ∀ ds ∈ datasets, ∀ c ∈ measuresOf ds, roleOf? c = some .s := by
  decide

/-- The engine's live PUBLIC views expose no forbidden column (checked
against the DuckDB-described column lists, not the source text). -/
theorem public_views_identifier_free :
    ∀ ds ∈ datasets, ∀ c ∈ publicViewColumns ds,
      c ∉ forbiddenColumns ∧ roleOf? c ≠ some .di := by
  decide

/-- Honesty: the INTERNAL unit views do carry the identifier — they exist
for fixed tools and disclosure machinery; the compilation theorems below
show compiled statements never select it. -/
theorem unit_views_carry_identifier :
    ∀ ds ∈ datasets, "donor_id" ∈ unitViewColumns ds := by
  decide

/-- Every referencable column exists on the unit view of its dataset. -/
theorem allowed_subset_unit_view :
    ∀ ds ∈ datasets, ∀ c ∈ allowedColumns ds, c ∈ unitViewColumns ds := by
  decide

/-- Every public dim/measure exists on the public view of its dataset. -/
theorem public_pool_in_public_view :
    ∀ ds ∈ datasets, ∀ c ∈ (dimsOf ds).map (·.1) ++ measuresOf ds,
      c ∈ publicViewColumns ds := by
  decide

/-- Fixed output names are neither forbidden nor internal nor witnesses. -/
theorem fixed_payload_names_safe :
    ∀ ds ∈ datasets, ∀ c ∈ ["value", "p_value", "n"],
      c ∉ forbiddenColumns ∧ c ∉ internalColumns ds ∧
      c ∉ ["dominance", "influence", "n_donors"] := by
  decide

/-- Group-by dimension names are never witness-column names. -/
theorem dims_not_witness_names :
    ∀ ds ∈ datasets, ∀ c ∈ (dimsOf ds).map (·.1),
      c ∉ ["dominance", "influence", "n_donors"] := by
  decide

/-! ## 2. Structural theorems over all specs -/

/-- A `lookup` hit means the key is present. -/
theorem mem_keys_of_lookup_isSome :
    ∀ {l : List (String × Kind)} {c : String},
      (l.lookup c).isSome → c ∈ l.map (·.1)
  | [], _, h => by simp [List.lookup] at h
  | (k, v) :: t, c, h => by
    simp only [List.lookup] at h
    cases hc : c == k
    · rw [hc] at h
      exact List.mem_cons_of_mem _ (mem_keys_of_lookup_isSome h)
    · have : c = k := eq_of_beq hc
      simp [this]

/-- A valid spec's dataset is catalogued. -/
theorem valid_dataset_mem {s : Spec} (h : valid s = true) :
    s.dataset ∈ datasets := by
  simp only [valid, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1.1.1

/-- A valid spec's group-by keys are public dimensions. -/
theorem valid_groupBy_dims {s : Spec} (h : valid s = true) :
    ∀ c ∈ s.groupBy, c ∈ (dimsOf s.dataset).map (·.1) := by
  simp only [valid, Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.2

/-- A valid spec's filters all validate. -/
theorem valid_filters_all {s : Spec} (h : valid s = true) :
    ∀ f ∈ s.filters, validFilter s.dataset f = true := by
  simp only [valid, Bool.and_eq_true, List.all_eq_true] at h
  exact h.1.2

/-- A valid spec's measure is admissible. -/
theorem valid_measure {s : Spec} (h : valid s = true) :
    validMeasure s.dataset s.measure = true := by
  simp only [valid, Bool.and_eq_true] at h
  exact h.2

/-- A valid spec's filter columns are filterable (dims or internal filters). -/
theorem valid_filter_columns {s : Spec} (h : valid s = true) :
    ∀ c ∈ s.filters.map (·.column),
      c ∈ (filterColumnsOf s.dataset).map (·.1) := by
  intro c hc
  rcases List.mem_map.1 hc with ⟨f, hf, rfl⟩
  have hvf := valid_filters_all h f hf
  unfold validFilter at hvf
  cases hk : (filterColumnsOf s.dataset).lookup f.column with
  | none => rw [hk] at hvf; cases hvf
  | some k => exact mem_keys_of_lookup_isSome (by simp [hk])

/-- A valid measure's columns coincide with the columns it reads. -/
theorem measure_columns_eq_read {ds : String} {m : Measure}
    (h : validMeasure ds m = true) :
    m.columns = measureReadColumns m := by
  unfold Measure.columns measureReadColumns
  cases hfn : m.fn <;>
    simp only [validMeasure, hfn, Bool.and_eq_true,
               Option.isNone_iff_eq_none] at h
  case count => simp [h.1.1, h.1.2, h.2]
  case corr => simp [h.1]
  all_goals simp [h.1.1, h.1.2]

/-- A valid spec's measure columns are in the corr pool
(public measures plus internal analysis measures). -/
theorem valid_measure_columns {s : Spec} (h : valid s = true) :
    ∀ c ∈ s.measure.columns, c ∈ corrPoolOf s.dataset := by
  intro c hc
  have hm := valid_measure h
  cases hfn : s.measure.fn <;>
    simp only [validMeasure, hfn, Bool.and_eq_true,
               Option.isNone_iff_eq_none] at hm
  case count =>
    simp [Measure.columns, hm.1.1, hm.1.2, hm.2] at hc
  case corr =>
    obtain ⟨hcol, hxy⟩ := hm
    split at hxy
    · rename_i x y hx hy
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hxy
      simp [Measure.columns, hcol, hx, hy] at hc
      rcases hc with rfl | rfl
      · exact hxy.1.2
      · exact hxy.2
    · simp at hxy
  all_goals {
    obtain ⟨⟨hx, hy⟩, hcol⟩ := hm
    split at hcol
    · rename_i c0 heq
      simp only [decide_eq_true_eq] at hcol
      simp [Measure.columns, hx, hy, heq] at hc
      subst hc
      exact List.mem_append_left _ hcol
    · simp at hcol
  }

/-- Group-by keys sit inside the allowlist. -/
theorem dims_sub_allowed {ds c} (hc : c ∈ (dimsOf ds).map (·.1)) :
    c ∈ allowedColumns ds := by
  apply List.mem_append_left
  simp only [filterColumnsOf, List.map_append]
  exact List.mem_append_left _ hc

/-- **Opportunity A — no valid QuerySpec references an identifier.**
Every column a valid spec mentions is allowlisted, and the allowlists are
disjoint from the identifier/free-text/timestamp set. Holds for the whole
(unbounded) spec space, independent of any test suite. -/
theorem no_identifier_reference {s : Spec} (h : valid s = true) :
    ∀ c ∈ referenced s, c ∉ forbiddenColumns := by
  intro c hc
  apply allowed_never_forbidden s.dataset (valid_dataset_mem h) c
  unfold referenced at hc
  rcases List.mem_append.1 hc with hc | hcm
  · rcases List.mem_append.1 hc with hg | hf
    · exact dims_sub_allowed (valid_groupBy_dims h c hg)
    · exact List.mem_append_left _ (valid_filter_columns h c hf)
  · exact List.mem_append_right _ (valid_measure_columns h c hcm)

/-- Internal-only non-release, part 1: internal columns are never group-by
keys of a valid spec. -/
theorem internal_never_grouped {s : Spec} (h : valid s = true) :
    ∀ c ∈ s.groupBy, c ∉ internalColumns s.dataset := fun c hc =>
  dims_disjoint_internal s.dataset (valid_dataset_mem h) c
    (valid_groupBy_dims h c hc)

/-- A released column is a group-by key or a fixed payload name. -/
theorem released_key_or_payload {s : Spec} :
    ∀ c ∈ releasedColumns s, c ∈ s.groupBy ∨ c ∈ ["value", "p_value", "n"] := by
  intro c hc
  unfold releasedColumns at hc
  rcases List.mem_append.1 hc with hg | hp
  · exact Or.inl hg
  · right
    split at hp
    · exact hp
    · unfold payloadColumns at hp
      split at hp <;> simp at hp
      · subst hp; simp
      · rcases hp with rfl | rfl <;> simp

/-- **End-to-end composition (validation → engine → gateway):** the released
frame of a valid spec carries only its group-by keys and fixed payload names
— never an identifier/free-text/timestamp column, never an internal-only
column, and never an internal witness column (those are attached for the
gateway and dropped by `_finalize` before release). -/
theorem end_to_end_release_safe {s : Spec} (h : valid s = true) :
    ∀ c ∈ releasedColumns s,
      c ∉ forbiddenColumns ∧ c ∉ internalColumns s.dataset ∧
      c ∉ ["dominance", "influence", "n_donors"] := by
  intro c hc
  have hds := valid_dataset_mem h
  rcases released_key_or_payload c hc with hg | hfix
  · have hdim := valid_groupBy_dims h c hg
    exact ⟨allowed_never_forbidden s.dataset hds c (dims_sub_allowed hdim),
           dims_disjoint_internal s.dataset hds c hdim,
           dims_not_witness_names s.dataset hds c hdim⟩
  · have := fixed_payload_names_safe s.dataset hds c hfix
    exact ⟨this.1, this.2.1, this.2.2⟩

/-! ## 3. Compilation safety (opportunity B) -/

/-- `filterAtom` preserves the column. -/
theorem filterAtom_column (f : Filter) :
    (filterAtom f).column = f.column := by
  unfold filterAtom
  cases f.op <;> rfl

/-- Guard atoms name only measure columns. -/
theorem guard_columns_sub_measure (m : Measure) :
    ∀ c ∈ (m.guards).map WhereAtom.column, c ∈ m.columns := by
  intro c hc
  unfold Measure.guards at hc
  cases hfn : m.fn <;> rw [hfn] at hc <;> simp at hc
  cases hx : m.x <;> cases hy : m.y <;> rw [hx, hy] at hc <;>
    simp [WhereAtom.column] at hc
  unfold Measure.columns
  rcases hc with rfl | rfl <;> simp [hx, hy]

/-- Aggregate-fragment columns name only measure columns. -/
theorem frag_columns_sub_measure (m : Measure) :
    ∀ {a}, m.frag = some a → ∀ c ∈ a.columns, c ∈ m.columns := by
  intro a ha c hc
  unfold Measure.frag at ha
  unfold Measure.columns
  cases hfn : m.fn <;> rw [hfn] at ha
  case count => cases ha
  case corr =>
    cases hx : m.x <;> cases hy : m.y <;> rw [hx, hy] at ha <;> cases ha
    simp [AggFrag.columns] at hc
    rcases hc with rfl | rfl <;> simp [hx, hy]
  all_goals {
    cases hcv : m.column <;> rw [hcv] at ha <;> cases ha
    simp [AggFrag.columns] at hc
    subst hc
    simp [hcv]
  }

/-- Everything a compiled statement mentions, the spec referenced. Holds for
every spec, valid or not — compilation invents no identifiers. -/
theorem compile_mentions_referenced (s : Spec) :
    ∀ c ∈ (compile s).mentioned, c ∈ referenced s := by
  intro c hc
  simp only [compile, SafeSelect.mentioned, List.map_append,
             List.mem_append] at hc
  unfold referenced
  rcases hc with (hg | hf | hguard) | hagg
  · exact List.mem_append_left _ (List.mem_append_left _ hg)
  · rcases List.mem_map.1 hf with ⟨a, hamem, rfl⟩
    rcases List.mem_map.1 hamem with ⟨g, hg, rfl⟩
    rw [filterAtom_column]
    exact List.mem_append_left _
      (List.mem_append_right _ (List.mem_map_of_mem hg))
  · exact List.mem_append_right _
      (guard_columns_sub_measure s.measure c hguard)
  · apply List.mem_append_right
    cases ha : s.measure.frag with
    | none => simp [ha] at hagg
    | some a =>
        simp [ha] at hagg
        exact frag_columns_sub_measure s.measure ha c hagg

/-- **Opportunity B, part 1 — no identifier in any compiled statement** of a
valid spec: not selected, not filtered, not guarded. -/
theorem compile_mentions_no_identifier {s : Spec} (h : valid s = true) :
    ∀ c ∈ (compile s).mentioned, c ∉ forbiddenColumns := fun c hc =>
  no_identifier_reference h c (compile_mentions_referenced s c hc)

/-- **Opportunity B, part 2 — one declared source view.** A compiled
statement reads the spec's public view, or its unit view exactly when the
spec uses declared internal columns (engine._source_view). -/
theorem compile_single_declared_view (s : Spec) :
    (compile s).view = (if usesInternalSource s
                        then "_" ++ s.dataset ++ "_u" else s.dataset) := rfl

/-- **Opportunity B, part 3 — mentioned columns exist on the source view.**
On the public branch nothing internal is mentioned; on the internal branch
everything mentioned is still allowlisted — never the identifier. -/
theorem compile_mentions_on_view {s : Spec} (h : valid s = true) :
    ∀ c ∈ (compile s).mentioned,
      c ∈ (if usesInternalSource s
           then unitViewColumns s.dataset else publicViewColumns s.dataset) := by
  intro c hc
  have hds := valid_dataset_mem h
  have href := compile_mentions_referenced s c hc
  cases hint : usesInternalSource s
  · show c ∈ publicViewColumns s.dataset
    apply public_pool_in_public_view s.dataset hds c
    simp only [usesInternalSource, Bool.or_eq_false_iff,
               List.any_eq_false, Bool.not_eq_true] at hint
    unfold referenced at href
    rcases List.mem_append.1 href with h1 | hm
    · rcases List.mem_append.1 h1 with hg | hf
      · exact List.mem_append_left _ (valid_groupBy_dims h c hg)
      · -- a filter column that is not internal is a public dim
        rcases List.mem_map.1 hf with ⟨f, hfmem, rfl⟩
        have hcol := valid_filter_columns h _ (List.mem_map_of_mem hfmem)
        simp only [filterColumnsOf, List.map_append, List.mem_append] at hcol
        rcases hcol with hd | hi
        · exact List.mem_append_left _ hd
        · exfalso
          rcases List.mem_map.1 hi with ⟨p, hp, hpc⟩
          have := hint.1 f hfmem p hp
          rw [hpc] at this
          simp at this
    · -- a measure column that is not internal is a public measure
      rcases List.mem_append.1 (valid_measure_columns h c hm) with hpub | hintm
      · exact List.mem_append_right _ hpub
      · exfalso
        have hcm : c ∈ measureReadColumns s.measure := by
          rw [← measure_columns_eq_read (valid_measure h)]; exact hm
        have hnot : c ∉ internalMeasuresOf s.dataset := by
          simpa [List.contains_eq_mem] using hint.2 c hcm
        exact hnot hintm
  · show c ∈ unitViewColumns s.dataset
    apply allowed_subset_unit_view s.dataset hds c
    unfold referenced at href
    rcases List.mem_append.1 href with h1 | hm
    · rcases List.mem_append.1 h1 with hg | hf
      · exact dims_sub_allowed (valid_groupBy_dims h c hg)
      · exact List.mem_append_left _ (valid_filter_columns h c hf)
    · exact List.mem_append_right _ (valid_measure_columns h c hm)

/-! ### Parameter accounting -/

theorem sumNats_append (a b : List Nat) :
    sumNats (a ++ b) = sumNats a + sumNats b := by
  induction a with
  | nil => simp [sumNats]
  | cons n t ih => simp [sumNats, ih, Nat.add_assoc]

/-- Guards bind no parameters. -/
theorem guards_bind_nothing (m : Measure) :
    sumNats ((m.guards).map WhereAtom.params) = 0 := by
  unfold Measure.guards
  cases m.fn <;> simp [sumNats]
  cases m.x <;> cases m.y <;> simp [sumNats, WhereAtom.params]

/-- A valid filter's atom binds exactly its value count. -/
theorem filterAtom_params {ds : String} {f : Filter}
    (h : validFilter ds f = true) :
    (filterAtom f).params = f.nvals := by
  unfold validFilter at h
  cases hk : (filterColumnsOf ds).lookup f.column <;> rw [hk] at h
  · cases h
  · simp only [Bool.and_eq_true] at h
    have hv := h.2
    cases ho : f.op <;> rw [ho] at hv
    case isIn => simp [filterAtom, ho, WhereAtom.params]
    all_goals {
      rw [if_neg (by simp)] at hv
      simp only [decide_eq_true_eq] at hv
      simp [filterAtom, ho, WhereAtom.params, hv]
    }

/-- Valid filter lists bind one parameter per value. -/
theorem sum_params_of_valid {ds : String} :
    ∀ {fs : List Filter}, (∀ f ∈ fs, validFilter ds f = true) →
      sumNats ((fs.map filterAtom).map WhereAtom.params)
        = sumNats (fs.map (·.nvals))
  | [], _ => rfl
  | f :: t, h => by
    simp only [List.map_cons, sumNats]
    rw [filterAtom_params (h f (List.mem_cons_self ..)),
        sum_params_of_valid (fun x hx => h x (List.mem_cons_of_mem _ hx))]

/-- **Opportunity B, part 4 — parameter accounting.** A valid spec's
compiled statement binds exactly one parameter per filter value; guards bind
none. Values themselves cannot appear anywhere: no type in the model can
hold one. -/
theorem compile_param_accounting {s : Spec} (h : valid s = true) :
    (compile s).paramCount = sumNats (s.filters.map (·.nvals)) := by
  simp only [compile, SafeSelect.paramCount, List.map_append, sumNats_append,
             guards_bind_nothing, Nat.add_zero]
  exact sum_params_of_valid (valid_filters_all h)

/-! ## 4. The engine pin (generated cases) -/

/-- The model is inhabited: a canonical spec validates (vacuity guard,
mirroring the Alloy model's `someAdmissibleSpec`). -/
theorem model_inhabited :
    valid ⟨"spend", ⟨.mean, some "amount_gbp", none, none⟩,
           ["age_band"], [⟨"sex", .eq, 1⟩]⟩ = true := by decide

/-- The covering enumeration is present (vacuity guard for the pin). -/
theorem cases_nonempty : cases.isEmpty = false := by native_decide

/-- **The pin:** every generated case validates, renders byte-for-byte to
engine.compile_query's SQL, and agrees on the bound-parameter count.
(`native_decide`: checked by compiled evaluation; the pytest sync hop
independently regenerates the same pairs from the live engine.) -/
theorem cases_pin_engine :
    cases.all (fun c =>
      valid c.1 && (render (compile c.1) == c.2.1) &&
      ((compile c.1).paramCount == c.2.2)) = true := by native_decide

end SafeTre
