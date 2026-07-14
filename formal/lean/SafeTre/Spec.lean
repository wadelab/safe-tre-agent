/-
QuerySpec validity — the Lean mirror of safetre/query.py::QuerySpec's
validators plus the procedure admissibility checks (O1) of
safetre/procedures.py.

What is abstracted: filter *values*. query.py type-checks them per column
kind; here a filter carries only its bound-parameter count, because no later
stage of the model (or of the engine) ever interpolates a value into SQL.
The property-based suite (tests/test_query_properties.py) covers the value
typing on the code side.
-/

import SafeTre.Catalogue

namespace SafeTre

/-- Operators permitted per column kind (query.py CAT_OPS / NUM_OPS). -/
def kindOps : Kind → List Op
  | .cat  => [.eq, .ne, .isIn]
  | .bool => [.eq, .ne, .isIn]
  | .int  => [.eq, .ne, .lt, .le, .gt, .ge, .isIn]

/-- Columns a spec may filter on: public dims plus internal-only filters
(query.py::check_filters). -/
def filterColumnsOf (ds : String) : List (String × Kind) :=
  dimsOf ds ++ internalFiltersOf ds

/-- Operand pool for corr: public measures plus internal analysis measures
(procedures.py::Corr.validate_measure). -/
def corrPoolOf (ds : String) : List String :=
  measuresOf ds ++ internalMeasuresOf ds

/-- Every column name a valid spec of dataset `ds` can reference. -/
def allowedColumns (ds : String) : List String :=
  (filterColumnsOf ds).map (·.1) ++ corrPoolOf ds

def maxGroupBy : Nat := 3
def maxFilters : Nat := 5
def maxInValues : Nat := 50

/-- query.py::check_filters + _check_filter_value (value shape only). -/
def validFilter (ds : String) (f : Filter) : Bool :=
  match (filterColumnsOf ds).lookup f.column with
  | none => false
  | some k =>
      (kindOps k).contains f.op &&
      (if f.op = .isIn
       then decide (1 ≤ f.nvals) && decide (f.nvals ≤ maxInValues)
       else decide (f.nvals = 1))

/-- Procedure admissibility (O1), per registered fn. -/
def validMeasure (ds : String) (m : Measure) : Bool :=
  match m.fn with
  | .count => m.column.isNone && m.x.isNone && m.y.isNone
  | .corr =>
      m.column.isNone &&
      match m.x, m.y with
      | some x, some y =>
          decide (x ≠ y) &&
          decide (x ∈ corrPoolOf ds) && decide (y ∈ corrPoolOf ds)
      | _, _ => false
  | _ =>
      m.x.isNone && m.y.isNone &&
      match m.column with
      | some c => decide (c ∈ measuresOf ds)
      | none => false

/-- QuerySpec validity (query.py::QuerySpec, all validators). -/
def valid (s : Spec) : Bool :=
  decide (s.dataset ∈ datasets) &&
  decide (s.groupBy.length ≤ maxGroupBy) &&
  (s.groupBy.eraseDups == s.groupBy) &&
  s.groupBy.all (fun g => decide (g ∈ (dimsOf s.dataset).map (·.1))) &&
  decide (s.filters.length ≤ maxFilters) &&
  s.filters.all (validFilter s.dataset) &&
  validMeasure s.dataset s.measure

/-- The columns a measure names (query.py::Measure fields). -/
def Measure.columns (m : Measure) : List String :=
  m.column.toList ++ m.x.toList ++ m.y.toList

/-- Every column a spec references, across group-by, filters, and measure. -/
def referenced (s : Spec) : List String :=
  s.groupBy ++ s.filters.map (·.column) ++ s.measure.columns

/-- The measure columns the procedure *reads*
(procedures.py::measure_columns — drives internal-view routing). -/
def measureReadColumns (m : Measure) : List String :=
  match m.fn with
  | .count => []
  | .corr => m.x.toList ++ m.y.toList
  | _ => m.column.toList

/-- engine.py::_uses_internal_source. -/
def usesInternalSource (s : Spec) : Bool :=
  s.filters.any (fun f =>
    (internalFiltersOf s.dataset).any (fun p => p.1 == f.column)) ||
  (measureReadColumns s.measure).any
    (fun c => (internalMeasuresOf s.dataset).contains c)

/-- engine.py::_source_view — the one declared view a spec compiles against. -/
def sourceView (s : Spec) : String :=
  if usesInternalSource s then "_" ++ s.dataset ++ "_u" else s.dataset

end SafeTre
