/-
Core types of the QuerySpec model (spec R16; FORMAL_METHODS_ANALYSIS §2 A/B).

These mirror the validated surface of safetre/query.py: every enum below is a
Pydantic `Literal` set in the code. Filter *values* are deliberately absent —
the engine only ever carries values as bound `?` parameters, so the model
abstracts a filter to its column, operator, and bound-parameter count
(`nvals`). Nothing in this model can hold a data value, which is the
type-level form of "values never appear in SQL text".
-/

namespace SafeTre

/-- Column kinds (`cat` / `bool` / `int`) — query.py's dim typing. -/
inductive Kind
  | cat
  | bool
  | int
deriving DecidableEq, Repr

/-- Disclosure roles from safetre/schema.py (`DI`/`QI`/`S`/`R`/`meta` —
the last is spelt `structural` here because `meta` is a Lean keyword). -/
inductive Role
  | di
  | qi
  | s
  | r
  | structural
deriving DecidableEq, Repr

/-- Aggregate procedures registered in safetre/procedures.py (`Measure.fn`). -/
inductive Fn
  | count
  | mean
  | sum
  | sumSq
  | corr
deriving DecidableEq, Repr

/-- Filter operators (`Filter.op` Literal in query.py). -/
inductive Op
  | eq
  | ne
  | lt
  | le
  | gt
  | ge
  | isIn
deriving DecidableEq, Repr

/-- A filter shape: column, operator, and how many `?` parameters it binds
(an `in`-list's length; exactly 1 for every scalar operator), and — for a
scalar integer comparison only — the value itself.

`value` is the one place this model holds a datum, and it is here for exactly
one reason: the band-alignment rule of hardening #39 is a statement ABOUT the
value, so a model that abstracts values away cannot express the property that
closed the finest differencing channel found so far. It is inert everywhere
else: `Sql.filterAtom` does not read it, and
`Proofs.compile_ignores_filter_values` proves the compiled statement is
identical for any two values — the theorem form of "values never appear in
SQL text", stronger than the silence it replaces. -/
structure Filter where
  column : String
  op : Op
  nvals : Nat
  value : Option Int
deriving DecidableEq, Repr

/-- A measure: `count` uses no column, `mean`/`sum`/`sum_sq` use `column`,
`corr` uses `x`/`y` — exactly query.py's `Measure`. -/
structure Measure where
  fn : Fn
  column : Option String := none
  x : Option String := none
  y : Option String := none
deriving DecidableEq, Repr

/-- The QuerySpec surface: dataset, measure, group-by, filter shapes. -/
structure Spec where
  dataset : String
  measure : Measure
  groupBy : List String := []
  filters : List Filter := []
deriving DecidableEq, Repr

end SafeTre
