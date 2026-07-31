/-
The SafeSQL grammar and the abstract compiler — the Lean mirror of
safetre/engine.py::compile_query (FORMAL_METHODS_ANALYSIS §2.B).

`SafeSelect` is the *entire* SQL language of this model: one SELECT of quoted
identifiers plus at most one aggregate fragment, over exactly one view, with
WHERE atoms that carry values only as `?`-placeholder counts, an optional
GROUP BY over the same identifiers, and the fixed `ORDER BY n DESC LIMIT`
cap. There are no other constructors — no DDL or DML, no joins, no
subqueries, and no field of any value type — so "the compiled statement is a
read-only single-view SELECT" and "no data value ever appears in SQL text"
hold by construction of the type, not by inspection of strings.

`render` reproduces engine.compile_query's output byte-for-byte;
Proofs.lean checks that against the engine's actual SQL for every generated
case in Cases.lean.
-/

import SafeTre.Spec

namespace SafeTre

/-- One aggregate SELECT fragment (the O2 fragments of procedures.py). -/
inductive AggFrag
  | mean (col : String)
  | sum (col : String)
  | sumSq (col : String)
  | corr (x y : String)
deriving DecidableEq, Repr

/-- One WHERE atom. `cmp` and `inList` bind parameters; `notNull` is the
corr operand guard. No constructor holds a value. -/
inductive WhereAtom
  | cmp (col : String) (op : Op)
  | inList (col : String) (n : Nat)
  | notNull (col : String)
deriving DecidableEq, Repr

/-- The SafeSQL statement shape. -/
structure SafeSelect where
  groupBy : List String
  agg : Option AggFrag
  view : String
  whereAtoms : List WhereAtom
deriving DecidableEq, Repr

/-- The aggregate fragment of a measure (procedures.py::select_exprs). -/
def Measure.frag (m : Measure) : Option AggFrag :=
  match m.fn with
  | .count => none
  | .mean  => m.column.map .mean
  | .sum   => m.column.map .sum
  | .sumSq => m.column.map .sumSq
  | .corr  =>
      match m.x, m.y with
      | some x, some y => some (.corr x y)
      | _, _ => none

/-- The measure's NOT-NULL guard clauses, in engine order.

Every measure that reads a column guards it. `count` alone has none, because
it counts rows rather than reading a value.

This used to say "corr only", which was true of the code and wrong as a rule
(hardening #92). `AVG`/`SUM` skip NULL and `COUNT(DISTINCT donor_id)` does not,
so an unguarded one-column aggregate makes the distinct-donor threshold count a
cohort while the released value describes only its respondents. The guard is
what keeps `n`, `n_donors`, the dominance witness and the contribution frame
describing the same rows. -/
def Measure.guards (m : Measure) : List WhereAtom :=
  match m.fn with
  | .count => []
  | .mean  => (m.column.map (WhereAtom.notNull ·)).toList
  | .sum   => (m.column.map (WhereAtom.notNull ·)).toList
  | .sumSq => (m.column.map (WhereAtom.notNull ·)).toList
  | .corr  =>
      match m.x, m.y with
      | some x, some y => [.notNull x, .notNull y]
      | _, _ => []

/-- One filter as a WHERE atom (engine.py::_where_triples). -/
def filterAtom (f : Filter) : WhereAtom :=
  match f.op with
  | .isIn => .inList f.column f.nvals
  | op => .cmp f.column op

/-- The abstract compiler — engine.py::compile_query's structure. -/
def compile (s : Spec) : SafeSelect :=
  { groupBy := s.groupBy
    agg := s.measure.frag
    view := sourceView s
    whereAtoms := s.filters.map filterAtom ++ s.measure.guards }

/-! ### Rendering — byte-for-byte the engine's SQL text -/

/-- engine.py::_ident quoting (the regex check is upstream, in validity). -/
def q (c : String) : String := "\"" ++ c ++ "\""

def opStr : Op → String
  | .eq => "==" | .ne => "!=" | .lt => "<" | .le => "<="
  | .gt => ">" | .ge => ">=" | .isIn => "in"

def AggFrag.render : AggFrag → String
  | .mean c  => "MEAN(" ++ q c ++ ") AS value"
  | .sum c   => "SUM(" ++ q c ++ ") AS value"
  | .sumSq c => "SUM(" ++ q c ++ " * " ++ q c ++ ") AS value"
  | .corr x y => "CORR(" ++ q x ++ ", " ++ q y ++ ") AS value"

def WhereAtom.render : WhereAtom → String
  | .cmp c op  => q c ++ " " ++ opStr op ++ " ?"
  | .inList c n => q c ++ " IN (" ++ String.intercalate ", " (List.replicate n "?") ++ ")"
  | .notNull c => q c ++ " IS NOT NULL"

def rowCap : Nat := 10000

def render (p : SafeSelect) : String :=
  let select := p.groupBy.map q
    ++ (p.agg.map AggFrag.render).toList ++ ["COUNT(*) AS n"]
  let whereClause :=
    if p.whereAtoms.isEmpty then ""
    else " WHERE " ++ String.intercalate " AND " (p.whereAtoms.map WhereAtom.render)
  let groupClause :=
    if p.groupBy.isEmpty then ""
    else " GROUP BY " ++ String.intercalate ", " (p.groupBy.map q)
  "SELECT " ++ String.intercalate ", " select
    ++ " FROM " ++ q p.view ++ whereClause ++ groupClause
    ++ " ORDER BY n DESC LIMIT " ++ toString rowCap

/-! ### Accounting -/

def WhereAtom.params : WhereAtom → Nat
  | .cmp _ _ => 1
  | .inList _ n => n
  | .notNull _ => 0

def sumNats : List Nat → Nat
  | [] => 0
  | n :: t => n + sumNats t

/-- Bound parameters the statement expects — engine's `len(plan.params)`. -/
def SafeSelect.paramCount (p : SafeSelect) : Nat :=
  sumNats (p.whereAtoms.map WhereAtom.params)

/-- Column of one WHERE atom. -/
def WhereAtom.column : WhereAtom → String
  | .cmp c _ => c
  | .inList c _ => c
  | .notNull c => c

def AggFrag.columns : AggFrag → List String
  | .mean c => [c] | .sum c => [c] | .sumSq c => [c] | .corr x y => [x, y]

/-- Every column identifier the statement mentions. -/
def SafeSelect.mentioned (p : SafeSelect) : List String :=
  p.groupBy ++ p.whereAtoms.map WhereAtom.column
    ++ (p.agg.map AggFrag.columns).getD []

/-- Released payload columns after the group-by keys
(procedures.py::payload_columns). -/
def payloadColumns : Fn → List String
  | .count => ["n"]
  | _ => ["value", "n"]

/-- The engine plan's output columns (SQLPlan.output_columns). -/
def outputColumns (s : Spec) : List String :=
  s.groupBy ++ payloadColumns s.measure.fn

/-- Columns of the *released* frame after postprocessing: corr inserts a
derived `p_value` (procedures.py::Corr.postprocess); the gateway's
`_finalize` then drops the internal witness columns before release. -/
def releasedColumns (s : Spec) : List String :=
  s.groupBy ++
    (if s.measure.fn = .corr then ["value", "p_value", "n"]
     else payloadColumns s.measure.fn)

end SafeTre
