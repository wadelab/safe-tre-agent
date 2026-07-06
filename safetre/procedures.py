"""Statistical procedures as registered contracts (spec R14).

A procedure is the unit of statistical capability: `count`, `mean`, `sum`,
Pearson `corr`. Each is a registered object that declares and discharges the
obligations of `docs/verifiable-extensions.md` §2:

- O1 admissibility — `validate_measure` accepts only allowlisted columns of the
  right kind, so identifiers/free-text/raw internal variables are not
  expressible;
- O2 compilation safety — a procedure supplies only *select-expression
  fragments* (`select_exprs`); the proven SafeSQL shape (single SELECT over one
  declared view, bound parameters, ORDER BY n DESC LIMIT cap) stays centralised
  in `engine.compile_query`, so a procedure cannot deviate from the shape, only
  inject `_ident`-checked aggregate expressions;
- O3 individual-influence bound — `witness_plans` returns the internal
  per-donor safety queries (`dominance`, `influence`) the gateway suppresses
  on and drops before release;
- O4 lineage identity — inherited: every procedure expresses its cohort
  through the standard `QuerySpec.filters`;
- output contract — `output_contract` names every released payload column and
  its disclosure class, so the gateway's treatment of an output is declared,
  not inferred from column names (the gap behind hardening #25);
- skeleton export — `measure_configs` enumerates the procedure's finite
  measure space for the exhaustive-enumeration check and the formal model.

The registry is the sole dispatch point (R14): validation, compilation,
execution, and disclosure classification all go through `get_procedure`, and an
unregistered function fails loudly rather than falling through to another
procedure's behaviour.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterator, Literal

if TYPE_CHECKING:  # types only — the engine imports this module at runtime
    import pandas as pd

    from .engine import SQLPlan
    from .query import Measure, QuerySpec

# How the gateway must treat a released column (spec R14):
#   cell_key  - a group-by key naming the cell
#   count     - a frequency: threshold-checked on donors, rounded on release
#   magnitude - a donor-additive quantity (sum/mean-like): dominance-checked
#   statistic - a bounded derived statistic (e.g. r): influence-checked
#   p_value   - a significance level derived from a released statistic
DisclosureClass = Literal["cell_key", "count", "magnitude", "statistic", "p_value"]


@dataclass(frozen=True)
class WitnessPlan:
    """An internal safety query and the helper column it attaches.

    The engine executes `plan` on the unit view, merges `column` onto the
    result (fail-closed: unresolved cells fill `+inf`), the gateway suppresses
    on it, and `_finalize` drops it before release.
    """

    plan: SQLPlan
    column: str


class AggregateProcedure:
    """Base class for single-query aggregate procedures.

    Subclasses fill in the class attributes and override the methods whose
    defaults do not apply. `fn` must match the `Measure.fn` literal member.
    """

    fn: str
    reads_individual_values: bool
    influence_control: str | None  # witness column name, None iff no per-value reads

    # --- O1: admissibility ----------------------------------------------------
    def validate_measure(self, m: Measure, cat: dict, dataset: str) -> None:
        raise NotImplementedError

    def measure_columns(self, m: Measure) -> tuple[str, ...]:
        """Measure columns this procedure reads (drives internal-view routing)."""
        return ()

    # --- O2: compilation fragments ---------------------------------------------
    def select_exprs(self, m: Measure) -> tuple[list[str], tuple[str, ...]]:
        """(SELECT fragments, extra NOT-NULL guard clauses) for the public SQL."""
        raise NotImplementedError

    def payload_columns(self, m: Measure) -> tuple[str, ...]:
        """Released payload columns, in order, after the group-by keys."""
        return ("value", "n")

    def postprocess(self, df: pd.DataFrame, spec: QuerySpec) -> pd.DataFrame:
        """Released-value shaping (rounding, derived statistics). No new data."""
        return df

    # --- O3: influence witnesses -----------------------------------------------
    def witness_plans(self, spec: QuerySpec) -> list[WitnessPlan]:
        return []

    # --- output contract ---------------------------------------------------------
    def output_contract(self, m: Measure) -> dict[str, DisclosureClass]:
        """Disclosure class of every payload column (group-by keys are implicit
        `cell_key`s). Every column in `payload_columns` must be classified."""
        raise NotImplementedError

    # --- skeleton export ----------------------------------------------------------
    def measure_configs(self, cat: dict) -> Iterator[dict[str, Any]]:
        """Every admissible measure configuration on one catalogue entry."""
        raise NotImplementedError


def _ident(name: str) -> str:
    # late import to keep module import acyclic (engine imports procedures)
    from .engine import _ident as engine_ident

    return engine_ident(name)


class Count(AggregateProcedure):
    fn = "count"
    reads_individual_values = False
    influence_control = None

    def validate_measure(self, m: Measure, cat: dict, dataset: str) -> None:
        if m.column is not None or m.x is not None or m.y is not None:
            raise ValueError("count takes no column")

    def select_exprs(self, m: Measure) -> tuple[list[str], tuple[str, ...]]:
        # A count's payload IS the row count, released as `n` alone. A duplicate
        # `COUNT(*) AS value` would escape count rounding (hardening #25).
        return [], ()

    def payload_columns(self, m: Measure) -> tuple[str, ...]:
        return ("n",)

    def output_contract(self, m: Measure) -> dict[str, DisclosureClass]:
        return {"n": "count"}

    def measure_configs(self, cat: dict) -> Iterator[dict[str, Any]]:
        yield {"fn": "count"}


class _ColumnAggregate(AggregateProcedure):
    """Shared behaviour for one-public-column aggregates (mean/sum/sum_sq)."""

    reads_individual_values = True
    influence_control = "dominance"

    def validate_measure(self, m: Measure, cat: dict, dataset: str) -> None:
        if m.x is not None or m.y is not None:
            raise ValueError(f"{self.fn} takes one column, not x/y")
        if m.column not in cat["measures"]:
            raise ValueError(
                f"measure column {m.column!r} not allowed for "
                f"dataset {dataset!r} (allowed: {sorted(cat['measures'])})")

    def measure_columns(self, m: Measure) -> tuple[str, ...]:
        return (m.column,)

    def select_exprs(self, m: Measure) -> tuple[list[str], tuple[str, ...]]:
        # fn is a Literal allowlist; column is allowlist- and regex-validated
        return [f"{self.fn.upper()}({_ident(m.column)}) AS value"], ()

    def postprocess(self, df: pd.DataFrame, spec: QuerySpec) -> pd.DataFrame:
        df["value"] = df["value"].round(2)
        return df

    def witness_plans(self, spec: QuerySpec) -> list[WitnessPlan]:
        from .engine import compile_dominance_query

        return [WitnessPlan(plan=compile_dominance_query(spec), column="dominance")]

    def output_contract(self, m: Measure) -> dict[str, DisclosureClass]:
        return {"value": "magnitude", "n": "count"}

    def measure_configs(self, cat: dict) -> Iterator[dict[str, Any]]:
        for column in sorted(cat["measures"]):
            yield {"fn": self.fn, "column": column}


class Mean(_ColumnAggregate):
    fn = "mean"


class Sum(_ColumnAggregate):
    fn = "sum"


class Corr(AggregateProcedure):
    fn = "corr"
    reads_individual_values = True
    influence_control = "influence"

    def validate_measure(self, m: Measure, cat: dict, dataset: str) -> None:
        corr_measures = cat["measures"] | cat.get("internal_measures", set())
        if m.column is not None:
            raise ValueError("corr takes x and y, not column")
        if m.x not in corr_measures or m.y not in corr_measures:
            raise ValueError(
                f"corr x/y must be approved analysis measure columns for dataset "
                f"{dataset!r} (allowed: {sorted(corr_measures)})")
        if m.x == m.y:
            raise ValueError("corr requires two distinct measure columns")

    def measure_columns(self, m: Measure) -> tuple[str, ...]:
        return (m.x, m.y)

    def select_exprs(self, m: Measure) -> tuple[list[str], tuple[str, ...]]:
        x, y = _ident(m.x), _ident(m.y)
        return ([f"CORR({x}, {y}) AS value"], (f"{x} IS NOT NULL", f"{y} IS NOT NULL"))

    def postprocess(self, df: pd.DataFrame, spec: QuerySpec) -> pd.DataFrame:
        # p_value is derived in postprocessing, so it appears in the output
        # contract but not in the compiled SQL's payload_columns
        from .stats import pearson_p_value

        df["value"] = df["value"].round(4)
        p_values = [
            pearson_p_value(float(r), int(n))
            for r, n in zip(df["value"], df["n"], strict=True)
        ]
        df.insert(df.columns.get_loc("value") + 1, "p_value", p_values)
        df["p_value"] = df["p_value"].round(3)
        return df

    def witness_plans(self, spec: QuerySpec) -> list[WitnessPlan]:
        from .engine import compile_influence_query

        return [WitnessPlan(plan=compile_influence_query(spec), column="influence")]

    def output_contract(self, m: Measure) -> dict[str, DisclosureClass]:
        return {"value": "statistic", "p_value": "p_value", "n": "count"}

    def measure_configs(self, cat: dict) -> Iterator[dict[str, Any]]:
        pool = sorted(cat["measures"] | cat.get("internal_measures", set()))
        for x, y in itertools.combinations(pool, 2):
            yield {"fn": "corr", "x": x, "y": y}


REGISTRY: dict[str, AggregateProcedure] = {
    p.fn: p for p in (Count(), Mean(), Sum(), Corr())
}


def get_procedure(fn: str) -> AggregateProcedure:
    """Sole dispatch point (R14): unknown functions fail loudly."""
    try:
        return REGISTRY[fn]
    except KeyError:
        raise ValueError(f"no registered procedure for measure fn {fn!r}") from None
