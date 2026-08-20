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
#   moment2   - a donor-additive SECOND moment (sum of squares): dominance-
#               checked on the squared scale, where the same nominal bound is
#               a much tighter rule (see VettingParameters.dominance_for)
#   moment3   - a donor-additive THIRD moment (sum of cubes): dominance-checked
#               on the SIGNED cubed scale (the witness is magnitude-and-released-
#               total aware, so it bounds a signed contribution correctly)
#   moment4   - a donor-additive FOURTH moment (sum of fourth powers): dominance-
#               checked on the fourth-power scale, where a single outlier's share
#               is higher still, so the same bound suppresses more concentration
#   statistic - a bounded derived statistic (e.g. r): influence-checked
#   p_value   - a significance level derived from a released statistic
DisclosureClass = Literal["cell_key", "count", "magnitude", "moment2",
                          "moment3", "moment4", "statistic", "p_value"]


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

    def contribution_expr(self, m: Measure) -> str | None:
        """SQL for one donor's contribution to a cell, or None if the
        procedure has no donor-additive contribution.

        An external output checker (roadmap item 1) decides on contributions,
        not on finished cells: a frequency threshold counts donors and the
        dominance rules need each donor's share, neither of which survives
        aggregation. Declaring the expression here rather than in the caller
        keeps it with the procedure that knows the scale its rule works on —
        `sum_sq` contributes on the squared scale, and getting that wrong
        would have the checker bound the wrong quantity.

        None means "no donor-additive contribution": `count` needs only donor
        presence, and `corr` has no ACRO analogue at all (best-practice D6).
        """
        return None

    def checker_aggfunc(self, m: Measure) -> str | None:
        """How an external checker must aggregate those contributions.

        A `mean` cell and a `sum` cell over the same contributions are
        different tables, and a checker told the wrong one checks the wrong
        numbers. None where there is nothing to aggregate.
        """
        return None

    def postprocess(self, df: pd.DataFrame, spec: QuerySpec) -> pd.DataFrame:
        """Released-value shaping (rounding, derived statistics). No new data.

        Runs on the gateway-FINALIZED frame — after suppression and count
        rounding, never on raw aggregates — so anything derived here is a
        function of numbers already released (hardening #26).
        """
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
        """The guard is the whole point (round 11, #92).

        `AVG`/`SUM`/`SUM(x*x)` skip NULL, and `COUNT(DISTINCT donor_id)` does
        not — so with no guard here the threshold counted donors in the COHORT
        while the released value described only the donors who ANSWERED. On any
        dataset with item non-response that is P5 broken outright: measured on
        a twelve-donor London cohort where two people answered the PGSI item,
        `mean`, `sum` and `sum_sq` all released, reporting `n=10`, and the pair
        `sum ÷ mean` gives the contributor count while `sum_sq` gives the
        variance — both scores recovered exactly.

        The dominance witness did not compensate: it drops the same NULL
        donors, so it bounds a donor's share AMONG CONTRIBUTORS, which is the
        right dominance question and no substitute for a missing threshold.
        `Corr` has always declared its guards; the one-column aggregates never
        did, and the demo corpus has no NULL in any measure column, which is
        why ten rounds did not meet it.

        With the guard, `n`, `n_donors`, the dominance witness and the
        contribution frame all describe exactly the rows the released value
        aggregated — which is what `_measure_guards` already claimed.
        """
        # fn is a Literal allowlist; column is allowlist- and regex-validated
        return ([f"{self.fn.upper()}({_ident(m.column)}) AS value"],
                (f"{_ident(m.column)} IS NOT NULL",))

    def postprocess(self, df: pd.DataFrame, spec: QuerySpec) -> pd.DataFrame:
        df["value"] = df["value"].round(2)
        return df

    def contribution_expr(self, m: Measure) -> str | None:
        return f"SUM({_ident(m.column)})"

    def checker_aggfunc(self, m: Measure) -> str | None:
        return "mean" if self.fn == "mean" else "sum"

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


class SumSq(_ColumnAggregate):
    """Sum of squares — the second-moment cell aggregate.

    Exists so a gaussian GLM's dispersion (and, later, L2 moment-cell
    procedures generalizing `corr`) is computable from *ordinary vetted
    aggregates*: every underlying model input stays a QuerySpec, inheriting
    P5–P7, rounding, lineage, and budget literally rather than by analogy.
    The dominance witness runs on the squared per-donor contribution; for the
    non-negative squared scale the largest contributor's share is what the
    p%-rule bounds, exactly as for `sum`.
    """

    fn = "sum_sq"

    def select_exprs(self, m: Measure) -> tuple[list[str], tuple[str, ...]]:
        # same guard as every other one-column aggregate, and for the same
        # reason (#92): SUM skips NULL, COUNT(DISTINCT donor_id) does not, so
        # without it the threshold counts a cohort while the value describes
        # only its respondents. This override exists for the squared
        # expression, not to opt out of the guard — which is how it came to be
        # missing here after the base class gained one.
        col = _ident(m.column)
        return [f"SUM({col} * {col}) AS value"], (f"{col} IS NOT NULL",)

    def contribution_expr(self, m: Measure) -> str | None:
        # the squared scale, as the dominance witness uses: a checker bounding
        # the raw-scale share would bound the wrong quantity entirely
        col = _ident(m.column)
        return f"SUM({col} * {col})"

    def output_contract(self, m: Measure) -> dict[str, DisclosureClass]:
        # not a `magnitude`: the bound that applies to a sum of squares is a
        # different rule in effect, and the contract is where that is said
        return {"value": "moment2", "n": "count"}


class SumCube(_ColumnAggregate):
    """Sum of cubes — the third-moment cell aggregate, for skewness.

    The per-donor contribution is `x³`, which is SIGNED: the dominance witness
    (engine.compile_dominance_query) is the magnitude-and-released-total aware
    `GREATEST(MAX|c|/SUM|c|, MAX|c|/|SUM c|)` built for exactly this (hardening
    #41, #93), so it bounds a donor's share of a signed third moment correctly.
    Exists so skewness — and with `sum_quad`, the Jarque-Bera normality test —
    is computable from ordinary vetted aggregates (safetre/normality.py).
    """

    fn = "sum_cube"

    def select_exprs(self, m: Measure) -> tuple[list[str], tuple[str, ...]]:
        col = _ident(m.column)
        return [f"SUM({col} * {col} * {col}) AS value"], (f"{col} IS NOT NULL",)

    def contribution_expr(self, m: Measure) -> str | None:
        col = _ident(m.column)
        return f"SUM({col} * {col} * {col})"

    def output_contract(self, m: Measure) -> dict[str, DisclosureClass]:
        return {"value": "moment3", "n": "count"}


class SumQuad(_ColumnAggregate):
    """Sum of fourth powers — the fourth-moment cell aggregate, for kurtosis.

    The per-donor contribution is `x⁴`, non-negative and even more concentrated
    than the square: a single outlier holds a larger share of a fourth moment
    than of a second, so the same dominance bound suppresses more outlier-driven
    cells — the protection tightens with the power, by construction.
    """

    fn = "sum_quad"

    def select_exprs(self, m: Measure) -> tuple[list[str], tuple[str, ...]]:
        col = _ident(m.column)
        return [f"SUM({col} * {col} * {col} * {col}) AS value"], (f"{col} IS NOT NULL",)

    def contribution_expr(self, m: Measure) -> str | None:
        col = _ident(m.column)
        return f"SUM({col} * {col} * {col} * {col})"

    def output_contract(self, m: Measure) -> dict[str, DisclosureClass]:
        return {"value": "moment4", "n": "count"}


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
        # contract but not in the compiled SQL's payload_columns. It is
        # computed from the FINALIZED (base-5 rounded) n, so the released
        # p carries no information beyond the released (value, n) pair
        # (hardening #26).
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
    p.fn: p for p in (Count(), Mean(), Sum(), SumSq(), SumCube(), SumQuad(), Corr())
}


def get_procedure(fn: str) -> AggregateProcedure:
    """Sole dispatch point (R14): unknown functions fail loudly."""
    try:
        return REGISTRY[fn]
    except KeyError:
        raise ValueError(f"no registered procedure for measure fn {fn!r}") from None


class ModelProcedure:
    """Base class for multi-query model procedures (spec R14/R15) — cells-first.

    A model procedure never executes anything itself. It (1) validates the
    untrusted proposal into a typed spec, (2) *plans* a list of ordinary
    QuerySpecs — so O2 compilation safety, O3 influence witnesses, and O4
    lineage identity are inherited from the aggregate registry, literally —
    and (3) fits from the gateway-FINALIZED tables the service hands it, as a
    pure function (P21). Any suppressed underlying cell means the service
    never calls `fit` at all (P19).
    """

    tool: str

    def validate(self, raw: dict):
        """Parse + allowlist-check the untrusted proposal (O1). Raises."""
        raise NotImplementedError

    def plan_aggregates(self, spec) -> list:
        """The design-cell QuerySpecs whose finalized outputs are the fit's
        only input. Every element MUST be a valid QuerySpec."""
        raise NotImplementedError

    def optional_roles(self, spec) -> frozenset[str]:
        """Planned tables the model can be fitted without.

        Everything else is required: if the gateway cannot fully release it,
        the model is refused (P19). An optional table is one whose absence
        costs the analyst part of the *output* rather than making the fit
        wrong — the gaussian dispersion, which buys standard errors and R²
        but no coefficient. It is used only if it releases COMPLETELY: a
        partly-suppressed table would silently change the number it feeds.
        """
        return frozenset()

    def preconditions(self, finalized: dict, spec) -> list[str]:
        """Estimability refusals, decidable from the finalized tables alone
        (P22): may name terms, never private quantities."""
        raise NotImplementedError

    def fit(self, finalized: dict, spec):
        """Pure fit from finalized tables -> (output_df, artifacts). P21:
        implementations must not touch the engine, views, or row-level data."""
        raise NotImplementedError

    def output_contract(self, spec) -> dict[str, dict[str, DisclosureClass]]:
        """Disclosure classes for every released frame (output + artifacts)."""
        raise NotImplementedError

    def model_key(self, spec) -> str:
        raise NotImplementedError

    def cost(self, spec) -> int:
        """Budget units — one per underlying aggregate (each is individually a
        differencable release, so each must individually count)."""
        return len(self.plan_aggregates(spec))

    def skeleton(self, catalogue: dict) -> list[dict[str, Any]]:
        """Every admissible no-filter spec, as JSON-able dicts (R16) — the
        finite space the exhaustive check and the formal model quantify over."""
        raise NotImplementedError


MODEL_REGISTRY: dict[str, ModelProcedure] = {}


def model_registry() -> dict[str, ModelProcedure]:
    """The model-procedure registry, populated on first use.

    The asymmetry with `REGISTRY` above is forced, not a design choice, and is
    worth stating because "one registry is a dict and the other is a function"
    otherwise reads as an inconsistency to tidy up. The aggregate procedures
    are defined in THIS module, so they can be instantiated eagerly at import.
    The model procedures live in `glm` and `anova`, which import their base
    class and the aggregate machinery from here — so importing them at module
    scope would be a cycle. Deferring the import to the first call registers
    them deterministically without import-order tricks, and every caller goes
    through this function rather than touching `MODEL_REGISTRY` directly, so
    there is no way to observe it half-populated.
    """
    from . import anova, glm, normality, series  # noqa: F401  (self-register on import)

    return MODEL_REGISTRY


def registry_skeleton() -> dict[str, Any]:
    """The registries' finite request space, exported as data (R16).

    Committed as `formal/skeleton.json`; a sync test regenerates it live so
    drift between the running catalogue/registries and the formal model's
    input fails CI. The formal model is generated FROM this file, giving the
    correspondence chain: code -> skeleton (pytest-checked) -> model
    (pytest-checked) -> solver-checked assertions.
    """
    from .query import CATALOGUE

    catalogue = {
        dataset: {
            "dims": dict(sorted(info["dims"].items())),
            "measures": sorted(info["measures"]),
            "internal_filters": sorted(info.get("internal_filters", {})),
            "internal_measures": sorted(info.get("internal_measures", set())),
            "glm_responses": {col: sorted(fams) for col, fams
                              in sorted(info.get("glm_responses", {}).items())},
        }
        for dataset, info in sorted(CATALOGUE.items())
    }
    aggregate = {
        dataset: [cfg for fn in sorted(REGISTRY)
                  for cfg in REGISTRY[fn].measure_configs(CATALOGUE[dataset])]
        for dataset in sorted(CATALOGUE)
    }
    model = {tool: proc.skeleton(CATALOGUE)
             for tool, proc in sorted(model_registry().items())}
    return {"skeleton_version": 1, "catalogue": catalogue,
            "aggregate": aggregate, "model": model}
