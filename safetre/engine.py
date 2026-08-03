"""Read-only query engine: a validated QuerySpec -> parameterised DuckDB SQL.

Security properties:
- Identifiers come only from the validated allowlist and are regex-checked
  before quoting; filter *values* are always bound parameters (no injection).
- The public views expose only allowlisted columns (no donor_id/free_text/ts/raw age).
- For sum/mean the engine also computes a **dominance** share (largest single
  contributor / total) using INTERNAL unit views that include donor_id — which
  are never selectable via a QuerySpec and never returned. The gateway uses this
  to suppress cells one record could dominate (the p%-rule).
- Resource bounds: per-connection memory/thread limits and a row cap on results.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any

import duckdb
import pandas as pd

from . import dataset as _dataset
from .dataset import UNIT_PERSON
from .procedures import get_procedure
from .query import CATALOGUE, QuerySpec
from .schema import declared_domain

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
ROW_CAP = 10_000          # backstop against pathological cross-products
MEMORY_LIMIT = "512MB"
THREADS = 2

# Public views: ONLY public allowlisted columns. The person key, free text, raw
# timestamps and other high-granularity variables never appear. Generated from
# the active dataset definition (safetre/dataset.py) and mirrored here.
_VIEWS: dict[str, str] = {}

# Internal unit views: the public columns plus the person key — projected under
# the machinery's fixed internal alias `UNIT_PERSON`, whatever the study calls
# it — and any internal analysis variables. Used ONLY for fixed tools and
# disclosure machinery. Not directly queryable.
_UNIT_VIEWS: dict[str, str] = {}


def _apply(defn) -> None:
    _VIEWS.clear()
    _VIEWS.update(defn.public_view_sql())
    _UNIT_VIEWS.clear()
    _UNIT_VIEWS.update(defn.unit_view_sql())


_dataset.register_sync(_apply)
_apply(_dataset.active())


def _ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"illegal identifier {name!r}")
    return f'"{name}"'


@dataclass(frozen=True)
class SQLPlan:
    """Compiled SQL plus the metadata needed to check its safety boundary."""

    sql: str
    params: tuple[Any, ...]
    output_columns: tuple[str, ...]
    source_view: str


_FILTER_OPS = {"==", "!=", "<", "<=", ">", ">=", "in"}


def _predicate_sql(filters) -> tuple[str, tuple[Any, ...]]:
    """(column, op, value) triples as a standalone boolean expression.

    No `WHERE` keyword, so the result composes: the differencing auditor needs
    to ask for rows matching one filter list and *not* another, which means the
    two predicates have to be negatable and combinable (`row_symdiff_donors`).
    An empty filter list selects everything.
    """
    clauses, params = [], []
    for column, op, value in filters:
        col = _ident(column)
        if op == "in":
            values = list(value)
            placeholders = ", ".join("?" for _ in values)
            clauses.append(f"{col} IN ({placeholders})")
            params.extend(values)
        elif op in _FILTER_OPS:
            clauses.append(f"{col} {op} ?")
            params.append(value)
        else:
            raise ValueError(f"illegal filter operator {op!r}")
    return (" AND ".join(clauses) if clauses else "TRUE"), tuple(params)


def _where_triples(filters) -> tuple[str, tuple[Any, ...]]:
    """WHERE clause from (column, op, value) triples; values stay bound params."""
    predicate, params = _predicate_sql(filters)
    return ("" if predicate == "TRUE" else f" WHERE {predicate}"), params


def _where(spec: QuerySpec, extra_clauses: tuple[str, ...] = ()) -> tuple[str, tuple[Any, ...]]:
    where, params = _where_triples((f.column, f.op, f.value) for f in spec.filters)
    if extra_clauses:
        prefix = " AND " if where else " WHERE "
        where += prefix + " AND ".join(extra_clauses)
    return where, params


def _uses_internal_source(spec: QuerySpec) -> bool:
    cat = CATALOGUE[spec.dataset]
    internal_filters = set(cat.get("internal_filters", {}))
    internal_measures = set(cat.get("internal_measures", set()))
    if any(f.column in internal_filters for f in spec.filters):
        return True
    touched = get_procedure(spec.measure.fn).measure_columns(spec.measure)
    return bool(set(touched) & internal_measures)


def _source_view(spec: QuerySpec) -> str:
    return f"_{spec.dataset}_u" if _uses_internal_source(spec) else spec.dataset


def compile_query(spec: QuerySpec) -> SQLPlan:
    """Compile a validated QuerySpec into the public read-only aggregate SQL.

    The registered procedure supplies only its aggregate SELECT fragments and
    NOT-NULL guards (O2); the SafeSQL *shape* — one SELECT over one declared
    view, bound parameters only, `ORDER BY n DESC LIMIT` cap — is fixed here,
    so no procedure can deviate from it.
    """
    proc = get_procedure(spec.measure.fn)
    fragments, extra = proc.select_exprs(spec.measure)
    select = [_ident(g) for g in spec.group_by] + fragments + ["COUNT(*) AS n"]

    where, params = _where(spec, extra)
    source = _source_view(spec)
    sql = f"SELECT {', '.join(select)} FROM {_ident(source)}{where}"  # nosec
    if spec.group_by:
        sql += " GROUP BY " + ", ".join(_ident(g) for g in spec.group_by)
    sql += f" ORDER BY n DESC LIMIT {ROW_CAP}"
    return SQLPlan(
        sql=sql,
        params=params,
        output_columns=tuple(spec.group_by) + proc.payload_columns(spec.measure),
        source_view=source,
    )


def compile_dominance_query(spec: QuerySpec) -> SQLPlan:
    """Compile the internal donor-level dominance query for donor-additive
    measures (sum/mean on the raw scale; sum_sq on the squared scale, so the
    p%-rule bounds the largest contributor's share of the released total)."""
    if spec.measure.fn not in ("mean", "sum", "sum_sq"):
        raise ValueError("dominance is only defined for donor-additive measures")

    where, params = _where(spec)
    col = _ident(spec.measure.column)
    contribution = f"{col} * {col}" if spec.measure.fn == "sum_sq" else col
    unit = _ident(f"_{spec.dataset}_u")
    gsel = ", ".join(_ident(g) for g in spec.group_by)
    gpre = (gsel + ", ") if spec.group_by else ""
    inner = (
        f"SELECT {gpre}{UNIT_PERSON}, SUM({contribution}) AS c FROM {unit}{where} "  # nosec
        f"GROUP BY {gpre}{UNIT_PERSON}"
    )
    # MAGNITUDE share, not signed share (hardening #41). `MAX(c)/SUM(c)` reads
    # the p%-rule as "the largest contributor's fraction of the total", which
    # silently assumes every contribution is non-negative. Real refund, net-flow
    # and delta measures are not: over a negative total, `MAX` selects the LEAST
    # negative donor while `SUM` is large and negative, so the ratio collapses
    # towards zero and a cell one donor dominates outright reports as safe.
    # Measured: negating one region's spend moved its witness from 0.620 to
    # 0.0027 with the concentration unchanged, and a single chargeback took a
    # cell to -0.081 while that donor held 66% of the magnitude and 210% of the
    # released total. `abs` is identical on non-negative data — the same MAX,
    # the same SUM — so no existing decision changes. A cell whose magnitudes
    # sum to zero yields NULL, which fills to +inf and suppresses (fail closed).
    # ...but the magnitude share is only HALF the question (round 11, #93).
    # It bounds a donor's share of the cell's total magnitude and says nothing
    # about their share of the number actually released. On the mixed-sign data
    # `abs` was introduced for, those diverge: 21 donors, one at +137.42 and
    # ten each at +/-50, gives a magnitude share of 0.12 — comfortably inside
    # the p%-rule — while the released total IS that donor's contribution,
    # exactly. The pre-#41 signed witness caught this one and inverted on
    # others, so neither witness is right alone; the rule is the worse of the
    # two. Identical on non-negative data, where SUM(abs(c)) == abs(SUM(c)), so
    # #41's "no existing decision changes" still holds. A zero cell total makes
    # the second term NULL -> +inf -> suppress, which is correct: a total of
    # zero bounds nobody's share of anything.
    sql = (
        f"SELECT {gpre}GREATEST("  # nosec
        f"MAX(abs(c)) / NULLIF(SUM(abs(c)), 0), "
        f"MAX(abs(c)) / NULLIF(abs(SUM(c)), 0)) AS dominance "
        f"FROM ({inner}) t" + (f" GROUP BY {gsel}" if spec.group_by else "")
    )
    return SQLPlan(
        sql=sql,
        params=params,
        output_columns=tuple(spec.group_by) + ("dominance",),
        source_view=f"_{spec.dataset}_u",
    )


def compile_influence_query(spec: QuerySpec) -> SQLPlan:
    """Compile the internal leave-one-donor-out influence query for corr specs.

    A correlation has no natural analogue of the sum/mean p%-dominance rule, yet
    a single high-leverage donor can drive it — so a released r on a small group
    can disclose that individual. This computes, per group, the largest change
    in Pearson r that removing any single *donor* produces (their whole set of
    rows, so it is correct even for event-level correlations where one donor has
    many events). The gateway suppresses cells whose influence exceeds the
    policy threshold. Runs on the internal unit view; only the max |Δr| per
    group is used, and it is never released.
    """
    if spec.measure.fn != "corr":
        raise ValueError("influence is only defined for corr measures")

    x = _ident(spec.measure.x)
    y = _ident(spec.measure.y)
    where, params = _where(spec, (f"{x} IS NOT NULL", f"{y} IS NOT NULL"))
    unit = _ident(f"_{spec.dataset}_u")
    gsel = ", ".join(_ident(g) for g in spec.group_by)
    gpre = (gsel + ", ") if spec.group_by else ""

    # per-donor partial sums (d*), then per-group totals (t*), then drop-one
    # recomputation. Note: DuckDB identifiers are case-INSENSITIVE, so the
    # per-donor and group column names must be textually distinct (not just
    # differ in case) or they silently alias each other.
    per_donor = (
        f"SELECT {gpre}{UNIT_PERSON}, "  # nosec
        f"SUM({x}) AS dx, SUM({y}) AS dy, SUM({x}*{x}) AS dxx, "
        f"SUM({y}*{y}) AS dyy, SUM({x}*{y}) AS dxy, COUNT(*) AS dm "
        f"FROM {unit}{where} GROUP BY {gpre}{UNIT_PERSON}"
    )
    grp = (
        f"SELECT {gpre}SUM(dx) AS tx, SUM(dy) AS ty, SUM(dxx) AS txx, "  # nosec
        f"SUM(dyy) AS tyy, SUM(dxy) AS txy, SUM(dm) AS tn "
        f"FROM per_donor" + (f" GROUP BY {gsel}" if spec.group_by else "")
    )
    join = (f"per_donor p JOIN grp g USING ({gsel})" if spec.group_by
            else "per_donor p, grp g")
    gcols_j = ("g." + ", g.".join(_ident(g) for g in spec.group_by) + ", ") if spec.group_by else ""
    # Guard the sqrt with a strictly-positive CASE, not NULLIF(x, 0): the
    # variance product is >= 0 in exact arithmetic but floating-point
    # cancellation can make it a tiny negative, and DuckDB's sqrt RAISES on a
    # negative argument rather than returning NaN. A non-positive product means a
    # degenerate (zero-variance) group, so NULL is the right answer — it flows to
    # a NULL influence, which fills to +inf and suppresses the cell (fail closed).
    r_full = ("(tn*txy - tx*ty) / "
              "sqrt(CASE WHEN (tn*txx - tx*tx) * (tn*tyy - ty*ty) > 0 "
              "THEN (tn*txx - tx*tx) * (tn*tyy - ty*ty) END)")
    # sums with this donor removed (subtract their partials)
    r_drop = ("((tn-dm)*(txy-dxy) - (tx-dx)*(ty-dy)) / "
              "sqrt(CASE WHEN ((tn-dm)*(txx-dxx) - (tx-dx)*(tx-dx)) * "
              "((tn-dm)*(tyy-dyy) - (ty-dy)*(ty-dy)) > 0 "
              "THEN ((tn-dm)*(txx-dxx) - (tx-dx)*(tx-dx)) * "
              "((tn-dm)*(tyy-dyy) - (ty-dy)*(ty-dy)) END)")
    sql = (
        f"WITH per_donor AS ({per_donor}), grp AS ({grp}), "  # nosec
        f"j AS (SELECT {gcols_j}"
        f"p.dx, p.dy, p.dxx, p.dyy, p.dxy, p.dm, "
        f"g.tx, g.ty, g.txx, g.tyy, g.txy, g.tn FROM {join}), "
        f"d AS (SELECT {gpre}"
        # An unresolved per-donor delta is INFINITE, not absent (round 11,
        # #94). `r_drop` is NULL exactly when removing that donor leaves a
        # degenerate group — no computable correlation without them — which is
        # maximal influence, not missing data. As a NULL it was one row among
        # many and `MAX` aggregated it away, so the single donor whose removal
        # destroys the correlation was precisely the donor the check ignored.
        # Measured: eleven donors at pgsi_score 0 and one at 15 — the ordinary
        # shape of a general-population screening score — released r = -0.9866
        # on a witness of 0.0028. The same reasoning already applies at cell
        # level, where a NULL influence fills to +inf and suppresses; this
        # makes the per-donor leg agree with it.
        f"COALESCE(CASE WHEN (tn-dm) >= 3 THEN abs(({r_full}) - ({r_drop})) END, "
        f"'Infinity') AS delta FROM j) "
        f"SELECT {gpre}MAX(delta) AS influence FROM d"
        + (f" GROUP BY {gsel}" if spec.group_by else "")
    )
    return SQLPlan(
        sql=sql,
        params=params,
        output_columns=tuple(spec.group_by) + ("influence",),
        source_view=f"_{spec.dataset}_u",
    )


def _measure_guards(spec: QuerySpec) -> tuple[str, ...]:
    """The procedure's NOT-NULL guard clauses (e.g. corr's operand guards), so
    internal safety queries see exactly the rows the public query saw."""
    return get_procedure(spec.measure.fn).select_exprs(spec.measure)[1]


def compile_donor_count_query(spec: QuerySpec) -> SQLPlan:
    """Compile the internal per-cell distinct-donor count.

    The frequency threshold rule protects *individuals* ("respondents"), not
    rows. On event-level datasets a cell can have many rows from few donors, so
    the public `n` (= COUNT(*)) is not a safe individual count. This counts
    distinct donors per cell on the internal unit view, mirroring the public
    query's filters (including the corr NOT-NULL predicates), so the gateway can
    enforce the threshold on donors. The count is a disclosure helper and is
    dropped before release.
    """
    where, params = _where(spec, _measure_guards(spec))
    unit = _ident(f"_{spec.dataset}_u")
    gsel = ", ".join(_ident(g) for g in spec.group_by)
    gpre = (gsel + ", ") if spec.group_by else ""
    sql = (
        f"SELECT {gpre}COUNT(DISTINCT {UNIT_PERSON}) AS n_donors "  # nosec
        f"FROM {unit}{where}" + (f" GROUP BY {gsel}" if spec.group_by else "")
    )
    return SQLPlan(
        sql=sql,
        params=params,
        output_columns=tuple(spec.group_by) + ("n_donors",),
        source_view=f"_{spec.dataset}_u",
    )


def compile_contribution_query(spec: QuerySpec) -> SQLPlan:
    """Compile the internal per-donor contribution query.

    One row per donor per cell: the group-by keys, the donor, and what that
    donor contributed, on the scale the procedure declares
    (`contribution_expr` — squared for `sum_sq`). This is what an external
    output checker decides on: a frequency threshold counts donors and the
    dominance rules need each donor's share, and neither survives aggregation
    into a cell table.

    Internal throughout: it names `donor_id`, so it is never a released frame
    and never leaves the safepod. The public query's own NOT-NULL guards are
    applied, so the checker sees exactly the rows the released cell counted.
    """
    proc = get_procedure(spec.measure.fn)
    contribution = proc.contribution_expr(spec.measure)
    where, params = _where(spec, _measure_guards(spec))
    unit = _ident(f"_{spec.dataset}_u")
    gsel = ", ".join(_ident(g) for g in spec.group_by)
    gpre = (gsel + ", ") if spec.group_by else ""
    value = f"{contribution} AS v, " if contribution else ""
    sql = (
        f"SELECT {gpre}{value}{UNIT_PERSON} "               # nosec
        f"FROM {unit}{where} GROUP BY {gpre}{UNIT_PERSON}"
    )
    columns = tuple(spec.group_by) + (("v",) if contribution else ()) + (UNIT_PERSON,)
    return SQLPlan(sql=sql, params=params, output_columns=columns,
                   source_view=f"_{spec.dataset}_u")


class QueryEngine:
    def __init__(self, tables: dict[str, pd.DataFrame]):
        self.con = duckdb.connect(database=":memory:")
        self.con.execute(f"SET memory_limit='{MEMORY_LIMIT}'")
        self.con.execute(f"SET threads={THREADS}")
        # Materialise rather than register (hardening #51). A registered pandas
        # frame is CONNECTION-scoped — a cursor cannot see it, verified — and a
        # cursor per thread is what makes concurrent use safe. Copying the data
        # into DuckDB's own storage is what lets every thread work from its own
        # cursor over one shared catalogue.
        # The base tables go in their own schema, the views in `main`
        # (dataset.BASE_SCHEMA). A study may publish a dataset under the name of
        # the table behind it, which in one namespace is a catalogue collision;
        # and a compiled query names its view unqualified, so keeping the raw
        # tables out of `main` means a bare name can never resolve to one.
        self.con.execute(f"CREATE SCHEMA IF NOT EXISTS {_ident(_dataset.BASE_SCHEMA)}")
        for name, df in tables.items():
            source = f"_src_{name}"
            self.con.register(source, df)
            # every identifier goes through `_ident`, which regex-checks against
            # a strict pattern before quoting, so nothing caller-controlled
            # reaches the statement (P9)
            ddl = (f"CREATE TABLE {_ident(_dataset.BASE_SCHEMA)}.{_ident(name)} "  # nosec
                   f"AS SELECT * FROM {_ident(source)}")
            self.con.execute(ddl)
            self.con.unregister(source)
        for ddl in (*_VIEWS.values(), *_UNIT_VIEWS.values()):
            self.con.execute(ddl)
        self._marginals: dict | None = None
        self._local = threading.local()

    @property
    def cursor(self):
        """This thread's cursor over the shared database.

        `QueryEngine` is built once and driven from FastAPI's threadpool by
        concurrent users, and DuckDB's Python client does not guarantee
        concurrent `execute().df()` on one connection. In this system that is
        not merely a correctness risk: a frame returned to the wrong request is
        a disclosure, because the vetting that approved one analyst's cells
        would be attached to another's, and the audit row would record the
        release under the wrong identity.

        `cursor()` is DuckDB's documented answer — an independent execution
        context over the same catalogue — so each thread gets one, made on
        first use and kept for the life of the thread.
        """
        cursor = getattr(self._local, "cursor", None)
        if cursor is None:
            cursor = self.con.cursor()
            self._local.cursor = cursor
        return cursor

    def run(self, spec: QuerySpec) -> pd.DataFrame:
        """Raw aggregate frame: exact values, safety helpers attached.

        Deliberately NOT postprocessed: released-value shaping (rounding,
        derived statistics such as corr's p_value) runs on the gateway-
        finalized frame in the service layer, so every shaped number is a
        function of data already released (hardening #26).
        """
        proc = get_procedure(spec.measure.fn)
        plan = compile_query(spec)
        result = self.cursor.execute(plan.sql, plan.params).df()

        # every procedure that reads individual values attaches its declared
        # influence witness (O3) — dominance for sums/means, leave-one-out for
        # corr — which the gateway suppresses on and drops before release.
        for witness in proc.witness_plans(spec):
            result = self._attach_witness(spec, witness.plan, witness.column, result)

        # every result carries an internal distinct-donor count so the gateway
        # enforces the frequency threshold on individuals, not rows.
        result = self._attach_donor_count(spec, compile_donor_count_query(spec), result)
        return result

    def contributions(self, spec: QuerySpec) -> pd.DataFrame:
        """One row per donor per cell, for an external checker to decide on.

        Internal only: it carries `donor_id` and un-aggregated contributions,
        so it goes to a checker inside the safepod and never towards a
        release. A donor whose contribution is NULL is dropped — there is no
        share for a dominance rule to weigh — which means a checker counting
        rows here sees one donor fewer on such cells than the gateway's own
        `n_donors` does.
        """
        plan = compile_contribution_query(spec)
        frame = self.cursor.execute(plan.sql, plan.params).df()
        return frame[frame["v"].notna()] if "v" in frame.columns else frame

    def cell_context(self, spec: QuerySpec, with_contributions: bool = False):
        """Everything a vetter needs about the query behind a cell table.

        Cheap by default: the disclosure class and the cell keys cost nothing,
        and only an external checker needs the donor-level contributions,
        which are a second query.
        """
        from .disclosure import CellContext

        proc = get_procedure(spec.measure.fn)
        contract = proc.output_contract(spec.measure)
        return CellContext(
            contributions=self.contributions(spec) if with_contributions else None,
            keys=tuple(spec.group_by),
            aggfunc=proc.checker_aggfunc(spec.measure),
            value_class=contract.get("value"))

    def _attach_witness(self, spec: QuerySpec, plan: SQLPlan, column: str,
                        result: pd.DataFrame) -> pd.DataFrame:
        """Merge an internal safety-witness column onto the result, per group.

        A missing/unresolved witness value is filled with +inf, not 0.0: an
        unresolved safety check must fail **closed** (be suppressed), never
        default to "safe". (For corr this covers e.g. every leave-one-out
        dropping below the 3-row floor.)
        """
        witness = self.cursor.execute(plan.sql, plan.params).df()
        if spec.group_by:
            result = result.merge(witness, on=spec.group_by, how="left")
        else:
            result = result.assign(**{column: (witness[column].iloc[0]
                                               if len(witness) else float("inf"))})
        result[column] = result[column].fillna(float("inf"))
        return result

    def _attach_dominance(self, spec: QuerySpec, plan: SQLPlan, result: pd.DataFrame):
        return self._attach_witness(spec, plan, "dominance", result)

    def _attach_influence(self, spec: QuerySpec, plan: SQLPlan, result: pd.DataFrame):
        return self._attach_witness(spec, plan, "influence", result)

    def _attach_donor_count(self, spec: QuerySpec, plan: SQLPlan, result: pd.DataFrame):
        """Distinct donors per cell (internal); a missing cell means zero donors."""
        nd = self.cursor.execute(plan.sql, plan.params).df()
        if spec.group_by:
            result = result.merge(nd, on=spec.group_by, how="left")
        else:
            result = result.assign(n_donors=(nd["n_donors"].iloc[0] if len(nd) else 0))
        result["n_donors"] = result["n_donors"].fillna(0).astype(int)
        return result

    def marginal_donor_counts(self) -> dict:
        """Published donor-frequency metadata: `{dataset: {dim: {value: n_donors}}}`.

        The distinct-donor count of every single filterable predicate value, on
        the internal unit views. This is a donor-frequency table — itself
        releasable under the threshold rule — and it is the only data the session
        auditor's differencing decision depends on, which is what makes that
        decision *simulatable* (see `disclosure.simulatable_cohort_bound`). Computed once
        and cached. Only the < threshold comparison is used downstream, so a
        production build can publish the sparse-flagged, rounded version.
        """
        if self._marginals is not None:
            return self._marginals
        out: dict = {}
        for dataset in _UNIT_VIEWS:
            cat = CATALOGUE[dataset]
            dims = list(cat["dims"]) + list(cat.get("internal_filters", {}))
            unit = self._unit_view(dataset)
            per_dim: dict = {}
            for dim in dims:
                col = _ident(dim)
                rows = self.cursor.execute(
                    f"SELECT {col} AS v, COUNT(DISTINCT {UNIT_PERSON}) AS c "  # nosec
                    f"FROM {unit} GROUP BY {col}"
                ).fetchall()
                per_dim[dim] = {v: int(c) for v, c in rows}
            out[dataset] = per_dim
        self._marginals = out
        return out

    def published_marginal_donor_counts(self, threshold: int = 10,
                                        round_base: int = 5) -> dict:
        """The disclosure-safe form of `marginal_donor_counts`, safe to expose.

        The simulatable-auditing argument (Kenthapadi–Mishra–Nissim, 2005) only
        holds if the metadata the auditor decides from is genuinely public. The
        raw marginals include sub-threshold cells (e.g. a rare `sex`/`age_years`
        value), which are themselves disclosive, so they are not published as-is.
        This returns the releasable projection: counts at or above `threshold` are
        rounded to `round_base`; counts below it are reported as `None`
        ("< threshold"). The endpoint serving this is what makes the auditor's
        deny/allow decision reproducible by an analyst *up to* that one bit — the
        residual (using the true sub-threshold count internally to actually catch
        rare-category isolation) is the documented, DP-closed deviation.

        Values outside a column's DECLARED domain are dropped entirely, not
        count-nulled: an undeclared value (a hostile string smuggled into a
        field, a data-entry typo) is disclosive by its mere *name*, and nulling
        the count still leaks the string as a key. Only declared categories — the
        public codebook vocabulary — appear.

        A column with NO declared domain has no public vocabulary, so its key
        set is derived from the data and publishing a key is itself a
        disclosure. For those columns a sub-threshold value is therefore
        **omitted**, not count-nulled. Count-nulling was enough for a declared
        domain — a rare category being a valid option is public knowledge — but
        on `age_years` it published the exact ages present in the study,
        including ages held by a single donor, which is the sub-threshold
        existence fact suppression exists to hide, on the one variable the
        catalogue calls internal and never-returnable.

        Omitting rather than nulling costs the auditor nothing, which is why
        the two cases can differ. Simulatability needs the analyst to be able
        to reproduce the deny/allow decision, and that decision turns only on
        `count < threshold`. An absent key means either "sub-threshold" or "not
        in the data at all", and *both* yield a bound below the threshold, so
        the analyst reaches the same verdict without being told which.
        """
        raw = self.marginal_donor_counts()
        pub: dict = {}
        for dataset, per_dim in raw.items():
            pub_dims: dict = {}
            for dim, counts in per_dim.items():
                domain = declared_domain(dim)
                if domain is None:
                    pub_dims[dim] = {
                        str(v): int(round(c / round_base) * round_base)
                        for v, c in counts.items() if c >= threshold
                    }
                    continue
                pub_dims[dim] = {
                    str(v): (int(round(c / round_base) * round_base) if c >= threshold else None)
                    for v, c in counts.items() if v in domain
                }
            pub[dataset] = pub_dims
        return pub

    def _unit_view(self, dataset: str) -> str:
        if dataset not in _UNIT_VIEWS:
            raise ValueError(f"unknown dataset {dataset!r}")
        return _ident(f"_{dataset}_u")

    def cohort_size(self, dataset: str, filters=()) -> int:
        """Distinct-donor count of a cohort, on the INTERNAL unit view.

        `filters` are normalized (column, op, value) triples from a *validated*
        QuerySpec. The count is used only by the session auditor and is never
        released.
        """
        where, params = _where_triples(filters)
        sql = f"SELECT COUNT(DISTINCT {UNIT_PERSON}) FROM {self._unit_view(dataset)}{where}"  # nosec
        return int(self.cursor.execute(sql, params).fetchone()[0])

    def row_symdiff_donors(self, dataset: str, filters_a, filters_b) -> int:
        """Distinct donors behind the rows exactly one of two queries counted.

        A released value is a function of the ROWS it aggregated, not of the
        cohort that produced them: two cohorts can hold exactly the same people
        while their rows differ by a whole suppressed cell, which every
        donor-set comparison correctly reports as no difference (#40).

        Load-bearing property: on donor-level filters this equals ``|A △ B|``
        exactly, so it subsumes the cohort comparison rather than trading it
        for something weaker. `cohort_symdiff` remains for callers that
        genuinely mean the donor sets.

        Exact rather than simulatable, deliberately (decision D7). That is an
        accepted, measured residual — the denial carries a bit the published
        marginals cannot reproduce, and 99.6% of differencing denials come from
        this leg: see hardening #62 for the measurement,
        `artifacts/exact_leg_channel.json` for the numbers,
        `formal/disclosure_policy.als::V8ExactLegIsNotSimulatable` for the
        model instance, and
        `test_the_two_differencing_legs_are_indistinguishable` for the pin that
        keeps the refusal byte-identical to the cheap leg's.
        """
        unit = self._unit_view(dataset)
        pa, params_a = _predicate_sql(filters_a)
        pb, params_b = _predicate_sql(filters_b)
        sql = (
            f"SELECT COUNT(DISTINCT {UNIT_PERSON}) FROM {unit} "            # nosec
            f"WHERE (({pa}) AND NOT ({pb})) OR (({pb}) AND NOT ({pa}))"
        )
        params = params_a + params_b + params_b + params_a
        return int(self.cursor.execute(sql, params).fetchone()[0])

    def cohort_symdiff(self, dataset: str, filters_a, filters_b,
                       dataset_b: str | None = None) -> int:
        """|A △ B|: distinct donors in exactly one of two cohorts.

        A small symmetric difference means the pair of released aggregates
        differs by only a few individuals — the signature of a differencing
        attack. Computed on the internal unit views; never released.

        `dataset_b` lets the two halves come from DIFFERENT views of the same
        people (round 11, #95). Every view in a definition projects the same
        person key under `UNIT_PERSON`, so the donor sets are directly
        comparable even where the rows are not — which is exactly the case
        `row_symdiff_donors` cannot answer and the reason it is not used
        across views.
        """
        unit_a = self._unit_view(dataset)
        unit_b = self._unit_view(dataset_b or dataset)
        wa, pa = _where_triples(filters_a)
        wb, pb = _where_triples(filters_b)
        a = f"SELECT DISTINCT {UNIT_PERSON} FROM {unit_a}{wa}"  # nosec
        b = f"SELECT DISTINCT {UNIT_PERSON} FROM {unit_b}{wb}"  # nosec
        # EXCEPT halves are distinct and disjoint, so UNION ALL is exact.
        sql = f"SELECT COUNT(*) FROM (({a} EXCEPT {b}) UNION ALL ({b} EXCEPT {a})) t"  # nosec
        return int(self.cursor.execute(sql, pa + pb + pb + pa).fetchone()[0])
