"""Dataset definitions — every dataset-specific fact lives in one operator-owned file.

The gateway machinery (query compiler, disclosure gateway, session auditor,
procedures, model tools) is dataset-agnostic: it reads the *active dataset
definition* — the base tables and their disclosure roles, the person key whose
distinct count the threshold rules protect, the public pre-joined views and
their allowlists, the band-edge rules for internal high-granularity filters,
and the natural-language vocabulary the planner and fidelity checks use.
Nothing in the package names a dataset column outside a definition file.

Trust boundary: a definition is OPERATOR configuration, like `config.yaml`. It
is loaded once at startup (env `SAFETRE_DATASET`, defaulting to the packaged
synthetic demo in `safetre/demo_dataset.yaml`) and is never influenced by
analyst input: analysts propose QuerySpecs against the catalogue the definition
publishes, and every identifier the definition contributes is validated against
the same strict pattern (`^[a-z_][a-z0-9_]*$`) and double-quoted into the
generated view SQL, with CASE/WHEN values rendered as escaped literals. The
definition decides what is queryable; it cannot execute anything.

The person key deserves a note. Base tables name it whatever the study calls
it (`donor_id`, `patient_id`, ...). The generated *unit views* — internal,
never analyst-facing — project it under the fixed internal alias `UNIT_PERSON`,
so the disclosure machinery's SQL (distinct-person counts, dominance, leave-one
-out influence, symmetric difference) is written once, against the alias, and
is independent of the source column's name. The alias never appears in a public
view or a released frame; it is part of the machinery's internal protocol (like
`n_donors` or `dominance`), not a dataset column name.

See docs/datasets.md for the file format.
"""

from __future__ import annotations

import os
import pathlib
import re
from typing import Any, Callable

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")

ROLES = ("DI", "QI", "S", "R", "meta")
DIM_KINDS = ("cat", "int", "bool")
GLM_FAMILIES = ("gaussian", "binomial", "poisson")
RANGE_RULE_OPS = (">=", "<=", "==")

# Fixed internal alias for the person key inside unit views and internal
# frames. NOT a dataset column name: the generated unit views project the
# definition's `person_key` under this name, and the disclosure machinery reads
# only the alias, so a study may call its person column anything.
UNIT_PERSON = "donor_id"

_PACKAGED = pathlib.Path(__file__).with_name("demo_dataset.yaml")


def _qident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"illegal identifier {name!r}")
    return f'"{name}"'


# The base tables live in their own DuckDB schema, and the public/unit views in
# `main`. Two reasons, and the second is the one that matters:
#
# 1. An operator may reasonably publish a dataset under the name of the table it
#    is built from — the clinic fixture's `visits` view over the `visits` table.
#    In one namespace that is a catalogue collision and the engine fails to
#    build at all.
# 2. A compiled query names its source view UNQUALIFIED (`FROM spend`), because
#    `engine._source_view` is the only thing that chooses it. With the raw
#    tables in `main` an operator could, by naming a dataset after a table,
#    make that bare name ambiguous between a public view and a table carrying
#    the person key. Here it cannot be: an unqualified name never reaches a
#    base table, so the raw rows are addressable only from the view DDL this
#    module generates.
BASE_SCHEMA = "base"


def _qtable(name: str) -> str:
    """A base table, schema-qualified. Only view DDL may name one."""
    return f"{_qident(BASE_SCHEMA)}.{_qident(name)}"


def _qref(ref: str) -> str:
    table, _, col = ref.partition(".")
    return f"{_qtable(table)}.{_qident(col)}"


def _sql_literal(value: Any) -> str:
    """A view-DDL literal from operator configuration: booleans and numbers
    inline, strings single-quoted with doubling (the only escaping DuckDB
    string literals recognise)."""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return repr(value)
    return "'" + str(value).replace("'", "''") + "'"


def _check_ident(name: str, what: str) -> None:
    if not _IDENT.match(name):
        raise ValueError(f"{what} {name!r} is not a legal identifier "
                         f"(must match {_IDENT.pattern})")


def _split_ref(ref: str, what: str) -> tuple[str, str]:
    table, sep, col = ref.partition(".")
    if not sep:
        raise ValueError(f"{what} {ref!r} must be qualified as <table>.<column>")
    _check_ident(table, f"{what} table")
    _check_ident(col, f"{what} column")
    return table, col


class Join(BaseModel):
    """`JOIN {table} ON {base}.{key} = {table}.{key}` (`LEFT JOIN` when how=left)."""
    model_config = ConfigDict(extra="forbid")
    table: str
    key: str
    how: str = "inner"


class SumIf(BaseModel):
    """`SUM(CASE WHEN {when} IN (...) THEN {column} ELSE 0 END)` — a conditional
    additive rollup, e.g. per-person spend over selected event types."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    column: str
    when: str
    in_: list[Any] = Field(alias="in", min_length=1)


class CountIf(BaseModel):
    """`SUM(CASE WHEN {column} = {equals} THEN 1 ELSE 0 END)` — a conditional
    row count, e.g. per-person purchase counts."""
    model_config = ConfigDict(extra="forbid")
    column: str
    equals: Any


class DerivedColumn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    sum_if: SumIf | None = None
    count_if: CountIf | None = None

    @model_validator(mode="after")
    def _one_expression(self):
        if (self.sum_if is None) == (self.count_if is None):
            raise ValueError(
                f"derived column {self.name!r} needs exactly one of sum_if / count_if")
        return self

    def refs(self) -> list[str]:
        if self.sum_if is not None:
            return [self.sum_if.column, self.sum_if.when]
        return [self.count_if.column]  # type: ignore[union-attr]

    def sql(self) -> str:
        if self.sum_if is not None:
            values = ", ".join(_sql_literal(v) for v in self.sum_if.in_)
            return (f"SUM(CASE WHEN {_qref(self.sum_if.when)} IN ({values}) "
                    f"THEN {_qref(self.sum_if.column)} ELSE 0 END) AS {_qident(self.name)}")
        count = self.count_if
        return (f"SUM(CASE WHEN {_qref(count.column)} = {_sql_literal(count.equals)} "  # type: ignore[union-attr]
                f"THEN 1 ELSE 0 END) AS {_qident(self.name)}")


class ViewDef(BaseModel):
    """One public, pre-joined, read-only dataset and its query allowlists.

    `columns` / `group_by` / `unit_columns` / `unit_group_by` are qualified
    `table.column` references; `dims` / `measures` / `internal_*` name the
    unqualified output columns an analyst may use. The unit view (internal
    only) adds the person key (as `UNIT_PERSON`) and `unit_columns`.
    """
    model_config = ConfigDict(extra="forbid")
    base: str
    person: str | None = None               # default f"{base}.{person_key}"
    # The population this view describes. Views of one definition usually
    # describe the same people, and then this is left unset (it defaults to
    # the person key); a definition holding genuinely disjoint populations —
    # a donors study and a staff study in one file — names them, so that a
    # cross-view comparison is attempted only between views of the same
    # people (roadmap 0.5; the companion of `quantities`).
    population: str | None = None
    joins: list[Join] = []
    columns: list[str | DerivedColumn] = []
    group_by: list[str] = []
    unit_columns: list[str] = []
    unit_group_by: list[str] = []
    dims: dict[str, str] = {}
    measures: list[str] = []
    internal_filters: dict[str, str] = {}
    internal_measures: list[str] = []
    glm_responses: dict[str, list[str]] = {}
    # Dimensions that are ORDERED time axes (`month`, `wave`): integer-kind
    # dims the `series` tool may lay a vetted per-window aggregate along.
    # Declared, not inferred — an integer dim is not necessarily a time.
    time_dims: list[str] = []

    def output_columns(self) -> list[str]:
        return [c.name if isinstance(c, DerivedColumn) else _split_ref(c, "column")[1]
                for c in self.columns]

    def unit_output_columns(self, person_key: str) -> list[str]:
        return ([UNIT_PERSON] + [_split_ref(c, "unit column")[1] for c in self.unit_columns]
                + self.output_columns())

    def _select_list(self, person_key: str, unit: bool) -> list[str]:
        out: list[str] = []
        if unit:
            person = self.person or f"{self.base}.{person_key}"
            out.append(f"{_qref(person)} AS {_qident(UNIT_PERSON)}")
            out.extend(_qref(c) for c in self.unit_columns)
        for c in self.columns:
            out.append(c.sql() if isinstance(c, DerivedColumn) else _qref(c))
        return out

    def sql(self, name: str, person_key: str, unit: bool) -> str:
        _check_ident(name, "dataset")
        selects = self._select_list(person_key, unit)
        text = f"FROM {_qtable(self.base)}"
        for j in self.joins:
            kw = "LEFT JOIN" if j.how == "left" else "JOIN"
            text += (f" {kw} {_qtable(j.table)}"
                     f" ON {_qtable(self.base)}.{_qident(j.key)}"
                     f" = {_qtable(j.table)}.{_qident(j.key)}")
        groups = list(self.group_by) + (list(self.unit_group_by) if unit else [])
        if groups:
            text += " GROUP BY " + ", ".join(_qref(g) for g in groups)
        view = f"_{name}_u" if unit else name
        return f"CREATE VIEW {_qident(view)} AS\nSELECT {', '.join(selects)}\n{text}"


class RangeRule(BaseModel):
    """Allowed predicates on an internal high-granularity filter: only these
    operators, and only these edge values, so a filter selects whole public
    bands (hardening #39)."""
    model_config = ConfigDict(extra="forbid")
    ops: list[str] = Field(min_length=1)
    edges: dict[str, list[Any]]

    @model_validator(mode="after")
    def _edges_match_ops(self):
        bad = [op for op in self.ops if op not in RANGE_RULE_OPS]
        if bad:
            raise ValueError(f"range-rule operators {bad!r} not in {RANGE_RULE_OPS}")
        if set(self.edges) != set(self.ops):
            raise ValueError("range-rule edges must be given for exactly the declared ops")
        for op, values in self.edges.items():
            if not values:
                raise ValueError(f"range-rule edges for {op!r} cannot be empty")
        # The `>=` edges are the bands' lower bounds and the `<=` edges their
        # upper bounds, so the two lists describe the SAME bands and must pair
        # up. Checked here rather than left to the formal artifacts, which do
        # catch it (`edges_are_the_band_boundaries`, and the Lean generator
        # refuses to derive bands from mismatched lists) — but only when
        # somebody regenerates them, whereas the operator wants to know while
        # they are editing the file.
        if len(self.edges) == 2 and len({len(v) for v in self.edges.values()}) != 1:
            counts = {op: len(v) for op, v in sorted(self.edges.items())}
            raise ValueError(
                f"range-rule edges must describe the same bands, so the lists "
                f"must pair up — got {counts}. The '>=' edges are the bands' "
                f"lower bounds and the '<=' edges their upper bounds")
        return self


class Lexicon(BaseModel):
    """The natural-language vocabulary of this dataset: dimension synonyms for
    the fidelity checks, response synonyms per dataset, and domain cues the
    intent filter accepts as on-topic."""
    model_config = ConfigDict(extra="forbid")
    dimension_synonyms: dict[str, str] = {}
    response_synonyms: dict[str, dict[str, str]] = {}
    domain_cues: list[str] = []


class PlannerExample(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request: str
    spec: dict[str, Any]


class UiQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str
    query: str


class DatasetDefinition(BaseModel):
    """A complete, validated description of one study the gateway may serve."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    person_key: str
    tables: dict[str, dict[str, str]] = Field(min_length=1)
    # public column metadata (safe to disclose): description + declared domain
    columns: dict[str, dict[str, Any]] = {}
    # disclosure roles for view-derived columns (not present in any base table)
    derived_roles: dict[str, str] = {}
    datasets: dict[str, ViewDef] = Field(min_length=1)
    # Declared measure equivalence (hardening #95, roadmap 0.0). A quantity
    # names measure columns on DIFFERENT views that measure the same thing per
    # person — `donor_spend.total_spend_gbp` IS the per-donor sum of
    # `spend.amount_gbp` — so the session auditor's differencing lineage can
    # compare a release on one view with a release on another. Only declared
    # pairs are compared across views: differencing binds only between
    # commensurable releases (a correlation minus a mean recovers nothing),
    # and the code cannot infer commensurability; the catalogue must say it.
    #     quantities:
    #       spend_gbp: [spend.amount_gbp, donor_spend.total_spend_gbp]
    quantities: dict[str, list[str]] = {}
    internal_range_rules: dict[str, RangeRule] = {}
    lexicon: Lexicon = Lexicon()
    planner_hints: list[str] = []
    planner_examples: list[PlannerExample] = []
    ui_queries: list[UiQuery] = []
    tour: list[str] = []

    _source: str = PrivateAttr(default="")

    # ------------------------------------------------------------------ #
    # validation                                                          #
    # ------------------------------------------------------------------ #
    @model_validator(mode="after")
    def _check(self):
        _check_ident(self.person_key, "person_key")
        if not self.tables:
            raise ValueError("a dataset definition needs at least one base table")
        seen_person = False
        for tname, cols in self.tables.items():
            _check_ident(tname, "table")
            if not cols:
                raise ValueError(f"table {tname!r} has no columns")
            for cname, role in cols.items():
                _check_ident(cname, f"column of {tname!r}")
                if role not in ROLES:
                    raise ValueError(
                        f"{tname}.{cname} has unknown disclosure role {role!r} "
                        f"(one of {ROLES})")
                if cname == self.person_key:
                    if role != "DI":
                        raise ValueError(
                            f"person key {tname}.{cname} must have role 'DI', got {role!r}")
                    seen_person = True
        if not seen_person:
            raise ValueError(
                f"person key {self.person_key!r} is not a column of any base table")

        for cname in self.columns:
            _check_ident(cname, "metadata column")
            meta = self.columns[cname] or {}
            unknown = set(meta) - {"desc", "domain"}
            if unknown:
                raise ValueError(f"metadata for {cname!r} has unknown keys {sorted(unknown)}")
            domain = meta.get("domain")
            if domain is not None and not isinstance(domain, list):
                raise ValueError(f"metadata domain for {cname!r} must be a list")
        for cname, role in self.derived_roles.items():
            _check_ident(cname, "derived column")
            if role not in ROLES:
                raise ValueError(f"derived column {cname!r} has unknown role {role!r}")

        all_internal_filters: set[str] = set()
        all_dims: set[str] = set()
        for dname, view in self.datasets.items():
            _check_ident(dname, "dataset")
            self._check_view(dname, view)
            all_internal_filters |= set(view.internal_filters)
            all_dims |= set(view.dims)
        self._check_quantities()

        for col in self.internal_range_rules:
            _check_ident(col, "internal range-rule column")
            if col not in all_internal_filters:
                raise ValueError(
                    f"range rule for {col!r}: not an internal filter of any dataset")

        for phrase, dim in self.lexicon.dimension_synonyms.items():
            if dim not in all_dims:
                raise ValueError(
                    f"dimension synonym {phrase!r} maps to {dim!r}, "
                    f"which is not a dimension of any dataset")
        for dname, syns in self.lexicon.response_synonyms.items():
            if dname not in self.datasets:
                raise ValueError(f"response synonyms name unknown dataset {dname!r}")
            view = self.datasets[dname]
            allowed = set(view.dims) | set(view.measures)
            for phrase, col in syns.items():
                if col not in allowed:
                    raise ValueError(
                        f"response synonym {phrase!r} maps to {col!r}, not a "
                        f"dimension or measure of {dname!r}")
        return self

    def _check_quantities(self) -> None:
        seen: dict[tuple[str, str], str] = {}
        for qname, members in self.quantities.items():
            _check_ident(qname, "quantity")
            if not isinstance(members, list) or len(members) < 2:
                raise ValueError(
                    f"quantity {qname!r} must list at least two <dataset>.<measure> members")
            views_seen: set[str] = set()
            for ref in members:
                dname, col = _split_ref(ref, f"quantity {qname!r} member")
                view = self.datasets.get(dname)
                if view is None:
                    raise ValueError(f"quantity {qname!r} names unknown dataset {dname!r}")
                if col not in view.measures:
                    raise ValueError(
                        f"quantity {qname!r}: {ref!r} is not a measure of {dname!r}")
                if dname in views_seen:
                    raise ValueError(
                        f"quantity {qname!r} names dataset {dname!r} twice; a quantity has "
                        "at most one column per view")
                views_seen.add(dname)
                if (dname, col) in seen:
                    raise ValueError(
                        f"{ref!r} belongs to quantities {seen[(dname, col)]!r} and {qname!r}; "
                        "a measure has at most one quantity")
                seen[(dname, col)] = qname

    def _check_view(self, dname: str, view: ViewDef) -> None:
        if view.base not in self.tables:
            raise ValueError(f"{dname}: base table {view.base!r} is not defined")
        reachable = {view.base}
        for j in view.joins:
            if j.table not in self.tables:
                raise ValueError(f"{dname}: join table {j.table!r} is not defined")
            # Each table may enter the view once. The generated SQL is
            # `JOIN t ON base.key = t.key`, so joining the base to itself, or
            # the same table twice, emits a predicate whose two sides name the
            # same relation — DuckDB then either self-matches every row or
            # rejects the duplicate alias, and neither is what the operator
            # meant. Rejected here so a definition fails at load with a
            # sentence, rather than at engine build with a catalogue error.
            if j.table in reachable:
                raise ValueError(
                    f"{dname}: table {j.table!r} is joined more than once "
                    f"(or joined to itself); each table may enter a view once")
            if j.how not in ("inner", "left"):
                raise ValueError(f"{dname}: join how must be 'inner' or 'left'")
            _check_ident(j.key, f"{dname} join key")
            if j.key not in self.tables[view.base]:
                raise ValueError(
                    f"{dname}: join key {j.key!r} is not a column of base {view.base!r}")
            if j.key not in self.tables[j.table]:
                raise ValueError(
                    f"{dname}: join key {j.key!r} is not a column of {j.table!r}")
            reachable.add(j.table)

        def ref_ok(ref: str, what: str) -> None:
            table, col = _split_ref(ref, f"{dname} {what}")
            if table not in reachable:
                raise ValueError(
                    f"{dname}: {what} {ref!r} names table {table!r}, which is "
                    f"not the base or a joined table")
            if col not in self.tables[table]:
                raise ValueError(f"{dname}: {what} {ref!r} is not a column of {table!r}")

        for c in view.columns:
            if isinstance(c, DerivedColumn):
                _check_ident(c.name, f"{dname} derived column")
                for r in c.refs():
                    ref_ok(r, "derived-column reference")
            else:
                ref_ok(c, "column")
        for g in (*view.group_by, *view.unit_group_by, *view.unit_columns):
            ref_ok(g, "group/unit column")
        person = view.person or f"{view.base}.{self.person_key}"
        ref_ok(person, "person column")

        outputs = view.output_columns()
        if len(outputs) != len(set(outputs)):
            raise ValueError(f"{dname}: duplicate output column names {outputs!r}")
        unit_outputs = view.unit_output_columns(self.person_key)
        if len(unit_outputs) != len(set(unit_outputs)):
            raise ValueError(
                f"{dname}: a unit/internal column name collides with a public "
                f"output or the person alias {UNIT_PERSON!r}")
        # direct identifiers never appear on a public view
        for out in outputs:
            for tname, cols in self.tables.items():
                if out in cols and cols[out] == "DI":
                    raise ValueError(
                        f"{dname}: public view exposes direct identifier {out!r}")
        if _split_ref(person, "person")[1] in outputs:
            raise ValueError(f"{dname}: public view exposes the person key")

        for kind, mapping in (("dimension", view.dims), ("internal filter", view.internal_filters)):
            for name, k in mapping.items():
                _check_ident(name, f"{dname} {kind}")
                if k not in DIM_KINDS:
                    raise ValueError(
                        f"{dname}: {kind} {name!r} has unknown kind {k!r} "
                        f"(one of {DIM_KINDS})")
        if not set(view.dims) <= set(outputs):
            raise ValueError(
                f"{dname}: dims {sorted(set(view.dims) - set(outputs))!r} are not "
                f"columns of the generated view")
        for m in view.measures:
            _check_ident(m, f"{dname} measure")
        if not set(view.measures) <= set(outputs):
            raise ValueError(
                f"{dname}: measures {sorted(set(view.measures) - set(outputs))!r} "
                f"are not columns of the generated view")
        if not set(view.internal_filters) <= set(unit_outputs):
            raise ValueError(
                f"{dname}: internal filters must be unit-view columns "
                f"(missing: {sorted(set(view.internal_filters) - set(unit_outputs))!r})")
        for m in view.internal_measures:
            _check_ident(m, f"{dname} internal measure")
        if not set(view.internal_measures) <= set(unit_outputs):
            raise ValueError(f"{dname}: internal measures must be unit-view columns")
        if set(view.dims) & set(view.internal_filters):
            raise ValueError(f"{dname}: a column cannot be both a dim and an internal filter")
        if set(view.measures) & set(view.internal_measures):
            raise ValueError(
                f"{dname}: a column cannot be both a measure and an internal measure")
        for t in view.time_dims:
            if t not in view.dims:
                raise ValueError(f"{dname}: time dimension {t!r} is not a dimension of the view")
            if view.dims[t] != "int":
                raise ValueError(
                    f"{dname}: time dimension {t!r} must be of kind 'int' (an ordered axis)")
        responses = set(view.dims) | set(view.measures)
        for resp, fams in view.glm_responses.items():
            if resp not in responses:
                raise ValueError(
                    f"{dname}: glm response {resp!r} is not a dimension or measure")
            bad = [f for f in fams if f not in GLM_FAMILIES]
            if bad:
                raise ValueError(
                    f"{dname}: glm response {resp!r} permits unknown families {bad!r}")

    # ------------------------------------------------------------------ #
    # projections into the structures the machinery consumes              #
    # ------------------------------------------------------------------ #
    def table_names(self) -> list[str]:
        return list(self.tables)

    def tables_as_dict(self) -> dict[str, dict[str, str]]:
        return {t: dict(cols) for t, cols in self.tables.items()}

    def column_meta_as_dict(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for name, meta in self.columns.items():
            entry: dict[str, Any] = {"desc": (meta or {}).get("desc", "")}
            if (meta or {}).get("domain") is not None:
                entry["domain"] = list(meta["domain"])
            out[name] = entry
        return out

    def catalogue(self) -> dict[str, dict[str, Any]]:
        """The QuerySpec allowlist structure (`safetre.query.CATALOGUE`)."""
        return {
            name: {
                "dims": dict(view.dims),
                "measures": set(view.measures),
                "internal_filters": dict(view.internal_filters),
                "internal_measures": set(view.internal_measures),
                "glm_responses": {r: set(fams) for r, fams in view.glm_responses.items()},
                "time_dims": list(view.time_dims),
            }
            for name, view in self.datasets.items()
        }

    def range_rules(self) -> dict[str, dict]:
        return {
            col: {"ops": tuple(rule.ops),
                  "edges": {op: tuple(vals) for op, vals in rule.edges.items()}}
            for col, rule in self.internal_range_rules.items()
        }

    def public_view_sql(self) -> dict[str, str]:
        return {name: view.sql(name, self.person_key, unit=False)
                for name, view in self.datasets.items()}

    def unit_view_sql(self) -> dict[str, str]:
        return {name: view.sql(name, self.person_key, unit=True)
                for name, view in self.datasets.items()}

    def quantity_of(self, dataset: str, column: str | None) -> str | None:
        """The declared quantity a measure column carries on a view, or None
        (undeclared measures are compared within their own view only)."""
        if column is None:
            return None
        for qname, members in self.quantities.items():
            if f"{dataset}.{column}" in members:
                return qname
        return None

    def quantity_columns(self, quantity: str) -> dict[str, str]:
        """{dataset: column} for every view carrying the quantity."""
        out: dict[str, str] = {}
        for ref in self.quantities.get(quantity, ()):
            dname, col = ref.split(".", 1)
            out[dname] = col
        return out

    def population_of(self, dataset: str) -> str:
        view = self.datasets[dataset]
        return view.population or self.person_key

    def glm_responses_text(self) -> str:
        parts = []
        for name, view in self.datasets.items():
            if view.glm_responses:
                rendered = ", ".join(f"{r} ({'/'.join(fams)})"
                                     for r, fams in view.glm_responses.items())
                parts.append(f"{name}: {rendered}")
        return "; ".join(parts)


# --------------------------------------------------------------------- #
# the active definition: one per process, like the disclosure policy      #
# --------------------------------------------------------------------- #

_ACTIVE: DatasetDefinition | None = None
_SYNCS: list[Callable[[DatasetDefinition], None]] = []


def register_sync(fn: Callable[[DatasetDefinition], None]) -> None:
    """Called by consumer modules (schema/query/engine/analyst) with the
    function that re-mirrors the active definition into their long-standing
    module-level structures. Runs on every `activate`."""
    _SYNCS.append(fn)


def load_dataset(path: str | os.PathLike) -> DatasetDefinition:
    """Load and validate a dataset definition file (operator configuration)."""
    path = str(path)
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    defn = DatasetDefinition.model_validate(doc or {})
    defn._source = path
    return defn


def active() -> DatasetDefinition:
    """The process's active dataset definition.

    Resolved lazily on first use: `SAFETRE_DATASET` if set, else the packaged
    synthetic demo. The web app may call `activate` explicitly at startup;
    tests activate fixture definitions and then restore the demo.
    """
    global _ACTIVE
    if _ACTIVE is None:
        _ACTIVE = load_dataset(os.environ.get("SAFETRE_DATASET") or _PACKAGED)
    return _ACTIVE


def activate(defn: DatasetDefinition) -> None:
    """Make `defn` the active definition and re-mirror every consumer module."""
    global _ACTIVE
    _ACTIVE = defn
    for fn in list(_SYNCS):
        fn(defn)


def active_source() -> str:
    return active()._source


def is_packaged_demo() -> bool:
    """Whether the active definition is the packaged synthetic demo — the one
    case where a synthetic generator can stand in for operator CSVs."""
    try:
        return pathlib.Path(active_source()).resolve() == _PACKAGED.resolve()
    except OSError:
        return False
