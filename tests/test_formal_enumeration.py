"""Exhaustive (not sampled) formal checks over the bounded query skeleton.

`docs/formal-methods-analysis.md` argues the query space is finite and decidable.
`test_query_properties.py` samples it with Hypothesis; this module *enumerates*
the no-filter skeleton in full — every dataset x every measure configuration x
every group-by subset of size 0..MAX_GROUP_BY — and machine-checks the decidable
prohibitions on every point. It is deliberately compile-only (no engine
execution) so the whole space is covered in milliseconds; end-to-end release
safety over the same space is covered by `test_query_properties` and
`test_procedure_conformance`.

Checks per point:
  P3   identifiers / free-text / timestamps never appear in the compiled SQL
  P4   an internal analysis variable (age_years) may feed a fixed tool (a corr
       operand / unit-view filter) but is never grouped or returned
  P8/P9 SafeSQL shape: SELECT .. FROM one known view [WHERE ?..] [GROUP BY]
       ORDER BY n DESC LIMIT ROW_CAP; every value bound; no ';' / DDL / DML
Plus a static information-flow (noninterference) proof over CATALOGUE + views.
"""
from __future__ import annotations

import itertools
import re

from safetre.engine import ROW_CAP, _UNIT_VIEWS, _VIEWS, compile_query
from safetre.query import CATALOGUE, MAX_GROUP_BY, QuerySpec
from safetre.schema import identifier_columns, role_of

HARD_FORBIDDEN = {"donor_id", "free_text", "ts", "enrolment_date",
                  "item_name", "app_name", "developer", "event_id", "app_id"}
INTERNAL_VARS = {"age_years"}
FORBIDDEN = HARD_FORBIDDEN | INTERNAL_VARS
DDL_DML = (" INSERT ", " UPDATE ", " DELETE ", " DROP ", " ALTER ", " CREATE ",
           " REPLACE ", " ATTACH ", " COPY ", " PRAGMA ", " EXPORT ")
KNOWN_VIEWS = set(_VIEWS) | {f"_{ds}_u" for ds in _UNIT_VIEWS}


def _measure_configs(dataset):
    cat = CATALOGUE[dataset]
    measures = sorted(cat["measures"])
    corr_pool = sorted(cat["measures"] | cat.get("internal_measures", set()))
    yield {"fn": "count"}
    for m in measures:
        yield {"fn": "mean", "column": m}
        yield {"fn": "sum", "column": m}
        yield {"fn": "sum_sq", "column": m}
    for x, y in itertools.combinations(corr_pool, 2):
        yield {"fn": "corr", "x": x, "y": y}


def _all_specs_no_filter():
    for dataset in CATALOGUE:
        dims = sorted(CATALOGUE[dataset]["dims"])
        gbs = [list(c) for k in range(MAX_GROUP_BY + 1)
               for c in itertools.combinations(dims, k)]
        for measure in _measure_configs(dataset):
            for gb in gbs:
                yield QuerySpec(dataset=dataset, measure=measure, group_by=gb)


def test_query_skeleton_is_enumerable_and_nonempty():
    specs = list(_all_specs_no_filter())
    # a finite, decidable space — this is the premise the formal analysis rests on
    assert 1500 < len(specs) < 5000, len(specs)


def test_exhaustive_compiled_sql_is_safe_over_whole_skeleton():
    for spec in _all_specs_no_filter():
        plan = compile_query(spec)
        sql = plan.sql
        ctx = (spec.dataset, spec.measure.model_dump(), spec.group_by)

        # P8/P9: fixed SafeSQL shape, fully parameterised, no ';'/DDL/DML
        assert plan.source_view in KNOWN_VIEWS, ctx
        assert sql.startswith("SELECT "), ctx
        assert sql.endswith(f" ORDER BY n DESC LIMIT {ROW_CAP}"), ctx
        assert ";" not in sql, ctx
        assert sql.count("?") == len(plan.params), ctx
        padded = f" {sql.upper()} "
        for verb in DDL_DML:
            assert verb not in padded, (verb, ctx)
        # exactly one FROM, targeting the declared source view
        assert re.findall(r'FROM\s+"([a-z0-9_]+)"', sql) == [plan.source_view], ctx

        # P3: identifiers/free-text/timestamps never in the public SQL
        for col in HARD_FORBIDDEN:
            assert not re.search(rf'"{col}"', sql), (col, ctx)
        # P4: internal vars never grouped or returned; only ever a corr operand
        for col in plan.output_columns:
            assert col not in FORBIDDEN, (col, ctx)
        assert not (set(spec.group_by) & INTERNAL_VARS), ctx
        if any(re.search(rf'"{v}"', sql) for v in INTERNAL_VARS):
            operands = ({spec.measure.x, spec.measure.y}
                        if spec.measure.fn == "corr" else set())
            assert INTERNAL_VARS & operands, ("internal var not a corr operand", ctx)


def test_static_noninterference_over_catalogue_and_views():
    """Opportunity C (lightweight): no Secret/DI-labelled column can reach the
    public query path — a static information-flow proof over CATALOGUE + views."""
    secret = identifier_columns() | {"free_text", "ts", "enrolment_date"}

    # no public view SELECTs a secret or internal column
    for name, ddl in _VIEWS.items():
        select_clause = ddl.lower().split("from")[0]
        for col in secret | INTERNAL_VARS:
            assert not re.search(rf"\b{col}\b", select_clause), (name, col)

    for ds, info in CATALOGUE.items():
        public_cols = set(info["dims"]) | set(info["measures"])
        assert not (public_cols & secret), (ds, public_cols & secret)
        assert not (public_cols & INTERNAL_VARS), ds
        for col in public_cols:
            assert role_of(col) != "DI", (ds, col)
        # sensitive columns are only ever aggregatable measures, never dimensions
        for dim in info["dims"]:
            assert role_of(dim) != "S", (ds, dim)
