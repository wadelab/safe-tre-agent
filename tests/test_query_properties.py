"""Property-based security checks for the finite QuerySpec space."""

from __future__ import annotations

import string

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from safetre import synth
from safetre.disclosure import COUNT_COLUMNS, ROUND_BASE, DisclosurePolicy, leak_detector
from safetre.engine import ROW_CAP, QueryEngine, compile_dominance_query, compile_query
from safetre.query import CATALOGUE, CAT_OPS, MAX_FILTERS, MAX_GROUP_BY, NUM_OPS, QuerySpec
from safetre.schema import identifier_columns, sensitive_columns

_ASCII_TEXT = string.ascii_letters + string.digits + " _-:;.'\"/()[]{}"
_ENGINE = QueryEngine(synth.generate(seed=17))
_FORBIDDEN_COLUMNS = sorted(
    identifier_columns()
    | {
        "free_text",
        "ts",
        "enrolment_date",
        "event_id",
        "app_id",
        "app_name",
        "developer",
        "item_name",
    }
)


def _scalar_for(kind: str) -> st.SearchStrategy:
    if kind == "cat":
        return st.text(alphabet=_ASCII_TEXT, min_size=0, max_size=24)
    if kind == "bool":
        return st.booleans()
    if kind == "int":
        return st.integers(min_value=-10, max_value=120)
    raise AssertionError(f"unknown catalogue kind {kind!r}")


@st.composite
def _filter_for(draw, dataset: str) -> dict:
    dims = CATALOGUE[dataset]["dims"] | CATALOGUE[dataset].get("internal_filters", {})
    column = draw(st.sampled_from(sorted(dims)))
    kind = dims[column]
    ops = CAT_OPS if kind in ("cat", "bool") else NUM_OPS
    op = draw(st.sampled_from(sorted(ops)))
    scalar = _scalar_for(kind)
    value = draw(st.lists(scalar, min_size=1, max_size=4)) if op == "in" else draw(scalar)
    return {"column": column, "op": op, "value": value}


@st.composite
def valid_queryspec_dicts(draw) -> dict:
    dataset = draw(st.sampled_from(sorted(CATALOGUE)))
    dims = sorted(CATALOGUE[dataset]["dims"])
    measures = sorted(CATALOGUE[dataset]["measures"])
    corr_measures = sorted(CATALOGUE[dataset]["measures"] | CATALOGUE[dataset].get("internal_measures", set()))
    fn = draw(st.sampled_from(["count", "mean", "sum", "corr"]))
    if fn == "count":
        measure = {"fn": fn}
    elif fn == "corr":
        x, y = draw(st.lists(st.sampled_from(corr_measures), min_size=2, max_size=2, unique=True))
        measure = {"fn": fn, "x": x, "y": y}
    else:
        measure = {"fn": fn, "column": draw(st.sampled_from(measures))}
    group_by = draw(
        st.lists(
            st.sampled_from(dims),
            min_size=0,
            max_size=min(MAX_GROUP_BY, len(dims)),
            unique=True,
        )
    )
    filters = draw(st.lists(_filter_for(dataset), min_size=0, max_size=MAX_FILTERS))
    return {"dataset": dataset, "measure": measure, "group_by": group_by, "filters": filters}


def _touched_columns(spec: QuerySpec) -> set[str]:
    cols = set(spec.group_by)
    cols.update(f.column for f in spec.filters)
    if spec.measure.column is not None:
        cols.add(spec.measure.column)
    if spec.measure.x is not None:
        cols.add(spec.measure.x)
    if spec.measure.y is not None:
        cols.add(spec.measure.y)
    return cols


@given(valid_queryspec_dicts())
@settings(max_examples=200, deadline=None)
def test_generated_valid_queryspecs_stay_inside_catalogue(raw):
    spec = QuerySpec(**raw)
    touched = _touched_columns(spec)
    allowed = (
        set(CATALOGUE[spec.dataset]["dims"])
        | set(CATALOGUE[spec.dataset]["measures"])
        | set(CATALOGUE[spec.dataset].get("internal_filters", {}))
        | set(CATALOGUE[spec.dataset].get("internal_measures", set()))
    )

    assert touched <= allowed
    assert not (touched & identifier_columns())
    assert "free_text" not in touched
    assert len(spec.group_by) == len(set(spec.group_by))
    assert len(spec.group_by) <= MAX_GROUP_BY
    assert len(spec.filters) <= MAX_FILTERS


@given(valid_queryspec_dicts())
@settings(max_examples=80, deadline=None)
def test_generated_valid_queryspecs_execute_without_unsafe_release(raw):
    spec = QuerySpec(**raw)

    df = _ENGINE.run(spec)
    released, action, _findings = DisclosurePolicy().apply(df)

    if action == "deny":
        assert released is None
        return

    assert released is not None
    assert not leak_detector(released)

    cols = {str(c) for c in released.columns}
    assert not (cols & identifier_columns())
    assert "free_text" not in cols
    raw_sensitive_cols = cols & (sensitive_columns() - identifier_columns())
    assert not raw_sensitive_cols

    for column in released.columns:
        if str(column).lower() in COUNT_COLUMNS:
            assert (released[column] >= DisclosurePolicy.DEFAULT_THRESHOLD).all()
            assert (released[column] % ROUND_BASE == 0).all()


@given(valid_queryspec_dicts())
@settings(max_examples=200, deadline=None)
def test_compiled_public_sql_has_safe_shape(raw):
    spec = QuerySpec(**raw)
    plan = compile_query(spec)

    assert plan.source_view in {spec.dataset, f"_{spec.dataset}_u"}
    assert plan.output_columns == tuple(spec.group_by) + ("value", "n")
    assert plan.sql.startswith("SELECT ")
    assert f' FROM "{plan.source_view}"' in plan.sql
    assert plan.sql.endswith(f" ORDER BY n DESC LIMIT {ROW_CAP}")
    assert plan.sql.count("?") == len(plan.params)
    assert ";" not in plan.sql
    assert "donor_id" not in plan.sql
    assert "free_text" not in plan.sql
    if "age_years" in plan.sql:
        assert plan.source_view == f"_{spec.dataset}_u"
        assert "age_years" not in plan.output_columns
    if plan.source_view == spec.dataset:
        assert "_spend_u" not in plan.sql
        assert "_donor_spend_u" not in plan.sql
        assert "_wellbeing_u" not in plan.sql

    forbidden_verbs = (" INSERT ", " UPDATE ", " DELETE ", " DROP ", " ALTER ", " CREATE ")
    padded_sql = f" {plan.sql.upper()} "
    assert not any(verb in padded_sql for verb in forbidden_verbs)


@given(valid_queryspec_dicts())
@settings(max_examples=200, deadline=None)
def test_dominance_sql_is_internal_and_only_for_sum_or_mean(raw):
    spec = QuerySpec(**raw)

    if spec.measure.fn not in ("mean", "sum"):
        with pytest.raises(ValueError):
            compile_dominance_query(spec)
        return

    plan = compile_dominance_query(spec)
    assert plan.source_view == f"_{spec.dataset}_u"
    assert plan.output_columns == tuple(spec.group_by) + ("dominance",)
    assert f'FROM "_{spec.dataset}_u"' in plan.sql
    assert f'FROM "{spec.dataset}"' not in plan.sql
    assert plan.sql.count("?") == len(plan.params)
    assert ";" not in plan.sql
    assert "free_text" not in plan.sql


def test_filter_values_are_only_bound_parameters_in_compiled_sql():
    evil = "x'; DROP TABLE events; --"
    spec = QuerySpec(
        dataset="spend",
        measure={"fn": "count"},
        group_by=["canton"],
        filters=[{"column": "canton", "op": "==", "value": evil}],
    )

    plan = compile_query(spec)

    assert evil not in plan.sql
    assert plan.params == (evil,)
    assert plan.sql.count("?") == 1


@given(
    dataset=st.sampled_from(sorted(CATALOGUE)),
    forbidden=st.sampled_from(_FORBIDDEN_COLUMNS),
)
def test_forbidden_columns_are_rejected_everywhere(dataset, forbidden):
    with pytest.raises(ValidationError):
        QuerySpec(dataset=dataset, measure={"fn": "count"}, group_by=[forbidden])

    with pytest.raises(ValidationError):
        QuerySpec(
            dataset=dataset,
            measure={"fn": "count"},
            filters=[{"column": forbidden, "op": "==", "value": "x"}],
        )

    with pytest.raises(ValidationError):
        QuerySpec(dataset=dataset, measure={"fn": "mean", "column": forbidden})

    with pytest.raises(ValidationError):
        QuerySpec(
            dataset=dataset,
            measure={"fn": "corr", "x": forbidden, "y": sorted(CATALOGUE[dataset]["measures"])[0]},
        )


@given(dataset=st.sampled_from(sorted(CATALOGUE)))
def test_internal_age_is_only_for_filters_and_fixed_corr(dataset):
    if "age_years" not in CATALOGUE[dataset].get("internal_filters", {}):
        return

    with pytest.raises(ValidationError):
        QuerySpec(dataset=dataset, measure={"fn": "count"}, group_by=["age_years"])

    with pytest.raises(ValidationError):
        QuerySpec(dataset=dataset, measure={"fn": "mean", "column": "age_years"})

    QuerySpec(
        dataset=dataset,
        measure={"fn": "count"},
        filters=[{"column": "age_years", "op": ">=", "value": 18}],
    )

    if "age_years" in CATALOGUE[dataset].get("internal_measures", set()):
        public_measure = sorted(CATALOGUE[dataset]["measures"])[0]
        QuerySpec(dataset=dataset, measure={"fn": "corr", "x": "age_years", "y": public_measure})


@given(dataset=st.sampled_from(sorted(CATALOGUE)))
def test_empty_in_filters_are_rejected(dataset):
    column = sorted(CATALOGUE[dataset]["dims"])[0]

    with pytest.raises(ValidationError):
        QuerySpec(
            dataset=dataset,
            measure={"fn": "count"},
            filters=[{"column": column, "op": "in", "value": []}],
        )


@given(dataset=st.sampled_from(sorted(CATALOGUE)))
def test_duplicate_group_by_dimensions_are_rejected(dataset):
    column = sorted(CATALOGUE[dataset]["dims"])[0]

    with pytest.raises(ValidationError):
        QuerySpec(dataset=dataset, measure={"fn": "count"}, group_by=[column, column])
