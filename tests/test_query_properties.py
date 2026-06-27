"""Property-based security checks for the finite QuerySpec space."""

from __future__ import annotations

import string

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from safetre import synth
from safetre.disclosure import COUNT_COLUMNS, ROUND_BASE, DisclosurePolicy, leak_detector
from safetre.engine import QueryEngine
from safetre.query import CATALOGUE, CAT_OPS, MAX_FILTERS, MAX_GROUP_BY, NUM_OPS, QuerySpec
from safetre.schema import identifier_columns, sensitive_columns

_ASCII_TEXT = string.ascii_letters + string.digits + " _-:;.'\"/()[]{}"
_ENGINE = QueryEngine(synth.generate(seed=17))
_FORBIDDEN_COLUMNS = sorted(
    identifier_columns()
    | {
        "free_text",
        "ts",
        "age_years",
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
    dims = CATALOGUE[dataset]["dims"]
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
    fn = draw(st.sampled_from(["count", "mean", "sum"]))
    measure = {"fn": fn, "column": None if fn == "count" else draw(st.sampled_from(measures))}
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
    return cols


@given(valid_queryspec_dicts())
@settings(max_examples=200, deadline=None)
def test_generated_valid_queryspecs_stay_inside_catalogue(raw):
    spec = QuerySpec(**raw)
    touched = _touched_columns(spec)
    allowed = set(CATALOGUE[spec.dataset]["dims"]) | set(CATALOGUE[spec.dataset]["measures"])

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
