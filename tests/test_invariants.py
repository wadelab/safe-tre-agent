"""Security invariants — these guard the boundary against a subtle backdoor.

If a change weakens the boundary (exposes an identifier in a view, lowers a
disclosure threshold, lets QuerySpec accept extra fields, makes a unit view
queryable), one of these fails. They are cheap insurance for the ~4 files the
whole security argument rests on.
"""

import re

import pytest
from pydantic import ValidationError

from safetre import disclosure, engine, query, schema
from safetre.schema import identifier_columns

FORBIDDEN_IN_PUBLIC_VIEWS = {"donor_id", "free_text", "age_years"}


def _select_list(ddl: str) -> str:
    m = re.search(r"select(.*?)from", ddl, re.I | re.S)
    return (m.group(1) if m else ddl).lower()


def test_public_views_never_expose_identifiers():
    for name, ddl in engine._VIEWS.items():
        cols = _select_list(ddl)
        for col in FORBIDDEN_IN_PUBLIC_VIEWS:
            assert col not in cols, f"{col!r} exposed in public view {name!r}"


def test_public_catalogue_excludes_identifiers_and_freetext():
    for ds, info in query.CATALOGUE.items():
        cols = set(info["dims"]) | set(info["measures"])
        assert "donor_id" not in cols and "free_text" not in cols
        assert not (cols & identifier_columns()), f"identifier in catalogue {ds!r}"


def test_every_catalogue_column_has_an_explicit_role():
    """schema.role_of falls back to 'R' (reference) for unknown columns, the
    LEAST protective label. A catalogue column relying on that default would
    be mislabelled silently, and the generated Lean label map would inherit
    the error — so require an explicit role for every exposed column."""
    declared = ({c for cols in schema.TABLES.values() for c in cols}
                | set(schema._DERIVED_ROLES))
    for ds, info in query.CATALOGUE.items():
        cols = (set(info["dims"]) | set(info["measures"])
                | set(info.get("internal_filters", {}))
                | set(info.get("internal_measures", set())))
        missing = cols - declared
        assert not missing, (
            f"{ds!r}: catalogue columns without an explicit disclosure "
            f"role: {sorted(missing)}")


def test_internal_analysis_columns_are_not_public_outputs():
    for ds, info in query.CATALOGUE.items():
        public_cols = set(info["dims"]) | set(info["measures"])
        internal_cols = set(info.get("internal_filters", {})) | set(info.get("internal_measures", set()))
        assert not (internal_cols & public_cols), f"internal column public in catalogue {ds!r}"


def test_unit_views_are_not_queryable():
    # The queryable datasets are exactly the ACTIVE definition's public ones
    # (validation is a catalogue membership check, so any study can be served);
    # internal unit views (prefixed "_") must never be among them, and
    # proposing one must fail validation.
    allowed = set(query.CATALOGUE)
    assert allowed == {"spend", "donor_spend", "wellbeing"}
    assert not any(d.startswith("_") for d in allowed)
    with pytest.raises(ValidationError):
        query.QuerySpec(dataset="_spend_u", measure={"fn": "count"})


def test_disclosure_thresholds_have_a_floor():
    assert disclosure.DisclosurePolicy().threshold >= 5
    assert disclosure.DOM_THRESHOLD <= 0.5
    assert disclosure.ROUND_BASE >= 5


def test_queryspec_forbids_extra_fields():
    for model in (query.QuerySpec, query.Measure, query.Filter):
        assert model.model_config.get("extra") == "forbid", f"{model.__name__} not strict"
