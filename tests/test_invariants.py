"""Security invariants — these guard the boundary against a subtle backdoor.

If a change weakens the boundary (exposes an identifier in a view, lowers a
disclosure threshold, lets QuerySpec accept extra fields, makes a unit view
queryable), one of these fails. They are cheap insurance for the ~4 files the
whole security argument rests on.
"""

import re
import typing

from safetre import disclosure, engine, query
from safetre.schema import identifier_columns

FORBIDDEN_IN_PUBLIC_VIEWS = {"donor_id", "free_text"}


def _select_list(ddl: str) -> str:
    m = re.search(r"select(.*?)from", ddl, re.I | re.S)
    return (m.group(1) if m else ddl).lower()


def test_public_views_never_expose_identifiers():
    for name, ddl in engine._VIEWS.items():
        cols = _select_list(ddl)
        for col in FORBIDDEN_IN_PUBLIC_VIEWS:
            assert col not in cols, f"{col!r} exposed in public view {name!r}"


def test_catalogue_excludes_identifiers_and_freetext():
    for ds, info in query.CATALOGUE.items():
        cols = set(info["dims"]) | set(info["measures"])
        assert "donor_id" not in cols and "free_text" not in cols
        assert not (cols & identifier_columns()), f"identifier in catalogue {ds!r}"


def test_unit_views_are_not_queryable():
    # QuerySpec.dataset is a closed Literal; internal unit views (prefixed "_")
    # must never be among its values.
    allowed = set(typing.get_args(query.QuerySpec.model_fields["dataset"].annotation))
    assert allowed == {"spend", "wellbeing"}
    assert not any(d.startswith("_") for d in allowed)


def test_disclosure_thresholds_have_a_floor():
    assert disclosure.DisclosurePolicy().threshold >= 5
    assert disclosure.DOM_THRESHOLD <= 0.5
    assert disclosure.ROUND_BASE >= 5


def test_queryspec_forbids_extra_fields():
    for model in (query.QuerySpec, query.Measure, query.Filter):
        assert model.model_config.get("extra") == "forbid", f"{model.__name__} not strict"
