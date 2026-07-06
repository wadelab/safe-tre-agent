"""The public data dictionary (/api/schema) is a safe schema disclosure.

It publishes design-time metadata only — column names, types, disclosure roles,
descriptions and DECLARED value domains — never row-level data. These tests pin
that contract: the codebook is complete and useful, and no participant-derived
or hostile content ever reaches it.
"""

import json

import pytest
from fastapi.testclient import TestClient

from safetre import synth
from safetre.manifest import public_schema
from safetre.query import CATALOGUE
from safetre.schema import COLUMN_META
from safetre.synth import INJECTION, POISON_DONORS
from safetre_web.app import app

client = TestClient(app)


def test_schema_covers_every_catalogue_column():
    schema = public_schema()["datasets"]
    assert set(schema) == set(CATALOGUE)
    for dataset, info in CATALOGUE.items():
        pub = schema[dataset]
        assert set(pub["dimensions"]) == set(info["dims"])
        assert set(pub["measures"]) == set(info["measures"])
        for name, dim in pub["dimensions"].items():
            assert dim["role"] in {"QI", "S", "R", "meta"}   # never DI
            assert dim["description"]                          # every column documented


def test_declared_domains_are_the_full_codebook():
    dims = public_schema()["datasets"]["spend"]["dimensions"]
    # region declares all 12 UK ITL1 regions, including the sub-threshold ones:
    # a valid *option* is design knowledge, not a row-level fact.
    assert "Northern Ireland" in dims["region"]["domain"]
    assert len(dims["region"]["domain"]) == 12
    assert dims["region"]["role"] == "QI"
    assert dims["age_rating"]["domain"] == [3, 7, 12, 16, 18]


def test_internal_analysis_variables_absent():
    # raw age is an internal filter; it must never appear as a groupable dim.
    for dataset in public_schema()["datasets"].values():
        assert "age_years" not in dataset["dimensions"]


def test_schema_leaks_no_row_level_or_hostile_content():
    blob = json.dumps(public_schema())
    assert INJECTION not in blob
    # every hostile payload string is absent. Legitimate field values a poison
    # row happens to carry (e.g. region "London") are declared categories and
    # may appear — only undeclared, smuggled content is the leak.
    declared = {v for m in COLUMN_META.values() for v in m.get("domain", [])}
    for p in POISON_DONORS:
        for field, value in p.items():
            if field == "donor_id" or value in declared:
                continue
            assert value not in blob


def test_schema_endpoint_serves_dictionary():
    r = client.get("/api/schema", headers={"Tailscale-User-Login": "member@example.test"})
    assert r.status_code == 200
    dims = r.json()["datasets"]["spend"]["dimensions"]
    assert "Northern Ireland" in dims["region"]["domain"]


def test_schema_endpoint_gated_on_allowlist(monkeypatch):
    # the allowlist is frozen at import, so force a not-allowed identity instead.
    import safetre_web.app as webapp
    monkeypatch.setattr(webapp, "current_user", lambda request: ("outsider@example.test", False))
    denied = client.get("/api/schema", headers={"Tailscale-User-Login": "outsider@example.test"})
    assert denied.status_code == 403


def test_published_marginals_drop_undeclared_values():
    from safetre.engine import QueryEngine
    from safetre.schema import declared_domain

    pub = QueryEngine(synth.generate(seed=7)).published_marginal_donor_counts()
    region = pub["donor_spend"]["region"]
    valid = set(declared_domain("region"))
    assert set(region) <= valid                      # only declared regions survive
    for p in POISON_DONORS:                           # smuggled region strings gone
        r = p.get("region")
        if r is not None and r not in valid:
            assert r not in region
    assert region.get("Northern Ireland", "missing") is None   # declared but suppressed
