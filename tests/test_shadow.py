"""Shadow data — the safety property, and that queries actually run on it.

The safety claim is narrow and checkable: *every value a shadow emits traces to
the dataset definition file*. Nothing is fitted to, measured from, or derived
from participant records, and there is no parameter through which such records
could reach the generator. These tests hold that line, and separately check
that the output is good enough to design an analysis against — the whole point
of the exercise.
"""

import json

import duckdb
import pandas as pd
import pytest

from safetre import dataset as _dataset
from safetre import query, shadow
from safetre.shadow import ShadowError, shadow_from_definition, write_shadow

DEMO = _dataset.load_dataset(_dataset._PACKAGED)

# Small but structurally complete: every table, every join, every dataset.
SMALL = dict(n_persons=40, rows={"events": 300, "survey": 60}, seed=3)


@pytest.fixture(scope="module")
def demo_shadow():
    return shadow_from_definition(DEMO, **SMALL)


# ------------------------------------------------------------------ #
# the safety property                                                 #
# ------------------------------------------------------------------ #
def test_every_categorical_value_comes_from_a_declared_domain(demo_shadow):
    """The strong form of the claim, stated over the data rather than the code:
    a shadow cannot contain a category the definition did not publish. This is
    what makes shadow data safe where a *fitted* synthesiser would not be —
    measured value sets leak the existence of rare categories."""
    for column, meta in DEMO.columns.items():
        declared = (meta or {}).get("domain")
        if declared is None:
            continue
        for table, cols in DEMO.tables.items():
            if column in cols:
                seen = set(demo_shadow.base[table][column].unique())
                assert seen <= set(declared), (
                    f"{table}.{column} invented {sorted(seen - set(declared))}")


def test_public_frames_carry_no_identifier_and_no_person(demo_shadow):
    identifiers = {c for cols in DEMO.tables.values()
                   for c, role in cols.items() if role == "DI"}
    people = set(demo_shadow.base["donors"][DEMO.person_key])
    for name, frame in demo_shadow.datasets.items():
        assert not identifiers & set(frame.columns), f"{name} exposes an identifier"
        for col in frame.columns:
            values = set(frame[col].dropna().astype(str))
            assert not values & people, f"{name}.{col} carries person ids"


def test_verification_catches_an_invented_value(demo_shadow):
    """`verify_shadow` runs on every build, so it has to actually bite. Poison a
    frame with a category outside the declared domain and confirm it refuses —
    otherwise the check is decoration."""
    tampered = shadow.Shadow(
        definition=demo_shadow.definition, seed=demo_shadow.seed,
        base={t: f.copy() for t, f in demo_shadow.base.items()},
        datasets=demo_shadow.datasets)
    tampered.base["donors"].loc[0, "region"] = "Atlantis"
    with pytest.raises(ShadowError, match="outside the declared domain"):
        shadow.verify_shadow(DEMO, tampered)


def test_generator_opens_no_database_on_disk(monkeypatch):
    """The generator holds no route to real data. Its only database is the
    in-memory one it builds the views in; if a future change ever pointed it at
    a file, this fails."""
    opened = []
    real_connect = duckdb.connect

    def spy(*args, **kwargs):
        opened.append(kwargs.get("database", args[0] if args else None))
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(shadow.duckdb, "connect", spy)
    shadow_from_definition(DEMO, n_persons=5, rows={"events": 10, "survey": 5})
    assert opened == [":memory:"], f"opened {opened}"


def test_person_ids_are_stamped(demo_shadow):
    """A shadow extract found on a disk somewhere must be recognisable as one at
    a glance, not mistaken for a real export."""
    for value in demo_shadow.base["donors"][DEMO.person_key]:
        assert str(value).startswith("SHADOW-")


# ------------------------------------------------------------------ #
# structural fidelity: it has to look like the real thing             #
# ------------------------------------------------------------------ #
def test_dataset_columns_match_the_real_views(demo_shadow):
    """The shadow is built by running the definition's own `public_view_sql`,
    so its columns are the real view's columns by construction. Asserted anyway
    because it is the property a researcher relies on: a model that fits here
    must fit there."""
    for name, view in DEMO.datasets.items():
        assert list(demo_shadow.datasets[name].columns) == view.output_columns()


def test_every_catalogue_dimension_has_all_its_levels(demo_shadow):
    """A factor missing a level would make a contrast estimable in the shadow
    and not in the real run, which is exactly the surprise this is meant to
    prevent."""
    for name, view in DEMO.datasets.items():
        frame = demo_shadow.datasets[name]
        for dim in view.dims:
            declared = (DEMO.columns.get(dim) or {}).get("domain")
            if declared is None:
                continue
            assert set(frame[dim].unique()) == set(declared), (
                f"{name}.{dim} is missing levels "
                f"{set(declared) - set(frame[dim].unique())}")


def test_joins_produce_rows(demo_shadow):
    """Foreign keys are drawn from the owning table's pool, so an inner join
    cannot come back empty — a shadow whose event table joined to nothing would
    look like a working dataset and behave like an empty one."""
    for name, frame in demo_shadow.datasets.items():
        assert len(frame) > 0, f"{name} is empty"


def test_queries_run_against_a_shadow_backed_engine(demo_shadow):
    """The end-to-end point of the exercise: a spec written against shadow data
    compiles and executes. Uses the real engine and the real QuerySpec
    validator, with only the tables swapped."""
    from safetre.engine import QueryEngine

    eng = QueryEngine(demo_shadow.base)
    spec = query.QuerySpec.model_validate({
        "dataset": "donor_spend",
        "measure": {"fn": "mean", "column": "total_spend_gbp"},
        "group_by": ["age_band"],
        "filters": [],
    })
    result = eng.run(spec)
    assert set(result["age_band"]) == set(DEMO.columns["age_band"]["domain"])
    assert result["value"].notna().all()


# ------------------------------------------------------------------ #
# determinism and reporting                                           #
# ------------------------------------------------------------------ #
def test_same_seed_same_data():
    a = shadow_from_definition(DEMO, **SMALL)
    b = shadow_from_definition(DEMO, **SMALL)
    for table in DEMO.tables:
        pd.testing.assert_frame_equal(a.base[table], b.base[table])


def test_different_seed_different_data():
    a = shadow_from_definition(DEMO, n_persons=40, rows={"events": 300}, seed=1)
    b = shadow_from_definition(DEMO, n_persons=40, rows={"events": 300}, seed=2)
    assert not a.base["events"]["amount_gbp"].equals(b.base["events"]["amount_gbp"])


def test_unbounded_numeric_columns_are_reported(demo_shadow):
    """A number invented on an arbitrary scale is fine; one invented silently is
    not — somebody would later read it as measured."""
    assert "amount_gbp" in demo_shadow.fallbacks
    assert demo_shadow.manifest()["fallback_range"] == list(shadow.FALLBACK_RANGE)


def test_declared_ranges_are_honoured():
    built = shadow_from_definition(DEMO, n_persons=20, rows={"events": 50, "survey": 20},
                                   ranges={"pgsi_score": (0, 27)})
    scores = built.base["survey"]["pgsi_score"]
    assert scores.min() >= 0 and scores.max() <= 27
    assert "pgsi_score" not in built.fallbacks


def test_range_rule_edges_bound_an_internal_column(demo_shadow):
    """`age_years` is bounded by its declared band edges, not by the fallback."""
    ages = demo_shadow.base["donors"]["age_years"]
    assert ages.min() >= 13 and ages.max() <= 69
    assert "age_years" not in demo_shadow.fallbacks


def test_manifest_and_readme_are_written(tmp_path, demo_shadow):
    written = write_shadow(demo_shadow, tmp_path)
    assert (tmp_path / "MANIFEST.json") in written
    manifest = json.loads((tmp_path / "MANIFEST.json").read_text())
    assert manifest["fitted_to_real_data"] is False
    assert manifest["seed"] == demo_shadow.seed
    readme = (tmp_path / "README.md").read_text()
    assert "not a statistical stand-in" in readme
    assert "independently" in readme
    for name in DEMO.datasets:
        assert (tmp_path / f"{name}.csv").exists()


# ------------------------------------------------------------------ #
# the banding coupling — opt-in, never inferred                       #
# ------------------------------------------------------------------ #
def test_bands_disagree_with_their_source_by_default():
    """Stated as a test because it is a documented limitation, not an accident:
    independent draws are what makes the generator safe, and the cost is that
    two columns describing the same quantity disagree."""
    built = shadow_from_definition(DEMO, n_persons=200, rows={"events": 200, "survey": 200})
    donors = built.base["donors"]
    mismatched = donors[(donors["age_band"] == "13-15") & (donors["age_years"] > 15)]
    assert len(mismatched) > 0


def test_derive_puts_each_value_in_its_declared_band():
    built = shadow_from_definition(DEMO, n_persons=200, rows={"events": 200, "survey": 200},
                                   derive={"age_band": "age_years"})
    bounds = {b: (lo, hi) for b, lo, hi in zip(
        DEMO.columns["age_band"]["domain"],
        DEMO.internal_range_rules["age_years"].edges[">="],
        DEMO.internal_range_rules["age_years"].edges["<="])}
    for band, group in built.base["donors"].groupby("age_band"):
        lo, hi = bounds[band]
        assert group["age_years"].min() >= lo and group["age_years"].max() <= hi


def test_derive_refuses_a_source_with_no_declared_edges():
    with pytest.raises(ShadowError, match="no internal range rule"):
        shadow_from_definition(DEMO, n_persons=10, rows={"events": 10, "survey": 10},
                               derive={"age_band": "sex"})


def test_derive_refuses_when_labels_and_edges_disagree():
    """Two declarations of different lengths are not a banding. Refused rather
    than paired up positionally, which would silently relabel every band."""
    defn = DEMO.model_copy(deep=True)
    defn.columns["age_band"]["domain"] = ["young", "old"]
    with pytest.raises(ShadowError, match="band labels"):
        shadow_from_definition(defn, n_persons=10, rows={"events": 10, "survey": 10},
                               derive={"age_band": "age_years"})


# ------------------------------------------------------------------ #
# refusals                                                            #
# ------------------------------------------------------------------ #
def test_categorical_without_a_domain_is_refused():
    """An analyst may group by a `cat` dimension, so its levels are the levels
    the operator published. Inventing them here would put words in the
    operator's mouth."""
    defn = DEMO.model_copy(deep=True)
    del defn.columns["region"]
    with pytest.raises(ShadowError, match="no `domain`"):
        shadow_from_definition(defn, n_persons=10, rows={"events": 10, "survey": 10})


def test_unknown_table_in_rows_is_refused():
    with pytest.raises(ShadowError, match="unknown tables"):
        shadow_from_definition(DEMO, n_persons=5, rows={"nope": 10})


def test_unknown_column_in_derive_is_refused():
    with pytest.raises(ShadowError, match="unknown columns"):
        shadow_from_definition(DEMO, n_persons=5, rows={"events": 5, "survey": 5},
                               derive={"nope": "age_years"})
