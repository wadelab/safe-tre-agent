"""The gateway machinery must be independent of the dataset it serves.

Two pins:

1. The packaged demo definition (`safetre/demo_dataset.yaml`) is the SINGLE
   source of every demo fact: the long-standing module structures
   (`query.CATALOGUE`, `schema.TABLES`, `engine._VIEWS`, the analyst lexicon)
   are mirrors of it, so a hard-coded column name cannot creep back into the
   code without this test noticing the divergence.

2. A second, differently-shaped definition — different table and column names
   and a DIFFERENT person key (`patient_id`, not `donor_id`) — drives the
   whole pipeline (spec validation, engine, disclosure gateway, session
   auditor, GLM, planner prompt, manifest) with no code changes. Everything
   below is exercised against the CLINIC fixture; nothing in it names a demo
   column except where it asserts demo names are rejected.
"""

from __future__ import annotations

import copy
import json
import pathlib

import pandas as pd
import pytest
import yaml
from pydantic import ValidationError

from safetre import analyst, dataset, engine, query, schema
from safetre.dataset import DatasetDefinition
from safetre.manifest import public_manifest, public_schema
from safetre.config import load_policy_config
from safetre.planner import planner_system
from safetre.query import QuerySpec
from safetre.service import WITHHELD_MESSAGE, QueryService

PACKAGED = pathlib.Path(dataset.__file__).with_name("demo_dataset.yaml")

# A second study: clinic visits. Nothing about it resembles the demo: two base
# tables, a `patient_id` person key, one event-level public dataset and one
# per-person rollup with derived conditional aggregates.
CLINIC: dict = {
    "name": "clinic-visits",
    "description": "Synthetic clinic visit costs (fixture).",
    "person_key": "patient_id",
    "tables": {
        "patients": {
            "patient_id": "DI",
            "enrolled": "meta",
            "sex": "QI",
            "site": "QI",
            "age_band": "QI",
            "age_years": "QI",
        },
        "visits": {
            "visit_id": "meta",
            "patient_id": "DI",
            "visit_type": "R",
            "cost_gbp": "S",
            "minutes": "S",
        },
    },
    "columns": {
        "sex": {"desc": "Recorded sex.", "domain": ["F", "M"]},
        "site": {"desc": "Clinic site.", "domain": ["A", "B"]},
        "age_band": {"desc": "Age band.", "domain": ["18-39", "40-64", "65+"]},
        "age_years": {"desc": "Exact age (internal)."},
        "visit_type": {"desc": "Kind of visit.", "domain": ["consultation", "procedure"]},
        "cost_gbp": {"desc": "Visit cost (GBP)."},
        "minutes": {"desc": "Visit length (minutes)."},
        "total_cost_gbp": {"desc": "Per-patient total cost (GBP)."},
        "consults": {"desc": "Per-patient consultation count."},
    },
    "derived_roles": {"total_cost_gbp": "S", "consults": "S"},
    "datasets": {
        "visits": {
            "base": "visits",
            "joins": [{"table": "patients", "key": "patient_id"}],
            "columns": [
                "patients.sex", "patients.site", "patients.age_band",
                "visits.visit_type", "visits.cost_gbp", "visits.minutes",
            ],
            "unit_columns": ["patients.age_years"],
            "dims": {"sex": "cat", "site": "cat", "age_band": "cat", "visit_type": "cat"},
            "measures": ["cost_gbp", "minutes"],
            "internal_filters": {"age_years": "int"},
            "glm_responses": {"cost_gbp": ["gaussian"], "minutes": ["gaussian"]},
        },
        "patient_cost": {
            "base": "patients",
            "joins": [{"table": "visits", "key": "patient_id", "how": "left"}],
            "group_by": ["patients.patient_id", "patients.sex", "patients.site",
                         "patients.age_band"],
            "unit_group_by": ["patients.age_years"],
            "columns": [
                "patients.sex", "patients.site", "patients.age_band",
                {"name": "total_cost_gbp",
                 "sum_if": {"column": "visits.cost_gbp", "when": "visits.visit_type",
                            "in": ["consultation", "procedure"]}},
                {"name": "consults",
                 "count_if": {"column": "visits.visit_type", "equals": "consultation"}},
            ],
            "unit_columns": ["patients.age_years"],
            "dims": {"sex": "cat", "site": "cat", "age_band": "cat"},
            "measures": ["total_cost_gbp", "consults"],
            "internal_filters": {"age_years": "int"},
            "internal_measures": ["age_years"],
            "glm_responses": {"total_cost_gbp": ["gaussian"], "consults": ["poisson"]},
        },
    },
    "internal_range_rules": {
        "age_years": {"ops": [">=", "<="],
                      "edges": {">=": [18, 40, 65], "<=": [39, 64, 89]}},
    },
    "lexicon": {
        "dimension_synonyms": {
            "site": "site", "clinic": "site", "sex": "sex",
            "age band": "age_band", "visit type": "visit_type",
        },
        "response_synonyms": {
            "visits": {"cost": "cost_gbp", "minutes": "minutes"},
            "patient_cost": {"total cost": "total_cost_gbp", "cost": "total_cost_gbp",
                             "consults": "consults"},
        },
        "domain_cues": ["cost", "visit", "clinic", "site", "sex", "age", "patient"],
    },
    "planner_examples": [
        {"request": "mean cost by site",
         "spec": {"dataset": "visits", "measure": {"fn": "mean", "column": "cost_gbp"},
                  "group_by": ["site"], "filters": []}},
    ],
    "ui_queries": [{"label": "Mean cost by site", "query": "mean cost by site"}],
    "tour": ["mean cost by site"],
}

N_PATIENTS = 60


def _clinic_tables() -> dict[str, pd.DataFrame]:
    patients = pd.DataFrame({
        "patient_id": [f"P{i:03d}" for i in range(N_PATIENTS)],
        "enrolled": pd.Timestamp("2024-01-01"),
        "sex": [["F", "M"][i % 2] for i in range(N_PATIENTS)],
        # `site` must vary INDEPENDENTLY of `sex`: keyed on `i % 2` as well,
        # every F was at site A and every M at site B, so site x sex x age_band
        # had 6 populated cells of 10 patients rather than the 12 of 5 the
        # sub-threshold test needs — and 10 clears the threshold, so the cells
        # the test expects to be withheld were released.
        "site": [["A", "B"][(i // 2) % 2] for i in range(N_PATIENTS)],
        "age_band": [["18-39", "40-64", "65+"][i % 3] for i in range(N_PATIENTS)],
        "age_years": [18 + i % 62 for i in range(N_PATIENTS)],
    })
    rows = []
    for i in range(N_PATIENTS):
        pid = f"P{i:03d}"
        rows.append((f"V{3*i:05d}", pid, "consultation", 50.0 + i % 40, 20 + i % 25))
        rows.append((f"V{3*i+1:05d}", pid, "consultation", 55.0 + i % 35, 22 + i % 25))
        rows.append((f"V{3*i+2:05d}", pid, "procedure", 120.0 + i % 60, 40 + i % 20))
    visits = pd.DataFrame(rows, columns=["visit_id", "patient_id", "visit_type",
                                         "cost_gbp", "minutes"])
    return {"patients": patients, "visits": visits}


@pytest.fixture
def clinic():
    """Activate the clinic definition; restore the packaged demo afterwards."""
    defn = DatasetDefinition.model_validate(copy.deepcopy(CLINIC))
    dataset.activate(defn)
    try:
        yield defn
    finally:
        dataset.activate(dataset.load_dataset(PACKAGED))


@pytest.fixture
def clinic_service(clinic):
    return QueryService(_clinic_tables())


# --------------------------------------------------------------------- #
# 1. the packaged demo is the single source of demo facts                #
# --------------------------------------------------------------------- #

def test_packaged_demo_is_the_single_source_of_demo_facts():
    dataset.activate(dataset.load_dataset(PACKAGED))   # idempotent
    defn = dataset.load_dataset(PACKAGED)
    assert defn.name == "demo-lootbox-study"
    assert defn.person_key == "donor_id"
    assert set(schema.TABLES) == {"donors", "apps", "events", "survey"}
    assert query.CATALOGUE == defn.catalogue()
    assert query.INTERNAL_RANGE_RULES == defn.range_rules()
    assert schema.COLUMN_META == defn.column_meta_as_dict()
    assert engine._VIEWS == defn.public_view_sql()
    assert engine._UNIT_VIEWS == defn.unit_view_sql()
    assert analyst.DIMENSION_SYNONYMS == dict(defn.lexicon.dimension_synonyms)
    assert analyst.DOMAIN_CUES == list(defn.lexicon.domain_cues)
    assert analyst.RESPONSE_SYNONYMS == {
        k: dict(v) for k, v in defn.lexicon.response_synonyms.items()}


# --------------------------------------------------------------------- #
# 2. the whole pipeline on a differently-shaped dataset                  #
# --------------------------------------------------------------------- #

def test_activation_replaces_the_catalogue(clinic):
    assert set(query.CATALOGUE) == {"visits", "patient_cost"}
    assert set(schema.TABLES) == {"patients", "visits"}
    assert set(engine._VIEWS) == {"visits", "patient_cost"}
    assert set(engine._UNIT_VIEWS) == {"visits", "patient_cost"}
    assert query.INTERNAL_RANGE_RULES["age_years"]["edges"][">="] == (18, 40, 65)


def test_demo_names_are_not_expressible(clinic):
    with pytest.raises(ValidationError):
        QuerySpec(dataset="spend", measure={"fn": "count"})
    with pytest.raises(ValidationError):
        QuerySpec(dataset="visits", measure={"fn": "count"}, group_by=["region"])
    with pytest.raises(ValidationError):
        # the person key is never a public dimension, whatever it is called
        QuerySpec(dataset="visits", measure={"fn": "count"}, group_by=["patient_id"])
    with pytest.raises(ValidationError):
        QuerySpec(dataset="_visits_u", measure={"fn": "count"})


def test_person_key_machinery_counts_patients_not_rows(clinic):
    eng = engine.QueryEngine(_clinic_tables())
    spec = QuerySpec(dataset="visits", measure={"fn": "mean", "column": "cost_gbp"},
                     group_by=["site"])
    df = eng.run(spec)
    # 30 distinct patients per site behind 90 visit rows each: the frequency
    # threshold machinery counts PEOPLE through the internal alias, and the
    # dominance witness is attached
    assert dict(zip(df["site"], df["n_donors"])) == {"A": 30, "B": 30}
    assert dict(zip(df["site"], df["n"])) == {"A": 90, "B": 90}
    assert "dominance" in df.columns

    ctx = eng.cell_context(spec, with_contributions=True)
    assert "donor_id" in ctx.contributions.columns          # the internal alias
    assert set(ctx.contributions["donor_id"]) == {f"P{i:03d}" for i in range(N_PATIENTS)}

    marginals = eng.marginal_donor_counts()
    assert set(marginals) == {"visits", "patient_cost"}
    assert marginals["visits"]["site"]["A"] == 30


def test_corr_over_internal_measure_runs(clinic):
    eng = engine.QueryEngine(_clinic_tables())
    spec = QuerySpec(dataset="patient_cost",
                     measure={"fn": "corr", "x": "age_years", "y": "total_cost_gbp"})
    df = eng.run(spec)
    assert "influence" in df.columns and "n_donors" in df.columns
    assert int(df["n_donors"].iloc[0]) == N_PATIENTS


def test_end_to_end_release_through_the_service(clinic_service):
    literal = json.dumps({"dataset": "visits",
                          "measure": {"fn": "mean", "column": "cost_gbp"},
                          "group_by": ["site"], "filters": []})
    result = clinic_service.handle(literal, planner=None)
    assert result.status == "released"
    out = result.output
    assert set(out["site"]) == {"A", "B"}
    assert set(out["n"]) == {90}
    # internal helpers never reach a release
    assert "n_donors" not in out.columns and "dominance" not in out.columns


def test_small_cells_are_withheld(clinic_service):
    # 12 site x sex x age_band cells of 5 patients each: all sub-threshold
    literal = json.dumps({"dataset": "visits",
                          "measure": {"fn": "mean", "column": "cost_gbp"},
                          "group_by": ["site", "sex", "age_band"], "filters": []})
    result = clinic_service.handle(literal, planner=None)
    assert result.status == "denied"
    assert result.message == WITHHELD_MESSAGE


def test_range_rules_come_from_the_definition(clinic):
    QuerySpec(dataset="visits", measure={"fn": "mean", "column": "cost_gbp"},
              group_by=["site"],
              filters=[{"column": "age_years", "op": ">=", "value": 40}])
    with pytest.raises(ValidationError):
        QuerySpec(dataset="visits", measure={"fn": "mean", "column": "cost_gbp"},
                  group_by=["site"],
                  filters=[{"column": "age_years", "op": ">=", "value": 41}])
    with pytest.raises(ValidationError):
        QuerySpec(dataset="visits", measure={"fn": "mean", "column": "cost_gbp"},
                  group_by=["site"],
                  filters=[{"column": "age_years", "op": "==", "value": 40}])


def test_glm_fits_on_the_second_dataset(clinic_service):
    literal = json.dumps({"tool": "glm", "dataset": "patient_cost",
                          "family": "gaussian", "response": "total_cost_gbp",
                          "terms": ["sex"], "filters": []})
    result = clinic_service.handle(literal, planner=None)
    assert result.status == "released"
    assert result.output is not None and len(result.output) >= 2


def test_natural_language_gates_use_the_definition_lexicon(clinic_service):
    ok, why = analyst.vet_request("mean cost by site")
    assert ok, why
    ok, why = analyst.check_grouping_coherence("mean cost by site", "visits", ["site"])
    assert ok, why

    class StubPlanner:
        def plan(self, q):
            return {"dataset": "visits",
                    "measure": {"fn": "mean", "column": "cost_gbp"},
                    "group_by": ["site"], "filters": []}

    result = clinic_service.handle("mean cost by site", StubPlanner())
    assert result.status == "released"


def test_planner_prompt_is_generated_from_the_active_definition(clinic):
    prompt = planner_system()
    assert '"dataset":"visits|patient_cost"' in prompt
    assert "cost_gbp" in prompt
    assert ">= one of 18, 40, 65" in prompt
    # nothing of the demo's vocabulary survives activation
    for ghost in ("wemwbs", "lootbox", "donor_spend", "wellbeing"):
        assert ghost not in prompt


def test_manifest_and_public_schema_follow_the_active_definition(clinic):
    manifest = public_manifest(load_policy_config())
    assert set(manifest["datasets"]) == {"visits", "patient_cost"}
    public = public_schema()
    assert set(public["datasets"]) == {"visits", "patient_cost"}


def test_definition_loads_from_a_yaml_file(clinic, tmp_path):
    path = tmp_path / "clinic.yaml"
    path.write_text(yaml.safe_dump(CLINIC))
    defn = dataset.load_dataset(path)
    dataset.activate(defn)
    assert set(query.CATALOGUE) == {"visits", "patient_cost"}
    assert defn.person_key == "patient_id"


# --------------------------------------------------------------------- #
# 3. definitions are validated strictly                                  #
# --------------------------------------------------------------------- #

def _broken(mutate) -> dict:
    doc = copy.deepcopy(CLINIC)
    mutate(doc)
    return doc


@pytest.mark.parametrize("doc", [
    _broken(lambda d: d.update(person_key="nope")),                 # not a column
    _broken(lambda d: d["tables"]["patients"].update(patient_id="QI")),  # not DI
    _broken(lambda d: d["datasets"]["visits"]["columns"].append("patients.patient_id")),
    _broken(lambda d: d["datasets"]["visits"]["dims"].update(nowhere="cat")),
    _broken(lambda d: d["datasets"]["visits"]["columns"].append("patients.nowhere")),
    _broken(lambda d: d["datasets"]["visits"]["joins"].append(
        {"table": "visits", "key": "visit_id"})),                   # joined to itself
    _broken(lambda d: d.update(internal_range_rules={"height_cm": {
        "ops": [">="], "edges": {">=": [150]}}})),                  # rule for nothing
    # the '>=' edges are the bands' floors and the '<=' edges their ceilings,
    # so lists of different lengths cannot describe the same bands
    _broken(lambda d: d["internal_range_rules"]["age_years"]["edges"]
            .update({">=": [18, 40]})),                             # edges do not pair
], ids=["person-not-a-column", "person-not-DI", "DI-on-public-view",
        "dim-not-in-view", "column-not-in-table", "self-join",
        "range-rule-for-nothing", "range-edges-do-not-pair"])
def test_bad_definitions_are_rejected(doc):
    with pytest.raises(ValidationError):
        DatasetDefinition.model_validate(doc)


def test_bad_identifier_in_definition_is_rejected():
    doc = _broken(lambda d: d["datasets"].update({"bad name": d["datasets"].pop("visits")}))
    with pytest.raises(ValidationError):
        DatasetDefinition.model_validate(doc)


def test_the_lean_generator_follows_the_active_definition(clinic, tmp_path):
    """The formal artifacts must be regenerable for the study they describe.

    `gen_lean_catalogue` read its live view columns from an engine built over
    `synth.generate()`, which knows only the packaged demo's tables — so on any
    operator dataset it died with `KeyError: 'events'`, and the committed Lean
    theorems could only ever be about the demo's catalogue. A proof about the
    wrong columns is worse than no proof, because it reads as assurance.

    It now builds the engine from EMPTY, correctly-typed frames derived from
    the active definition: only column names are wanted, so no data are needed
    and none are invented.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_lean_catalogue",
        pathlib.Path(__file__).resolve().parent.parent / "scripts"
        / "gen_lean_catalogue.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    text = gen.catalogue_lean()
    assert 'def datasets : List String := ["patient_cost", "visits"]' in text
    # the person key is projected under the internal alias on the unit view ...
    assert '"visits" => ["donor_id", "age_years"' in text
    # ... and never on the public one
    public = next(line for line in text.splitlines()
                  if line.startswith('  | "visits" => ["sex"'))
    assert "donor_id" not in public and "patient_id" not in public
    # nothing demo-shaped survives
    assert "donor_spend" not in text and "amount_gbp" not in text
