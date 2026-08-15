"""The NIGHTPLAY study (studies/nightplay/) — the synthetic population built
for the inside-analyst phase (docs/nightplay-study.md).

Three pins:

1. The definition loads and drives the dataset-independent machinery
   (the property tests/test_dataset_independence.py establishes in general,
   asserted here for the study that will actually be served).
2. The generator plants what its docstring says it plants: the truths are
   present in the unvetted rows, the panel agrees with the event tables it
   was derived from, and every adversarial structure is present.
3. The truths are recoverable THROUGH the gateway and the traps are caught
   by it — `verify.run` on a fresh small population — because a study that
   is rich on disk and empty at the boundary would justify nothing.
"""

from __future__ import annotations

import pathlib

import numpy as np
import pandas as pd
import pytest

from safetre import dataset
from safetre.dataset import load_dataset
from studies.nightplay import generate as G
from studies.nightplay import verify as V

PACKAGED = pathlib.Path(dataset.__file__).with_name("demo_dataset.yaml")
N_TEST = 2500   # enough for every check in verify.py; generation < 2 s


@pytest.fixture(scope="module")
def study():
    tables, truth = G.generate(n_people=N_TEST)
    return tables, truth


def test_definition_loads_and_names_every_table():
    defn = load_dataset(G.DEFINITION)
    assert defn.name == "nightplay-study"
    assert defn.person_key == "person_id"
    assert set(defn.table_names()) == set(G.TABLE_NAMES)
    assert set(defn.datasets) == {"sessions", "bets", "panel", "wellbeing", "giving"}
    # no collision with the packaged demo, so both CSV sets can share data/
    demo = load_dataset(PACKAGED)
    assert not set(demo.table_names()) & set(defn.table_names())


def test_generator_is_deterministic():
    a, ta = G.generate(n_people=400)
    b, tb = G.generate(n_people=400)
    for name in G.TABLE_NAMES:
        pd.testing.assert_frame_equal(a[name], b[name])
    assert ta["truths"] == tb["truths"]


def test_panel_agrees_with_the_event_tables(study):
    tables, _ = study
    panel = tables["person_month"]
    sess = tables["phone_sessions"]
    txns = tables["gambling_txns"]
    late = sess[sess["hour_band"] == "late_night"].groupby(["person_id", "month"]).size()
    got = panel.set_index(["person_id", "month"])["late_night_sessions"]
    assert int(got.sum()) == int(late.sum())
    assert (got.reindex(late.index).to_numpy() == late.to_numpy()).all()
    stake = txns.groupby(["person_id", "month"])["stake_gbp"].sum()
    got = panel.set_index(["person_id", "month"])["stake_gbp"].reindex(stake.index)
    assert np.allclose(got.to_numpy(), stake.to_numpy(), atol=0.02)
    # the cohort band is a function of the person's own late-night sessions
    annual = panel.groupby("person_id")["late_night_sessions"].sum()
    people = tables["people"].set_index("person_id")
    assert (G.night_use_band(annual.reindex(people.index).to_numpy())
            == people["night_use_band"].to_numpy()).all()


def test_the_truths_are_in_the_rows(study):
    _, truth = study
    t = truth["truths"]
    bands = G.PARAMS["night_use_bands"]
    m = t["T1_dose_response"]["oracle_mean_monthly_stake_by_band"]
    assert all(m[a] < m[b] for a, b in zip(bands, bands[1:])), m
    c = t["T2_confounding"]
    assert c["naive_heavy_minus_rare"] > c["adjusted_heavy_minus_rare"] > 0, c
    assert abs(t["T3_planted_null"]["oracle_corr_late_sessions_vs_donation"]) < 0.03
    h = t["T4_heterogeneity"]["oracle_mean_stake_by_product_and_band"]
    assert h["casino"]["heavy"] / h["casino"]["rare"] > 1.2
    assert h["lottery"]["heavy"] / h["lottery"]["rare"] < 1.2
    month = t["T5_time_structure"]["oracle_mean_stake_by_month"]
    assert max(month, key=month.get) in ("6", "7", 6, 7)
    hour = t["T5_time_structure"]["oracle_mean_stake_by_hour_band"]
    assert hour["late_night"] == max(hour.values())
    p = t["T6_longitudinal"]["oracle_mean_pgsi_by_band_and_wave"]
    assert p["heavy"]["3"] - p["heavy"]["1"] > 1.0 if "3" in p["heavy"] else p["heavy"][3] - p["heavy"][1] > 1.0


def test_the_traps_are_in_the_rows(study):
    tables, truth = study
    adv = truth["adversarial"]
    assert adv["sub_threshold_counts"] == {
        "region=Northern Ireland": 8, "sex=X": 7, "employment=armed_forces": 6}
    assert adv["nulls"]["sleep_quality"] > 0
    assert adv["nulls"]["duration_min"] > 0
    assert adv["nulls"]["net_loss_gbp"] > 0
    assert adv["negative_net_loss_rows"] > 0
    assert "whale" in adv and "zero_sum_cell" in adv and "influence_plant" in adv
    people, sess, txns = tables["people"], tables["phone_sessions"], tables["gambling_txns"]
    # hostile strings sit in the columns the manifest says
    assert set(G.POISON_APP_CATEGORY) <= set(sess["app_category"].unique())
    assert set(G.POISON_REGION) <= set(people["region"].unique())
    assert set(G.POISON_FREE_TEXT) <= set(tables["questionnaire"]["free_text"].unique())
    # the whale really dominates its cell
    w = adv["whale"]
    reg = people.set_index("person_id")["region"]
    cell = txns[(reg.reindex(txns["person_id"]).to_numpy() == w["region"])
                & (txns["product"] == w["product"])]
    share = cell.groupby("person_id")["stake_gbp"].sum().max() / cell["stake_gbp"].sum()
    assert share > 0.55, share
    # the zero-sum cell really cancels
    z = adv["zero_sum_cell"]
    cell = txns[(reg.reindex(txns["person_id"]).to_numpy() == z["region"])
                & (txns["product"] == z["product"])]
    assert abs(cell["net_loss_gbp"].sum() - z["planted_total"]) < 0.01


def test_truths_recoverable_and_traps_caught_through_the_gateway(study, tmp_path, monkeypatch):
    monkeypatch.setenv("SAFETRE_AUDIT_DB", str(tmp_path / "audit.db"))
    tables, truth = study
    report = V.run(tables, truth, verbose=False)
    failed = [c for c in report["checks"] if not c["ok"]]
    assert not failed, failed
    # every reference request went through the real service, none errored
    assert all(r["status"] in ("released", "redacted") for r in report["releases"]), \
        [r for r in report["releases"] if r["status"] not in ("released", "redacted")]
    # and the demo definition is active again afterwards
    assert dataset.active().name == "demo-lootbox-study"
