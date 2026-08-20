"""formal/skeleton.json must equal the live registry export (R16).

The committed skeleton is the formal model's input: the Alloy catalogue block
is generated from it, so this test is the first hop of the correspondence
chain (code -> skeleton). If the catalogue, a procedure's measure space, or a
model's term space changes without regenerating the export (and therefore the
model), this fails CI.

Regenerate with:
    uv run python scripts/gen_alloy_catalogue.py --write
"""

from __future__ import annotations

import json
import os

from safetre.procedures import registry_skeleton

SKELETON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "formal", "skeleton.json")


def test_committed_skeleton_matches_live_registry():
    with open(SKELETON) as fh:
        committed = json.load(fh)
    live = registry_skeleton()
    assert committed == live, (
        "formal/skeleton.json is stale — regenerate it (and the generated "
        "block of the formal model) with scripts/gen_alloy_catalogue.py --write")


def test_skeleton_export_is_json_roundtrippable_and_bounded():
    live = registry_skeleton()
    assert json.loads(json.dumps(live)) == live
    assert set(live) == {"skeleton_version", "catalogue", "aggregate", "model"}
    assert set(live["model"]) == {"glm", "anova", "series", "normality"}
    assert 500 < len(live["model"]["glm"]) < 2000
    assert 0 < len(live["model"]["anova"]) < 200
    # the demo declares one time axis (`wave`, two windows), which the series
    # tool refuses at the request; its admissible demo space is therefore
    # empty and the tool is exercised on the NIGHTPLAY study instead
    assert len(live["model"]["series"]) == 0
    assert 20 < sum(len(v) for v in live["aggregate"].values()) < 200
