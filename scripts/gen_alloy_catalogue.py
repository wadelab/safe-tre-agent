"""Regenerate the formal artifacts from the live procedure registries (R16).

Two outputs, both committed:
- formal/skeleton.json — the registries' finite request space as data;
- the generated block of formal/glm_gateway.als (between the GENERATED
  markers), giving the Alloy model the real catalogue atoms.

`tests/test_skeleton_sync.py` and `tests/test_formal_alloy_sync.py` regenerate
both in-memory and fail CI on drift, so the solver always checks the space the
code actually exposes.

Usage:
    uv run python scripts/gen_alloy_catalogue.py           # check (exit 1 on drift)
    uv run python scripts/gen_alloy_catalogue.py --write   # rewrite the artifacts
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre.procedures import registry_skeleton   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKELETON = os.path.join(ROOT, "formal", "skeleton.json")
ALLOY = os.path.join(ROOT, "formal", "glm_gateway.als")
MARK_BEGIN = "// --- GENERATED FROM formal/skeleton.json — do not edit by hand ---"
MARK_END = "// --- END GENERATED ---"


def skeleton_text() -> str:
    return json.dumps(registry_skeleton(), indent=1, sort_keys=True) + "\n"


def _atom(name: str) -> str:
    """A column/dataset name as an Alloy atom identifier."""
    return "C_" + "".join(ch if ch.isalnum() else "_" for ch in name)


def alloy_block() -> str:
    """The generated section of the Alloy model: the real datasets, columns,
    role memberships, and the family -> (dataset, response) map."""
    sk = registry_skeleton()
    catalogue = sk["catalogue"]
    columns: set[str] = set()
    for info in catalogue.values():
        columns |= set(info["dims"]) | set(info["measures"])
        columns |= set(info["internal_filters"]) | set(info["internal_measures"])
        columns |= set(info["glm_responses"])

    lines: list[str] = [MARK_BEGIN]
    lines.append("one sig " + ", ".join(sorted(_atom(c) for c in columns))
                 + " extends Column {}")
    ds_names = {ds: "D_" + ds for ds in sorted(catalogue)}
    lines.append("one sig " + ", ".join(ds_names[ds] for ds in sorted(catalogue))
                 + " extends Dataset {}")
    lines.append("fact Catalogue {")
    for ds in sorted(catalogue):
        info = catalogue[ds]
        dims = " + ".join(sorted(_atom(c) for c in info["dims"])) or "none"
        lines.append(f"  {ds_names[ds]}.dims = {dims}")
        internal = sorted(_atom(c) for c in
                          set(info["internal_filters"]) | set(info["internal_measures"]))
        lines.append(f"  {ds_names[ds]}.internal = "
                     + (" + ".join(internal) or "none"))
    pairs_by_family: dict[str, list[str]] = {"gaussian": [], "binomial": [], "poisson": []}
    for ds in sorted(catalogue):
        for col, fams in sorted(catalogue[ds]["glm_responses"].items()):
            for fam in fams:
                pairs_by_family[fam].append(f"{ds_names[ds]} -> {_atom(col)}")
    for fam in ("gaussian", "binomial", "poisson"):
        rel = " + ".join(pairs_by_family[fam]) or "none -> none"
        lines.append(f"  Cat.allowedResponse[{fam.capitalize()}] = {rel}")
    lines.append("}")
    lines.append(MARK_END)
    return "\n".join(lines) + "\n"


def spliced_alloy() -> str | None:
    """The committed .als with its generated block replaced by a fresh one,
    or None when the model file does not exist yet (pre-Stage-3 tree)."""
    if not os.path.exists(ALLOY):
        return None
    with open(ALLOY) as fh:
        text = fh.read()
    begin = text.index(MARK_BEGIN)
    end = text.index(MARK_END) + len(MARK_END) + 1
    return text[:begin] + alloy_block() + text[end:]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="rewrite the artifacts")
    args = ap.parse_args()

    drift = False
    with open(SKELETON) as fh:
        if fh.read() != skeleton_text():
            drift = True
            print("formal/skeleton.json is stale")
    fresh = spliced_alloy()
    if fresh is not None:
        with open(ALLOY) as fh:
            if fh.read() != fresh:
                drift = True
                print("formal/glm_gateway.als generated block is stale")

    if args.write:
        with open(SKELETON, "w") as fh:
            fh.write(skeleton_text())
        if fresh is not None:
            with open(ALLOY, "w") as fh:
                fh.write(fresh)
        print("formal artifacts rewritten")
        return 0
    if drift:
        print("run: uv run python scripts/gen_alloy_catalogue.py --write")
        return 1
    print("formal artifacts in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
