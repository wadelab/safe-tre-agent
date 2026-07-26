"""What composing an external checker with the stand-in actually costs.

Turning an external output checker on is monotone — a cell is suppressed if
either rule set says so — so it cannot regress protection. What it can do is
refuse analyses that used to be available, and nobody has measured how many.

The unmeasured part is models specifically. A gaussian model dies if either
of its moment cell tables is suppressed, and the external checker vets those
tables like any other, at *its own* parameters: `AcroVetter` does not read
`VettingParameters`, so the per-class dominance bound this project added for
second moments (`moment2_dom_threshold`) governs the stand-in's rules and not
the checker's. Composing therefore applies ACRO's NK and p% rules to sums of
squares — the exact thing the integration design said must be decided
deliberately rather than inherited.

Two levels, as with the dispersion measurement:

  cells   how many cells each rule set suppresses, and how many the union
          suppresses that the stand-in alone would have released
  models  the gaussian skeleton under each, split into full fits,
          coefficients-only (the dispersion table refused) and refused

Runs the checker IN PROCESS: the comparison harness already proves the
out-of-process boundary returns identical verdicts, and a subprocess per cell
table would make this sweep take hours to reach the same answer.

Usage:
    uv run --no-default-groups --group acro python \\
        scripts/measure_composite_cost.py --json artifacts/composite_cost.json
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "redteam"))

from acro_vetter import AcroVetter                              # noqa: E402

from safetre import synth                                       # noqa: E402
from safetre.disclosure import (                                # noqa: E402
    CompositeVetter, DisclosurePolicy, StandinVetter,
)
from safetre.engine import QueryEngine                          # noqa: E402
from safetre.glm import GLMProcedure                            # noqa: E402
from safetre.query import CATALOGUE, GLMSpec, QuerySpec         # noqa: E402

DEMO_SEED, DEMO_DONORS = 7, 800
MAX_CELL_DIMS = 2


def policies() -> dict[str, DisclosurePolicy]:
    """The stand-in alone, and the union an operator would be switching on."""
    return {
        "standin": DisclosurePolicy(),
        "standin+acro": DisclosurePolicy(vetter=CompositeVetter(
            StandinVetter(), AcroVetter(pd.DataFrame(), [], None))),
    }


def measure_cells(engine: QueryEngine) -> dict:
    """Per-cell verdicts of each rule set over the plain query skeleton."""
    counts = {name: 0 for name in policies()}
    counts["cells"] = 0
    counts["only_acro_suppresses"] = 0
    counts["only_standin_suppresses"] = 0
    for dataset, info in CATALOGUE.items():
        dims = sorted(info["dims"])
        for column in sorted(info["measures"]):
            for width in range(MAX_CELL_DIMS + 1):
                for group_by in itertools.combinations(dims, width):
                    spec = QuerySpec(dataset=dataset, group_by=list(group_by),
                                     measure={"fn": "sum", "column": column})
                    cells = engine.run(spec)
                    context = engine.cell_context(spec, with_contributions=True)
                    verdicts = {
                        name: policy.vetter.vet(cells, policy.parameters(), context)
                        for name, policy in policies().items()}
                    standin = verdicts["standin"].suppress
                    union = verdicts["standin+acro"].suppress
                    counts["cells"] += len(cells)
                    counts["standin"] += int(standin.sum())
                    counts["standin+acro"] += int(union.sum())
                    counts["only_acro_suppresses"] += int((union & ~standin).sum())
                    counts["only_standin_suppresses"] += 0   # union cannot release
    return counts


def measure_models(engine: QueryEngine) -> dict:
    """The gaussian skeleton under each rule set."""
    procedure = GLMProcedure()
    out: dict[str, dict] = {}
    for name, policy in policies().items():
        tally = {"points": 0, "full_fit": 0, "coefficients_only": 0, "refused": 0}
        for point in procedure.skeleton(CATALOGUE):
            spec = GLMSpec(**point)
            if spec.family != "gaussian":
                continue
            tally["points"] += 1
            refused = set()
            for aggregate in procedure.plan_aggregates(spec):
                cells = engine.run(aggregate)
                context = engine.cell_context(aggregate, with_contributions=True)
                verdicts = policy.vetter.vet(cells, policy.parameters(), context)
                # the model needs the table complete: any suppressed cell, or a
                # denial, costs it that table
                if bool(verdicts.suppress.any()) or verdicts.deny:
                    refused.add(aggregate.measure.fn)
            if not refused:
                tally["full_fit"] += 1
            elif refused <= {"sum_sq"}:
                tally["coefficients_only"] += 1
            else:
                tally["refused"] += 1
        out[name] = tally
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEMO_SEED)
    parser.add_argument("--donors", type=int, default=DEMO_DONORS)
    parser.add_argument("--json", dest="json_out", default=None)
    args = parser.parse_args()

    engine = QueryEngine(synth.generate(seed=args.seed, n_donors=args.donors))
    engine.con.execute("SET enable_progress_bar=false")
    cells = measure_cells(engine)
    models = measure_models(engine)

    available = {name: t["full_fit"] + t["coefficients_only"]
                 for name, t in models.items()}
    summary = {"seed": args.seed, "donors": args.donors,
               "cells": cells, "models": models,
               "models_lost_to_the_checker":
                   available["standin"] - available["standin+acro"],
               "full_fits_lost_to_the_checker":
                   models["standin"]["full_fit"] - models["standin+acro"]["full_fit"]}

    print(f"cells examined                        : {cells['cells']}")
    print(f"  suppressed by the stand-in          : {cells['standin']}")
    print(f"  suppressed by the union             : {cells['standin+acro']}")
    print(f"  ... suppressed ONLY by the checker  : {cells['only_acro_suppresses']}")
    print()
    for name, tally in models.items():
        print(f"gaussian models, {name:13s}: {tally['full_fit']} full, "
              f"{tally['coefficients_only']} coefficients-only, "
              f"{tally['refused']} refused")
    print()
    print(f"models that stop being available at all : "
          f"{summary['models_lost_to_the_checker']}")
    print(f"models that lose their inference        : "
          f"{summary['full_fits_lost_to_the_checker']}")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(summary, fh, indent=2)
            fh.write("\n")
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
