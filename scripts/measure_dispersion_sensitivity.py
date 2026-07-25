"""Measure which cell decides whether a cells-first model may be released.

A gaussian model fitted from vetted cells needs two of them: the group means
and the group *sums of squares*. Both are ordinary aggregates, so both face
the same dominance bound — one donor may not hold more than `dom_threshold`
of the cell. But squaring is not share-preserving. A donor holding a fraction
p of a cell's total holds

    p^2 / (p^2 + (1 - p)^2 / (k - 1))

of its sum of squares when the cell's other k-1 donors are equal, which
crosses one half at p = 1 / (1 + sqrt(k - 1)) — about 0.19 for a twenty-donor
cell and 0.13 for a fifty-donor one. Real cells are heavy-tailed, so the true
squared share is higher still. The same nominal 50% rule is therefore a much
tighter rule on the second moment than on the first, and it is the second
moment that decides whether the model releases at all (P19).

This script measures the gap rather than asserting it, at both levels:

  cells   every design cell at or above the frequency threshold, with its
          largest donor's share of the linear total and of the squared total;
  models  every gaussian point of the model skeleton, with the cell that
          caused a refusal — so the models lost *only* to the dispersion cell
          can be counted.

Run inside the safepod (it reads true contributor shares, which never leave;
the output is a summary, not data).

Usage:
    uv run python scripts/measure_dispersion_sensitivity.py
    uv run python scripts/measure_dispersion_sensitivity.py --json out.json
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                                   # noqa: E402
from safetre.disclosure import DisclosurePolicy             # noqa: E402
from safetre.engine import QueryEngine                      # noqa: E402
from safetre.glm import GLMProcedure                        # noqa: E402
from safetre.query import CATALOGUE, GLMSpec, QuerySpec     # noqa: E402

MAX_CELL_DIMS = 2       # design cells of 0-2 terms; 3-term cells are almost all
                        # below the frequency threshold, which decides first


def _finite(value) -> float | None:
    """A dominance witness that never resolved (`+inf`, NaN) states no share —
    the gateway fails such a cell closed, and it is not evidence either way."""
    number = float(value)
    return None if math.isnan(number) or math.isinf(number) else number


def measure_cells(engine: QueryEngine, policy: DisclosurePolicy) -> dict:
    """Largest-donor share of every design cell, on both scales."""
    linear_pass = squared_fail = squared_pass_linear_fail = both_pass = total = 0
    linear_shares: list[float] = []
    squared_shares: list[float] = []
    for dataset, info in CATALOGUE.items():
        dims = sorted(info["dims"])
        for column in sorted(info["measures"]):
            for width in range(MAX_CELL_DIMS + 1):
                for group_by in itertools.combinations(dims, width):
                    keys = list(group_by)
                    base = dict(dataset=dataset, group_by=keys)
                    linear = engine.run(QuerySpec(
                        measure={"fn": "sum", "column": column}, **base))
                    squared = engine.run(QuerySpec(
                        measure={"fn": "sum_sq", "column": column}, **base))
                    # join on the cell key, never positionally: the engine
                    # orders by the exact count and leaves ties unspecified,
                    # so the two frames need not agree row for row
                    paired = (linear.merge(squared[keys + ["dominance"]], on=keys,
                                           suffixes=("", "_squared"))
                              if keys else
                              linear.assign(dominance_squared=squared["dominance"].iloc[0]))
                    for lin, sq, donors in zip(paired["dominance"],
                                               paired["dominance_squared"],
                                               paired["n_donors"], strict=True):
                        # the frequency threshold decides small cells before any
                        # dominance rule is reached
                        if donors < policy.threshold:
                            continue
                        lin, sq = _finite(lin), _finite(sq)
                        if lin is None or sq is None:
                            continue
                        total += 1
                        linear_shares.append(lin)
                        squared_shares.append(sq)
                        if lin <= policy.dom_threshold:
                            linear_pass += 1
                            if sq > policy.dom_threshold:
                                squared_fail += 1
                            else:
                                both_pass += 1
                        elif sq <= policy.dom_threshold:
                            squared_pass_linear_fail += 1
    linear_shares.sort()
    squared_shares.sort()

    def median(values: list[float]) -> float | None:
        return values[len(values) // 2] if values else None

    return {
        "cells_at_or_above_threshold": total,
        "pass_linear_bound": linear_pass,
        "pass_linear_fail_squared": squared_fail,
        "pass_squared_fail_linear": squared_pass_linear_fail,
        "pass_both": both_pass,
        "median_linear_share": median(linear_shares),
        "median_squared_share": median(squared_shares),
    }


def measure_models(engine: QueryEngine, policy: DisclosurePolicy) -> dict:
    """Gaussian skeleton points, by the cell that refused them."""
    procedure = GLMProcedure()
    counts = {"gaussian_points": 0, "released": 0, "denied": 0,
              "denied_by_dispersion_cell_alone": 0, "denied_by_mean_cell": 0}
    for point in procedure.skeleton(CATALOGUE):
        spec = GLMSpec(**point)
        if spec.family != "gaussian":
            continue
        counts["gaussian_points"] += 1
        refused = set()
        for aggregate in procedure.plan_aggregates(spec):
            _, action, _ = policy.apply(engine.run(aggregate))
            if action != "release":
                refused.add(aggregate.measure.fn)
        if not refused:
            counts["released"] += 1
            continue
        counts["denied"] += 1
        if refused == {"sum_sq"}:
            counts["denied_by_dispersion_cell_alone"] += 1
        else:
            counts["denied_by_mean_cell"] += 1
    available = counts["released"] + counts["denied_by_dispersion_cell_alone"]
    counts["releasable_but_for_the_dispersion_cell"] = available
    counts["availability_cost"] = (
        counts["denied_by_dispersion_cell_alone"] / available if available else None)
    return counts


def crossover(k: int) -> float:
    """The linear-scale share at which an equal-rest cell of `k` donors crosses
    a one-half squared-scale bound."""
    return 1.0 / (1.0 + math.sqrt(k - 1)) if k > 1 else 1.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--donors", type=int, default=500)
    parser.add_argument("--json", dest="json_out", default=None)
    args = parser.parse_args()

    policy = DisclosurePolicy()
    engine = QueryEngine(synth.generate(seed=args.seed, n_donors=args.donors))
    cells = measure_cells(engine, policy)
    models = measure_models(engine, policy)
    summary = {
        "seed": args.seed,
        "donors": args.donors,
        "dom_threshold": policy.dom_threshold,
        "threshold": policy.threshold,
        "cells": cells,
        "models": models,
        "equal_rest_crossover": {str(k): round(crossover(k), 4)
                                 for k in (10, 20, 50, 100)},
    }

    print(f"design cells at or above the threshold : {cells['cells_at_or_above_threshold']}")
    print(f"  pass the bound on the linear scale   : {cells['pass_linear_bound']}")
    print(f"    ... of which FAIL when squared     : {cells['pass_linear_fail_squared']}")
    print(f"  pass squared but fail linear         : {cells['pass_squared_fail_linear']}")
    print(f"  median share  linear {cells['median_linear_share']:.3f}"
          f"  squared {cells['median_squared_share']:.3f}")
    print()
    print(f"gaussian skeleton points               : {models['gaussian_points']}")
    print(f"  released                             : {models['released']}")
    print(f"  refused by the dispersion cell ALONE : "
          f"{models['denied_by_dispersion_cell_alone']}")
    print(f"  refused with the mean cell too       : {models['denied_by_mean_cell']}")
    if models["availability_cost"] is not None:
        print(f"  availability cost of the dispersion cell: "
              f"{models['availability_cost']:.0%} of otherwise-releasable models")
    print()
    print("equal-rest crossover (linear share at which the squared share hits 1/2):")
    for k, p in summary["equal_rest_crossover"].items():
        print(f"  {k:>4} donors: {p:.3f}")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(summary, fh, indent=2)
            fh.write("\n")
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
