"""Measure the price of fitting on finalized (count-rounded) cell tables.

The cells-first architecture fits models on the gateway-FINALIZED tables, so
cell weights are the base-5 rounded counts (P21: the released model must be a
function of released-equivalent data). The cost is a deterministic weight
perturbation of at most round_base/2 on cells of at least the threshold —
this script measures it rather than asserting it, for every releasable model
in the skeleton: each is fitted twice, on the finalized tables and on the
raw (true-count) tables, and the coefficient and standard-error deltas are
summarised per family.

Run inside the safepod (it reads true counts, which never leave; the output
is a distortion summary, not data).

Usage:
    uv run python scripts/measure_rounding_distortion.py           # terms <= 2
    uv run python scripts/measure_rounding_distortion.py --full    # all 718
    uv run python scripts/measure_rounding_distortion.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                          # noqa: E402
from safetre.disclosure import DisclosurePolicy    # noqa: E402
from safetre.engine import QueryEngine             # noqa: E402
from safetre.glm import GLMProcedure               # noqa: E402
from safetre.procedures import get_procedure       # noqa: E402
from safetre.query import CATALOGUE                # noqa: E402

HELPERS = ["dominance", "influence", "n_donors"]


def _fit_pair(engine: QueryEngine, policy: DisclosurePolicy, proc: GLMProcedure,
              point: dict):
    """(finalized fit, raw fit) for a skeleton point, or None when the model
    would not be released (any non-release aggregate, or unestimable)."""
    spec = proc.validate(point)
    finalized, raw = {}, {}
    for role, agg in zip(proc.table_roles(spec), proc.plan_aggregates(spec),
                         strict=True):
        df = engine.run(agg)
        released, action, _ = policy.apply(df)
        if action != "release":
            return None
        # mirror the service pipeline (hardening #26): value shaping runs on
        # the finalized cells; the raw side stays genuinely raw
        finalized[role] = get_procedure(agg.measure.fn).postprocess(released, agg)
        raw[role] = df.drop(columns=HELPERS, errors="ignore")
    if proc.preconditions(finalized, spec) or proc.preconditions(raw, spec):
        return None
    return proc.fit(finalized, spec), proc.fit(raw, spec), spec


def _relative_deltas(a: list[float], b: list[float]) -> list[float]:
    out = []
    for x, y in zip(a, b):
        scale = max(abs(x), abs(y))
        if scale > 1e-9:
            out.append(abs(x - y) / scale)
    return out


def _quantiles(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    ordered = sorted(values)
    pick = lambda q: ordered[min(len(ordered) - 1, int(q * len(ordered)))]  # noqa: E731
    return {"n": len(values), "median": pick(0.5), "p90": pick(0.9),
            "max": ordered[-1]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--full", action="store_true", help="all skeleton points")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()

    engine = QueryEngine(synth.generate(seed=args.seed))
    policy = DisclosurePolicy()
    proc = GLMProcedure()

    rel: dict[tuple[str, str], list[float]] = {}
    absolute: dict[tuple[str, str], list[float]] = {}
    fitted = skipped = 0
    for point in proc.skeleton(CATALOGUE):
        if not args.full and len(point["terms"]) > 2:
            continue
        pair = _fit_pair(engine, policy, proc, point)
        if pair is None:
            skipped += 1
            continue
        (coef_fin, _), (coef_raw, _), spec = pair
        fitted += 1
        for column in ("estimate", "std_error"):
            fin, raw = list(coef_fin[column]), list(coef_raw[column])
            rel.setdefault((spec.family, column), []).extend(_relative_deltas(fin, raw))
            absolute.setdefault((spec.family, column), []).extend(
                abs(x - y) for x, y in zip(fin, raw))

    summary = {
        "seed": args.seed,
        "round_base": policy.round_base,
        "threshold": policy.threshold,
        "models_fitted_both_ways": fitted,
        "models_not_releasable": skipped,
        "relative_delta": {f"{fam}.{col}": _quantiles(v)
                           for (fam, col), v in sorted(rel.items())},
        "absolute_delta": {f"{fam}.{col}": _quantiles(v)
                           for (fam, col), v in sorted(absolute.items())},
    }
    print(f"models fitted both ways: {fitted}   not releasable: {skipped}")
    for label, block in (("relative", summary["relative_delta"]),
                         ("absolute", summary["absolute_delta"])):
        for key, q in block.items():
            if q["n"]:
                print(f"  {label} {key:20s} n={q['n']:4d}  "
                      f"median={q['median']:.2e}  p90={q['p90']:.2e}  max={q['max']:.2e}")
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(summary, fh, indent=2)
        print(f"results -> {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
