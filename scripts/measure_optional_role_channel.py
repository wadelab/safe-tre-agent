"""Price the optional-role channel: what a model tells you by releasing without
its dispersion.

A gaussian model needs two cell tables — the group means and the group sums of
squares. The second is an *optional role* (`GLMProcedure.optional_roles`): when
its cells fail the dominance bound the model still releases, from vetted means
alone, and says so. That message is a fact about the data, so it is a channel,
and the red-team report asked for it to be priced rather than assumed harmless.

This measures it, and the answer has two halves.

**How often it fires.** Over the gaussian model skeleton, counted here.

**What it is made of.** Not the message. A model released without dispersion
carries three columns where a complete one carries six — no `std_error`, no
`statistic`, no `p_value` — because a coefficient's standard error is computed
from the within-cell scatter the sum-of-squares table supplies. The analyst can
therefore see the omission in the result whether or not anything says so, which
means deleting the `model_table_withheld` finding would remove the sentence and
leave the channel. That is worth measuring precisely because the cheap "fix" is
the one that looks like a fix.

Run inside the safepod (it reads true contributor shares, which never leave;
the output is a summary, not data).

Usage:
    uv run python scripts/measure_optional_role_channel.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                                      # noqa: E402
from safetre.disclosure import DisclosurePolicy, SessionAuditor  # noqa: E402
from safetre.engine import QueryEngine                         # noqa: E402
from safetre.glm import GLMProcedure                           # noqa: E402
from safetre.query import CATALOGUE, GLMSpec                   # noqa: E402
from safetre.service import QueryService                       # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "artifacts", "optional_role_channel.json")
SEED, DONORS = 7, 500


def measure() -> dict:
    tables = synth.generate(seed=SEED, n_donors=DONORS)
    engine, policy = QueryEngine(tables), DisclosurePolicy()
    service = QueryService(tables)
    procedure = GLMProcedure()

    counts = {"gaussian_points": 0, "released_complete": 0,
              "released_without_dispersion": 0, "denied": 0}
    shapes: dict[str, list[str]] = {}

    for point in procedure.skeleton(CATALOGUE):
        spec = GLMSpec(**point)
        if spec.family != "gaussian":
            continue
        counts["gaussian_points"] += 1

        # which cell tables the gateway would refuse, decided the same way the
        # service decides it
        refused = {aggregate.measure.fn
                   for aggregate in procedure.plan_aggregates(spec)
                   if policy.apply(engine.run(aggregate))[1] != "release"}

        result = service.handle(json.dumps(point), planner=None,
                                auditor=SessionAuditor(budget=10 ** 6),
                                audit_log=None)
        if result.status != "released":
            counts["denied"] += 1
            continue
        partial = refused == {"sum_sq"}
        key = "without_dispersion" if partial else "complete"
        counts["released_without_dispersion" if partial
               else "released_complete"] += 1
        shapes.setdefault(key, list(result.output.columns))

    released = counts["released_complete"] + counts["released_without_dispersion"]
    counts["released"] = released
    counts["fires_on_share_of_released_models"] = (
        counts["released_without_dispersion"] / released if released else None)
    return {
        "seed": SEED, "donors": DONORS,
        "dom_threshold": policy.dom_threshold, "threshold": policy.threshold,
        "models": counts,
        "released_columns": shapes,
        "channel_is_structural": shapes.get("complete") != shapes.get("without_dispersion"),
    }


def main() -> None:
    report = measure()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    models = report["models"]
    share = models["fires_on_share_of_released_models"]
    print(f"gaussian skeleton points            : {models['gaussian_points']}")
    print(f"  released, complete                : {models['released_complete']}")
    print(f"  released, dispersion withheld     : {models['released_without_dispersion']}")
    print(f"  denied outright                   : {models['denied']}")
    print(f"the bit fires on                    : "
          f"{share:.0%} of released gaussian models" if share is not None
          else "the bit fires on                    : n/a")
    print(f"complete release columns            : {report['released_columns'].get('complete')}")
    print(f"partial release columns             : "
          f"{report['released_columns'].get('without_dispersion')}")
    print(f"channel survives deleting the note  : {report['channel_is_structural']}")
    print(f"report -> {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
