"""Price the exact-leg channel: what a differencing denial tells you that the
published marginals do not.

The session auditor decides a differencing pair with two bounds
(`service._difference_bound`). The cheap one, `simulatable_cohort_bound`, is
computed from the marginals `/api/marginals` already publishes, so an analyst
can predict its verdict without asking — a denial from that leg carries no new
information. The exact one, `engine.row_symdiff_donors`, counts the donors
behind the rows exactly one of the two queries aggregated. It is a query
against live data, so when it denies where the cheap leg would have allowed,
that denial is a fact about records the analyst has just been refused.

Hardening #40 introduced the exact leg because the cheap one could not see the
attack: two cohorts holding precisely the same people over different rows. This
prices what that cost. The bit is real and accepted; what it is not is free,
and the code used to say it was — "the bit it exposes is the one a direct query
for the difference cell already returns" — which is wrong, because that direct
query is a sub-threshold cell and is SUPPRESSED. The analyst does not otherwise
hold it. `formal/disclosure_policy.als::V8ExactLegIsNotSimulatable` exhibits
the same gap as a satisfiable model instance; this measures how wide it is on
real data.

What is counted, over every pair of cohorts drawn from the demo catalogue's
one- and two-filter predicates:

- `both_allow`      — neither leg denies: no channel, the common case;
- `cheap_denies`    — the simulatable leg denies, so the verdict was already
                      predictable from published marginals: no new bit;
- `exact_only`      — the simulatable leg allows and the exact leg denies.
                      THIS is the channel: one bit per pair, not simulatable.

The denial message is identical either way (`tests/test_hardening.py::
test_the_two_differencing_legs_are_indistinguishable` pins that), so the
analyst learns "too close to a prior release" and never which leg said so —
the bit is one bit, not a number.

Run inside the safepod (it reads true donor counts, which never leave; the
output is a summary, not data).

Usage:
    uv run python scripts/measure_exact_leg_channel.py
"""

from __future__ import annotations

import itertools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                                       # noqa: E402
from safetre.disclosure import (                                # noqa: E402
    DisclosurePolicy, simulatable_cohort_bound,
)
from safetre.engine import QueryEngine                          # noqa: E402
from safetre.query import CATALOGUE                             # noqa: E402
from safetre.schema import declared_domain                      # noqa: E402

SEED = 7
N_DONORS = 500
DATASET = "spend"
ARTIFACT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "artifacts", "exact_leg_channel.json")


def _cohorts(dataset: str, max_filters: int = 2) -> list[tuple]:
    """Every normalized cohort of up to `max_filters` equality predicates over
    the dataset's declared categorical domains — the shape an analyst writes."""
    atoms: list[tuple] = []
    for column, kind in sorted(CATALOGUE[dataset]["dims"].items()):
        if kind != "cat":
            continue
        for value in (declared_domain(column) or []):
            atoms.append((column, "==", value))
    out: list[tuple] = [()]
    for size in range(1, max_filters + 1):
        for combo in itertools.combinations(atoms, size):
            if len({a[0] for a in combo}) != size:
                continue                       # one predicate per column
            out.append(tuple(sorted(combo, key=repr)))
    return out


def main() -> int:
    engine = QueryEngine(synth.generate(seed=SEED, n_donors=N_DONORS))
    threshold = DisclosurePolicy.DEFAULT_THRESHOLD
    marginals = engine.marginal_donor_counts()
    cohorts = _cohorts(DATASET)

    counts = {"both_allow": 0, "cheap_denies": 0, "exact_only": 0}
    for a, b in itertools.combinations(cohorts, 2):
        cheap = simulatable_cohort_bound(marginals, DATASET, a, b)
        if cheap < threshold:
            counts["cheap_denies"] += 1
            continue
        # the exact leg runs only where the cheap one has not already denied,
        # which is exactly where its verdict is not simulatable
        if engine.row_symdiff_donors(DATASET, a, b) < threshold:
            counts["exact_only"] += 1
        else:
            counts["both_allow"] += 1

    pairs = sum(counts.values())
    reached = counts["exact_only"] + counts["both_allow"]
    result = {
        "seed": SEED,
        "donors": N_DONORS,
        "dataset": DATASET,
        "threshold": threshold,
        "cohorts": len(cohorts),
        "pairs": pairs,
        "counts": counts,
        # of all pairs, how many carry a bit the marginals cannot reproduce
        "non_simulatable_share_of_pairs":
            counts["exact_only"] / pairs if pairs else 0.0,
        # of the pairs that actually reach the exact leg, how many it denies
        "non_simulatable_share_of_pairs_reaching_the_exact_leg":
            counts["exact_only"] / reached if reached else 0.0,
        # the number that matters: of every denial the auditor issues, how many
        # carry a bit the published marginals cannot reproduce. The cheap leg
        # turns out to catch almost nothing on its own, so this is close to 1 —
        # the differencing control is, in practice, the non-simulatable one.
        "non_simulatable_share_of_all_denials":
            counts["exact_only"] / (counts["exact_only"] + counts["cheap_denies"])
            if (counts["exact_only"] + counts["cheap_denies"]) else 0.0,
    }
    os.makedirs(os.path.dirname(ARTIFACT), exist_ok=True)
    with open(ARTIFACT, "w") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    print(json.dumps(result, indent=2))
    print(f"\nwritten to {os.path.relpath(ARTIFACT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
