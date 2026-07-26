"""How much a query's *latency* says about a cohort the release suppressed.

The security model calls data-dependent latency "a theoretical channel …
sub-millisecond on the synthetic scale and swamped by jitter". That is an
assertion, and two things make it worth checking rather than repeating: it has
never been measured, and an external output checker adds a round-trip whose
cost scales with the cohort, which is nowhere near sub-millisecond.

The channel that matters is not which *stage* denied a request — the analyst
is told that. It is that the work done is a function of data the release
blurs: ask about a sub-threshold cohort, receive nothing, and the time taken
still depends on how many rows were scanned. Repeat across categories and you
rank suppressed cells by size, which is the thing suppression exists to
prevent.

What is measured, per cohort of known true size:

  latency     repeated timings of the full service path, warm-ups discarded
  signal      how strongly median latency tracks cohort size (Spearman)
  usable?     the number that decides it — given the observed noise, how many
              samples an attacker needs to tell two suppressed cohorts apart,
              against a per-session budget that caps them at 20

Run it against both vetters: the second is the case the assertion predates.

    uv run python scripts/measure_timing_channel.py
    uv run --no-default-groups --group acro python \\
        scripts/measure_timing_channel.py --vetter standin+external \\
        --checker "uv run --no-default-groups --group acro python redteam/acro_checker.py"
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from safetre import synth                                        # noqa: E402
from safetre.disclosure import (                                 # noqa: E402
    DisclosurePolicy, SessionAuditor, build_vetter,
)
from safetre.service import QueryService                         # noqa: E402

DEMO_SEED, DEMO_DONORS = 7, 800
WARMUPS, SAMPLES = 3, 25


def cohorts(tables, threshold: int) -> list[dict]:
    """Cohorts of known true size, over two dimensions so the sub-threshold
    end is populated.

    The split that matters is `published` versus `secret`. Donor marginals are
    published for cells at or above the frequency threshold (rounded) and as
    null below it, so an attacker already knows the ordering of the large
    cohorts — timing that merely reproduces public information reveals
    nothing. The question is whether it resolves the small ones.
    """
    donors = tables["donors"]
    out = []
    for column in ("region", "sex"):
        for value, n in donors.groupby(column)["donor_id"].nunique().items():
            if any(ch in str(value) for ch in "=<>[]|;"):     # planted payloads
                continue
            out.append({"dimension": column, "cohort": str(value),
                        "donors": int(n),
                        "published": bool(int(n) >= threshold)})
    return sorted(out, key=lambda c: c["donors"])


def time_query(service: QueryService, dimension: str, value: str
               ) -> tuple[float, str]:
    spec = {"dataset": "donor_spend",
            "measure": {"fn": "sum", "column": "total_spend_gbp"},
            "filters": [{"column": dimension, "op": "==", "value": value}]}
    payload = json.dumps(spec)
    started = time.perf_counter()
    # a fresh auditor each time: otherwise the differencing rule refuses the
    # repeats and we would be timing the refusal, not the query
    result = service.handle(payload, planner=None, auditor=SessionAuditor())
    return (time.perf_counter() - started) * 1000.0, result.status


def separability(a: list[float], b: list[float]) -> float:
    """How many samples of each cohort an attacker needs before their mean
    latencies are two standard errors apart — the point at which the ordering
    stops being a coin flip. `inf` when the distributions are indistinguishable.
    """
    gap = abs(statistics.median(a) - statistics.median(b))
    spread = statistics.pstdev(a + b)
    if gap == 0 or spread == 0:
        return float("inf") if gap == 0 else 1.0
    # two-sample: n such that 2 * sd/sqrt(n) < gap
    return (2.0 * spread / gap) ** 2


def spearman(xs: list[float], ys: list[float]) -> float:
    def ranks(values):
        order = sorted(range(len(values)), key=lambda i: values[i])
        out = [0.0] * len(values)
        for rank, index in enumerate(order):
            out[index] = float(rank)
        return out

    rx, ry = ranks(xs), ranks(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry, strict=True))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return num / den if den else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vetter", default="standin")
    parser.add_argument("--checker", default="")
    parser.add_argument("--samples", type=int, default=SAMPLES)
    parser.add_argument("--budget", type=int, default=20,
                        help="per-session query budget the attacker is capped by")
    parser.add_argument("--json", dest="json_out", default=None)
    args = parser.parse_args()

    tables = synth.generate(seed=DEMO_SEED, n_donors=DEMO_DONORS)
    policy = DisclosurePolicy(vetter=build_vetter(args.vetter, args.checker))
    service = QueryService(tables, policy)

    rows = []
    for entry in cohorts(tables, policy.threshold):
        for _ in range(WARMUPS):
            time_query(service, entry["dimension"], entry["cohort"])
        timings, status = [], ""
        for _ in range(args.samples):
            elapsed, status = time_query(service, entry["dimension"],
                                         entry["cohort"])
            timings.append(elapsed)
        entry.update(status=status,
                     median_ms=round(statistics.median(timings), 3),
                     iqr_ms=round(statistics.quantiles(timings, n=4)[2]
                                  - statistics.quantiles(timings, n=4)[0], 3),
                     timings=[round(t, 3) for t in timings])
        rows.append(entry)
        print(f"{entry['cohort']:26s} {entry['donors']:4d} donors  "
              f"{entry['median_ms']:8.2f} ms  ±{entry['iqr_ms']:6.2f}  "
              f"{entry['status']:9s} "
              f"{'published' if entry['published'] else 'SECRET'}")

    correlation = spearman([r["donors"] for r in rows],
                           [r["median_ms"] for r in rows])

    def pairs_among(subset: list[dict]) -> list[dict]:
        found = []
        for i, a in enumerate(subset):
            for b in subset[i + 1:]:
                found.append({
                    "a": a["cohort"], "b": b["cohort"],
                    "true_gap": abs(a["donors"] - b["donors"]),
                    "samples_needed": round(
                        separability(a["timings"], b["timings"]), 1)})
        return found

    secret = [r for r in rows if not r["published"]]
    secret_pairs = pairs_among(secret)
    public_pairs = pairs_among([r for r in rows if r["published"]])
    breakable = [p for p in secret_pairs if p["samples_needed"] <= args.budget]

    print()
    print(f"vetter                              : {args.vetter}")
    print(f"latency vs cohort size (Spearman)   : {correlation:+.3f}")
    print()
    print("The large cohorts are already public: donor marginals publish "
          "rounded counts at or above the threshold, so ordering those by "
          "latency reveals nothing an analyst cannot fetch.")
    print(f"  published pairs orderable in <= {args.budget} queries : "
          f"{sum(1 for p in public_pairs if p['samples_needed'] <= args.budget)}"
          f"/{len(public_pairs)}")
    print()
    print(f"SUB-THRESHOLD cohorts (counts published as null): {len(secret)}")
    print(f"  pairs orderable within the {args.budget}-query budget : "
          f"{len(breakable)}/{len(secret_pairs)}")
    for pair in sorted(secret_pairs, key=lambda p: p["samples_needed"])[:6]:
        needed = pair["samples_needed"]
        shown = "inf" if needed == float("inf") else f"{needed:.0f}"
        print(f"    {pair['a']} vs {pair['b']}: {shown} samples needed "
              f"(true gap {pair['true_gap']} donors)")

    summary = {"vetter": args.vetter, "samples": args.samples,
               "budget": args.budget, "spearman_size_vs_latency": correlation,
               "cohorts": rows, "secret_pairs": secret_pairs,
               "public_pairs": public_pairs,
               "secret_pairs_orderable_within_budget": len(breakable)}
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(summary, fh, indent=2)
            fh.write("\n")
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
