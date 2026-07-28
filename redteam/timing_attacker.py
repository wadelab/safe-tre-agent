"""An adaptive attacker against the response-time channel, not a measurement.

`scripts/measure_timing_channel.py` measures the defence: it times a fixed set
of cohorts and reports how separable they are. The red-team report's objection
was that nothing *attacks* it — a passive measurement spends its samples evenly,
and a real attacker spends them where they are paying off. This does that, and
runs the three vectors the report named:

**(a) Bucket-index readout.** Quantising makes `ceil(work / quantum)` the only
observable, so the attack is not "which cohort is slower" but "which cohort
crosses the bucket edge more often". Two cohorts whose work straddles an edge
are separable by the *rate* at which they land in the higher bucket, and that
rate is estimable however small the underlying difference is — it just costs
samples. The attacker therefore ranks pairs by crossing-rate gap and spends its
remaining budget on the most promising, which is what makes it adaptive.

**(b) Ceiling straddle.** Before hardening #54 the ceiling was a post-hoc check:
an overrunning request was answered when it finished, so tuning work against the
ceiling gauged cohort size directly. This runs that vector and expects it to
find nothing; if it ever finds something again, the deadline has regressed.

**(c) Row-count-via-work.** The sharpest of the three. Work tracks *rows*, and
the donor threshold suppresses on *donors*, so a cohort with few donors and many
rows does real work while its count is withheld. A large timing signature on a
suppressed cohort therefore says "a hyperactive donor is in here" — which is the
fact D4's donor threshold exists to hide. Run against the adversarial fixture,
which plants exactly such a donor.

The output is a number to hold a line against: the fewest samples any pair of
SUB-THRESHOLD cohorts needs before their ordering stops being a coin flip.
Cohorts at or above the threshold have their counts published already, so
ordering those reveals nothing and they are excluded.

Usage:
    uv run python redteam/timing_attacker.py --samples 40
    uv run python redteam/timing_attacker.py --json artifacts/timing_attacker.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# A harness must never write to the operator's real audit log. `safetre_web.app`
# opens `SAFETRE_AUDIT_DB` at import and now appends a policy record there
# (#55), so merely importing it from a script pollutes `./audit.db` — which is
# hardening #36 all over again, and did happen (#57). Pin a throwaway path
# BEFORE the import, exactly as `tests/conftest.py` does for the test suite.
import os as _os          # noqa: E402
import tempfile as _tempfile  # noqa: E402

_os.environ.setdefault(
    "SAFETRE_AUDIT_DB",
    _os.path.join(_tempfile.gettempdir(), "safetre-harness-audit.db"))

import fixtures                                        # noqa: E402

from safetre import synth                              # noqa: E402
from safetre.config import load_policy_config          # noqa: E402
from safetre.schema import declared_domain             # noqa: E402
from safetre.service import QueryService               # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The session budget from D5: an ordering an attacker cannot reach inside one
# session is a different proposition from one they can.
SESSION_BUDGET = 20


def _cohorts(tables, threshold: int) -> list[dict]:
    """Candidate cohorts with their true donor counts, sub-threshold first.

    Declared categories only. The demo data carry planted payload strings in
    these columns (`synth.POISON_DONORS`, and more in the adversarial fixture),
    and since hardening #43 those never release as cell keys at all — timing
    them would measure a cohort no analyst can ask about and report a channel
    that is not there.
    """
    donors = tables["donors"]
    out = []
    for column in ("region", "sex", "income_band"):
        domain = set(declared_domain(column) or ())
        counts = donors.groupby(column)["donor_id"].nunique()
        for value, n in counts.items():
            if value is None or value not in domain:
                continue
            out.append({"dimension": column, "cohort": str(value),
                        "donors": int(n), "published": int(n) >= threshold})
    return sorted(out, key=lambda c: c["donors"])


class WebClient:
    """Drives the real app, because the padding is middleware.

    Timing `QueryService` directly measures the *unpadded* channel and would
    make the control look absent — the attacker has to stand where the analyst
    stands, at the deployment boundary, or it is attacking something nobody
    is exposed to.
    """

    def __init__(self, tables):
        os.environ.setdefault("SAFETRE_ALLOW_TEST_CLIENT", "1")
        from fastapi.testclient import TestClient

        import safetre_web.app as web

        # point the app at this fixture, and give each request its own session
        # so the differencing rule does not refuse the repeats (we would then
        # be timing a refusal rather than a query)
        web.service = QueryService(tables, web._policy)
        self._web = web
        self._client = TestClient(web.app)

    def time(self, cohort: dict) -> float:
        spec = {"dataset": "donor_spend",
                "measure": {"fn": "sum", "column": "total_spend_gbp"},
                "filters": [{"column": cohort["dimension"], "op": "==",
                             "value": cohort["cohort"]}]}
        self._web.sessions._sessions.clear()
        started = time.perf_counter()
        self._client.post("/api/query", json={"q": json.dumps(spec)})
        return (time.perf_counter() - started) * 1000.0


def _samples_to_order(a: list[float], b: list[float]) -> float:
    """How many samples per cohort before two medians are two standard errors
    apart — the point at which the ordering stops being a coin flip."""
    gap = abs(statistics.median(a) - statistics.median(b))
    spread = statistics.pstdev(a + b)
    if gap == 0:
        return float("inf")
    if spread == 0:
        return 1.0
    return (2.0 * spread / gap) ** 2


def _bucket_rates(samples: list[float], quantum_ms: float) -> float:
    """The share of samples landing above the median bucket — the observable
    quantisation actually leaves, as opposed to the raw latency."""
    if quantum_ms <= 0:
        return 0.0
    buckets = [math.floor(s / quantum_ms) for s in samples]
    edge = statistics.median(buckets)
    return sum(1 for b in buckets if b > edge) / len(buckets)


def attack(tables, label: str, samples: int, quantum_ms: float,
           threshold: int) -> dict:
    """Vectors (a) and (c): spend samples where they are paying off."""
    client = WebClient(tables)
    candidates = _cohorts(tables, threshold)
    secret = [c for c in candidates if not c["published"]]
    if len(secret) < 2:
        return {"fixture": label, "sub_threshold_cohorts": len(secret),
                "verdict": "no sub-threshold pair to attack on this fixture"}

    # first pass: a cheap, even budget over every sub-threshold cohort
    timings = {c["cohort"]: [client.time(c) for _ in range(samples // 2)]
               for c in secret}

    # adaptive pass: rank pairs by apparent separability and spend the rest of
    # the budget on the most promising, which is what a passive sweep will not do
    def pair_cost(x, y):
        return _samples_to_order(timings[x["cohort"]], timings[y["cohort"]])

    pairs = sorted(((x, y) for i, x in enumerate(secret) for y in secret[i + 1:]),
                   key=lambda p: pair_cost(*p))
    for x, y in pairs[:3]:
        for c in (x, y):
            timings[c["cohort"]] += [client.time(c)
                                     for _ in range(samples // 2)]

    results = []
    for x, y in pairs:
        need = _samples_to_order(timings[x["cohort"]], timings[y["cohort"]])
        results.append({
            "a": x["cohort"], "b": y["cohort"],
            "true_donors": [x["donors"], y["donors"]],
            "samples_to_order": None if need == float("inf") else round(need, 1),
            "within_one_session": need <= SESSION_BUDGET,
        })
    results.sort(key=lambda r: (r["samples_to_order"] is None,
                                r["samples_to_order"] or 0))

    orderable = [r for r in results if r["within_one_session"]]
    return {
        "fixture": label,
        "sub_threshold_cohorts": len(secret),
        "pairs": len(results),
        "closest_pair": results[0] if results else None,
        "pairs_orderable_within_a_session": len(orderable),
        "bucket_crossing_rates": {
            c["cohort"]: round(_bucket_rates(timings[c["cohort"]], quantum_ms), 3)
            for c in secret},
        "worst_pairs": results[:3],
    }


def ceiling_straddle(samples: int = 5) -> dict:
    """Vector (b): does an overrun still reveal how far it overran?

    Closed by hardening #54, and this is its regression test — the ceiling used
    to be a post-hoc body swap, so the answer arrived when the work finished and
    its arrival time was the size gauge.

    Built on a purpose-made app rather than by bolting a route onto the real
    one: a probe that quietly fails to be the thing under test reports "no
    channel" for the wrong reason, which is the failure mode this whole round
    has been about.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from safetre_web.timing import ResponseTimeBoundary

    quantum_ms, ceiling_ms = 50, 200
    probe = FastAPI()

    @probe.get("/work/{ms}")
    def work(ms: int):                              # pragma: no cover - harness
        time.sleep(ms / 1000.0)
        return {"ok": True}

    probe.add_middleware(ResponseTimeBoundary,
                         settings=lambda: (quantum_ms, ceiling_ms))
    client = TestClient(probe)

    observed, statuses = {}, set()
    for work_ms in (400, 800, 1600, 3200):
        times = []
        for _ in range(samples):
            started = time.perf_counter()
            response = client.get(f"/work/{work_ms}")
            times.append((time.perf_counter() - started) * 1000.0)
        statuses.add(response.status_code)
        observed[work_ms] = {"status": response.status_code,
                             "median_ms": round(statistics.median(times), 1)}

    medians = [v["median_ms"] for v in observed.values()]
    spread = max(medians) - min(medians)
    return {
        "quantum_ms": quantum_ms, "ceiling_ms": ceiling_ms,
        "observed": observed,
        "spread_ms": round(spread, 1),
        # every overrun must refuse, or the probe is not exercising the ceiling
        "all_refused": statuses == {503},
        # and 8x the work must not be visible in the answer time
        "reveals_overrun_size": spread > quantum_ms,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=40,
                        help="timing samples per cohort (split across two passes)")
    parser.add_argument("--json", dest="json_out", default=None)
    args = parser.parse_args()

    cfg = load_policy_config()
    quantum = float(cfg.response_quantum_ms)
    report = {
        "quantum_ms": cfg.response_quantum_ms,
        "ceiling_ms": cfg.response_ceiling_ms,
        "threshold": cfg.min_cell_size,
        "session_budget": SESSION_BUDGET,
        "samples_per_cohort": args.samples,
    }

    for label, tables in (("default", synth.generate(seed=7)),
                          ("adversarial", fixtures.adversarial())):
        report[label] = attack(tables, label, args.samples, quantum,
                               cfg.min_cell_size)

    report["ceiling_straddle"] = ceiling_straddle()

    print(f"quantum {cfg.response_quantum_ms} ms, ceiling {cfg.response_ceiling_ms} ms, "
          f"threshold {cfg.min_cell_size} donors\n")
    for label in ("default", "adversarial"):
        section = report[label]
        print(f"{label} fixture: {section.get('sub_threshold_cohorts', 0)} "
              f"sub-threshold cohorts")
        if section.get("closest_pair"):
            closest = section["closest_pair"]
            need = closest["samples_to_order"]
            print(f"  closest pair            : {closest['a']} vs {closest['b']} "
                  f"({closest['true_donors'][0]} vs {closest['true_donors'][1]} donors)")
            print(f"  samples to order it     : "
                  f"{'indistinguishable' if need is None else need}")
            print(f"  orderable in a session  : "
                  f"{section['pairs_orderable_within_a_session']}/{section['pairs']} pairs")
        print()

    straddle = report["ceiling_straddle"]
    print("ceiling straddle (400/800/1600/3200 ms of work past a 200 ms ceiling):")
    for work, seen in straddle["observed"].items():
        print(f"  {work:5d} ms work -> HTTP {seen['status']} at {seen['median_ms']} ms")
    print(f"  spread {straddle['spread_ms']} ms — reveals overrun size: "
          f"{straddle['reveals_overrun_size']}")

    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out) or ".", exist_ok=True)
        with open(args.json_out, "w") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
        print(f"\nwrote {args.json_out}")

    # the gate: every overrun must refuse, and must not reveal its size
    if not straddle["all_refused"]:
        print("\nFAIL: the probe did not exercise the ceiling at all")
        return 1
    return 1 if straddle["reveals_overrun_size"] else 0


if __name__ == "__main__":
    sys.exit(main())
