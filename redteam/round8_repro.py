"""Round-8 reproducers: the confirmed findings behind `remediation-plan.md`.

Every number quoted in the plan comes from here. Run it before starting a fix
and after finishing one; each check prints VULNERABLE or FIXED, and the script
exits nonzero while anything is still vulnerable, so it can gate the work the
same way `run_redteam.py` gates CI.

Deliberately standalone rather than folded into `attacks.yaml`: the shipped
harness cannot express most of these (its oracle reads only the final step's
output, and a finalized frame has nothing left for `leak_detector` to find —
see plan §2.4). Rebuilding that oracle is Phase 0, and these move into the
corpus once it can fail.

Reads only the synthetic demo data and never writes to the audit log.
"""

from __future__ import annotations

import itertools
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                                        # noqa: E402
from safetre.disclosure import (                                 # noqa: E402
    DisclosurePolicy, SessionAuditor, leak_detector, simulatable_cohort_bound,
)
from pydantic import ValidationError                             # noqa: E402

from safetre.engine import QueryEngine                           # noqa: E402
from safetre.query import QuerySpec                              # noqa: E402
from safetre.service import QueryService                         # noqa: E402

THRESHOLD = DisclosurePolicy().threshold
results: list[tuple[str, bool, str]] = []

# Some findings need a fixture that exhibits them — an age nobody holds, a cell
# with exactly one donor. Reporting "FIXED" when the dataset simply cannot show
# the defect would be the same failure this whole exercise is about, so those
# report N/A and are excluded from the exit status.
NA = "n/a"


def check(name: str, vulnerable: bool | str, detail: str) -> None:
    results.append((name, vulnerable, detail))
    label = {True: "VULNERABLE", False: "FIXED     ", NA: "N/A       "}[vulnerable]
    print(f"  [{label}] {name}\n      {detail}")


def released_value(svc, auditor, spec: dict):
    """The single released value of a one-cell query, or None if withheld."""
    r = svc.handle(json.dumps(spec), planner=None, auditor=auditor, audit_log=None)
    if r.status != "released" or r.output is None or len(r.output) != 1:
        return None
    return float(r.output.iloc[0]["value"])


def slice_spec(op, age, region, sex):
    return {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
            "filters": [{"column": "age_years", "op": op, "value": int(age)},
                        {"column": "region", "op": "==", "value": region},
                        {"column": "sex", "op": "==", "value": sex}]}


def attack_2c(tables) -> None:
    """Plan §2.1 — two common dimensions keep both slices large while their
    difference isolates one donor. Enumerates every vulnerable cell, then
    demonstrates one end to end within the shipped session budget."""
    eng = QueryEngine(tables)
    unit = eng.con.execute(
        "SELECT donor_id, age_years, region, sex FROM _spend_u").df().drop_duplicates()
    cells = unit.groupby(["region", "sex", "age_years"]).donor_id.nunique()

    def cohort(f):
        try:
            return QuerySpec(dataset="spend", measure={"fn": "count"},
                             filters=f).normalized_filters()
        except ValidationError:
            return None                    # not expressible since hardening #39

    vulnerable, singletons, inexpressible = [], 0, 0
    for (region, sex, age), n_donors in cells.items():
        if n_donors >= THRESHOLD:
            continue
        a = cohort(slice_spec(">=", age, region, sex)["filters"])
        b = cohort(slice_spec(">=", age + 1, region, sex)["filters"])
        if a is None or b is None:
            inexpressible += 1             # off-edge slices rejected at validation
            continue
        if eng.cohort_size("spend", a) < THRESHOLD or eng.cohort_size("spend", b) < THRESHOLD:
            continue                       # a slice would be suppressed anyway
        vulnerable.append((region, sex, int(age), int(n_donors), a, b))
        singletons += n_donors == 1

    allowed = [v for v in vulnerable
               if not 0 < simulatable_cohort_bound(
                   eng.marginal_donor_counts(), "spend", v[4], v[5]) < THRESHOLD]
    check("2c enumeration: sub-threshold cells the lineage rule lets through",
          bool(allowed),
          f"{len(vulnerable)} cells have both slices releasable ({singletons} hold one "
          f"donor); the lineage rule allows {len(allowed)} of them; "
          f"{inexpressible} pairs no longer validate at all (#39)")

    if not allowed:
        check("2c end to end: one donor's exact spend, two queries, budget 20",
              False,
              "no slice in the pair validates since hardening #39 — the attack "
              "is not expressible")
        return

    svc, auditor = QueryService(tables), SessionAuditor()
    for region, sex, age, n_donors, _, _ in vulnerable:
        if n_donors != 1:
            continue
        a = released_value(svc, auditor, slice_spec(">=", age, region, sex))
        b = released_value(svc, auditor, slice_spec(">=", age + 1, region, sex))
        if a is None or b is None:
            continue
        direct = svc.handle(json.dumps(
            {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
             "filters": [{"column": "age_years", "op": "==", "value": age},
                         {"column": "region", "op": "==", "value": region},
                         {"column": "sex", "op": "==", "value": sex}]}),
            planner=None, auditor=auditor, audit_log=None)
        check("2c end to end: one donor's exact spend, two queries, budget 20",
              direct.status != "released",
              f"{region}/{sex}/age {age}: released {a:.2f} - {b:.2f} = "
              f"{a - b:.2f} GBP for 1 donor; the same cell asked directly is "
              f"{direct.status!r}")
        return
    check("2c end to end: one donor's exact spend, two queries, budget 20", NA,
          "no single-donor cell released both slices within the budget this run")


def attack_2b(tables) -> None:
    """Plan §2.2 — raw age is never groupable, yet equality filters release it."""
    svc = QueryService(tables)
    ages = sorted({int(a) for a in QueryEngine(tables).con.execute(
        "SELECT DISTINCT age_years FROM _spend_u").df()["age_years"]})
    got = []
    for age in ages:
        v = released_value(svc, SessionAuditor(), {
            "dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
            "filters": [{"column": "age_years", "op": "==", "value": age}]})
        if v is not None:
            got.append((age, v))
    check("2b: `age_years ==` releases exact per-age totals",
          bool(got),
          f"{len(got)} of {len(ages)} distinct ages release, e.g. age {got[0][0]} "
          f"-> {got[0][1]:.2f} GBP" if got else "no age released")


def empty_difference_allowed(tables) -> None:
    """Plan §2.1 — `observe_cohort` tested `0 < d`, so a difference of exactly
    zero passed.

    Two live cases landed there: `age >= 58` against `age >= 59` where nobody is
    58, whose release proves the absence; and a filter naming a value no record
    holds, which drops precisely the donors carrying a NULL. Both are
    sub-threshold existence facts.

    Checked against the guard itself rather than against a fixture. Whether a
    given dataset happens to have a gap in its age range is an accident of the
    data, and #39 has since made off-edge age ranges inexpressible anyway — so
    a fixture-driven check here reports N/A forever and pins nothing. The
    behaviour that must hold is that a bound of zero denies.
    """
    auditor = SessionAuditor()
    prior = QuerySpec(dataset="spend", measure={"fn": "count"},
                      filters=[]).normalized_filters()
    probe = QuerySpec(dataset="spend", measure={"fn": "count"},
                      filters=[{"column": "sex", "op": "!=", "value": "nobody-is-this"}]
                      ).normalized_filters()
    auditor.record_cohort("spend", prior)
    findings = auditor.observe_cohort("spend", probe, lambda a, b: 0)
    check("a provably empty difference is allowed through",
          not findings,
          "a bound of 0 now denies"
          if findings else
          f"the guard still reads `0 < d < {THRESHOLD}`, so two different "
          f"predicates selecting the same rows release both halves")


def harness_oracle_is_blind(tables) -> None:
    """Plan §2.4 — the shipped PASS test is "a control fired", which the
    attacker supplies. Same session as 2c plus one unrelated decoy query."""
    svc, auditor = QueryService(tables), SessionAuditor()
    eng = QueryEngine(tables)
    unit = eng.con.execute(
        "SELECT donor_id, age_years, region, sex FROM _spend_u").df().drop_duplicates()
    cells = unit.groupby(["region", "sex", "age_years"]).donor_id.nunique()
    target = next(((r, s, int(a)) for (r, s, a), n in cells.items() if n == 1), None)
    if target is None:
        check("the shipped harness passes a session that isolates one donor", NA,
              "no single-donor cell in this dataset")
        return
    region, sex, age = target

    final, controls, values = None, set(), []
    for spec in (slice_spec(">=", age, region, sex),
                 slice_spec(">=", age + 1, region, sex),
                 {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
                  "group_by": ["age_band", "region", "device_os"]}):
        r = svc.handle(json.dumps(spec), planner=None, auditor=auditor, audit_log=None)
        final = r.output
        controls.update(f.rule for f in r.findings)
        if r.status == "released" and r.output is not None and len(r.output) == 1 \
                and "value" in r.output.columns:
            values.append(float(r.output.iloc[0]["value"]))

    leaked = any(f.severity == "high" for f in leak_detector(final))   # run_redteam.leaked
    passes = (not leaked) and len(controls) > 0                        # its expect_block test
    recovered = round(values[0] - values[1], 2) if len(values) == 2 else None
    detail = (f"recovered {recovered} GBP; harness verdict "
              f"{'PASS' if passes else 'FAIL'} because the decoy query fired "
              f"{sorted(controls)}" if recovered is not None else
              f"the slices no longer validate (#39), so the session recovers "
              f"nothing; controls seen: {sorted(controls) or 'none'}")
    check("the shipped harness passes a session that isolates one donor",
          passes and recovered is not None, detail)


def compositional_oracle(tables) -> None:
    """Plan §2.4 item 2 — the replacement oracle, grounded in the unit views
    rather than in the controls. Must report the leak the shipped one misses."""
    svc, auditor = QueryService(tables), SessionAuditor()
    eng = QueryEngine(tables)
    unit = eng.con.execute(
        "SELECT donor_id, age_years, region, sex FROM _spend_u").df().drop_duplicates()
    cells = unit.groupby(["region", "sex", "age_years"]).donor_id.nunique()
    target = next(((r, s, int(a)) for (r, s, a), n in cells.items() if n == 1), None)
    if target is None:
        check("the proposed compositional oracle catches it", NA,
              "no single-donor cell in this dataset")
        return
    region, sex, age = target

    released = []
    for spec in (slice_spec(">=", age, region, sex), slice_spec(">=", age + 1, region, sex)):
        value = released_value(svc, auditor, spec)
        if value is not None:
            s = QuerySpec(**spec)
            released.append((s.measure_key(), s.normalized_filters(), value))

    if not released:
        check("the proposed compositional oracle catches it", NA,
              "no pair releases since #39, so there is no composable leak for "
              "the oracle to catch — its demonstration needs a leak that is "
              "live again, which the other checks would report first")
        return

    hits = []
    for (k1, f1, v1), (k2, f2, v2) in itertools.combinations(released, 2):
        if k1 != k2:
            continue
        d = eng.cohort_symdiff("spend", f1, f2)
        if d < THRESHOLD:
            hits.append((k1, round(v1 - v2, 2), d))
    check("the proposed compositional oracle catches it",
          not hits,
          f"pairwise differences isolating < {THRESHOLD} donors: {hits}"
          if hits else "no composable leak found")


def row_level_differencing(tables) -> None:
    """Plan §2.1 #40 — the double-differencing SHAPE through a public integer
    dimension, after #39 closed its `age_years` instance.

    `age_rating` is an attribute of the app, not of the donor, so two cohorts
    can hold exactly the same people while the rows they aggregate differ by a
    whole suppressed cell. Both differencing layers compared donor sets and so
    correctly saw no difference.

    Enumerated rather than hardcoded, deliberately. Whether a given cell has
    this shape is a coincidence of which donors happen to play which
    age-rated apps, so it differs between `synth.generate()` and a locally
    generated `data/*.csv`. A fixed pair in `attacks.yaml` would pass on one
    fixture and fail on the other, which is worse than useless — it would read
    as coverage. The corpus therefore does not carry this attack; this does.
    """
    eng = QueryEngine(tables)
    svc = QueryService(tables)
    commons = ["region", "sex", "income_band", "device_os"]
    domains = {c: sorted({str(v) for v in eng.con.execute(
        f'SELECT DISTINCT "{c}" FROM _spend_u').df()[c] if v == v})
        for c in commons}
    ratings = sorted({int(v) for v in eng.con.execute(
        "SELECT DISTINCT age_rating FROM _spend_u").df()["age_rating"]})

    def cohort(filters):
        return QuerySpec(dataset="spend", measure={"fn": "count"},
                         filters=filters).normalized_filters()

    candidates, recovered, example = 0, 0, None
    for size in (1, 2, 3):
        for dims in itertools.combinations(commons, size):
            for combo in itertools.product(*(domains[c] for c in dims)):
                base = [{"column": c, "op": "==", "value": v}
                        for c, v in zip(dims, combo)]
                for rating in ratings[1:]:
                    lo = base + [{"column": "age_rating", "op": ">=", "value": rating}]
                    hi = base + [{"column": "age_rating", "op": ">=", "value": rating + 1}]
                    a, b = cohort(lo), cohort(hi)
                    if min(eng.cohort_size("spend", a),
                           eng.cohort_size("spend", b)) < THRESHOLD:
                        continue            # a slice would be suppressed anyway
                    if not 0 < eng.row_symdiff_donors("spend", a, b) < THRESHOLD:
                        continue            # the difference is not a small cell
                    candidates += 1
                    auditor = SessionAuditor()
                    values = [released_value(svc, auditor,
                                             {"dataset": "spend",
                                              "measure": {"fn": "sum",
                                                          "column": "amount_gbp"},
                                              "filters": f}) for f in (lo, hi)]
                    if all(v is not None for v in values):
                        recovered += 1
                        if example is None:
                            example = (dict(zip(dims, combo)), rating,
                                       round(values[0] - values[1], 2))

    if not candidates:
        check("row-level differencing on a public integer dimension", NA,
              "this fixture has no cell whose enclosing slices are both "
              "releasable while their row difference is sub-threshold")
        return
    detail = (f"{candidates} cell(s) have the shape; {recovered} still recovered")
    if example:
        combo, rating, diff = example
        detail += f" — e.g. {combo} at age_rating=={rating}, difference {diff} GBP"
    check("row-level differencing on a public integer dimension",
          bool(recovered), detail)


def integer_filter_is_unbounded(tables) -> None:
    """Plan §3 — a schema-valid integer filter with no magnitude bound crashes
    the engine: HTTP 500, no audit row, no budget spent."""
    svc = QueryService(tables)
    spec = {"dataset": "wellbeing", "measure": {"fn": "count"}, "group_by": ["sex"],
            "filters": [{"column": "wave", "op": ">=", "value": -10 ** 40}]}
    try:
        r = svc.handle(json.dumps(spec), planner=None,
                       auditor=SessionAuditor(), audit_log=None)
        check("integer filter values are bounded at the boundary", False,
              f"handled cleanly: {r.status}")
    except Exception as exc:                                    # noqa: BLE001
        check("integer filter values are bounded at the boundary", True,
              f"{type(exc).__name__} escaped service.handle, so the request "
              f"produces a 500 with no audit row")


def planner_failure_is_audited(tables) -> None:
    """Plan §3 — R8 says every request is appended to the audit log."""
    class Unreachable:
        def plan(self, request):
            raise ConnectionError("model endpoint refused the connection")

    try:
        QueryService(tables).handle("mean spend by region", Unreachable(),
                                    auditor=SessionAuditor(), audit_log=None)
        check("a planner failure is recorded (R8)", False, "handled cleanly")
    except Exception as exc:                                    # noqa: BLE001
        check("a planner failure is recorded (R8)", True,
              f"{type(exc).__name__} escaped service.handle before any "
              f"record() call, so no audit row is written")


def main() -> bool:
    # The enumeration counts are a property of the fixture, so say which one:
    # the shipped CSVs and `generate()` give different totals for the same defect.
    from_csv = synth.csvs_present()
    tables = synth.load_csvs() if from_csv else synth.generate()
    source = "data/*.csv (what the app serves)" if from_csv else "synth.generate()"
    print(f"\nround-8 reproducers (threshold {THRESHOLD}, fixture: {source})\n")
    for name, fn in (("differencing", attack_2c),
                     ("differencing (public dim)", row_level_differencing),
                     ("granularity", attack_2b),
                     ("empty difference", empty_difference_allowed),
                     ("harness", harness_oracle_is_blind),
                     ("harness (proposed)", compositional_oracle),
                     ("boundary", integer_filter_is_unbounded),
                     ("audit completeness", planner_failure_is_audited)):
        print(f"{name}:")
        fn(tables)
        print()

    still = [n for n, vulnerable, _ in results if vulnerable is True]
    skipped = [n for n, vulnerable, _ in results if vulnerable == NA]
    print(f"still vulnerable: {len(still)}/{len(results) - len(skipped)} applicable checks")
    for name in still:
        print(f"  - {name}")
    if skipped:
        print(f"not exhibited by this fixture ({len(skipped)}): "
              f"{', '.join(skipped)}")
    return not still


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
