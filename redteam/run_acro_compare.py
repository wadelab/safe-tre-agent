"""Compare ACRO's cell decisions with the stand-in gateway's (roadmap item 1).

Read-only: nothing here touches the release path. Every plain QuerySpec in
the service-path red-team corpus (plus the divergence-targeted fixtures
below) is run twice — through the stand-in `DisclosurePolicy`, and through
ACRO's `crosstab` over the same microdata — and the per-cell decisions are
classified:

    agree_release / agree_suppress   the two gateways decide alike
    acro_stricter                    ACRO suppresses a cell the stand-in
                                     releases: candidate under-suppression
    standin_stricter                 the stand-in suppresses a cell ACRO
                                     releases (expected for complementary
                                     suppression, which ACRO does not do)
    not_comparable                   corr/influence cells (D6) and specs the
                                     validation boundary refuses before any
                                     gateway runs — recorded, never skipped

Protection unit: ACRO is fed ONE ROW PER DONOR per cell (the donor's summed
contribution from the dataset's unit view), so its frequency threshold
counts donors exactly as the stand-in's `n_donors` check does (spec P5,
best-practice D4). For `mean` this makes ACRO's cell *value* a mean of
donor means — the decisions stay comparable, the values do not. The session
auditor (lineage, budget) is deliberately absent: those controls sit above
ACRO in the integration design and have no ACRO analogue.

The exit code reports HARNESS integrity, not agreement: any translation or
execution failure exits nonzero (no silent skips, R13); divergence is the
measurement, written to redteam/acro_results.csv.

Usage:
    uv run --no-default-groups --group acro python redteam/run_acro_compare.py

(The dedicated environment matters: ACRO 0.4.x pins pandas < 3, the project
runtime uses pandas 3 — see [tool.uv] conflicts in pyproject.toml.)
"""

from __future__ import annotations

import csv
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acro as acro_mod                                          # noqa: E402, F401 - asserts the env; version reported in the summary

from safetre import synth                                        # noqa: E402
from safetre.disclosure import (                                 # noqa: E402
    DisclosurePolicy, VettingParameters,
)
from safetre.engine import QueryEngine                           # noqa: E402
from safetre.procedures import model_registry                    # noqa: E402
from safetre.query import QuerySpec                              # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safetre.external_checker import ExternalCheckerVetter      # noqa: E402
from acro_vetter import AGGFUNC, AcroVetter                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_CSV = os.path.join(HERE, "acro_results.csv")

# must match scripts/make_data.py, so the numbers are the same with or without
# a generated `data/` directory
DEMO_SEED, DEMO_DONORS = 7, 800

# how this repository starts the checker in ACRO's own environment. An operator
# configures their own command (SAFETRE_CHECKER_CMD); nothing in safetre/ knows
# this path, because a checker the operator did not choose is not one they can
# vouch for.
DEV_CHECKER = ["uv", "run", "--frozen", "--no-default-groups", "--group", "acro",
               "python", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "acro_checker.py")]

# ACRO decides with its own configuration, so these are inert for the ACRO
# side; they are the stand-in's, passed for interface conformance only.
VETTING = VettingParameters(threshold=10, max_rows=100,
                            dom_threshold=0.5, influence_threshold=0.5)

# Divergence-targeted fixtures beyond the corpus: the deterministic anchors
# (sub-threshold Northern Ireland and sex X), the planted dominance anchors,
# and a whole-population baseline. Each is an ordinary QuerySpec dict.
#
# The dominance fixtures are the D3 lens. The two gateways' dominance rules
# are different rules — the stand-in suppresses a cell where one donor holds
# more than half of it, ACRO's defaults fire on the p%-rule and on the top two
# donors holding 90% — so the corpus alone cannot calibrate them: sampled
# spend is nowhere near concentrated enough for either to fire. The generator
# plants three regions that separate them (`synth.DOMINANCE_ANCHORS`):
# Scotland one donor at 62%, Wales two at 46% each, East Midlands 60% + 35%.
FIXTURES = [
    ("fixture_count_by_region_threshold_edge",
     {"dataset": "spend", "measure": {"fn": "count"}, "group_by": ["region"]}),
    ("fixture_count_by_sex_anchor",
     {"dataset": "spend", "measure": {"fn": "count"}, "group_by": ["sex"]}),
    ("fixture_mean_spend_by_region",
     {"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
      "group_by": ["region"]}),
    ("fixture_donor_sum_by_region_dominance",
     {"dataset": "donor_spend",
      "measure": {"fn": "sum", "column": "total_spend_gbp"},
      "group_by": ["region"]}),
    ("fixture_donor_mean_by_region_dominance",
     {"dataset": "donor_spend",
      "measure": {"fn": "mean", "column": "total_spend_gbp"},
      "group_by": ["region"]}),
    ("fixture_event_sum_by_region_dominance",
     {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"},
      "group_by": ["region"]}),
    # one cell each, so the results file names the verdict per anchor shape
    ("fixture_anchor_scotland_single_donor_over_half",
     {"dataset": "donor_spend",
      "measure": {"fn": "sum", "column": "total_spend_gbp"},
      "filters": [{"column": "region", "op": "==", "value": "Scotland"}]}),
    ("fixture_anchor_wales_top_two_over_nk",
     {"dataset": "donor_spend",
      "measure": {"fn": "sum", "column": "total_spend_gbp"},
      "filters": [{"column": "region", "op": "==", "value": "Wales"}]}),
    ("fixture_anchor_east_midlands_over_both",
     {"dataset": "donor_spend",
      "measure": {"fn": "sum", "column": "total_spend_gbp"},
      "filters": [{"column": "region", "op": "==", "value": "East Midlands"}]}),
    ("fixture_total_spend_no_groupby",
     {"dataset": "spend", "measure": {"fn": "sum", "column": "amount_gbp"}}),
]

def standin_decisions(engine: QueryEngine, policy: DisclosurePolicy,
                      spec: QuerySpec) -> dict[tuple, str]:
    """Per-cell decision of the stand-in gateway: release / suppress / deny."""
    df = engine.run(spec)
    released, action, _ = policy.apply(df)

    def key(row) -> tuple:
        if not spec.group_by:
            return ("total",)
        return tuple(str(row[g]) for g in spec.group_by)

    all_keys = [key(r) for _, r in df.iterrows()]
    if action == "deny" or released is None:
        return {k: "deny" for k in all_keys}
    kept = {key(r) for _, r in released.iterrows()}
    return {k: ("release" if k in kept else "suppress") for k in all_keys}


def verify_boundary(engine: QueryEngine) -> list[str]:
    """Check the out-of-process checker agrees with the in-process vetter.

    The comparison runs ACRO in this process; production cannot (C3), so it
    calls the same rules across the boundary of `safetre/external_checker.py`. If the two
    ever disagree, the numbers this harness publishes describe rules the
    gateway does not actually apply — so this runs on every comparison, with
    the real `uv run --group acro` entry rather than a shortcut, and any
    disagreement is a harness error.
    """
    spec = QuerySpec(dataset="donor_spend",
                     measure={"fn": "sum", "column": "total_spend_gbp"},
                     group_by=["region"])
    cells = engine.run(spec)
    contributions = engine.contributions(spec)
    aggfunc = AGGFUNC.get(spec.measure.fn)
    here = AcroVetter(contributions, spec.group_by, aggfunc).vet(cells, VETTING)
    there_vetter = ExternalCheckerVetter(DEV_CHECKER, spec.group_by, aggfunc,
                                         contributions)
    there = there_vetter.vet(cells, VETTING)

    if there.deny:
        return [f"boundary: checker denied — {[f.detail for f in there.findings]}"]
    if not here.suppress.equals(there.suppress):
        return [f"boundary: in-process and out-of-process decisions differ "
                f"(in {here.suppress.tolist()}, out {there.suppress.tolist()})"]
    print(f"boundary: checker {there_vetter.version} agrees in and out of "
          f"process over {len(cells)} cell(s)")
    return []


def classify(standin: str, acro_rule: str) -> str:
    acro = "release" if acro_rule == "ok" else "suppress"
    if standin == "release":
        return "agree_release" if acro == "release" else "acro_stricter"
    return "standin_stricter" if acro == "release" else "agree_suppress"


def iter_specs(attacks: list) -> list[tuple[str, dict]]:
    """(scenario_name, spec_dict) for every service-path step, with model
    specs expanded to their planned aggregates."""
    out = []
    for atk in attacks:
        if atk.get("path") != "service":
            continue
        for i, step in enumerate(atk["steps"]):
            out.append((f"{atk['name']}[{i}]", step["spec"]))
    return out


def main() -> int:
    # the demo dataset, whether it has been written out or not: `data/` is not
    # in the repository, so CI generates it — with the same seed and size
    # `scripts/make_data.py` uses, or the published numbers would describe a
    # dataset nobody else can reproduce
    tables = (synth.load_csvs()
              if os.path.isdir("data") and os.listdir("data")
              else synth.generate(seed=DEMO_SEED, n_donors=DEMO_DONORS))
    engine = QueryEngine(tables)
    policy = DisclosurePolicy()
    attacks = yaml.safe_load(open(os.path.join(HERE, "attacks.yaml")))

    rows, errors = [], verify_boundary(engine)
    for name, raw in iter_specs(attacks) + FIXTURES:
        # model specs expand to their planned design-cell aggregates — the
        # exact frames _handle_model vets one by one (P19)
        if isinstance(raw, dict) and "tool" in raw:
            proc = model_registry().get(raw.get("tool"))
            try:
                spec_obj = proc.validate(raw)
                aggs = proc.plan_aggregates(spec_obj)
            except Exception as exc:            # noqa: BLE001
                rows.append({"scenario": name, "cell": "-", "standin": "-",
                             "acro": "-", "acro_rules": "-",
                             "classification": "not_comparable",
                             "reason": f"validation_refused: {exc}"})
                continue
            specs = [(f"{name}/{role}", a) for role, a in
                     zip(proc.table_roles(spec_obj), aggs, strict=True)]
        else:
            try:
                specs = [(name, QuerySpec(**raw))]
            except Exception as exc:            # noqa: BLE001
                rows.append({"scenario": name, "cell": "-", "standin": "-",
                             "acro": "-", "acro_rules": "-",
                             "classification": "not_comparable",
                             "reason": f"validation_refused: {exc}"})
                continue

        for sub_name, spec in specs:
            if spec.measure.fn == "corr":
                rows.append({"scenario": sub_name, "cell": "-", "standin": "-",
                             "acro": "-", "acro_rules": "-",
                             "classification": "not_comparable",
                             "reason": "corr/influence has no ACRO analogue (D6)"})
                continue
            try:
                standin = standin_decisions(engine, policy, spec)
                # the ACRO side now goes through the CellVetter seam; the
                # stand-in side stays at POLICY level because complementary
                # suppression is part of the gateway being compared, not of
                # its per-cell rules
                acro = AcroVetter(engine.contributions(spec), spec.group_by,
                                  AGGFUNC.get(spec.measure.fn)).decisions()
            except Exception as exc:            # noqa: BLE001
                errors.append(f"{sub_name}: {exc!r}")
                continue
            for cell, decision in sorted(standin.items()):
                rule = acro.get(cell)
                if rule is None:
                    errors.append(f"{sub_name}: cell {cell} missing from ACRO outcome")
                    continue
                rows.append({"scenario": sub_name, "cell": "|".join(cell),
                             "standin": decision, "acro":
                             "release" if rule == "ok" else "suppress",
                             "acro_rules": rule, "classification":
                             classify(decision, rule), "reason": ""})

    with open(OUT_CSV, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "scenario", "cell", "standin", "acro", "acro_rules",
            "classification", "reason"])
        writer.writeheader()
        writer.writerows(rows)

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1
    from importlib.metadata import version
    print(f"\nacro {version('acro')} vs stand-in DisclosurePolicy")
    print(f"dataset: {len(tables['donors'])} donors, {len(tables['events'])} events")
    print(f"cells compared: {sum(v for k, v in counts.items() if k != 'not_comparable')}")
    for k in ("agree_release", "agree_suppress", "acro_stricter",
              "standin_stricter", "not_comparable"):
        print(f"{k:18s}: {counts.get(k, 0)}")
    for r in rows:
        if r["classification"] == "acro_stricter":
            print(f"  ACRO STRICTER: {r['scenario']} cell={r['cell']} "
                  f"rules={r['acro_rules']}")
    print(f"results -> {OUT_CSV}")

    if errors:
        print(f"\n{len(errors)} harness error(s) — the comparison is incomplete:")
        for e in errors:
            print(f"  ERROR: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
