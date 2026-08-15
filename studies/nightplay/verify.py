"""Check that the NIGHTPLAY truths are recoverable THROUGH the gateway, and
that its traps are caught by it.

The generator writes what is true of the unvetted rows. That is not yet
evidence the study justifies an inside analyst: the disclosure controls
could suppress the very cells that carry the signal, and then the dataset
would be rich on disk and empty at the boundary. So this script plays the
reference analyst — literal QuerySpecs, no planner, the same QueryService
and DisclosurePolicy the web app builds — and marks the released frames
against `nightplay_ground_truth.json`:

  T1  released mean stake by night_use_band is monotone increasing
  T2  the GLM adjusted for employment shrinks the heavy-vs-rare effect but
      keeps it positive
  T3  the planted null is flat in the released means; the released corr is ~0
  T4  casino and slots rise heavy-vs-rare far more than lottery
  T5  the released stake-by-month peaks in 6/7; late_night is the largest hour band
  T6  released PGSI rises wave 1 -> 3 for heavy, not for rare; sleep falls by band
  A3  the whale cell is suppressed (dominance)
  A5  the sub-threshold subgroups are suppressed / the totals do not leak them
  A6  no hostile string appears in any released frame

Every check reads only what the gateway RELEASED. Exit status is nonzero on
any failure. Usage:

    uv run python studies/nightplay/verify.py [--data data] [--json out.json]

The test suite calls `run()` on a freshly generated small population.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from safetre import dataset as dataset_mod          # noqa: E402
from safetre.config import load_policy_config      # noqa: E402
from safetre.disclosure import DisclosurePolicy, build_vetter  # noqa: E402
from safetre.service import QueryService           # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFINITION = os.path.join(HERE, "nightplay.yaml")
BANDS = ["rare", "occasional", "regular", "heavy"]


def build_service(tables: dict[str, pd.DataFrame]) -> QueryService:
    """The web app's own policy construction (safetre_web/app.py), so the
    verdicts here are the verdicts a real session would get."""
    cfg = load_policy_config()
    policy = DisclosurePolicy(
        threshold=cfg.min_cell_size, max_rows=cfg.max_output_rows,
        dom_threshold=cfg.dom_threshold, influence_threshold=cfg.influence_threshold,
        round_base=cfg.round_base, moment2_dom_threshold=cfg.moment2_dom_threshold,
        vetter=build_vetter(cfg.vetter, cfg.checker_cmd))
    return QueryService(tables, policy)


class Reference:
    """The reference analyst: literal specs through `QueryService.handle`."""

    def __init__(self, service: QueryService):
        self.service = service
        self.log: list[dict] = []

    def ask(self, spec: dict):
        res = self.service.handle(json.dumps(spec), planner=None)
        self.log.append({"spec": spec, "status": res.status,
                         "findings": [getattr(f, "rule", str(f)) for f in res.findings]})
        return res

    def mean_by(self, dataset: str, column: str, group_by: list[str], filters=()) -> pd.Series | None:
        res = self.ask({"dataset": dataset, "measure": {"fn": "mean", "column": column},
                        "group_by": group_by, "filters": list(filters)})
        if res.output is None or res.status == "denied":
            return None
        out = res.output
        key = group_by[0] if len(group_by) == 1 else group_by
        val = "value" if "value" in out.columns else column
        if len(group_by) == 1:
            return out.set_index(key)[val]
        return out.set_index(key)[val]


def _released_value_col(out: pd.DataFrame) -> str:
    for c in ("value", "mean", "sum", "corr"):
        if c in out.columns:
            return c
    return [c for c in out.columns if c not in ("n",)][-1]


def run(tables: dict[str, pd.DataFrame], truth: dict, verbose: bool = True) -> dict:
    """Return a report dict {ok, checks: [...], releases: [...]}."""
    defn = dataset_mod.load_dataset(DEFINITION)
    previous = dataset_mod.active()
    dataset_mod.activate(defn)
    try:
        return _run(tables, truth, verbose)
    finally:
        dataset_mod.activate(previous)


def _run(tables, truth, verbose) -> dict:
    ref = Reference(build_service(tables))
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        if verbose:
            print(f"  [{'ok ' if ok else 'FAIL'}] {name}: {detail}")

    # ---- T1 dose-response --------------------------------------------------
    r = ref.ask({"dataset": "panel", "measure": {"fn": "mean", "column": "stake_gbp"},
                 "group_by": ["night_use_band"], "filters": []})
    if r.status in ("released", "redacted") and r.output is not None:
        v = r.output.set_index("night_use_band")[_released_value_col(r.output)].reindex(BANDS)
        mono = all(v[a] < v[b] for a, b in zip(BANDS, BANDS[1:]))
        check("T1 released mean stake by band is monotone", mono,
              " < ".join(f"{b}={v[b]:.2f}" for b in BANDS))
    else:
        check("T1 released mean stake by band is monotone", False, f"status={r.status}")

    # ---- T2 confounding: GLM with and without employment -------------------
    def glm_heavy_effect(terms: list[str]) -> float | None:
        r = ref.ask({"tool": "glm", "dataset": "panel", "family": "gaussian",
                     "response": "stake_gbp", "terms": terms,
                     "filters": [{"column": "employment", "op": "!=", "value": "armed_forces"}]})
        if r.status != "released" or r.output is None:
            return None
        coef = r.output
        row = coef[(coef["term"] == "night_use_band") & (coef["level"] == "heavy")]
        base = coef[(coef["term"] == "night_use_band") & (coef["level"] == "rare")]
        if row.empty:
            return None
        est = float(row["estimate"].iloc[0])
        return est - (float(base["estimate"].iloc[0]) if not base.empty else 0.0)

    unadj = glm_heavy_effect(["night_use_band"])
    adj = glm_heavy_effect(["night_use_band", "employment"])
    if unadj is None or adj is None:
        check("T2 adjusted GLM shrinks the effect", False,
              f"unadjusted={unadj} adjusted={adj} (a model was denied)")
    else:
        check("T2 adjusted GLM shrinks the effect but keeps it positive",
              adj > 0 and adj < unadj,
              f"heavy-vs-rare unadjusted={unadj:.2f} adjusted={adj:.2f} "
              f"(oracle naive={truth['truths']['T2_confounding']['naive_heavy_minus_rare']}, "
              f"adjusted={truth['truths']['T2_confounding']['adjusted_heavy_minus_rare']})")

    # ---- T3 planted null -----------------------------------------------------
    r = ref.ask({"dataset": "panel", "measure": {"fn": "mean", "column": "donation_gbp"},
                 "group_by": ["night_use_band"], "filters": []})
    if r.output is not None and r.status != "denied":
        v = r.output.set_index("night_use_band")[_released_value_col(r.output)].reindex(BANDS)
        spread = float((v.max() - v.min()) / v.mean())
        check("T3 released donation by band is flat (spread < 20% of mean)", spread < 0.20,
              ", ".join(f"{b}={v[b]:.2f}" for b in BANDS) + f"; spread={spread:.1%}")
    else:
        check("T3 released donation by band is flat", False, f"status={r.status}")
    r = ref.ask({"dataset": "panel", "measure": {"fn": "corr", "column": None,
                                                 "x": "late_night_sessions", "y": "donation_gbp"},
                 "group_by": [], "filters": []})
    if r.output is not None and r.status != "denied":
        c = float(r.output[_released_value_col(r.output)].iloc[0])
        check("T3 released corr(late-night sessions, donation) ~ 0", abs(c) < 0.05, f"r={c:.3f}")
    else:
        check("T3 released corr(late-night sessions, donation) ~ 0", False, f"status={r.status}")
    r = ref.ask({"dataset": "panel", "measure": {"fn": "corr", "column": None,
                                                 "x": "late_night_sessions", "y": "stake_gbp"},
                 "group_by": [], "filters": []})
    if r.output is not None and r.status != "denied":
        c = float(r.output[_released_value_col(r.output)].iloc[0])
        # small on purpose: the panel is zero-inflated and heavy-tailed, so
        # the linear correlation understates a five-fold banded effect — a
        # lesson the question bank asks the analyst to notice
        check("T1 released corr(late-night sessions, stake) is positive (> 0.05)", c > 0.05,
              f"r={c:.3f} (weak by design; the banded comparison is the sharper instrument)")

    # ---- T4 heterogeneity ------------------------------------------------------
    r = ref.ask({"dataset": "bets", "measure": {"fn": "mean", "column": "stake_gbp"},
                 "group_by": ["product", "night_use_band"], "filters": []})
    if r.output is not None and r.status != "denied":
        out = r.output
        vc = _released_value_col(out)
        ratio = {}
        for p in ("casino", "slots", "lottery"):
            sub = out[out["product"] == p].set_index("night_use_band")[vc]
            if "heavy" in sub.index and "rare" in sub.index:
                ratio[p] = float(sub["heavy"] / sub["rare"])
        ok = (ratio.get("casino", 0) > 1.2 and ratio.get("slots", 0) > 1.2
              and ratio.get("lottery", 9) < 1.2)
        check("T4 casino/slots heavy:rare ratio > 1.2, lottery < 1.2", ok,
              ", ".join(f"{k}={v:.2f}" for k, v in ratio.items()))
    else:
        check("T4 heterogeneity", False, f"status={r.status}")

    # ---- T5 time structure ----------------------------------------------------
    r = ref.ask({"dataset": "bets", "measure": {"fn": "mean", "column": "stake_gbp"},
                 "group_by": ["month"], "filters": []})
    if r.output is not None and r.status != "denied":
        v = r.output.set_index("month")[_released_value_col(r.output)]
        peak = int(v.idxmax())
        check("T5 released stake-by-month peaks in June/July", peak in (6, 7), f"argmax month={peak}")
    r = ref.ask({"dataset": "bets", "measure": {"fn": "mean", "column": "stake_gbp"},
                 "group_by": ["hour_band"], "filters": []})
    if r.output is not None and r.status != "denied":
        v = r.output.set_index("hour_band")[_released_value_col(r.output)]
        check("T5 late_night is the largest hour band", v.idxmax() == "late_night",
              ", ".join(f"{k}={x:.2f}" for k, x in v.items()))

    # ---- T6 longitudinal ------------------------------------------------------
    r = ref.ask({"dataset": "wellbeing", "measure": {"fn": "mean", "column": "pgsi_score"},
                 "group_by": ["night_use_band", "wave"], "filters": []})
    if r.output is not None and r.status != "denied":
        out = r.output
        vc = _released_value_col(out)
        def w(b, wave):
            s = out[(out["night_use_band"] == b) & (out["wave"] == wave)][vc]
            return float(s.iloc[0]) if len(s) else float("nan")
        heavy_rise = w("heavy", 3) - w("heavy", 1)
        rare_rise = w("rare", 3) - w("rare", 1)
        check("T6 PGSI rises wave1->3 for heavy (>1) not rare (<0.5)",
              heavy_rise > 1.0 and abs(rare_rise) < 0.5,
              f"heavy +{heavy_rise:.2f}, rare {rare_rise:+.2f}")
    r = ref.ask({"dataset": "wellbeing", "measure": {"fn": "mean", "column": "sleep_quality"},
                 "group_by": ["night_use_band"], "filters": []})
    if r.output is not None and r.status != "denied":
        v = r.output.set_index("night_use_band")[_released_value_col(r.output)].reindex(BANDS)
        check("T6 sleep quality falls with night use", bool(v["heavy"] < v["rare"]),
              ", ".join(f"{b}={v[b]:.2f}" for b in BANDS))

    # ---- A3 whale: sum stake by region x product -----------------------------
    wh = truth["adversarial"].get("whale")
    r = ref.ask({"dataset": "bets", "measure": {"fn": "sum", "column": "stake_gbp"},
                 "group_by": ["region", "product"], "filters": []})
    if wh and r.output is not None:
        out = r.output
        hit = out[(out["region"] == wh["region"]) & (out["product"] == wh["product"])]
        check("A3 the whale cell is not released as a value",
              hit.empty or hit[_released_value_col(out)].isna().all() or r.status == "denied",
              f"status={r.status}; whale cell rows released={len(hit)}")

    # ---- A5 sub-threshold subgroups ------------------------------------------
    r = ref.ask({"dataset": "panel", "measure": {"fn": "count", "column": None},
                 "group_by": ["region"], "filters": []})
    if r.output is not None:
        out = r.output
        ni = out[out["region"] == "Northern Ireland"]
        released_n = ni["n"] if "n" in out.columns else pd.Series(dtype=float)
        check("A5 Northern Ireland (8 people) is not released with a count",
              ni.empty or released_n.isna().all(), f"status={r.status}; NI rows={len(ni)}")
    r = ref.ask({"dataset": "panel", "measure": {"fn": "mean", "column": "stake_gbp"},
                 "group_by": ["employment"], "filters": []})
    if r.output is not None:
        out = r.output
        af = out[out["employment"] == "armed_forces"]
        vc = _released_value_col(out)
        check("A5 armed_forces (6 people) mean is not released",
              af.empty or af[vc].isna().all(), f"status={r.status}; rows={len(af)}")

    # ---- A6 hostile strings never released -----------------------------------
    hostile = [s for vals in truth["adversarial"]["hostile_values"].values() for s in vals]
    r = ref.ask({"dataset": "sessions", "measure": {"fn": "count", "column": None},
                 "group_by": ["app_category"], "filters": []})
    leaked = []
    frames = [r.output] if r.output is not None else []
    r2 = ref.ask({"dataset": "panel", "measure": {"fn": "count", "column": None},
                  "group_by": ["region"], "filters": []})
    if r2.output is not None:
        frames.append(r2.output)
    for fr in frames:
        text = fr.to_csv(index=False)
        leaked += [h for h in hostile if h in text]
    check("A6 no hostile string appears in a released frame", not leaked,
          f"leaked={leaked[:2]}" if leaked else "none of "
          f"{len(hostile)} payloads released")

    ok = all(c["ok"] for c in checks)
    return {"ok": ok, "checks": checks, "releases": ref.log}


def load_tables(data_dir: str) -> tuple[dict[str, pd.DataFrame], dict]:
    from studies.nightplay.generate import MANIFEST_NAME, TABLE_NAMES
    tables = {name: pd.read_csv(os.path.join(data_dir, f"{name}.csv")) for name in TABLE_NAMES}
    with open(os.path.join(data_dir, MANIFEST_NAME)) as fh:
        truth = json.load(fh)
    return tables, truth


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", default="data")
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()
    tables, truth = load_tables(args.data)
    print(f"nightplay verify: {truth['n_people']} people, seed {truth['seed']}")
    report = run(tables, truth)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
    n_ok = sum(c["ok"] for c in report["checks"])
    print(f"{n_ok}/{len(report['checks'])} checks passed; "
          f"{len(report['releases'])} requests through the gateway")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
