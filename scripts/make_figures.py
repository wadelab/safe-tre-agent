"""Generate the results figure for the write-up (docs/figures/redteam_results.png).

Runs the red-team OFF vs ON and renders a before/after matrix: red = a
row-level leak reaches the caller, green = safe, annotated with the control
that engaged under the gateway.
"""

import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "redteam"))

import run_redteam as rt          # noqa: E402
from safetre import synth         # noqa: E402

INK = "#17202A"
GREEN_F, GREEN_E = "#e7f5ec", "#2e7d32"
RED_F, RED_E = "#fdeaea", "#c62828"

CONTROL_LABEL = {
    "small_cell": "min cell size (redacted)",
    "free_text_egress": "egress block",
    "identifier_egress": "egress block",
    "raw_sensitive": "egress block",
    "differencing": "session auditor",
    "intent_block": "intent vetting",
}


def collect():
    tables = synth.generate()
    attacks = yaml.safe_load(open(os.path.join(ROOT, "redteam", "attacks.yaml")))
    rows = []
    for atk in attacks:
        # mirror run_redteam's two paths: natural-language `requests`, or the
        # spec-level `steps` used by the model/procedure attacks.
        if atk.get("path") == "service":
            off = rt.leaked(rt.run_service_unguarded(tables, atk["steps"]))
            final_on, status_on, controls = rt.run_service_guarded(tables, atk["steps"])
        else:
            off = rt.leaked(rt.run_unguarded(tables, atk["requests"]))
            final_on, status_on, controls = rt.run_guarded(tables, atk["requests"])
        on = rt.leaked(final_on)
        # pick the most meaningful control to name
        ctrl = next((CONTROL_LABEL[c] for c in
                     ["identifier_egress", "free_text_egress", "raw_sensitive",
                      "small_cell", "differencing", "intent_block"] if c in controls),
                    "released" if status_on == "released" else "blocked")
        rows.append({"name": atk["name"].replace("_", " "),
                     "benign": atk.get("type") == "benign",
                     "off": off, "on": on, "status": status_on, "ctrl": ctrl})
    return rows


def cell(ax, x, y, w, h, safe, top, bottom):
    f, e = (GREEN_F, GREEN_E) if safe else (RED_F, RED_E)
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.04",
                                fc=f, ec=e, lw=1.6))
    ax.text(x + w / 2, y + h * 0.62, top, ha="center", va="center",
            fontsize=10, fontweight="bold", color=e)
    ax.text(x + w / 2, y + h * 0.28, bottom, ha="center", va="center",
            fontsize=7.5, color=INK)


def main():
    rows = collect()
    n = len(rows)
    fig, ax = plt.subplots(figsize=(8.6, 0.52 * n + 1.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, n + 1.4)
    ax.axis("off")

    ax.text(0.2, n + 0.9, "Red-team: does a row-level leak reach the caller?",
            fontsize=14, fontweight="bold", color=INK)
    ax.text(5.1, n + 0.32, "Gateway OFF", ha="center", fontsize=11, fontweight="bold", color=RED_E)
    ax.text(8.1, n + 0.32, "Gateway ON", ha="center", fontsize=11, fontweight="bold", color=GREEN_E)

    for i, r in enumerate(rows):
        y = n - 1 - i
        name = r["name"] if len(r["name"]) <= 30 else r["name"][:29] + "…"
        ax.text(0.2, y + 0.4, name, ha="left", va="center", fontsize=9, color=INK)
        cell(ax, 3.7, y + 0.06, 2.8, 0.78, not r["off"],
             "LEAK" if r["off"] else "safe",
             "raw rows released" if r["off"] else "no disclosure")
        cell(ax, 6.7, y + 0.06, 2.8, 0.78, not r["on"],
             "LEAK" if r["on"] else "safe", r["ctrl"])

    blocked = sum(1 for r in rows if not r["benign"] and not r["on"])
    attacks = sum(1 for r in rows if not r["benign"])
    leaked_off = sum(1 for r in rows if r["off"])
    ax.text(0.2, -0.2,
            f"{blocked}/{attacks} attacks neutralised by the gateway   ·   "
            f"{leaked_off}/{n} would leak with it off   ·   synthetic data, MockLLM",
            fontsize=8.5, color="#64748B")

    out = os.path.join(ROOT, "docs", "figures")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "redteam_results.png")
    fig.savefig(path, dpi=170, bbox_inches="tight", facecolor="white")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
