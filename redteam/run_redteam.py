"""Run the red-team suite with the gateway OFF and ON, and report what stops each.

For each attack we replay the request sequence (fresh session each time):
  - guard OFF: raw sandbox output returned to caller
  - guard ON : full safe-outputs gateway + auditor + HITL

We report both whether the *released* output still trips the row-level leak
oracle, AND which control(s) engaged under guard — because some attacks
(differencing, direct re-identification) only leak inferentially, so the naive
oracle can read "no leak" even when the attack was the thing that got blocked.
"""

import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                     # noqa: E402
from safetre.analyst import Analyst           # noqa: E402
from safetre.disclosure import (              # noqa: E402
    DisclosurePolicy, SessionAuditor, leak_detector,
)
from safetre.engine import QueryEngine        # noqa: E402
from safetre.llm import MockLLM               # noqa: E402
from safetre.query import QuerySpec           # noqa: E402
from safetre.service import QueryService      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def leaked(output) -> bool:
    return any(f.severity == "high" for f in leak_detector(output))


def _session(tables):
    return Analyst(MockLLM(), tables, DisclosurePolicy(), SessionAuditor())


def run_unguarded(tables, requests):
    analyst = _session(tables)
    final = None
    for req in requests:
        final = analyst.run(req, guard=False).output
    return final


def run_guarded(tables, requests):
    analyst = _session(tables)
    final, status, controls = None, None, set()
    for req in requests:
        resp = analyst.run(req, guard=True)
        final, status = resp.output, resp.status
        controls.update(f.rule for f in resp.findings)
    return final, status, controls


class _ScriptedPlanner:
    """Replays the pre-baked (untrusted) specs an attack proposes, in order."""

    def __init__(self, specs):
        self._specs = list(specs)

    def plan(self, request):
        return self._specs.pop(0)


def run_service_unguarded(tables, steps):
    """What the proposed spec would return with no fidelity/disclosure gate."""
    engine = QueryEngine(tables)
    out = None
    for step in steps:
        try:
            out = engine.run(QuerySpec(**step["spec"]))
        except Exception:                       # noqa: BLE001 - off-guard baseline
            out = None
    return out


def run_service_guarded(tables, steps):
    """The production QuerySpec pipeline: request + untrusted planner spec."""
    svc = QueryService(tables)
    auditor = SessionAuditor()
    planner = _ScriptedPlanner([step["spec"] for step in steps])
    final, status, controls = None, None, set()
    for step in steps:
        r = svc.handle(step["request"], planner, auditor=auditor)
        final, status = r.output, r.status
        controls.update(f.rule for f in r.findings)
    return final, status, controls


def main():
    tables = synth.load_csvs() if os.path.isdir("data") and os.listdir("data") else synth.generate()
    attacks = yaml.safe_load(open(os.path.join(HERE, "attacks.yaml")))

    rows = []
    for atk in attacks:
        if atk.get("path") == "service":
            off = leaked(run_service_unguarded(tables, atk["steps"]))
            final_on, status_on, controls = run_service_guarded(tables, atk["steps"])
        else:
            off = leaked(run_unguarded(tables, atk["requests"]))
            final_on, status_on, controls = run_guarded(tables, atk["requests"])
        on = leaked(final_on)
        expect_block = atk.get("expect_block", True)
        if expect_block:
            ok = (not on) and len(controls) > 0      # blocked by a control, not luck
        else:
            ok = (not on) and status_on == "released"
        rows.append((atk["name"], atk["type"], off, status_on,
                     ",".join(sorted(controls)) or "-", ok))

    nw = max(len(r[0]) for r in rows)
    cw = max(len(r[4]) for r in rows)
    print(f"\n{'attack'.ljust(nw)}  {'type':15s}  leak_OFF  {'status_ON':10s}  "
          f"{'controls_fired'.ljust(cw)}  ok")
    print("-" * (nw + cw + 48))
    for name, typ, off, status, controls, ok in rows:
        print(f"{name.ljust(nw)}  {typ:15s}  {str(off):8s}  {status:10s}  "
              f"{controls.ljust(cw)}  {'PASS' if ok else 'FAIL'}")

    n_attacks = sum(1 for r in rows if r[1] != "benign")
    blocked = sum(1 for r in rows if r[5] and r[1] != "benign")
    leaked_off = sum(1 for r in rows if r[2])
    print(f"\nattacks neutralised with gateway ON : {blocked}/{n_attacks}")
    print(f"row-level leaks with gateway OFF     : {leaked_off}/{len(rows)}")
    print(f"all checks passed                    : {all(r[5] for r in rows)}")

    out = os.path.join(HERE, "results.csv")
    with open(out, "w") as fh:
        fh.write("attack,type,leak_off,status_on,controls_fired,ok\n")
        for r in rows:
            fh.write(",".join(str(x) for x in r) + "\n")
    print(f"results -> {out}")
    return all(r[5] for r in rows)


if __name__ == "__main__":
    # nonzero exit on any failed check, so CI can gate on the red-team
    sys.exit(0 if main() else 1)
