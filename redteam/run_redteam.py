"""Run the red-team suite with the gateway OFF and ON, and report what leaked.

For each attack we replay the request sequence (fresh session each time):
  - guard OFF: raw sandbox / raw engine output returned to caller
  - guard ON : full safe-outputs gateway + auditor + HITL

**The verdict is about disclosure, not about activity.** This harness used to
pass an attack when `(nothing looked wrong in the final frame) and (at least one
control fired)`. Both halves were broken. `leak_detector` on a finalized frame
has nothing left to test — the dominance, influence and donor-count columns are
dropped and the counts rounded before release — so the first half was vacuously
true, and the second could be supplied by the attacker: a three-step session
that recovered one donor's exact spend reported PASS as soon as an unrelated
over-granular query was appended, because that decoy tripped `small_cell` and
`dominance`.

So the oracle now lives in `redteam/oracle.py`, is computed from the row-level
data rather than from the gateway's own reasoning, watches EVERY step rather
than the last, and asks what the released outputs *combine* into. An attack
passes when the session disclosed nothing — whether or not a control announced
itself. Which controls fired is still reported, because "blocked, or merely
lucky" is worth seeing, and a `expect_block` attack that leaks nothing while
firing no control is called out as UNGUARDED rather than counted as a defence.
"""

import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                     # noqa: E402
from safetre.disclosure import (              # noqa: E402
    DisclosurePolicy, SessionAuditor, leak_detector,
)
from safetre.engine import QueryEngine        # noqa: E402
from safetre.llm import MockLLM               # noqa: E402
from safetre.procedures import model_registry  # noqa: E402
from safetre.query import QuerySpec           # noqa: E402
from safetre.service import QueryService      # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures                               # noqa: E402
from legacy.sandbox import Analyst            # noqa: E402
from oracle import SessionOracle              # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def leaked(output) -> bool:
    """The row-level check, kept ONLY for the guard-OFF baseline.

    Off-guard output is raw — un-aggregated rows, identifier columns, exact
    counts — so the row-level rules do have something to test there, and the
    baseline column answers "would this have leaked without the gateway?".
    It is deliberately not used to judge guarded output; see the module note.
    """
    return any(f.severity == "high" for f in leak_detector(output))


def _session(tables):
    """The legacy code-writing path (`redteam/legacy/`), NOT a shipped component.

    Its `guard=True` is not a security bar and this table must not be read as
    saying it is: `static_check` is a denylist and `np.memmap` walks past it
    (`tests/test_legacy_sandbox.py` pins the bypass). What the OFF/ON comparison
    legitimately measures on this path is the *disclosure gateway* — the same
    thresholds, dominance and suppression the secure path uses — running behind
    a sandbox that cannot be trusted to stop code from reaching a file.
    """
    return Analyst(MockLLM(), tables, DisclosurePolicy(), SessionAuditor())


def run_unguarded(tables, requests):
    analyst = _session(tables)
    final = None
    for req in requests:
        final = analyst.run(req, guard=False).output
    return final


def run_guarded(tables, requests):
    """The analyst path, with the oracle watching every step."""
    analyst = _session(tables)
    oracle = SessionOracle(tables)
    final, status, controls = None, None, set()
    for step, req in enumerate(requests, 1):
        resp = analyst.run(req, guard=True)
        final, status = resp.output, resp.status
        controls.update(f.rule for f in resp.findings)
        if resp.status in ("released", "redacted"):
            # no QuerySpec on this path, so the oracle checks egress and
            # released values rather than cohort composition
            oracle.observe(step, None, resp.output)
    return final, status, controls, oracle.findings()


class _ScriptedPlanner:
    """Replays the pre-baked (untrusted) specs an attack proposes, in order."""

    def __init__(self, specs):
        self._specs = list(specs)

    def plan(self, request):
        return self._specs.pop(0)


def run_service_unguarded(tables, steps):
    """What the proposed spec would return with no fidelity/disclosure gate.

    For a model spec the baseline is its raw design-cell tables straight off
    the engine — unrounded, unsuppressed, safety helpers attached — i.e. what
    a fit would consume if the gateway did not sit in front of it.
    """
    engine = QueryEngine(tables)
    out = None
    for step in steps:
        try:
            spec = step["spec"]
            if isinstance(spec, dict) and "tool" in spec:
                proc = model_registry()[spec["tool"]]
                for agg in proc.plan_aggregates(proc.validate(spec)):
                    out = engine.run(agg)
            else:
                out = engine.run(QuerySpec(**spec))
        except Exception:                       # noqa: BLE001 - off-guard baseline
            out = None
    return out


def run_service_guarded(tables, steps):
    """The production QuerySpec pipeline, with the oracle watching every step."""
    svc = QueryService(tables)
    auditor = SessionAuditor()
    oracle = SessionOracle(tables)
    planner = _ScriptedPlanner([step["spec"] for step in steps])
    final, status, controls = None, None, set()
    for step_no, step in enumerate(steps, 1):
        r = svc.handle(step["request"], planner, auditor=auditor)
        final, status = r.output, r.status
        controls.update(f.rule for f in r.findings)
        if r.status in ("released", "redacted"):
            oracle.observe(step_no, r.spec, r.output)
            # a model also releases its vetted cell table and summary block
            for frame in (r.artifacts or {}).values():
                oracle.observe(step_no, r.spec, frame)
    return final, status, controls, oracle.findings()


def main():
    tables = synth.load_csvs() if synth.csvs_present() else synth.generate()
    attacks = yaml.safe_load(open(os.path.join(HERE, "attacks.yaml")))

    rows, details = [], {}
    built: dict = {}
    for atk in attacks:
        # an attack may ask for hostile data (`fixture: adversarial`); the
        # build is cached, since it is the same tables for every entry
        name = atk.get("fixture", "default")
        if name not in built:
            built[name] = fixtures.load(name, tables)
        data = built[name]

        if atk.get("path") == "service":
            off = leaked(run_service_unguarded(data, atk["steps"]))
            _, status_on, controls, leaks = run_service_guarded(data, atk["steps"])
        else:
            off = leaked(run_unguarded(data, atk["requests"]))
            _, status_on, controls, leaks = run_guarded(data, atk["requests"])

        expect_block = atk.get("expect_block", True)
        # The verdict is disclosure, not activity: an attack passes when the
        # session gave nothing away. A benign entry must additionally have been
        # answered, or the suite would "pass" by refusing everything.
        ok = not leaks if expect_block else (not leaks and status_on == "released")
        # an attack that leaked nothing while no control engaged was not
        # defended, it just missed; say so rather than bank it as protection
        unguarded = expect_block and not leaks and not controls
        rows.append((atk["name"], atk["type"], off, status_on,
                     ",".join(sorted(controls)) or "-", len(leaks),
                     "UNGUARDED" if unguarded else ("PASS" if ok else "FAIL")))
        if leaks:
            details[atk["name"]] = leaks

    nw = max(len(r[0]) for r in rows)
    cw = max(len(r[4]) for r in rows)
    print(f"\n{'attack'.ljust(nw)}  {'type':15s}  leak_OFF  {'status_ON':10s}  "
          f"{'controls_fired'.ljust(cw)}  leaks  verdict")
    print("-" * (nw + cw + 56))
    for name, typ, off, status, controls, n_leaks, verdict in rows:
        print(f"{name.ljust(nw)}  {typ:15s}  {str(off):8s}  {status:10s}  "
              f"{controls.ljust(cw)}  {n_leaks:5d}  {verdict}")

    for name, leaks in details.items():
        print(f"\n{name} disclosed:")
        for leak in leaks[:8]:
            print(f"  - {leak}")
        if len(leaks) > 8:
            print(f"  ... and {len(leaks) - 8} more")

    n_attacks = sum(1 for r in rows if r[1] != "benign")
    blocked = sum(1 for r in rows if r[6] == "PASS" and r[1] != "benign")
    unguarded = sum(1 for r in rows if r[6] == "UNGUARDED")
    leaked_off = sum(1 for r in rows if r[2])
    ok = all(r[6] != "FAIL" for r in rows)
    print(f"\nattacks that disclosed nothing        : {blocked}/{n_attacks}")
    if unguarded:
        print(f"  of which no control engaged         : {unguarded} "
              f"(not defended — see UNGUARDED above)")
    print(f"row-level leaks with gateway OFF      : {leaked_off}/{len(rows)}")
    print(f"sessions that disclosed something     : {len(details)}")
    print(f"all checks passed                     : {ok}")

    out = os.path.join(HERE, "results.csv")
    with open(out, "w") as fh:
        fh.write("attack,type,leak_off,status_on,controls_fired,leaks,verdict\n")
        for r in rows:
            fh.write(",".join(str(x) for x in r) + "\n")
    print(f"results -> {out}")
    return ok


if __name__ == "__main__":
    # nonzero exit on any failed check, so CI can gate on the red-team
    sys.exit(0 if main() else 1)
