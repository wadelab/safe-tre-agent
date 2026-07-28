"""Round-9 reproducers: the four confirmed findings of `round9_report.md`.

Same contract as `round8_repro.py`. Each check prints VULNERABLE or FIXED and
the script exits nonzero while anything is still vulnerable, so it gates the
work and then keeps gating it: these are regression checks, not a one-off
demonstration.

All four live in the state-accounting and restart paths that hardening #49
introduced, which is the surface no prior round had attacked. The report's
closing note asked for them to be promoted here once the fixes landed
(#58, #59, #60); this is that.

What each check asserts, in the language of the attack rather than the fix:

  V1  spend the budget on models, restart, and see whether the session comes
      back with the spend it actually made — a refund is a doubled budget on
      the control that bounds accumulation;
  V2  fit a binomial, restart, and see whether the successes cohort — whose
      filter the PROCEDURE adds and the model spec cannot express — is still
      in the lineage;
  V3  delete one row of the log (write access, no key), restart, and see
      whether the rebuild notices. Dropping a cohort is the unsafe direction,
      and `verify()` detected it all along without being asked;
  V4  fail five queries before the engine and see whether they cost anything.

Reads only the synthetic demo data. Writes to a THROWAWAY audit database in a
temporary directory, never the operator's: `SAFETRE_AUDIT_DB` is pinned before
`safetre_web` is imported, because since #55 importing the app appends to
whatever that variable points at (hardening #57 is that mistake).

Usage:
    uv run python redteam/round9_repro.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_TMP = tempfile.mkdtemp(prefix="safetre-round9-")
os.environ["SAFETRE_AUDIT_DB"] = os.path.join(_TMP, "audit.db")
os.environ.setdefault("SAFETRE_AUDIT_KEY", "0" * 64)

from safetre import synth                                        # noqa: E402
from safetre.audit import AuditLog                               # noqa: E402
from safetre.disclosure import SessionAuditor                    # noqa: E402
from safetre.service import QueryService                         # noqa: E402
from safetre_web.session import (                                # noqa: E402
    AuditChainUnverified, SessionStore,
)

THRESHOLD = 10
BUDGET = 20
results: list[tuple[str, bool, str]] = []


def check(name: str, vulnerable: bool, detail: str) -> None:
    results.append((name, vulnerable, detail))
    label = "VULNERABLE" if vulnerable else "FIXED     "
    print(f"  [{label}] {name}\n      {detail}")


def fresh_log(tag: str) -> AuditLog:
    return AuditLog(os.path.join(_TMP, f"{tag}.db"))


def gaussian_glm() -> str:
    return json.dumps({"tool": "glm", "dataset": "donor_spend",
                       "family": "gaussian", "response": "total_spend_gbp",
                       "terms": ["age_band"]})


def binomial_glm() -> str:
    return json.dumps({"tool": "glm", "dataset": "spend", "family": "binomial",
                       "response": "contains_lootboxes", "terms": ["price_tier"]})


# --- V1: the budget must survive a restart at the size it actually was --------

def v1_budget_is_restart_faithful(tables) -> None:
    log = fresh_log("v1")
    svc = QueryService(tables)
    live = SessionStore(threshold=THRESHOLD, budget=BUDGET)
    auditor = live.get("analyst@org").auditor
    r = svc.handle(gaussian_glm(), planner=None, auditor=auditor,
                   audit_log=log, user="analyst@org")
    if r.status != "released":
        check("V1 budget restart-faithful for models", True,
              f"the model did not release ({r.status}); cannot measure")
        return

    after = SessionStore(threshold=THRESHOLD, budget=BUDGET)
    after.rehydrate(log, window_hours=24)
    replayed = after.get("analyst@org").auditor.spent
    check("V1 budget restart-faithful for models", replayed != auditor.spent,
          f"live _spent={auditor.spent}, rehydrated _spent={replayed} "
          f"({'refunded' if replayed < auditor.spent else 'equal'})")


# --- V2: every released cohort survives, including the ones nobody wrote ------

def v2_successes_cohort_survives(tables) -> None:
    log = fresh_log("v2")
    svc = QueryService(tables)
    live = SessionStore(threshold=THRESHOLD, budget=BUDGET)
    auditor = live.get("analyst@org").auditor
    r = svc.handle(binomial_glm(), planner=None, auditor=auditor,
                   audit_log=log, user="analyst@org")
    if r.status != "released":
        check("V2 binomial successes cohort survives restart", True,
              f"the model did not release ({r.status}); cannot measure")
        return

    after = SessionStore(threshold=THRESHOLD, budget=BUDGET)
    after.rehydrate(log, window_hours=24)
    replayed = after.get("analyst@org").auditor._cohorts
    successes = ("spend", (("contains_lootboxes", "==", True),))
    check("V2 binomial successes cohort survives restart",
          successes not in replayed,
          f"live cohorts={len(auditor._cohorts)}, rehydrated={len(replayed)}; "
          f"successes cohort {'present' if successes in replayed else 'LOST'}")


# --- V3: a deleted row must stop the rebuild, not silently shrink it ----------

def v3_deletion_is_refused(tables) -> None:
    log = fresh_log("v3")
    svc = QueryService(tables)
    store = SessionStore(threshold=THRESHOLD, budget=BUDGET)
    auditor = store.get("analyst@org").auditor
    for spec in ({"dataset": "spend", "measure": {"fn": "count"},
                  "group_by": ["age_band"]},
                 {"dataset": "spend", "measure": {"fn": "sum",
                                                  "column": "amount_gbp"},
                  "filters": [{"column": "region", "op": "==",
                               "value": "South West"}]}):
        svc.handle(json.dumps(spec), planner=None, auditor=auditor,
                   audit_log=log, user="analyst@org")
    before = len(auditor._cohorts)

    # the attack: remove the first half of the pair. No forged MAC — a DELETE.
    log.con.execute("DELETE FROM records WHERE id = (SELECT MIN(id) FROM records)")
    log.con.commit()
    detected = not log.verify()

    try:
        rebuilt = SessionStore(threshold=THRESHOLD, budget=BUDGET)
        rebuilt.rehydrate(log, window_hours=24)
        restored = len(rebuilt.get("analyst@org").auditor._cohorts)
        check("V3 deletion defeats the rebuilt lineage", True,
              f"verify()={not detected}, rebuild proceeded and restored "
              f"{restored}/{before} cohorts without objecting")
    except AuditChainUnverified:
        check("V3 deletion defeats the rebuilt lineage", False,
              f"verify() returned False and the rebuild refused to run "
              f"(would otherwise have lost {before - 1}/{before} cohorts)")


# --- V4: a failing query is not a free query ----------------------------------

def v4_errors_cost_budget(tables) -> None:
    class Exploding:
        def plan(self, request):
            raise RuntimeError("planner is down")

    log = fresh_log("v4")
    svc = QueryService(tables)
    store = SessionStore(threshold=THRESHOLD, budget=BUDGET)
    auditor = store.get("analyst@org").auditor
    for _ in range(5):
        svc.handle("mean spend by age band", planner=Exploding(),
                   auditor=auditor, audit_log=log, user="analyst@org")

    after = SessionStore(threshold=THRESHOLD, budget=BUDGET)
    after.rehydrate(log, window_hours=24)
    replayed = after.get("analyst@org").auditor.spent
    check("V4 a pipeline error spends budget",
          auditor.spent == 0 or replayed != auditor.spent,
          f"5 failing queries: live _spent={auditor.spent}, "
          f"rehydrated _spent={replayed}")


def selftest(tables) -> bool:
    """Prove the V1/V2 checks can still report VULNERABLE.

    Hardening #48 is the standing reason for this: a harness that cannot fail
    is not evidence, and four green checks are indistinguishable from four
    checks that stopped looking. So replay a chain shaped like a genuine
    pre-#58 one — valid rows, no `accounting` block — which is exactly what an
    operator's existing log holds and what `_rehydrate_legacy` is kept for.
    The old defect must still be visible there.

    Editing the accounting of a NEW row would not do: it is inside the MAC, so
    the chain stops verifying and #59 refuses the rebuild before #58 is
    reached. The two fixes cover each other, which is why this needs a row that
    never had an accounting block rather than one whose block was removed.
    """
    log = fresh_log("selftest")
    svc = QueryService(tables)
    auditor = SessionAuditor(threshold=THRESHOLD, budget=BUDGET)
    spec = json.loads(binomial_glm())
    r = svc.handle(binomial_glm(), planner=None, auditor=auditor,
                   audit_log=None, user="analyst@org")
    if r.status != "released":
        print("  [SKIP] the binomial did not release on this fixture")
        return True

    log.append(user="analyst@org", request=json.dumps(spec), spec=r.spec,
               status="released", findings=[], output_shape=[3, 2])
    assert log.verify(), "the pre-#58 chain must still verify"
    after = SessionStore(threshold=THRESHOLD, budget=BUDGET)
    after.rehydrate(log, window_hours=24)
    replayed = after.get("analyst@org").auditor

    refunded = replayed.spent != auditor.spent
    lost = len(replayed._cohorts) != len(auditor._cohorts)
    print(f"  pre-#58 chain: live _spent={auditor.spent} cohorts="
          f"{len(auditor._cohorts)}; replayed _spent={replayed.spent} "
          f"cohorts={len(replayed._cohorts)}")
    if refunded and lost:
        print("  [OK] the checks still detect both defects on a legacy chain")
        return True
    print("  [BLIND] a legacy chain no longer exhibits the defect — either the "
          "fallback changed or these checks have stopped looking")
    return False


def main() -> bool:
    from_csv = synth.csvs_present()
    tables = synth.load_csvs() if from_csv else synth.generate()
    source = "data/*.csv (what the app serves)" if from_csv else "synth.generate()"
    print(f"\nround-9 reproducers (threshold {THRESHOLD}, fixture: {source})\n")
    for name, fn in (("V1 budget", v1_budget_is_restart_faithful),
                     ("V2 lineage", v2_successes_cohort_survives),
                     ("V3 log integrity", v3_deletion_is_refused),
                     ("V4 error cost", v4_errors_cost_budget)):
        print(f"{name}:")
        fn(tables)
        print()

    print("falsifiability (can these checks still fail?):")
    sighted = selftest(tables)
    print()

    still = [n for n, vulnerable, _ in results if vulnerable]
    print(f"still vulnerable: {len(still)}/{len(results)} checks")
    for name in still:
        print(f"  - {name}")
    if not sighted:
        print("  - the harness itself (see falsifiability, above)")
    return not still and sighted


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
