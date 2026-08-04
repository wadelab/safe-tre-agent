"""The external-checker boundary fails closed, in every way it can fail.

`safetre/external_checker.py` calls an output checker in another process (§4 of
`docs/acro-integration.md`). The rules it carries are ACRO's and are measured
elsewhere; what matters here is the part with no second opinion — what the
gateway does when the checker exits non-zero, hangs, answers in the wrong
protocol, answers with nonsense, or answers about the wrong cells.

Every one of those must **deny**. There is deliberately no path that shrugs
and releases under the stand-in's rules: a release claims the checks that ran,
and a checker that is down is not a checker that approved. These tests drive
fake checkers, so they need neither ACRO nor its environment.
"""

from __future__ import annotations

import json
import sys
import textwrap
import threading
import time

import pandas as pd
import pytest

from safetre.disclosure import DisclosurePolicy, VettingParameters
from safetre.external_checker import (
    PROTOCOL, ExternalCheckerVetter, build_request, parse_response,
)

PARAMS = VettingParameters(threshold=10, max_rows=100, dom_threshold=0.5,
                           influence_threshold=0.5)
CELLS = pd.DataFrame({"region": ["A", "B"], "value": [1.0, 2.0], "n": [40, 50]})
CONTRIBUTIONS = pd.DataFrame({"region": ["A", "A", "B"], "donor_id": [1, 2, 3],
                              "v": [1.0, 2.0, 3.0]})


def _fake_checker(tmp_path, body: str) -> list[str]:
    """A checker that behaves however the test needs it to."""
    script = tmp_path / "fake_checker.py"
    script.write_text(textwrap.dedent(body))
    return [sys.executable, str(script)]


def _vetter(command, **kw) -> ExternalCheckerVetter:
    return ExternalCheckerVetter(command, ["region"], "sum", CONTRIBUTIONS, **kw)


ANSWERS = f"""
    import json, sys
    for line in sys.stdin:
        request = json.loads(line)
        print(json.dumps({{"protocol": {PROTOCOL}, "id": request["id"],
                           "checker": "acro", "version": "0.4.12",
                           "verdicts": [{{"cell": ["A"], "rule": "nk-rule;"}},
                                        {{"cell": ["B"], "rule": "ok"}}]}}),
              flush=True)
"""


def test_a_working_checker_decides_cell_by_cell(tmp_path):
    verdicts = _vetter(_fake_checker(tmp_path, ANSWERS)).vet(CELLS, PARAMS)
    assert verdicts.suppress.tolist() == [True, False]
    assert verdicts.deny is False
    assert [f.rule for f in verdicts.findings] == ["acro_nk-rule"]


def test_the_checker_version_is_recorded_for_the_release(tmp_path):
    # "which rules did this output pass?" must have an answer a year later
    vetter = _vetter(_fake_checker(tmp_path, ANSWERS))
    vetter.vet(CELLS, PARAMS)
    assert vetter.version == "0.4.12"


@pytest.mark.parametrize("label,body", [
    ("exits without answering", """
        import sys
        sys.stdin.readline()
        print("something went wrong", file=sys.stderr)
        sys.exit(3)
    """),
    ("crash", """
        import sys
        sys.stdin.readline()
        raise SystemError("checker blew up")
    """),
    ("not JSON", """
        import sys
        sys.stdin.readline()
        print("this is not json", flush=True)
    """),
    ("not an object", """
        import sys
        sys.stdin.readline()
        print("[1, 2, 3]", flush=True)
    """),
    ("wrong protocol", """
        import json, sys
        request = json.loads(sys.stdin.readline())
        print(json.dumps({"protocol": 99, "id": request["id"],
                          "version": "0.4.12", "verdicts": []}), flush=True)
    """),
    ("reported error", """
        import json, sys
        request = json.loads(sys.stdin.readline())
        print(json.dumps({"protocol": %d, "id": request["id"],
                          "error": "acro is not installed"}), flush=True)
    """ % PROTOCOL),
    ("malformed verdict", """
        import json, sys
        request = json.loads(sys.stdin.readline())
        print(json.dumps({"protocol": %d, "id": request["id"], "version": "x",
                          "verdicts": [{"cell": ["A"]}]}), flush=True)
    """ % PROTOCOL),
])
def test_every_way_the_checker_can_fail_denies(tmp_path, label, body):
    verdicts = _vetter(_fake_checker(tmp_path, body)).vet(CELLS, PARAMS)
    assert verdicts.deny is True, label
    assert verdicts.suppress.all(), label
    assert verdicts.findings, label


def test_a_hanging_checker_denies_rather_than_waiting(tmp_path):
    slow = _fake_checker(tmp_path, """
        import sys, time
        sys.stdin.readline()
        time.sleep(30)
    """)
    verdicts = _vetter(slow, timeout=0.5).vet(CELLS, PARAMS)
    assert verdicts.deny is True
    assert any("within" in f.detail for f in verdicts.findings)


def test_a_checker_that_cannot_be_started_denies():
    verdicts = _vetter(["/nonexistent/checker"]).vet(CELLS, PARAMS)
    assert verdicts.deny is True
    assert verdicts.suppress.all()


def test_a_partial_answer_denies_the_whole_table(tmp_path):
    # covering some cells is not covering the table: releasing the answered
    # part would claim a check that never ran on the rest
    partial = _fake_checker(tmp_path, f"""
        import json, sys
        request = json.loads(sys.stdin.readline())
        print(json.dumps({{"protocol": {PROTOCOL}, "id": request["id"],
                           "version": "0.4.12",
                           "verdicts": [{{"cell": ["A"], "rule": "ok"}}]}}),
              flush=True)
    """)
    verdicts = _vetter(partial).vet(CELLS, PARAMS)
    assert verdicts.deny is True
    assert verdicts.suppress.all()
    assert any(f.rule == "checker_incomplete" for f in verdicts.findings)


def test_a_denying_vetter_withholds_the_whole_table_through_the_policy(tmp_path):
    # end to end: the policy honours the vetter's denial, and no frame escapes
    policy = DisclosurePolicy(vetter=_vetter(["/nonexistent/checker"]))
    released, action, findings = policy.apply(CELLS)
    assert action == "deny"
    assert released is None
    assert any(f.rule == "checker_unavailable" for f in findings)


def test_the_request_carries_what_the_checker_needs_and_no_frame():
    # records, not a pandas object: the contract must not depend on the
    # library version whose conflict is the reason for the boundary
    request = build_request(CONTRIBUTIONS, ["region"], "sum")
    assert request["protocol"] == PROTOCOL
    assert request["keys"] == ["region"]
    assert request["aggfunc"] == "sum"
    assert request["contributions"][0]["region"] == "A"
    json.dumps(request)                      # must round-trip as plain JSON


def test_parse_response_rejects_what_it_cannot_trust():
    good = json.dumps({"protocol": PROTOCOL, "version": "0.4.12",
                       "verdicts": [{"cell": ["A"], "rule": "ok"}]})
    verdicts, reported = parse_response(good)
    assert verdicts == {("A",): "ok"} and reported == "0.4.12"
    for bad in ("{", "[]", json.dumps({"protocol": PROTOCOL + 1})):
        with pytest.raises(ValueError):
            parse_response(bad)

# --- the process is reused, and never reused after doubt ------------------------

COUNTING = f"""
    import json, sys, pathlib
    tally = pathlib.Path(__file__).with_name("starts")
    tally.write_text(str(int(tally.read_text()) + 1) if tally.exists() else "1")
    for line in sys.stdin:
        request = json.loads(line)
        print(json.dumps({{"protocol": {PROTOCOL}, "id": request["id"],
                           "version": "0.4.12",
                           "verdicts": [{{"cell": ["A"], "rule": "ok"}},
                                        {{"cell": ["B"], "rule": "ok"}}]}}),
              flush=True)
"""


def test_the_checker_is_started_once_and_reused(tmp_path):
    # the whole point of the streamed protocol: a process per cell table cost
    # a second or two of imports each, which is what made an external checker
    # too slow to be anyone's default
    vetter = _vetter(_fake_checker(tmp_path, COUNTING))
    try:
        for _ in range(3):
            assert not vetter.vet(CELLS, PARAMS).deny
    finally:
        vetter.close()
    assert (tmp_path / "starts").read_text() == "1", "the checker was restarted"


def test_an_answer_to_the_wrong_question_denies(tmp_path):
    # the failure a reused pipe makes possible, and the one that must never
    # pass: a stale answer read as the answer to the current table would vet
    # cells against verdicts computed for a different query
    liar = _fake_checker(tmp_path, f"""
        import json, sys
        for line in sys.stdin:
            json.loads(line)
            print(json.dumps({{"protocol": {PROTOCOL}, "id": 999,
                               "version": "0.4.12",
                               "verdicts": [{{"cell": ["A"], "rule": "ok"}},
                                            {{"cell": ["B"], "rule": "ok"}}]}}),
                  flush=True)
    """)
    vetter = _vetter(liar)
    try:
        verdicts = vetter.vet(CELLS, PARAMS)
    finally:
        vetter.close()
    assert verdicts.deny is True
    assert any("desynchronised" in f.detail for f in verdicts.findings)


def test_a_timed_out_checker_is_not_reused(tmp_path):
    # a late answer to an abandoned request would be read as the answer to the
    # next one, so the process is discarded rather than trusted again
    slow = _fake_checker(tmp_path, f"""
        import json, sys, time
        for line in sys.stdin:
            request = json.loads(line)
            time.sleep(5)
            print(json.dumps({{"protocol": {PROTOCOL}, "id": request["id"],
                               "version": "0.4.12", "verdicts": []}}),
                  flush=True)
    """)
    vetter = _vetter(slow, timeout=0.5)
    try:
        assert vetter.vet(CELLS, PARAMS).deny is True
        assert vetter._process is None, "a timed-out checker was kept"
    finally:
        vetter.close()


def test_a_checker_that_changes_version_mid_session_denies(tmp_path):
    # a release records which checker approved it, so the version must hold
    # still for as long as the session does — whether it drifts because the
    # process was restarted or because the process itself changed its mind
    drifting = _fake_checker(tmp_path, f"""
        import json, sys
        for n, line in enumerate(sys.stdin):
            request = json.loads(line)
            print(json.dumps({{"protocol": {PROTOCOL}, "id": request["id"],
                               "version": "0.4." + str(n),
                               "verdicts": [{{"cell": ["A"], "rule": "ok"}},
                                            {{"cell": ["B"], "rule": "ok"}}]}}),
                  flush=True)
    """)
    vetter = _vetter(drifting)
    try:
        assert not vetter.vet(CELLS, PARAMS).deny      # 0.4.0 recorded
        second = vetter.vet(CELLS, PARAMS)             # 0.4.1 reported
    finally:
        vetter.close()
    assert second.deny is True
    assert any("version changed" in f.detail for f in second.findings)


def test_a_checker_that_keeps_dying_stops_being_restarted(tmp_path):
    dying = _fake_checker(tmp_path, """
        import sys
        sys.exit(1)
    """)
    vetter = _vetter(dying, max_starts=2)
    try:
        for _ in range(3):
            assert vetter.vet(CELLS, PARAMS).deny is True
        assert any("not restarting" in f.detail
                   for f in vetter.vet(CELLS, PARAMS).findings)
    finally:
        vetter.close()


# --- one vetter, many users (red-team, 2026-07-26) -----------------------------

ECHOES_WHAT_IT_SAW = f"""
    import json, sys
    for line in sys.stdin:
        request = json.loads(line)
        keys, seen = request["keys"], []
        for row in request["contributions"]:
            cell = [str(row[k]) for k in keys]
            if cell not in seen:
                seen.append(cell)
        print(json.dumps({{"protocol": {PROTOCOL}, "id": request["id"],
                           "version": "1.0",
                           "verdicts": [{{"cell": c, "rule": "ok"}} for c in seen]}}),
              flush=True)
"""


def test_vetting_leaves_no_table_on_the_shared_vetter(tmp_path):
    """The web app builds ONE vetter and serves users in parallel. If `vet`
    writes the table it was handed onto `self`, another thread can overwrite it
    before the payload is built, and the checker is asked about the wrong
    table — with a matching request id, because the id is minted after the
    swap. Nothing per-call may live on the instance."""
    from safetre.disclosure import CellContext

    vetter = ExternalCheckerVetter(_fake_checker(tmp_path, ECHOES_WHAT_IT_SAW))
    before = (vetter.contributions, list(vetter.keys), vetter.aggfunc)
    context = CellContext(contributions=CONTRIBUTIONS, keys=("region",),
                          aggfunc="sum", value_class="magnitude")
    vetter.vet(CELLS, PARAMS, context)
    vetter.close()
    assert (vetter.contributions, list(vetter.keys), vetter.aggfunc) == before


def test_concurrent_users_are_never_answered_about_each_others_tables(tmp_path):
    """The same property under load. Each thread vets a table with unique cell
    keys and the checker answers for every cell it is actually sent, so a
    thread reporting `checker_incomplete` was handed verdicts computed for a
    different table. Fine-grained preemption exposes the window; this failed at
    2 in 240 before the per-call state moved off the instance."""
    import sys as _sys
    import threading

    from safetre.disclosure import CellContext

    vetter = ExternalCheckerVetter(_fake_checker(tmp_path, ECHOES_WHAT_IT_SAW))
    bad: list[str] = []
    lock = threading.Lock()

    def one(tag: str) -> None:
        cells = [f"{tag}-{i}" for i in range(4)]
        frame = pd.DataFrame({"region": cells, "n": [50] * 4})
        context = CellContext(
            contributions=pd.DataFrame(
                {"region": [c for c in cells for _ in range(12)],
                 "v": [1.0] * 48, "donor_id": list(range(48))}),
            keys=("region",), aggfunc="sum", value_class="magnitude")
        verdicts = vetter.vet(frame, PARAMS, context)
        rules = [f.rule for f in verdicts.findings]
        if any(r in ("checker_incomplete", "checker_unavailable") for r in rules):
            with lock:
                bad.append(f"{tag}: {rules}")

    original = _sys.getswitchinterval()
    _sys.setswitchinterval(1e-6)
    try:
        for round_ in range(20):
            threads = [threading.Thread(target=one, args=(f"r{round_}u{u}",))
                       for u in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
    finally:
        _sys.setswitchinterval(original)
        vetter.close()
    assert not bad, f"verdicts computed for another table: {bad}"


# --- #67: one user's hang must not be everyone's ------------------------------

def test_a_hanging_checker_does_not_stall_other_users(tmp_path):
    """#67 (round-9 V7): the app builds ONE vetter, so one checker process and
    one lock serve every user. A contribution frame that made the checker hang
    held that lock for the whole timeout — 120 s against a 5 s response
    ceiling — so a poisoned cell key denied the vetting path to everybody, and
    repeating it sustained the outage.

    The exchange timeout bounds one user's wait; it cannot bound the queue
    behind them, so waiting for the pipe is bounded separately. A user who
    cannot get it fails closed at once rather than joining the queue.
    """
    slow = _fake_checker(tmp_path, """
        import sys, time
        sys.stdin.readline()
        time.sleep(30)
    """)
    vetter = _vetter(slow, timeout=5.0, lock_wait=0.2)

    started = threading.Event()
    victim: dict = {}

    def hog():
        started.set()
        vetter.vet(CELLS, PARAMS)          # takes the lock and hangs on it

    def other_user():
        began = time.monotonic()
        verdicts = vetter.vet(CELLS, PARAMS)
        victim["elapsed"] = time.monotonic() - began
        victim["deny"] = verdicts.deny
        victim["findings"] = [f.detail for f in verdicts.findings]

    t1 = threading.Thread(target=hog, daemon=True)
    t1.start()
    started.wait(timeout=2)
    time.sleep(0.2)                        # let the hog reach the pipe
    t2 = threading.Thread(target=other_user, daemon=True)
    t2.start()
    t2.join(timeout=10)

    assert victim, "the second user never got an answer at all"
    assert victim["deny"] is True, "an unchecked table must not release"
    assert victim["elapsed"] < 2.0, (
        f"the second user waited {victim['elapsed']:.1f}s behind the first")
    assert any("busy" in d for d in victim["findings"]), victim["findings"]


def test_a_shared_checker_cannot_hold_one_querys_state():
    """#33's defect, closed by construction rather than by coincidence.

    A vetter built from configuration is long-lived and shared by every request
    in flight, so per-query state on it belongs to whichever request set it
    last -- which is how one analyst's verdicts were returned about another's
    table. The service builds it with no table today, so the stored-table
    fallback was unreachable there by accident. `shared=True` makes that a
    property of the object instead: the two modes are now named, and the
    dangerous combination cannot be constructed at all.
    """
    import pytest

    for kwargs in ({"keys": ["region"]}, {"aggfunc": "sum"},
                   {"contributions": CONTRIBUTIONS}):
        with pytest.raises(ValueError, match="shared checker"):
            ExternalCheckerVetter(["/bin/true"], shared=True, **kwargs)

    # a shared vetter with no context has nothing to check, and fails closed
    shared = ExternalCheckerVetter(["/bin/true"], shared=True)
    verdicts = shared.vet(CELLS, PARAMS)
    assert verdicts.deny
    assert all(verdicts.suppress)
    assert [f.rule for f in verdicts.findings] == ["checker_uninformed"]

    # and the single-use harness mode is unaffected
    assert ExternalCheckerVetter(["/bin/true"], ["region"], "sum",
                                 CONTRIBUTIONS).contributions is not None


def test_the_checker_environment_is_an_allowlist(monkeypatch):
    # The checker is distrusted with poisoned input (#44). A denylist let every
    # secret it did not name -- the LLM key, cloud/db creds -- cross to it; it
    # now gets an allowlist of runtime state and nothing else (#97, V-2).
    import safetre.external_checker as ec

    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("SAFETRE_LLM_API_KEY", "sk-must-not-cross")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-cross")
    monkeypatch.setenv("SAFETRE_AUDIT_KEY", "must-not-cross")
    monkeypatch.setenv("SAFETRE_PROXY_SHARED_SECRET", "must-not-cross")
    monkeypatch.setenv("AN_UNLISTED_VAR", "must-not-cross")

    env = ec._checker_env()

    # what a program needs to start still crosses
    assert env.get("PATH") == "/usr/bin"
    # no secret, no app config, nothing unlisted -- it is an allowlist
    for blocked in ("SAFETRE_LLM_API_KEY", "AWS_SECRET_ACCESS_KEY",
                    "SAFETRE_AUDIT_KEY", "SAFETRE_PROXY_SHARED_SECRET",
                    "AN_UNLISTED_VAR"):
        assert blocked not in env
    # every key that DID cross is one we explicitly allow
    assert set(env).issubset(set(ec._CHECKER_ENV_ALLOW))
