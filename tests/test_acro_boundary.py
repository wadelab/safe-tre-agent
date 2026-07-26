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
    json.loads(sys.stdin.read())
    print(json.dumps({{"protocol": {PROTOCOL}, "checker": "acro",
                       "version": "0.4.12",
                       "verdicts": [{{"cell": ["A"], "rule": "nk-rule;"}},
                                    {{"cell": ["B"], "rule": "ok"}}]}}))
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
    ("non-zero exit", """
        import sys
        print("something went wrong", file=sys.stderr)
        sys.exit(3)
    """),
    ("crash", """
        raise SystemError("checker blew up")
    """),
    ("not JSON", """
        print("this is not json")
    """),
    ("not an object", """
        print("[1, 2, 3]")
    """),
    ("wrong protocol", """
        import json
        print(json.dumps({"protocol": 99, "version": "0.4.12", "verdicts": []}))
    """),
    ("reported error", """
        import json
        print(json.dumps({"protocol": %d, "error": "acro is not installed"}))
    """ % PROTOCOL),
    ("malformed verdict", """
        import json
        print(json.dumps({"protocol": %d, "version": "x",
                          "verdicts": [{"cell": ["A"]}]}))
    """ % PROTOCOL),
])
def test_every_way_the_checker_can_fail_denies(tmp_path, label, body):
    verdicts = _vetter(_fake_checker(tmp_path, body)).vet(CELLS, PARAMS)
    assert verdicts.deny is True, label
    assert verdicts.suppress.all(), label
    assert verdicts.findings, label


def test_a_hanging_checker_denies_rather_than_waiting(tmp_path):
    slow = _fake_checker(tmp_path, """
        import time
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
        json.loads(sys.stdin.read())
        print(json.dumps({{"protocol": {PROTOCOL}, "version": "0.4.12",
                           "verdicts": [{{"cell": ["A"], "rule": "ok"}}]}}))
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
