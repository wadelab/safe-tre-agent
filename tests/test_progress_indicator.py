"""The progress indicator reports the clock, never the work (decision D11).

An interface that shows an analyst nothing for three minutes is a bad interface,
and the obvious repair — advance a pipeline step as each one finishes — is a
disclosure three times over. What was built instead is a readout driven entirely
by the browser's own clock and the ceiling the manifest publishes, so it renders
two numbers the page already holds and adds no server behaviour at all.

That argument is only as good as the invariants it rests on, and every one of
them is the kind a later change breaks while trying to be helpful:

1. **The server sends nothing between the request and the quantised response.**
   `safetre_web/timing.py` buffers rather than streams, and the buffering IS
   R18: an event emitted when a stage finishes is an unpadded timestamp of that
   stage's work. Streaming per-stage progress would give an attacker one timing
   sample PER STAGE where R18 leaves one per request — worse than the channel
   [D5](../docs/decisions/D5-timing-channel.md) measured at Spearman +0.86.
2. **No response carries per-stage timing or a step count.** The content half:
   a step reporting its own outcome reports the gateway's verdict on the cohort,
   which is hardening #109's disclosure by a different route.
3. **The front end has no streaming client.** No `EventSource`, no
   `ReadableStream` reader, no progress endpoint. Stated as a test rather than a
   convention because adding one is a two-line change that nothing else notices.
4. **The indicator's cadence is a constant.** If it ever advanced on server
   events its rate would track the work, which is the whole thing being avoided.
"""

from __future__ import annotations

import os
import re

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from safetre.config import load_policy_config  # noqa: E402
from safetre.manifest import public_manifest  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, "safetre_web", "static", "app.js")
INDEX = os.path.join(ROOT, "safetre_web", "templates", "index.html")


def _js() -> str:
    with open(APP_JS, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def client():
    from safetre_web.app import app
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------------- #
# the manifest publishes what the client calibrates to                        #
# --------------------------------------------------------------------------- #

def test_the_manifest_publishes_the_response_timing_dials():
    timing = public_manifest(load_policy_config())["response_timing"]
    cfg = load_policy_config()
    assert timing["quantum_ms"] == cfg.response_quantum_ms
    assert timing["ceiling_ms"] == cfg.response_ceiling_ms
    assert timing["streamed"] is False


def test_publishing_the_dials_discloses_nothing_query_dependent():
    """They are policy constants: the same manifest for every caller and every
    request, which is why publishing them is R9's business and not a channel."""
    first = public_manifest(load_policy_config())["response_timing"]
    second = public_manifest(load_policy_config())["response_timing"]
    assert first == second
    assert set(first) == {"quantum_ms", "ceiling_ms", "streamed", "note"}


# --------------------------------------------------------------------------- #
# 1. nothing is streamed                                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("q", [
    "mean spend by age band",                     # a release
    "mean spend by donor id",                     # a refusal
    "count of donors",
])
def test_no_response_is_streamed(client, q):
    """One body, delivered once. An attacker gets exactly one timing sample per
    request, which is what R18's quantisation is calculated against."""
    resp = client.post("/api/query", json={"q": q})
    assert resp.status_code in (200, 400, 403, 422), resp.status_code
    assert resp.headers.get("transfer-encoding") != "chunked"
    # a buffered body has a length known before it is sent
    if resp.status_code == 200:
        assert "content-length" in {k.lower() for k in resp.headers}


def test_the_index_page_is_not_streamed(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers.get("transfer-encoding") != "chunked"


# --------------------------------------------------------------------------- #
# 2. no response carries per-stage timing or a step count                     #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("q", ["mean spend by age band", "mean spend by donor id"])
def test_a_response_carries_no_per_stage_timing(client, q):
    body = client.post("/api/query", json={"q": q}).text.lower()
    for leak in ("elapsed_ms", "stage_ms", "duration_ms", "step_ms",
                 "timings", "step_count", "steps_taken", "progress"):
        assert leak not in body, f"{leak!r} in the response body"


def test_the_step_display_is_resolved_only_from_the_public_trace():
    """The tags are set to "Checking" together at submission and resolved
    together from `data-stages`, which `service._public_trace` has already
    stripped for a data-derived refusal. Advancing them individually would mean
    advancing them on completion — the same channel in a smaller costume."""
    js = _js()
    assert "steps.forEach((s) => setStep(s, \"checking\"))" in js
    # `finishSteps` is called with the returned card, never from a timer or an
    # event stream
    assert re.search(r"finishSteps\(card\)", js)
    assert not re.search(r"setInterval\([^)]*finishSteps", js)
    assert not re.search(r"setTimeout\([^)]*setStep", js)


# --------------------------------------------------------------------------- #
# 3. the front end has no streaming client                                    #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("forbidden", [
    "EventSource", "text/event-stream", "getReader", "ReadableStream",
    "WebSocket", "/api/progress", "onprogress",
])
def test_the_front_end_has_no_streaming_client(forbidden):
    assert forbidden not in _js(), (
        f"{forbidden!r} in app.js — a streamed progress channel is exactly what "
        "D11 rejects, because an event emitted when a stage finishes is an "
        "unpadded timestamp of that stage's work (R18, D5)")


def test_the_app_exposes_no_streaming_route():
    from safetre_web.app import app

    paths = {getattr(r, "path", "") for r in app.routes}
    assert not [p for p in paths if "progress" in p or "stream" in p or "events" in p]


# --------------------------------------------------------------------------- #
# 4. the indicator is the client's own clock, at a constant cadence           #
# --------------------------------------------------------------------------- #

def test_the_indicator_is_driven_by_the_clients_clock():
    js = _js()
    assert "const startElapsed" in js
    # its only inputs: performance.now() and the published ceiling
    block = js[js.index("const startElapsed"):js.index("/* --- table decoration")]
    assert "performance.now()" in block
    assert "dataset.ceilingMs" in block
    assert "fetch(" not in block, "the indicator must not talk to the server"
    assert "await" not in block


def test_the_indicator_advances_on_a_constant_interval():
    js = _js()
    block = js[js.index("const startElapsed"):js.index("/* --- table decoration")]
    intervals = re.findall(r"setInterval\(\s*\w+\s*,\s*(\d+)\s*\)", block)
    assert intervals == ["1000"], (
        f"expected one constant cadence, found {intervals}; a rate that varies "
        "with the work is the work reported through a side door")


def test_the_indicator_reports_elapsed_not_a_fraction():
    """"How far along" has no request-decided denominator for a loop that stops
    when it has concluded, so a fraction cannot be made safe here."""
    js = _js()
    block = js[js.index("const startElapsed"):js.index("/* --- table decoration")]
    assert "elapsed" in block.lower()
    for fraction in ("%", "percent", "Math.min(1,", "/ total", "step of"):
        assert fraction not in block, f"{fraction!r} implies a fraction complete"


def test_both_slow_paths_show_the_indicator():
    js = _js()
    assert 'startElapsed(document.getElementById("q-elapsed"))' in js
    assert 'startElapsed(document.getElementById("cq-elapsed"))' in js
    assert js.count("stopElapsed()") == 2, "every start needs a stop in `finally`"


def test_the_markup_carries_the_ceiling_and_no_server_state():
    with open(INDEX, encoding="utf-8") as fh:
        html = fh.read()
    # the elements start empty and hidden: nothing about this request is
    # rendered server-side into them
    assert html.count('class="hint elapsed" hidden') == 2


def test_only_the_path_with_a_ceiling_claims_one():
    """`/api/chimp` is DEADLINE_EXEMPT, so there is no ceiling on that path to
    count toward. Claiming one would put a false number in front of an analyst,
    which is a smaller failure than a disclosure and still a failure."""
    from safetre_web.timing import DEADLINE_EXEMPT

    with open(INDEX, encoding="utf-8") as fh:
        html = fh.read()
    assert "/api/chimp" in DEADLINE_EXEMPT
    assert html.count("data-ceiling-ms=") == 1, (
        "exactly one indicator sits on a path the ceiling governs")
    q_block = html[html.index('id="q-elapsed"'):]
    assert q_block.startswith('id="q-elapsed" class="hint elapsed" hidden')
    assert "data-ceiling-ms" in q_block[:200]


def test_the_rendered_indicator_is_identical_for_every_visitor(client):
    """It is server-rendered from a policy constant, so two page loads — and so
    two different analysts — get byte-identical indicator markup."""
    first = client.get("/").text
    second = client.get("/").text
    pattern = re.compile(r'<p id="(?:q|cq)-elapsed"[^>]*>')
    assert pattern.findall(first) == pattern.findall(second)
    assert pattern.findall(first), "the indicator markup should be present"
