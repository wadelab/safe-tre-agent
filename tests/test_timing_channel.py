"""Response time says nothing that suppression hides (spec R18).

Latency tracks how much work a query did, and work tracks cohort size —
measured, closely enough to put sub-threshold cells in size order within a few
queries (`scripts/measure_timing_channel.py`, decision D5). The deployment
boundary therefore holds every response until the next multiple of a quantum,
and refuses anything past a ceiling.

Timing assertions are flaky by nature, so the split here is deliberate: the
arithmetic is a pure function and is tested exhaustively, while the tests that
touch a clock assert only what stays true on a loaded machine — that a
response is never *faster* than its bucket. A test that asserted an upper
bound would fail on a busy CI runner and teach everyone to ignore it.
"""

from __future__ import annotations

import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from safetre_web.app import app, sleep_to_boundary

QUANTUM = 0.05


@pytest.fixture
def client():
    return TestClient(app)


# --- the arithmetic ------------------------------------------------------------

@pytest.mark.parametrize("elapsed,expected_total", [
    (0.0, 0.05), (0.001, 0.05), (0.049, 0.05),
    (0.051, 0.10), (0.099, 0.10), (0.13, 0.15),
])
def test_padding_lands_on_the_next_boundary(elapsed, expected_total):
    total = elapsed + sleep_to_boundary(elapsed, QUANTUM)
    assert total == pytest.approx(expected_total, abs=1e-9)


def test_work_that_lands_exactly_on_a_boundary_still_waits():
    # otherwise finishing at exactly one quantum is distinguishable from
    # finishing just after it, and the boundary itself becomes the signal
    assert sleep_to_boundary(QUANTUM, QUANTUM) == pytest.approx(QUANTUM)


def test_a_quantum_of_zero_disables_padding():
    # the escape hatch an operator gets, and the one the catalogue warns
    # reopens the channel
    assert sleep_to_boundary(0.013, 0.0) == 0.0


def test_padding_never_asks_to_travel_backwards():
    for elapsed in (0.0, 0.017, 0.05, 0.4999, 1.7):
        assert sleep_to_boundary(elapsed, QUANTUM) > 0


# --- the boundary itself -------------------------------------------------------

def test_no_response_is_faster_than_its_bucket(client, monkeypatch):
    import safetre_web.app as web

    monkeypatch.setattr(web, "_cfg", replace(
        web._cfg, response_quantum_ms=120))
    started = time.monotonic()
    response = client.get("/healthz")
    elapsed = time.monotonic() - started
    assert response.status_code == 200
    assert elapsed >= 0.120, f"answered in {elapsed:.3f}s, faster than a bucket"


def test_a_trivial_endpoint_and_a_query_share_a_bucket(client, monkeypatch):
    # the property that matters: the cheap path must not be distinguishable
    # from the expensive one by how quickly it answers
    import safetre_web.app as web

    monkeypatch.setattr(web, "_cfg", replace(
        web._cfg, response_quantum_ms=250))
    timings = {}
    for label, call in (("healthz", lambda: client.get("/healthz")),
                        ("manifest", lambda: client.get("/api/manifest"))):
        started = time.monotonic()
        call()
        timings[label] = time.monotonic() - started
    for label, elapsed in timings.items():
        assert elapsed >= 0.250, f"{label} answered in {elapsed:.3f}s"


def test_exceeding_the_ceiling_is_refused(client, monkeypatch):
    # a ceiling of zero makes every request an overrun, which is the only way
    # to exercise the branch without an artificially slow endpoint
    import safetre_web.app as web

    monkeypatch.setattr(web, "_cfg", replace(
        web._cfg, response_quantum_ms=10, response_ceiling_ms=0))
    response = client.get("/healthz")
    assert response.status_code == 503
    assert "ceiling" in response.json()["detail"]


def test_the_refusal_is_padded_like_everything_else(client, monkeypatch):
    # an unpadded refusal would be its own signal — the fast answer that means
    # "your query was expensive"
    import safetre_web.app as web

    monkeypatch.setattr(web, "_cfg", replace(
        web._cfg, response_quantum_ms=150, response_ceiling_ms=0))
    started = time.monotonic()
    response = client.get("/healthz")
    elapsed = time.monotonic() - started
    assert response.status_code == 503
    assert elapsed >= 0.150, f"refusal answered in {elapsed:.3f}s"


# --- #54: the ceiling is a deadline, not a post-hoc check ------------------------

def test_an_overrun_does_not_reveal_how_far_it_overran():
    """#34 stood open for a round: the handler ran to completion and only then
    was the body swapped, so a query taking 1.2 s against a 0.2 s ceiling was
    answered at 1.256 s — advertising its size exactly as it would have with no
    ceiling at all.

    Driven through `redteam/timing_attacker.py` so the assertion and the
    adversarial artifact cannot drift apart.
    """
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "redteam"))
    from timing_attacker import ceiling_straddle

    result = ceiling_straddle(samples=3)
    assert result["all_refused"], (
        "the probe never hit the ceiling, so it measured nothing: "
        f"{result['observed']}")
    assert not result["reveals_overrun_size"], (
        "8x the work is visible in the answer time, which is #34 again: "
        f"{result['observed']}")
