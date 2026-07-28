"""Response-time boundary: quantised padding and a real deadline (spec R18).

Latency tracks how much work a query did, and work tracks cohort size — closely
enough, measured, to put sub-threshold cohorts in size order within a few
queries, which is what suppression exists to prevent (decision D5). So every
response is held to the next multiple of a quantum, and work that would run
past a ceiling is refused rather than answered late, because an overrunning
request advertises its size by overrunning.

**Why this is raw ASGI and not a `@app.middleware("http")` function.**
Hardening #34 stood open for a round because the ceiling was a post-hoc check:
the handler ran to completion and only then was the body swapped, so a query
taking 1.2 s against a 0.2 s ceiling was answered at 1.256 s — advertising its
size exactly as it would have with no ceiling at all. The obvious repair is to
race the handler against a deadline, and inside Starlette's `BaseHTTPMiddleware`
that does not work, for two compounding reasons measured here:

1. `asyncio.wait_for` cancels, and FastAPI runs a sync handler through anyio's
   thread pool, which is not cancellable by default. The await returns when the
   thread finishes. Measured: 1203 ms against a 200 ms ceiling.
2. Abandoning the task instead of cancelling does not help either, because
   `BaseHTTPMiddleware` runs `call_next` inside an anyio task group and the
   group does not exit until its child does. The early response is produced on
   time and then *delivered* late. Measured: identical 1203 ms.

A raw ASGI middleware sits outside that task group and can answer while the
inner application is still running, which is the only arrangement that makes
the ceiling a deadline. The response is buffered rather than streamed — every
response this app produces is a small JSON or HTML body — and once the deadline
has been answered, anything the inner app subsequently writes goes to the
discard buffer and never reaches the client.

What this still does NOT do, stated because it would be easy to over-claim: the
abandoned work keeps its thread. The clock stops talking; the resource cost
stays. The ceiling is a disclosure control and is not also a compute cap — the
row, memory and thread limits in the engine are what bound cost.
"""

from __future__ import annotations

import asyncio
import json
import math
import time


def sleep_to_boundary(elapsed: float, quantum: float) -> float:
    """How long to wait so that `elapsed` becomes a whole number of quanta.

    Pure, so the arithmetic is tested exhaustively rather than by watching a
    clock. Note it rounds *up to the next* boundary even when elapsed is
    already an exact multiple: landing exactly on a boundary is itself
    information about how long the work took.
    """
    if quantum <= 0:
        return 0.0
    return (math.floor(elapsed / quantum) + 1) * quantum - elapsed


class ResponseTimeBoundary:
    """Pad every response to the next quantum; refuse anything past the ceiling.

    Added last so it is the outermost layer: the channel check, the identity
    gate and template rendering all happen inside its window, and a fast-fail
    path that skipped the padding would become the channel this exists to close.
    """

    def __init__(self, app, settings):
        """`settings()` returns `(quantum_ms, ceiling_ms)` and is called PER
        REQUEST, not captured here.

        Same reason `VettingParameters` are passed at call time rather than
        held on the vetter: a safety parameter read once at construction is a
        safety parameter that can go stale, and the configured value must be
        the one that bites (spec R10). It also keeps the dials testable without
        rebuilding the application.
        """
        self.app = app
        self.settings = settings
        self._abandoned: set[asyncio.Task] = set()

    def _refusal(self, ceiling_ms: int) -> list[dict]:
        body = json.dumps({
            "detail": "refused: this request exceeded the response-time ceiling",
            "ceiling_ms": ceiling_ms,
        }).encode()
        return [
            {"type": "http.response.start", "status": 503,
             "headers": [(b"content-type", b"application/json"),
                         (b"content-length", str(len(body)).encode())]},
            {"type": "http.response.body", "body": body},
        ]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        quantum_ms, ceiling_ms = self.settings()
        quantum, ceiling = quantum_ms / 1000.0, ceiling_ms / 1000.0
        started = time.monotonic()
        buffered: list[dict] = []
        answered = False

        async def capture(message):
            # Everything the inner app writes lands here. After the deadline has
            # been answered it is simply dropped, so the inner app can never
            # write a second response onto the wire.
            if not answered:
                buffered.append(message)

        async def hold():
            await asyncio.sleep(
                max(0.0, sleep_to_boundary(time.monotonic() - started, quantum)))

        task = asyncio.ensure_future(self.app(scope, receive, capture))
        done, _ = await asyncio.wait({task}, timeout=ceiling)

        if task not in done:
            answered = True
            # keep a reference so the orphan is not garbage-collected mid-flight,
            # and swallow its eventual result or error
            self._abandoned.add(task)
            task.add_done_callback(self._abandoned.discard)
            task.add_done_callback(lambda t: t.cancelled() or t.exception())
            await hold()
            for message in self._refusal(ceiling_ms):
                await send(message)
            return

        await hold()
        if task.exception() is not None:
            # an error path that answered faster than every other path would be
            # the channel wearing a different hat, so it is padded too
            raise task.exception()
        for message in buffered:
            await send(message)
