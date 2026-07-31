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

What it now DOES do is stop that admission being unbounded (round-9 V11,
hardening #68). Abandoned tasks used to accumulate without limit, so an
attacker who could reliably exceed the ceiling could hold arbitrarily many
threads doing work nobody would ever read, at a cost of one cheap request each.

**The cap is PER CALLER, and #68's first version was not** (round 10, #76).
A single process-wide pool checked at the outermost layer meant sixteen cheap
requests from one identity returned 503 to everybody, on every route including
`/healthz` and `/static` — so a liveness probe would declare the app dead and
restart it. That trades an unbounded compute pool for a global kill switch,
which is a worse bargain: the thing being bounded is one caller's waste, so
that is what the bound has to be keyed on. A global backstop remains, an order
of magnitude higher, for the case where many callers overrun at once.

It also stopped being a cross-user oracle in the process. With one shared pool
an attacker could hold it one slot below the limit and read, from a cheap
probe, exactly when somebody else's query crossed the ceiling and when it
finished — the wall-clock duration of another user's over-ceiling work,
unpadded. Per-caller pools do not move when anybody else runs a query.
"""

from __future__ import annotations

import asyncio
import json
import math
import time

from .headers import SECURITY_HEADERS


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


# How many ceiling-exceeded requests ONE CALLER may have still running before
# their next request is refused at the door. Each holds a thread doing work no
# client will ever read, so this is the bound on that waste (round-9 V11).
MAX_ABANDONED_PER_CALLER = 4

# A backstop for everyone together, an order of magnitude higher, so that many
# callers overrunning at once still cannot grow the pool without limit. Reached
# only when the per-caller bound has already failed to contain things.
MAX_ABANDONED_TOTAL = 64

# Never refused, whatever the pool looks like: a liveness probe that fails
# under load gets the service restarted, and static assets cost nothing.
ALWAYS_ADMITTED = ("/healthz",)


class ResponseTimeBoundary:
    """Pad every response to the next quantum; refuse anything past the ceiling.

    Added last so it is the outermost layer: the channel check, the identity
    gate and template rendering all happen inside its window, and a fast-fail
    path that skipped the padding would become the channel this exists to close.
    """

    @staticmethod
    def _caller(scope) -> str:
        """Who to charge an abandoned task to.

        The presented identity where there is one, the peer otherwise. This is
        a RESOURCE bucket, not an authorisation decision, so an unverified
        header is fine to key on: rotating it buys more slots but stays inside
        the global backstop, and every other control still refuses the forged
        identity itself.
        """
        for name, value in scope.get("headers", ()):
            if name == b"tailscale-user-login" and value:
                return "user:" + value.decode("latin-1", "replace")[:200]
        client = scope.get("client")
        return "peer:" + (client[0] if client else "?")

    def __init__(self, app, settings,
                 max_abandoned: int = MAX_ABANDONED_PER_CALLER,
                 max_abandoned_total: int = MAX_ABANDONED_TOTAL):
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
        self.max_abandoned = max_abandoned
        self.max_abandoned_total = max_abandoned_total
        self._abandoned: set[asyncio.Task] = set()
        # caller key -> that caller's still-running abandoned tasks
        self._abandoned_by: dict[str, set[asyncio.Task]] = {}

    def _refusal(self, ceiling_ms: int) -> list[dict]:
        body = json.dumps({
            "detail": "refused: this request exceeded the response-time ceiling",
            "ceiling_ms": ceiling_ms,
        }).encode()
        return [
            {"type": "http.response.start", "status": 503,
             "headers": [(b"content-type", b"application/json"),
                         (b"content-length", str(len(body)).encode())]
                        + SECURITY_HEADERS},
            {"type": "http.response.body", "body": body},
        ]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        quantum_ms, ceiling_ms = self.settings()
        # Refuse before starting work when THIS CALLER's pool is full (#68,
        # corrected in #76). Starting it would add another orphan thread to a
        # set already at its limit, which is the unbounded growth this cap
        # exists to stop — but the bound is on one caller's waste, so a caller
        # who has not overrun anything is never refused for someone else's.
        caller = self._caller(scope)
        mine = self._abandoned_by.get(caller, ())
        if (scope.get("path") not in ALWAYS_ADMITTED
                and (len(mine) >= self.max_abandoned
                     or len(self._abandoned) >= self.max_abandoned_total)):
            started = time.monotonic()
            await asyncio.sleep(
                max(0.0, sleep_to_boundary(time.monotonic() - started,
                                           quantum_ms / 1000.0)))
            for message in self._refusal(ceiling_ms):
                await send(message)
            return
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
            bucket = self._abandoned_by.setdefault(caller, set())
            bucket.add(task)
            task.add_done_callback(self._abandoned.discard)
            task.add_done_callback(bucket.discard)
            # do not let the per-caller map grow without bound
            task.add_done_callback(
                lambda _t, k=caller: self._abandoned_by.pop(k, None)
                if not self._abandoned_by.get(k) else None)
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
