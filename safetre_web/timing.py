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
unpadded.

**But only once the pool key was trustworthy** (round 11, #91). "Per-caller
pools do not move when anybody else runs a query" was written of a key taken
from an UNVERIFIED header, so they moved whenever the caller named somebody
else: an attacker who could not authenticate held a chosen victim's pool at one
below the cap and read that victim's over-ceiling durations off a cheap probe,
and locked them out of every route with four stalled request bodies that cost
no thread at all. #76 did not close the oracle so much as aim it. `_caller` now
believes a login only where the proxy secret proves it, which makes the key
space the allowlist and the bound real.

`/static/` is admitted alongside `/healthz`: the comment below always said
static assets cost nothing, and serving a 503 for the stylesheet while the
liveness probe stays green is the outage being invisible twice over.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import math
import os
import time

from . import identity
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
# under load gets the service restarted, and static assets cost nothing. Both
# are matched the way `app.rate_limit` matches them — an exact path or a
# prefix WITH its separator, never a bare `startswith` (#77d).
ALWAYS_ADMITTED = ("/healthz",)
ALWAYS_ADMITTED_PREFIXES = ("/static/",)


def _always_admitted(path: str) -> bool:
    return path in ALWAYS_ADMITTED or path.startswith(ALWAYS_ADMITTED_PREFIXES)


# Paths exempt from the response-time DEADLINE entirely (not merely the pool
# cap). The inside analyst (`/api/chimp` and its streaming sibling
# `/api/chimp/stream`, which relays each step as it settles) runs a whole
# multi-step analysis and legitimately takes far longer than the per-query
# ceiling — and the stream must not be buffered by this boundary at all; racing it against
# that deadline would refuse every real research question. Its timing reveals
# how many analyses the analyst ran, not any withheld cell value — the dossier
# carries only vetted releases, so this is a weaker and different channel than
# the per-query one this boundary closes. The principled answer for a
# long-running analyst is asynchronous submit-and-collect (decision D5); until
# that lands, this synchronous exemption is a stated proof-of-concept limit,
# and it is the ONLY path allowed past the deadline.
DEADLINE_EXEMPT = ("/api/chimp", "/api/chimp/stream")


def _deadline_exempt(path: str) -> bool:
    return path in DEADLINE_EXEMPT


class ResponseTimeBoundary:
    """Pad every response to the next quantum; refuse anything past the ceiling.

    Added last so it is the outermost layer: the channel check, the identity
    gate and template rendering all happen inside its window, and a fast-fail
    path that skipped the padding would become the channel this exists to close.
    """

    @staticmethod
    def _caller(scope) -> str:
        """Who to charge an abandoned task to.

        The presented identity **only when the proxy secret proves it**, and
        the peer otherwise.

        The first version keyed on the raw header and argued that an unverified
        one was fine because this is a resource bucket rather than an
        authorisation decision. That was wrong in a way #76 made worse rather
        than better (round 11, #91). #76 replaced one shared pool with a pool
        per caller and claimed "per-caller pools do not move when anybody else
        runs a query" — but they move when the caller NAMES somebody else. An
        unauthenticated attacker holding a named user's pool at one below the
        cap turns each cheap probe into a one-bit read of whether THAT user has
        over-ceiling work in flight, and polling recovers its duration: the
        wall-clock size of another user's query, which is the quantity R18's
        ceiling and D5's quantisation exist to destroy. Measured: three held
        sockets, no credentials, 0.99 s read against a 1.00 s overrun. The
        oracle #76 closed for everyone, it reopened for a chosen target.

        The same key is also a targeted denial of service — four stalled
        request bodies, which cost the attacker nothing and hold no thread,
        lock a named user out of every route.

        This is raw ASGI, so it reads the scope directly rather than a
        `Request`, but it applies `identity.py`'s rule and not a weaker one.
        It used to say it did while doing three things differently: it took the
        LAST of a repeated `tailscale-user-login` (where #45 refuses ambiguity
        outright, because an appending proxy makes the client's forged value
        win), and it consulted no allowlist. Both are fixed below; a repeated
        or comma-joined header now falls back to the peer key, which is the
        fail-closed direction.

        One difference remains, stated rather than implied away:
        `identity.rate_limit_key` also requires `identity_is_verifiable()` (the
        channel/opt-in posture), which needs config this layer does not read.
        Here the proxy secret alone stands in for it. That is sound for this
        use — the secret is exactly what proves the header was not forged by a
        client, and this key only selects a resource bucket — but it is a
        weaker precondition than the session path's, so do not copy this
        function's shape into an authorisation decision.
        """
        secret = os.environ.get("SAFETRE_PROXY_SHARED_SECRET", "")
        logins, presented = [], None
        for name, value in scope.get("headers", ()):
            if name == b"tailscale-user-login" and value:
                logins.append(value.decode("latin-1", "replace")[:200])
            elif name == b"x-safetre-proxy-auth" and value:
                presented = value.decode("latin-1", "replace")
        # exactly one header, no comma-joined pair of identities (#45)
        login = logins[0].strip() if len(logins) == 1 else ""
        if "," in login:
            login = ""
        if (secret and login and presented is not None
                and hmac.compare_digest(presented, secret)
                and identity._allowed(login)):
            return "user:" + login
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

        # The inside analyst is exempt from the whole boundary (see
        # DEADLINE_EXEMPT): it runs to completion, unpadded, because a
        # multi-step analysis cannot fit the per-query window and its timing is
        # not the per-cell channel this control closes.
        if _deadline_exempt(scope.get("path", "")):
            return await self.app(scope, receive, send)

        quantum_ms, ceiling_ms = self.settings()
        # Refuse before starting work when THIS CALLER's pool is full (#68,
        # corrected in #76). Starting it would add another orphan thread to a
        # set already at its limit, which is the unbounded growth this cap
        # exists to stop — but the bound is on one caller's waste, so a caller
        # who has not overrun anything is never refused for someone else's.
        caller = self._caller(scope)
        mine = self._abandoned_by.get(caller, ())
        if (not _always_admitted(scope.get("path", ""))
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
