"""Request-body ceiling: refuse an oversized body before anything reads it.

`QueryRequest.q` is capped at 500 characters by Pydantic, which bounds what the
*application* accepts and nothing about what the *transport* buffers. Validation
happens after the body has been read, so `{"q": "ok", "pad": "<2 GB>"}` is
received in full and only then rejected as an extra field. One request is
enough, the rate limiter does not help because the cost is paid before the
first check, and uvicorn imposes no default body limit (round-9 V5; flagged in
round 8 §6 as "pin body limits at uvicorn/tailscale" and still unfixed in code
until now — hardening #64).

Raw ASGI, for the same reason `ResponseTimeBoundary` is: it has to act before
the inner application awaits the body, and a `BaseHTTPMiddleware` function
cannot see the body without consuming it. Two gates, because either alone
leaks:

- **Declared size.** A `Content-Length` above the ceiling is refused without
  reading a byte.
- **Actual size.** A chunked request declares no length at all, so the receive
  channel is wrapped and the bytes counted as they arrive; crossing the ceiling
  ends the stream and answers 413. Without this the first gate is advisory, and
  an attacker chooses whether to declare.

The ceiling is deliberately small. The only body this app accepts is a JSON
object with one 500-character string, so a few kilobytes is generous; anything
larger is not a request this service has a use for. It is a cost control, not a
disclosure control, so it sits OUTSIDE the response-time padding: a 413 says
only that the body was too large, which the sender already knows, and paying
the padding on it would be the denial-of-service paid twice.
"""

from __future__ import annotations

import json

# Enough for `{"q": "<500 chars>"}` many times over, and far below anything
# that costs memory to hold.
DEFAULT_MAX_BODY_BYTES = 8 * 1024


class RequestSizeLimit:
    def __init__(self, app, max_bytes: int = DEFAULT_MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    @staticmethod
    def _too_large(limit: int) -> list[dict]:
        body = json.dumps({
            "detail": "request body too large",
            "limit_bytes": limit,
        }).encode()
        return [
            {"type": "http.response.start", "status": 413,
             "headers": [(b"content-type", b"application/json"),
                         (b"content-length", str(len(body)).encode()),
                         (b"connection", b"close")]},
            {"type": "http.response.body", "body": body},
        ]

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        for name, value in scope.get("headers", ()):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = self.max_bytes + 1      # unparseable: fail closed
                if declared > self.max_bytes:
                    for message in self._too_large(self.max_bytes):
                        await send(message)
                    return

        seen = 0
        exceeded = False

        async def counted_receive():
            nonlocal seen, exceeded
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    exceeded = True
                    # Stop the stream rather than hand the inner app a truncated
                    # body it might treat as complete: `more_body` false with an
                    # empty payload ends the request cleanly, and the guard below
                    # answers 413 instead of whatever the app made of it.
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        answered = False

        async def guarded_send(message):
            nonlocal answered
            if exceeded:
                return                                # discard the app's answer
            answered = True
            await send(message)

        await self.app(scope, counted_receive, guarded_send)
        if exceeded and not answered:
            for message in self._too_large(self.max_bytes):
                await send(message)
