"""The security headers, once, so the layers outside the header middleware
carry them too.

`security_headers` is a `@app.middleware` function, so it can only decorate
what the layers inside it produce. The body ceiling and the response-time
boundary are raw ASGI and deliberately OUTSIDE it — one has to refuse before
anything reads the body, the other has to answer while the inner application is
still running — so their refusals would otherwise go out bare (round 10, #77).
"""

from __future__ import annotations

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
       "script-src 'self'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")

SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
]
