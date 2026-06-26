"""Identity = Safe People.

Behind `tailscale serve`, the proxy injects the authenticated tailnet identity
as a header. Because the app binds 127.0.0.1, only the local tailscale proxy can
reach it, so a remote client cannot forge that header. An optional allowlist
(SAFETRE_ALLOWLIST, comma-separated logins) is the application-level gate.
"""

from __future__ import annotations

import os

from fastapi import Request

_ALLOWLIST = {u.strip() for u in os.environ.get("SAFETRE_ALLOWLIST", "").split(",") if u.strip()}
_HEADERS = ("tailscale-user-login", "x-tailscale-user-login")


def current_user(request: Request) -> tuple[str, bool]:
    """Return (login, allowed)."""
    login = next((request.headers[h] for h in _HEADERS if h in request.headers), None)
    if not login:
        login = "local@dev"          # no tailscale header => local-only dev (localhost bind)
    allowed = (not _ALLOWLIST) or (login in _ALLOWLIST)
    return login, allowed
