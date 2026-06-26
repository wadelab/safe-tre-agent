"""Identity = Safe People.

Behind `tailscale serve`, the proxy injects the authenticated tailnet identity
as the `Tailscale-User-Login` header. Because the app binds 127.0.0.1, only the
local tailscale proxy can reach it, so the header cannot be forged by a remote
client.

Hardening notes:
- We trust ONLY the canonical `Tailscale-User-Login` header. The `X-...` variant
  is deliberately not accepted (a non-stripping upstream proxy would make it
  spoofable).
- The `127.0.0.1` bind is load-bearing. Never bind 0.0.0.0.
- Set `SAFETRE_REQUIRE_IDENTITY=1` in production to fail closed when no tailnet
  identity is present (instead of the `local@dev` development fallback).
"""

from __future__ import annotations

import os

from fastapi import Request

_ALLOWLIST = {u.strip() for u in os.environ.get("SAFETRE_ALLOWLIST", "").split(",") if u.strip()}
_HEADER = "tailscale-user-login"
_REQUIRE_IDENTITY = os.environ.get("SAFETRE_REQUIRE_IDENTITY", "").lower() in ("1", "true", "yes")


def _allowed(login: str) -> bool:
    return (not _ALLOWLIST) or (login in _ALLOWLIST)


def current_user(request: Request) -> tuple[str, bool]:
    """Return (login, allowed)."""
    login = request.headers.get(_HEADER)
    if login:
        return login, _allowed(login)
    # no tailnet identity present
    if _REQUIRE_IDENTITY:
        return "anonymous", False           # fail closed in production
    return "local@dev", _allowed("local@dev")
