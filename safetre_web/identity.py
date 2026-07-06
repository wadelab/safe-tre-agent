"""Identity = Safe People.

Behind `tailscale serve`, the proxy injects the authenticated tailnet identity
as the `Tailscale-User-Login` header. Because the app binds 127.0.0.1, only the
local tailscale proxy can reach it, so the header cannot be forged by a remote
client.

The load-bearing subtlety: **that header is only trustworthy while the app is
reachable solely over loopback.** The moment the restricted channel is widened
(e.g. `SAFETRE_CHANNEL_ALLOW_NETS` broadened to a LAN range), any host that can
reach the socket can forge `Tailscale-User-Login: someone@allowed.org` and
impersonate an allowlisted user — and the audit trail would attribute their
actions to the victim. Identity trust and channel trust were therefore silently
coupled. This module makes the coupling explicit and fails closed:

- If the channel is loopback-only, the header is trusted (the original posture).
- If the channel is widened, the header is trusted ONLY when the operator
  explicitly opts in with `SAFETRE_TRUST_FORWARDED_IDENTITY=1` (asserting a
  trusted upstream proxy that sets/strips the header). Otherwise identity is
  treated as unverified and fails closed.
- Independently, if `SAFETRE_PROXY_SHARED_SECRET` is set, the request must also
  carry a matching `X-Safetre-Proxy-Auth` header (constant-time compare) before
  the identity header is trusted — defence in depth for operators whose proxy can
  inject a secret.

Hardening notes:
- We trust ONLY the canonical `Tailscale-User-Login` header. The `X-...` variant
  is deliberately not accepted (a non-stripping upstream proxy would make it
  spoofable).
- The `127.0.0.1` bind is load-bearing. Never bind 0.0.0.0.
- Set `SAFETRE_REQUIRE_IDENTITY=1` in production to fail closed when no tailnet
  identity is present (instead of the `local@dev` development fallback).
"""

from __future__ import annotations

import hmac
import os

from fastapi import Request

from .channel import channel_is_loopback_only

_ALLOWLIST = {u.strip() for u in os.environ.get("SAFETRE_ALLOWLIST", "").split(",") if u.strip()}
_HEADER = "tailscale-user-login"
# HTTP header name the proxy secret is presented in (not itself a secret).
_SECRET_HEADER = "x-safetre-proxy-auth"  # nosec B105
_REQUIRE_IDENTITY = os.environ.get("SAFETRE_REQUIRE_IDENTITY", "").lower() in ("1", "true", "yes")


def _allowed(login: str) -> bool:
    return (not _ALLOWLIST) or (login in _ALLOWLIST)


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _secret_ok(request: Request) -> bool:
    """If a proxy shared secret is configured, require a matching header."""
    secret = os.environ.get("SAFETRE_PROXY_SHARED_SECRET", "")
    if not secret:
        return True
    presented = request.headers.get(_SECRET_HEADER, "")
    return hmac.compare_digest(presented, secret)


def _header_trustworthy(request: Request) -> bool:
    """Whether the identity header may be believed given the channel + secret."""
    if not _secret_ok(request):
        return False
    if channel_is_loopback_only():
        return True
    # channel is wider than loopback: only trust the header behind an explicit
    # "there is a trusted upstream proxy" opt-in.
    return _truthy("SAFETRE_TRUST_FORWARDED_IDENTITY")


def current_user(request: Request) -> tuple[str, bool]:
    """Return (login, allowed)."""
    login = request.headers.get(_HEADER)
    if login and _header_trustworthy(request):
        return login, _allowed(login)
    if login and not _header_trustworthy(request):
        # a header is present but cannot be trusted in this deployment -> refuse
        # to impersonate; fail closed rather than believe a spoofable header.
        return "unverified", False
    # no tailnet identity present
    if _REQUIRE_IDENTITY:
        return "anonymous", False           # fail closed in production
    return "local@dev", _allowed("local@dev")
