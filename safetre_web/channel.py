"""Restricted-channel enforcement for the safepod boundary.

The web app should only be reachable through the narrow channel that bridges
into the safepod. In the default deployment this means `tailscale serve` talks
to uvicorn over loopback, and researchers never reach uvicorn directly.

This check is defence in depth for a bad bind address or firewall mistake. It
uses the real peer address reported by ASGI and deliberately ignores forwarded
headers, which are data supplied by the caller unless a trusted proxy strips
and rewrites them.
"""

from __future__ import annotations

import ipaddress
import os

from fastapi import Request

DEFAULT_CHANNEL_NETS = "127.0.0.1/32,::1/128"
FALSEY = {"0", "false", "no", "off"}
TRUTHY = {"1", "true", "yes", "on"}


def restricted_channel_enabled() -> bool:
    return os.environ.get("SAFETRE_RESTRICTED_CHANNEL", "1").strip().lower() not in FALSEY


def _test_client_allowed() -> bool:
    """Starlette's TestClient presents peer host 'testclient'. Honouring it is a
    test affordance, so it is OFF by default and must be explicitly enabled
    (tests set SAFETRE_ALLOW_TEST_CLIENT via conftest). Never leave it on in a
    real deployment: it is a channel-check bypass sentinel."""
    return os.environ.get("SAFETRE_ALLOW_TEST_CLIENT", "").strip().lower() in TRUTHY


def _allowed_networks():
    raw = os.environ.get("SAFETRE_CHANNEL_ALLOW_NETS", DEFAULT_CHANNEL_NETS)
    nets = []
    for token in (part.strip() for part in raw.split(",")):
        if token:
            nets.append(ipaddress.ip_network(token, strict=False))
    return nets


def _net_is_loopback(net) -> bool:
    return net.network_address.is_loopback and net.broadcast_address.is_loopback


def channel_is_loopback_only() -> bool:
    """True iff the restricted channel is enabled and admits only loopback peers.

    Identity trust (the `Tailscale-User-Login` header) is only sound when the app
    is reachable solely over loopback, because the header is otherwise forgeable
    by anyone who can reach the socket. `identity.py` uses this to decide whether
    trusting the header is safe or must be gated behind an explicit opt-in.
    """
    if not restricted_channel_enabled():
        return False
    try:
        nets = _allowed_networks()
    except ValueError:
        return False
    return bool(nets) and all(_net_is_loopback(net) for net in nets)


def channel_allowed(request: Request) -> tuple[bool, str]:
    """Return whether this request arrived over an allowed physical/logical path."""
    if not restricted_channel_enabled():
        return True, "restricted channel disabled"
    if request.client is None:
        return False, "missing client address"

    host = request.client.host
    if host == "testclient" and _test_client_allowed():
        return True, "test client"

    try:
        peer = ipaddress.ip_address(host)
    except ValueError:
        return False, f"invalid client address {host!r}"

    try:
        allowed = _allowed_networks()
    except ValueError as exc:
        return False, f"invalid restricted-channel config: {exc}"
    if any(peer in net for net in allowed):
        return True, "allowed channel"
    return False, f"client address {host} is outside the restricted channel"
