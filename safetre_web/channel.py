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


def restricted_channel_enabled() -> bool:
    return os.environ.get("SAFETRE_RESTRICTED_CHANNEL", "1").strip().lower() not in FALSEY


def _allowed_networks():
    raw = os.environ.get("SAFETRE_CHANNEL_ALLOW_NETS", DEFAULT_CHANNEL_NETS)
    nets = []
    for token in (part.strip() for part in raw.split(",")):
        if token:
            nets.append(ipaddress.ip_network(token, strict=False))
    return nets


def channel_allowed(request: Request) -> tuple[bool, str]:
    """Return whether this request arrived over an allowed physical/logical path."""
    if not restricted_channel_enabled():
        return True, "restricted channel disabled"
    if request.client is None:
        return False, "missing client address"

    host = request.client.host
    if host == "testclient":
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
