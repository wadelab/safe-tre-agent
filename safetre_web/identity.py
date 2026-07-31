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

- If the channel is widened, the header is trusted ONLY when the operator
  explicitly opts in with `SAFETRE_TRUST_FORWARDED_IDENTITY=1` (asserting a
  trusted upstream proxy that sets/strips the header). Otherwise identity is
  treated as unverified and fails closed.
- In production (`SAFETRE_REQUIRE_IDENTITY=1`) the request must ALSO carry a
  matching `X-Safetre-Proxy-Auth` header (constant-time compare), and an
  explicit `SAFETRE_ALLOWLIST` must be set. Both fail closed.

**Loopback is not a trust boundary here, and treating it as one was the bug.**
The original posture trusted the header whenever the channel admitted only
loopback peers, reasoning that just the local proxy could reach the socket.
The threat model says otherwise: `docs/security.md` places the model runtime in
the UNTRUSTED zone and `deploy/safetre-web.service` runs it at
`127.0.0.1:8000`. So the condition chosen to justify trusting the header is
exactly the condition under which an untrusted component can forge it. Any
local process could present any login; the audit log attributed its queries to
that person; and because the session budget and the differencing lineage are
keyed on the login, rotating the header reset both. Hardening #45 therefore
requires the shared secret in production rather than merely honouring it when
present — that is the one measure verified to refuse a forged header.

Hardening notes:
- We trust ONLY the canonical `Tailscale-User-Login` header. The `X-...` variant
  is deliberately not accepted (a non-stripping upstream proxy would make it
  spoofable).
- A repeated or comma-joined identity header is refused, not resolved.
- The `127.0.0.1` bind is load-bearing. Never bind 0.0.0.0.
- Set `SAFETRE_REQUIRE_IDENTITY=1` in production to fail closed when no tailnet
  identity is present (instead of the `local@dev` development fallback).
"""

from __future__ import annotations

import hmac
import os

from fastapi import Request

from .channel import channel_is_loopback_only

_HEADER = "tailscale-user-login"
# HTTP header name the proxy secret is presented in (not itself a secret).
_SECRET_HEADER = "x-safetre-proxy-auth"  # nosec B105


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _allowlist() -> set[str]:
    """The Safe People allowlist, read at call time.

    Read per request rather than captured at import: a module-level snapshot
    makes the value depend on which module imported this one first, which is
    the trap hardening #36 was about, and it makes the gate untestable without
    reimporting.
    """
    return {u.strip() for u in os.environ.get("SAFETRE_ALLOWLIST", "").split(",")
            if u.strip()}


def _require_identity() -> bool:
    return _truthy("SAFETRE_REQUIRE_IDENTITY")


def is_production() -> bool:
    """`SAFETRE_REQUIRE_IDENTITY=1` is what a real deployment sets, so it is
    the marker other controls read to decide whether a development convenience
    is still acceptable (the audit key's dev fallback, hardening #65)."""
    return _require_identity()


def _allowed(login: str) -> bool:
    """Whether this login is a Safe Person.

    An EMPTY allowlist means "everyone" in development and "nobody" in
    production. AGENTS.md requires a production deployment to set both
    `SAFETRE_REQUIRE_IDENTITY=1` and an explicit allowlist; the shipped unit
    set the first and not the second, so every forged login was admitted and
    the Safe People gate — which reads like a control — was not one
    (hardening #45). Failing closed here makes the missing allowlist loud
    instead of silent.
    """
    allowlist = _allowlist()
    if not allowlist:
        return not _require_identity()
    return login in allowlist


def _secret_ok(request: Request) -> bool:
    """Whether the proxy shared secret is present and correct.

    Required whenever `SAFETRE_REQUIRE_IDENTITY=1`, not merely honoured when
    configured. The old rule — trust the header on a loopback-only channel —
    took "only the local proxy can reach the socket" as given. The threat model
    does not: `docs/security.md` puts the model runtime in the UNTRUSTED zone,
    and `deploy/safetre-web.service` runs it at `127.0.0.1:8000`. Loopback is
    therefore a shared trust domain, and any local process — the model server,
    the checker, a cron job — could present any login and have the audit log
    attribute its queries to that person. Verified against a real server:
    21 forged requests accepted and attributed to a victim, and each new login
    minted a fresh session budget and empty differencing lineage, so the
    session controls were keyed on a string the caller chose.
    """
    secret = os.environ.get("SAFETRE_PROXY_SHARED_SECRET", "")
    if not secret:
        return not _require_identity()
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


def _presented_login(request: Request) -> str | None:
    """The single identity this request presents, or None.

    Ambiguity is refused rather than resolved. Starlette returns the FIRST of a
    repeated header, which is the wrong way round when the upstream proxy
    appends rather than replaces — the client's forged value would win — and
    there is no reading of two identities that is safe to guess at. A
    comma-joined value is refused for the same reason: it was accepted verbatim
    as one login, so `"a@org, b@org"` became a session key and an audit
    identity of its own (hardening #45).
    """
    headers = request.headers
    getlist = getattr(headers, "getlist", None)
    values = list(getlist(_HEADER)) if getlist is not None else (
        [v] if (v := headers.get(_HEADER)) is not None else [])
    if len(values) != 1:
        return None if not values else ""       # "" -> present but ambiguous
    login = values[0].strip()
    if not login or "," in login:
        return ""
    return login


def configuration_problems() -> list[str]:
    """Production settings that read as controls but are not configured.

    Reported at startup so an operator learns before an analyst does. The
    request path fails closed on each of these independently; this exists so
    the failure is explicable rather than a wall of 403s.
    """
    problems = []
    if _require_identity():
        if not os.environ.get("SAFETRE_PROXY_SHARED_SECRET", ""):
            problems.append(
                "SAFETRE_REQUIRE_IDENTITY=1 without SAFETRE_PROXY_SHARED_SECRET: "
                "the identity header is forgeable by any process that can reach "
                "the socket, loopback included, so it is not trusted")
        if not _allowlist():
            problems.append(
                "SAFETRE_REQUIRE_IDENTITY=1 without SAFETRE_ALLOWLIST: the Safe "
                "People gate admits nobody until an allowlist is set")
        if not os.environ.get("SAFETRE_AUDIT_HEAD_ANCHOR", "").strip():
            problems.append(
                "SAFETRE_REQUIRE_IDENTITY=1 without SAFETRE_AUDIT_HEAD_ANCHOR: "
                "the chain is checked only for internal consistency, so a "
                "wholesale rewrite by someone holding the key verifies. An "
                "off-box anchor is what makes that detectable")
    # Shape-checked whatever the posture: an anchor that is not 64 hex will
    # never match a MAC, so it fails the chain at startup and reads as
    # tampering. Said here so the operator learns it is their typo (#87).
    anchor = os.environ.get("SAFETRE_AUDIT_HEAD_ANCHOR", "").strip()
    if anchor and (len(anchor) != 64
                   or any(c not in "0123456789abcdef" for c in anchor.lower())):
        problems.append(
            "SAFETRE_AUDIT_HEAD_ANCHOR is not 64 hex characters, so it cannot "
            "match any chain head: the app will refuse to start and report the "
            "chain unverified. Copy the `head` from /api/audit/verify")
    problems += waived_controls()
    return problems


# Every environment variable whose whole purpose is to turn a control OFF, and
# what each one stops doing. Reported by `configuration_problems()` because
# #73's deploy-unit test derives its requirements from this function — so
# adding a sentinel here makes the test demand the shipped unit not set it,
# without restating a list anywhere (round 11, #99).
#
# #73 closed one half of "nothing in CI reads the shipped unit": that it SETS
# what production needs. The other half was that it must not set what production
# forbids, and a unit carrying all eight of these passed all eight deploy tests
# while serving a 1-donor cell threshold with no rounding.
CONTROL_WAIVERS = {
    "SAFETRE_ALLOW_UNSAFE_POLICY":
        "the resolved-policy safety floors are not enforced",
    "SAFETRE_ALLOW_HOST_AUDIT_KEY":
        "the audit chain may be signed by a key generated beside it (#65)",
    "SAFETRE_ALLOW_UNVERIFIED_REHYDRATE":
        "session state is rebuilt from a chain that failed to verify (#59)",
    "SAFETRE_ALLOW_UNMARKED_CHAIN":
        "the truncation check is skipped on a chain with no high-water mark (#82)",
    "SAFETRE_ALLOW_TEST_CLIENT":
        "the restricted-channel check honours the test client's fake peer",
    "SAFETRE_ALLOW_PREFILL_AUTORUN":
        "a visited `/#q=` link may run itself on load (#50)",
    "SAFETRE_ALLOW_REMOTE_LLM":
        "the model endpoint host allowlist is not enforced; research questions "
        "may leave the safepod",
    "SAFETRE_TRUST_FORWARDED_IDENTITY":
        "the identity header is believed from beyond loopback",
}


def waived_controls() -> list[str]:
    """Which control-waiving sentinels are set in this environment."""
    return [f"{name} is set: {effect}"
            for name, effect in sorted(CONTROL_WAIVERS.items())
            if os.environ.get(name, "").strip()
            and os.environ.get(name, "").strip().lower() not in ("0", "false", "no", "off")]


def identity_is_verifiable() -> bool:
    """Whether a presented login can be BELIEVED in this deployment.

    `_header_trustworthy` answers "is the header good enough to act on", and
    outside production it says yes vacuously: `_secret_ok` returns
    `not _require_identity()` when no secret is configured, and `_allowed`
    does the same for an empty allowlist. That is the right answer for
    AUTHORISATION in a demo — there is nobody to impersonate — and the wrong
    answer for a resource KEY, where the question is not "may this caller in"
    but "can this caller choose their own bucket" (round 11, #91).

    So: a login is a sound key only where a proxy secret actually exists and
    actually matched.
    """
    return bool(os.environ.get("SAFETRE_PROXY_SHARED_SECRET", ""))


def _peer_key(request: Request) -> str:
    client = request.client
    return f"peer:{client.host if client else '?'}"


def rate_limit_key(request: Request) -> str:
    """The bucket a request's rate limit is charged to.

    The login ONLY when the header is trustworthy in this deployment — that is,
    when a proxy secret is configured AND checks out. In production that is
    already true; in the default/demo posture there is no secret and no
    allowlist, so `current_user` returns `(login, True)` for any string the
    caller invents and every rotation of the header minted a fresh bucket: the
    limiter was keyed on something the caller chooses (round 10, #77, the same
    root as #45). Falling back to the peer address costs nothing where identity
    is real and is the only sound key where it is not.

    **Round 11, #91**: the first version of this gated on `_header_trustworthy`
    alone, which is vacuously true outside production — so in the posture the
    docstring named as the problem, the docstring was describing a check the
    code was not making. Both directions were live: mint fresh buckets to
    escape the limit, or name a victim to spend theirs.

    The key is length-bounded for the same reason `timing._caller` bounds
    itself: it becomes a dictionary key, and `max_keys` counts entries rather
    than bytes, so an 8 kB header against a 100 000-key bound is 0.8 GB inside
    a `MemoryMax=1G` unit.
    """
    login = _presented_login(request)
    if (login and identity_is_verifiable()
            and _header_trustworthy(request) and _allowed(login)):
        return login[:200]
    return _peer_key(request)


def current_user(request: Request) -> tuple[str, bool]:
    """Return (login, allowed)."""
    login = _presented_login(request)
    if login == "":
        # a header is present but ambiguous (repeated, or comma-joined)
        return "unverified", False
    if login and _header_trustworthy(request):
        return login, _allowed(login)
    if login and not _header_trustworthy(request):
        # a header is present but cannot be trusted in this deployment -> refuse
        # to impersonate; fail closed rather than believe a spoofable header.
        return "unverified", False
    # no tailnet identity present
    if _require_identity():
        return "anonymous", False           # fail closed in production
    return "local@dev", _allowed("local@dev")
