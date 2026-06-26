"""Web layer for safe-tre-agent (Phase 1).

FastAPI over the GuardedQueryService. Binds localhost only; intended to be
exposed to a tailnet via `tailscale serve` (which supplies the authenticated
identity used for Safe People + the audit log).
"""
