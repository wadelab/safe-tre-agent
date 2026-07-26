"""FastAPI app — Phase 1 of the secure web interface.

Security posture:
- binds 127.0.0.1 only (exposed via `tailscale serve`);
- rejects requests outside the configured restricted channel;
- strict security headers incl. a tight Content-Security-Policy (script-src 'self');
- requests validated by Pydantic (length-capped); JSON only (no multipart dep);
- identity -> Safe People allowlist; per-user SessionAuditor;
- every request written to the hash-chained audit log;
- the model never runs code — it only proposes a QuerySpec (see safetre.service).
"""

from __future__ import annotations

import os
import pathlib
import math

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from safetre import synth
from safetre.audit import AuditLog
from safetre.config import load_policy_config
from safetre.disclosure import DisclosurePolicy, build_vetter
from safetre.manifest import manifest_for_response, public_schema
from safetre.planner import LLMPlanner, MockPlanner
from safetre.query import CATALOGUE
from safetre.service import QueryService

from .channel import channel_allowed
from .identity import current_user
from .rate import RateLimiter
from .session import SessionStore

BASE = pathlib.Path(__file__).parent
app = FastAPI(title="safe-tre-agent", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(BASE / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

# One authoritative disclosure policy: defaults < config.yaml < env. This is what
# makes the thresholds in config.yaml / SAFETRE_MIN_CELL actually take effect.
_cfg = load_policy_config()
_data = pathlib.Path("data")
_tables = synth.load_csvs() if _data.is_dir() and any(_data.glob("*.csv")) else synth.generate()
_policy = DisclosurePolicy(
    threshold=_cfg.min_cell_size, max_rows=_cfg.max_output_rows,
    dom_threshold=_cfg.dom_threshold, influence_threshold=_cfg.influence_threshold,
    round_base=_cfg.round_base,
    moment2_dom_threshold=_cfg.moment2_dom_threshold,
    vetter=build_vetter(_cfg.vetter, _cfg.checker_cmd))
service = QueryService(_tables, _policy)
audit_log = AuditLog(os.environ.get("SAFETRE_AUDIT_DB", "audit.db"))
# Off-box anchor for the audit chain head (optional); when set, /api/audit/verify
# checks the recomputed head against it, not just internal consistency.
_audit_head_anchor = os.environ.get("SAFETRE_AUDIT_HEAD_ANCHOR") or None
sessions = SessionStore(threshold=_cfg.differencing_delta, budget=_cfg.query_budget)
limiter = RateLimiter(int(os.environ.get("SAFETRE_RATE_LIMIT", "120")))


def make_planner():
    """Always plan with the real (online/local) LLM.

    There is no silent offline fallback: if the model is missing or unreachable
    the request fails loudly rather than quietly dropping to the deterministic
    MockPlanner. The stub ignores group-by and other request nuance, so falling
    back to it silently degrades result quality (e.g. a grouped correlation
    collapses to a single aggregate). The offline stub is opt-in for tests/CI
    only, via an explicit SAFETRE_LLM=mock; an unrecognised mode is a
    configuration error and fails loudly.
    """
    from safetre.llm import LLMClient, resolve_planner_mode
    if resolve_planner_mode(default="real") == "mock":
        return MockPlanner()
    return LLMPlanner(LLMClient())


def _format_p_value(value) -> str:
    try:
        p = float(value)
    except (TypeError, ValueError):
        return ""
    if not math.isfinite(p):
        return ""
    return f"{p:.3f}"


class QueryRequest(BaseModel):
    q: str = Field(..., min_length=1, max_length=500)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.middleware("http")
async def restricted_channel(request: Request, call_next):
    allowed, reason = channel_allowed(request)
    if not allowed:
        return JSONResponse(
            {"detail": "restricted channel required", "reason": reason},
            status_code=403,
        )
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user, allowed = current_user(request)
    manifest = manifest_for_response()
    return templates.TemplateResponse(request, "index.html", {
        "user": user, "allowed": allowed, "catalogue": CATALOGUE,
        "manifest": manifest, "schema": public_schema(),
    })


@app.post("/api/query", response_class=HTMLResponse)
def query(request: Request, body: QueryRequest):
    user, allowed = current_user(request)
    if not allowed:
        raise HTTPException(403, "not on the Safe People allowlist")
    if not limiter.allow(user):
        raise HTTPException(429, "rate limit exceeded; slow down")

    sess = sessions.get(user)
    # Serialise a single identity's requests across the whole check-then-act
    # critical section (observe -> apply -> record_cohort). Without this, two
    # concurrent requests could both pass the differencing-lineage check before
    # either records its cohort, bypassing the control. Cross-user parallelism is
    # unaffected — the lock is per session.
    with sess.lock:
        result = service.handle(body.q, make_planner(), auditor=sess.auditor,
                                audit_log=audit_log, user=user)
        sess.history.append((body.q, result.status))

    table_html = None
    if result.output is not None:
        formatters = {"p_value": _format_p_value} if "p_value" in result.output.columns else None
        table_html = result.output.to_html(index=False, border=0,
                                            classes="agg", escape=True,
                                            formatters=formatters)
        table_html = table_html.replace(' style="text-align: right;"', "")
    spent = getattr(sess.auditor, "_spent", 0)
    return templates.TemplateResponse(request, "_result.html", {
        "r": result, "table_html": table_html,
        "budget_left": max(0, sess.auditor.budget - spent),
    })


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/api/manifest")
def manifest(request: Request):
    _, allowed = current_user(request)
    if not allowed:
        raise HTTPException(403, "not on the Safe People allowlist")
    return manifest_for_response()


@app.get("/api/schema")
def schema(request: Request):
    """The disclosure-safe data dictionary: each dataset's dimensions and
    measures with type, disclosure role, description and declared value domains.
    Design-time metadata only — the study codebook, no row counts (those are
    /api/marginals). Lets an analyst see the legal filter/group-by vocabulary
    without guessing. Gated on the Safe People allowlist like the other
    metadata endpoints."""
    _, allowed = current_user(request)
    if not allowed:
        raise HTTPException(403, "not on the Safe People allowlist")
    return public_schema()


@app.get("/api/marginals")
def marginals(request: Request):
    """The disclosure-safe donor-frequency table the differencing auditor's
    decision is defined against (sub-threshold cells reported as null). Publishing
    it is what lets an analyst reproduce the auditor's deny/allow decision — the
    simulatable-auditing property (see docs/security.md)."""
    _, allowed = current_user(request)
    if not allowed:
        raise HTTPException(403, "not on the Safe People allowlist")
    return service.engine.published_marginal_donor_counts(
        threshold=_cfg.min_cell_size, round_base=_cfg.round_base)


@app.get("/api/audit/verify")
def audit_verify(request: Request):
    _, allowed = current_user(request)
    if not allowed:
        raise HTTPException(403, "not on the Safe People allowlist")
    return {"chain_intact": audit_log.verify(expected_head=_audit_head_anchor)}
