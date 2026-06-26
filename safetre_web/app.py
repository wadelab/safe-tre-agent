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

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from safetre import synth
from safetre.audit import AuditLog
from safetre.manifest import manifest_for_response
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

_data = pathlib.Path("data")
_tables = synth.load_csvs() if _data.is_dir() and any(_data.glob("*.csv")) else synth.generate()
service = QueryService(_tables)
audit_log = AuditLog(os.environ.get("SAFETRE_AUDIT_DB", "audit.db"))
sessions = SessionStore()
limiter = RateLimiter(int(os.environ.get("SAFETRE_RATE_LIMIT", "120")))


def make_planner():
    if os.environ.get("SAFETRE_LLM", "mock").lower() == "real":
        from safetre.llm import LLMClient
        return LLMPlanner(LLMClient())
    return MockPlanner()


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
        "manifest": manifest,
    })


@app.post("/api/query", response_class=HTMLResponse)
def query(request: Request, body: QueryRequest):
    user, allowed = current_user(request)
    if not allowed:
        raise HTTPException(403, "not on the Safe People allowlist")
    if not limiter.allow(user):
        raise HTTPException(429, "rate limit exceeded; slow down")

    sess = sessions.get(user)
    result = service.handle(body.q, make_planner(), auditor=sess.auditor,
                            audit_log=audit_log, user=user)
    sess.history.append((body.q, result.status))

    table_html = None
    if result.output is not None:
        table_html = result.output.to_html(index=False, border=0,
                                            classes="agg", escape=True)
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
def manifest():
    return manifest_for_response()


@app.get("/api/audit/verify")
def audit_verify():
    return {"chain_intact": audit_log.verify()}
