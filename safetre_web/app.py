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

import logging
import math
import os
import pathlib

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from safetre import __version__ as _version
from safetre import dataset as dataset_mod
from safetre import synth
from safetre.audit import AuditLog
from safetre.config import load_policy_config
from safetre.disclosure import DisclosurePolicy, build_vetter
from safetre.manifest import manifest_for_response, public_schema
from safetre.planner import LLMPlanner, MockPlanner
from safetre.query import CATALOGUE
from safetre.service import QueryService

from .channel import channel_allowed
from .identity import configuration_problems, current_user
from .rate import RateLimiter
from .session import SessionStore
from .timing import ResponseTimeBoundary, sleep_to_boundary  # noqa: F401

BASE = pathlib.Path(__file__).parent
app = FastAPI(title="safe-tre-agent", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(BASE / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

# One authoritative dataset definition: SAFETRE_DATASET points at the operator's
# YAML (docs/datasets.md); otherwise the packaged synthetic demo. Activation
# re-mirrors the catalogue, views and lexicon package-wide, so it must happen
# before the engine is built.
_env_dataset = os.environ.get("SAFETRE_DATASET")
if _env_dataset:
    dataset_mod.activate(dataset_mod.load_dataset(_env_dataset))
_definition = dataset_mod.active()

# One authoritative disclosure policy: defaults < config.yaml < env. This is what
# makes the thresholds in config.yaml / SAFETRE_MIN_CELL actually take effect.
_cfg = load_policy_config()
if synth.csvs_present(names=_definition.table_names()):
    _tables = synth.load_csvs(names=_definition.table_names())
elif dataset_mod.is_packaged_demo():
    _tables = synth.generate()
else:
    raise RuntimeError(
        f"dataset {_definition.name!r} (from {dataset_mod.active_source()}): "
        f"data/ does not hold one CSV per base table "
        f"({', '.join(_definition.table_names())}), and only the packaged demo "
        f"has a synthetic generator")
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
# A full-chain verification is an integrity scan, not an interactive read: it
# reads every row under the audit lock and recomputes every MAC. It gets its
# own, much tighter budget on top of the global one, because the ordinary rate
# still permits enough concurrent scans to matter (hardening #47).
verify_limiter = RateLimiter(
    int(os.environ.get("SAFETRE_AUDIT_VERIFY_RATE_LIMIT", "6")))

# Say out loud what the effective policy is, and refuse to be quiet about a
# production deployment whose Safe People gate is not configured. Both fail
# closed on the request path anyway; a deployment should learn which control is
# off before an analyst meets a wall of 403s, and a release should be traceable
# to the thresholds that allowed it (hardening #45, #46).
_log = logging.getLogger("safetre")
_log.info("active dataset: %s (%d base table(s), %d public dataset(s)) from %s",
          _definition.name, len(_definition.tables), len(_definition.datasets),
          dataset_mod.active_source())
_log.info("effective disclosure policy: %s", _cfg.digest())
for _problem in configuration_problems():
    _log.warning("Safe People misconfiguration: %s", _problem)

# Put the effective policy INSIDE the tamper-evident chain, at the point it
# takes effect (hardening #55). A released row records the request, the spec
# and the status but nothing about the thresholds that allowed it, so a clean
# release under `min_cell=1` is schema-identical to one under the shipped
# policy — the log could not answer "which rules approved this?", the question
# `CellVetter.describe` exists to answer. A distinguished record needs no
# schema change and no chain migration: every row after it is attributable to
# the policy in force at its own position in the chain.
#
# Rehydration runs FIRST, before this append: it verifies the chain and raises
# on a failure (hardening #59), and a log an operator is about to be told not
# to trust is not a log to write a fresh row into.
#
# Session state is a control, so it must not evaporate on a deploy. Rebuild each
# identity's differencing lineage and query budget from the audit log before the
# first request is served (hardening #49); without this, the two halves of a
# differencing pair could simply be split across a restart.
_restored = sessions.rehydrate(audit_log, _cfg.session_window_hours,
                               expected_head=_audit_head_anchor)
_log.info("restored %d session(s) from the last %d hour(s) of audit history",
          _restored, _cfg.session_window_hours)

audit_log.append(user="system", request="policy",
                 spec={"policy": _cfg.digest(), "dataset": _definition.name},
                 status="config", findings=[], output_shape=None)


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


# Registered between the security headers and the channel check, so it runs
# INSIDE the response-time padding (an unpadded 429 would be its own signal)
# and AFTER the channel gate (a request off the channel should not spend a
# bucket at all).
@app.middleware("http")
async def rate_limit(request: Request, call_next):
    """Rate-limit every route, not only `/api/query` (hardening #47).

    `limiter.allow` used to be called from one handler. `/api/audit/verify`,
    `/api/marginals`, `/api/schema` and `/api/manifest` were unlimited — and
    verify is not a cheap read: it rescans the whole HMAC chain holding the
    audit lock that every append also takes. Measured: 400 GETs drew zero 429s,
    and twelve concurrent verifiers moved `/api/query` median latency from
    51 ms to 1582 ms. At 31x that is not only a shared-fate denial of service
    on the control everything serialises on, it walks honest queries into the
    response-time ceiling, so the timing control starts refusing real analysis.

    Keyed on the authenticated login where there is one, and on the peer
    address otherwise, so an unauthenticated flood cannot spend an identity's
    budget — nor share one bucket with every other refused caller.
    """
    path = request.url.path
    if path == "/healthz" or path.startswith("/static"):
        return await call_next(request)
    user, allowed = current_user(request)
    key = user if allowed else f"peer:{request.client.host if request.client else '?'}"
    if not limiter.allow(key):
        return JSONResponse({"detail": "rate limit exceeded; slow down"},
                            status_code=429)
    return await call_next(request)


@app.middleware("http")
async def restricted_channel(request: Request, call_next):
    allowed, reason = channel_allowed(request)
    if not allowed:
        return JSONResponse(
            {"detail": "restricted channel required", "reason": reason},
            status_code=403,
        )
    return await call_next(request)


def _autorun_prefill() -> bool:
    """Whether a `/#q=...` link may run itself on load.

    Off by default (hardening #50): a link that runs on load writes an
    attacker-chosen request into the tamper-evident log under whoever opened
    it, and records it as answered. It survives only for the screenshot and
    deck scripts, which drive a headless browser that cannot click. Like
    `SAFETRE_ALLOW_TEST_CLIENT` this is a sentinel — never set it on a real
    deployment.
    """
    return os.environ.get("SAFETRE_ALLOW_PREFILL_AUTORUN", "").strip().lower() \
        in ("1", "true", "yes", "on")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user, allowed = current_user(request)
    manifest = manifest_for_response()
    return templates.TemplateResponse(request, "index.html", {
        "user": user, "allowed": allowed, "catalogue": CATALOGUE,
        "manifest": manifest, "schema": public_schema(),
        "autorun_prefill": _autorun_prefill(),
        "examples": _definition.ui_queries,
        "dataset_description": _definition.description,
        "version": _version,
    })


@app.post("/api/query", response_class=HTMLResponse)
def query(request: Request, body: QueryRequest):
    user, allowed = current_user(request)
    if not allowed:
        raise HTTPException(403, "not on the Safe People allowlist")
    # rate limiting moved to the `rate_limit` middleware (#47), which covers
    # every route; charging the bucket twice here would halve this one's budget

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
    user, allowed = current_user(request)
    if not allowed:
        raise HTTPException(403, "not on the Safe People allowlist")
    if not verify_limiter.allow(user):
        raise HTTPException(429, "audit verification is rate limited; slow down")
    return {"chain_intact": audit_log.verify(expected_head=_audit_head_anchor)}


# Added LAST so it is the OUTERMOST layer: the channel rejection, the rate
# limit, the identity gate and template rendering all happen inside its window.
# It is raw ASGI rather than an `@app.middleware("http")` function because only
# that can answer while the inner application is still running — see
# `safetre_web/timing.py` for the two measurements that forced it (#34, #54).
# The settings are read per request, not captured, so `config.yaml` and the
# environment stay the values that bite (R10) — and so the dials remain
# testable without rebuilding the application.
app.add_middleware(ResponseTimeBoundary,
                   settings=lambda: (_cfg.response_quantum_ms,
                                     _cfg.response_ceiling_ms))
