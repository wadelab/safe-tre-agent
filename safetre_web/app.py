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
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from safetre import __version__ as _version
from safetre import dataset as dataset_mod
from safetre import synth
from safetre.audit import AuditLog, claim_exclusive
from safetre.config import load_policy_config
from safetre.disclosure import DisclosurePolicy, build_vetter
from safetre.manifest import manifest_for_response, public_schema
from safetre.planner import LLMPlanner, MockPlanner
from safetre.query import CATALOGUE
from safetre.service import QueryService

from .body import DEFAULT_MAX_BODY_BYTES, RequestSizeLimit
from .channel import channel_allowed
from .headers import CSP
from .identity import (
    configuration_problems, current_user, is_production, rate_limit_key,
)
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
# `require_external_key` in production: without SAFETRE_AUDIT_KEY the log would
# be signed by a key generated beside it, so a host compromise holds both and
# can re-MAC a forged chain that verify() accepts — the exact threat the chain
# exists to address. The shipped unit set the database path and not the key,
# and startup only warned (hardening #65).
_audit_db = os.environ.get("SAFETRE_AUDIT_DB", "audit.db")
# One server process per audit database, checked rather than assumed (hardening
# #81). A second worker on the same database breaks the chain in ordinary
# operation — two writers append from the same head, nothing raises, and
# `verify()` goes False — and splits the session budget and the differencing
# lineage, which live in this process's memory, across processes that cannot
# see each other. The claim is held for the process lifetime; the kernel drops
# it when we exit, so a crash needs no cleanup.
_audit_claim = claim_exclusive(_audit_db)
audit_log = AuditLog(_audit_db, require_external_key=is_production())
# Off-box anchor for the audit chain head (optional); when set, /api/audit/verify
# checks the recomputed head against it, not just internal consistency.
# `.strip()` because an operator copy-pastes this off a terminal, and a
# trailing newline made the anchor miss, `rehydrate` raise, and the app refuse
# to start — pointing them at SAFETRE_ALLOW_UNVERIFIED_REHYDRATE, i.e. at
# turning the control off (round 11, #87). A malformed anchor is reported by
# `configuration_problems()` rather than silently ignored.
_audit_head_anchor = (os.environ.get("SAFETRE_AUDIT_HEAD_ANCHOR") or "").strip() or None
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
    # the RESOLVED policy, so the prompt's embedded manifest cannot announce a
    # `minimum_cell_size` the gateway is not enforcing — a planner uses that
    # number to decide what to ask for (#89)
    return LLMPlanner(LLMClient(), policy=_cfg)


def _format_p_value(value) -> str:
    try:
        p = float(value)
    except (TypeError, ValueError):
        return ""
    if not math.isfinite(p):
        return ""
    return f"{p:.3f}"


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    """A validation failure names the FIELD and the RULE, never the input.

    FastAPI's default handler echoes the offending value back inside the error
    body (`input`, and whatever a validator put in `ctx`). Two problems, one of
    them live (round 11, #85):

      * **It turns a 422 into a 500.** Rendering that body means encoding the
        input as UTF-8, and the input is exactly the thing that failed. A `q`
        carrying a lone surrogate — legal JSON, and an ordinary `str` once
        Python decodes it — made the default handler raise while building the
        refusal, so the caller got a bare 500 from Starlette's
        `ServerErrorMiddleware`. That is the one response class registered
        OUTSIDE every `@app.middleware`, so it is also the one that #77's
        header work cannot reach: no CSP, no `nosniff`.
      * **It is a reflection surface.** The body is the caller's own input, so
        nothing leaks about the data — but a fixed refusal is the house style
        everywhere else here, and an error that quotes untrusted content back
        is the shape #71 asked people to stop writing.

    The rule is still stated in full, because a validation failure is decided
    from the REQUEST: the analyst holds it and can see for themselves what is
    wrong. That is the same line `service.WITHHELD_MESSAGE` draws.
    """
    return JSONResponse(
        status_code=422,
        content={"detail": [{"loc": [str(p) for p in err.get("loc", ())],
                             "type": err.get("type", "value_error"),
                             "msg": str(err.get("msg", "invalid"))}
                            for err in exc.errors()]})


class QueryRequest(BaseModel):
    q: str = Field(..., min_length=1, max_length=500)

    @field_validator("q")
    @classmethod
    def storable(cls, value: str) -> str:
        """A request that cannot be written to the audit log is not a request
        this system can accept (hardening #85).

        `{"q": "…\\ud800"}` is legal JSON and Python decodes a lone surrogate
        into a perfectly ordinary `str`, which passes `max_length` — and then
        SQLite, which must encode TEXT as UTF-8, raises. That made R8's
        "exactly one audit record per request" breakable by anyone: HTTP 500,
        zero rows, and the auditor charged. Refusing at the boundary is the
        right place, because this is a fact about the REQUEST — the analyst
        holds it and can see for themselves what is wrong with it — so it may
        be explained in full, unlike a refusal decided from the data.
        """
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError(
                "the request contains characters that cannot be encoded "
                "(unpaired surrogates); send valid UTF-8") from None
        return value


# Runs INSIDE the response-time padding (an unpadded 429 would be its own
# signal) and AFTER the channel gate (a request off the channel should not
# spend a bucket at all).
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
    # `/static` (no slash) also matched `/static-anything`, an unmetered path
    # that is not a static file (round 10, #77)
    if path == "/healthz" or path.startswith("/static/"):
        return await call_next(request)
    key = rate_limit_key(request)
    if not limiter.allow(key):
        return JSONResponse({"detail": "rate limit exceeded; slow down"},
                            status_code=429)
    return await call_next(request)


@app.middleware("http")
async def same_site_only(request: Request, call_next):
    """Refuse a state-changing request that a browser says came from elsewhere
    (round-9 V15, hardening #70).

    There is no session cookie here — identity arrives as a header the proxy
    injects — so the classic CSRF token has nothing to protect. The ambient
    credential is the proxy itself: a page the analyst visits could try to make
    their browser issue a request through it, and the header would be attached
    for them. Today that fails anyway, because the only state-changing route
    takes JSON and a cross-origin JSON POST needs a preflight this app never
    answers. That is a defence by accident of content type, and it lasts
    exactly until someone adds a form-encoded endpoint.

    `Sec-Fetch-Site` is the browser's own account of where the request came
    from, so it cannot be forged by the page — and a non-browser client (curl,
    the CLI, the test client) simply does not send it, which is why an absent
    header is allowed. This refuses `cross-site` and `same-site` explicitly
    rather than allowlisting: those are the two values that mean "another
    origin caused this".
    """
    # `/api/audit/verify` is a GET with a real side effect: it rescans the
    # whole chain under the audit lock, which #47 measured at 31x median
    # latency for everyone. A visited page could fire the victim's whole
    # verify budget at it, so it is gated like a state-changing route
    # (round 10, #77).
    expensive_get = request.url.path == "/api/audit/verify"
    if expensive_get or request.method not in ("GET", "HEAD", "OPTIONS"):
        site = request.headers.get("sec-fetch-site", "")
        if site in ("cross-site", "same-site"):
            return JSONResponse(
                {"detail": "cross-origin request refused"}, status_code=403)
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


# Registered LAST of the `@app.middleware` functions, which makes it the
# OUTERMOST of them — so the headers land on responses the other layers
# generate themselves, not only on router output. They used to reach neither
# the 403s, the 413, the 429 nor the 503 refusal, while the module docstring
# claimed strict headers throughout; `nosniff` was missing on every one
# (round 10, #77). The bodies are fixed JSON so nothing was live, but a
# refusal is a response like any other.
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


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
    manifest = manifest_for_response(_cfg)
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
    return manifest_for_response(_cfg)


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
    # The head is returned so an operator can actually record an anchor: the
    # shipped unit told them to set SAFETRE_AUDIT_HEAD_ANCHOR to "the chain
    # head from /api/audit/verify" and nothing ever returned one (round 10,
    # #75). A MAC discloses nothing about the rows it covers.
    return {"chain_intact": audit_log.verify(expected_head=_audit_head_anchor),
            "head": audit_log.head_is_reachable(),
            "anchored": _audit_head_anchor is not None}


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

# And this one outside even that (hardening #64). The body ceiling is a cost
# control, not a disclosure control: a 413 tells the sender only how big their
# own request was. Padding it would mean holding an oversized body for the full
# quantum, which is the denial of service paying for itself.
app.add_middleware(RequestSizeLimit,
                   max_bytes=int(os.environ.get("SAFETRE_MAX_BODY_BYTES",
                                                DEFAULT_MAX_BODY_BYTES)))
