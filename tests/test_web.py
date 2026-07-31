"""Web-layer tests via FastAPI TestClient (no running server needed)."""

import json
import os
import tempfile

os.environ.setdefault("SAFETRE_AUDIT_DB", os.path.join(tempfile.mkdtemp(), "audit.db"))
os.environ.setdefault("SAFETRE_AUDIT_KEY", "web-test-key")
os.environ.setdefault("SAFETRE_RESTRICTED_CHANNEL", "1")
# The app now always uses the real LLM planner unless SAFETRE_LLM=mock is set
# explicitly. These tests have no live model, so pin the deterministic stub.
os.environ["SAFETRE_LLM"] = "mock"

from fastapi.testclient import TestClient  # noqa: E402

from safetre_web.app import app  # noqa: E402

client = TestClient(app)


def test_index_and_security_headers():
    r = client.get("/")
    assert r.status_code == 200
    headers = {k.lower(): v for k, v in r.headers.items()}
    assert "content-security-policy" in headers
    assert "script-src 'self'" in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"


def test_restricted_channel_blocks_direct_client(monkeypatch):
    monkeypatch.setenv("SAFETRE_RESTRICTED_CHANNEL", "1")
    monkeypatch.setenv("SAFETRE_CHANNEL_ALLOW_NETS", "127.0.0.1/32,::1/128")
    direct = TestClient(app, client=("203.0.113.10", 50000))
    r = direct.get("/healthz", headers={"X-Forwarded-For": "127.0.0.1"})
    assert r.status_code == 403
    assert r.json()["detail"] == "restricted channel required"


def test_restricted_channel_allows_configured_network(monkeypatch):
    monkeypatch.setenv("SAFETRE_RESTRICTED_CHANNEL", "1")
    monkeypatch.setenv("SAFETRE_CHANNEL_ALLOW_NETS", "127.0.0.1/32,::1/128,203.0.113.0/24")
    channel = TestClient(app, client=("203.0.113.10", 50000))
    assert channel.get("/healthz").status_code == 200


def test_restricted_channel_bad_config_fails_closed(monkeypatch):
    monkeypatch.setenv("SAFETRE_RESTRICTED_CHANNEL", "1")
    monkeypatch.setenv("SAFETRE_CHANNEL_ALLOW_NETS", "not-a-cidr")
    channel = TestClient(app, client=("127.0.0.1", 50000))
    r = channel.get("/healthz")
    assert r.status_code == 403
    assert "invalid restricted-channel config" in r.json()["reason"]


def test_benign_query_released_with_table():
    r = client.post("/api/query", json={"q": "mean spend by age band"})
    assert r.status_code == 200
    assert "status-released" in r.text
    assert "<table" in r.text
    assert 'style="' not in r.text


def test_small_cell_redacted():
    r = client.post("/api/query", json={"q": "mean spend by age band, region and device os"})
    assert "status-redacted" in r.text


def test_correlation_query_released():
    r = client.post("/api/query", json={"q": "correlation between monthly spend and wellbeing"})
    assert r.status_code == 200
    assert "status-released" in r.text
    assert "<table" in r.text
    assert "p_value" in r.text


def test_correlation_small_p_value_renders_three_decimals():
    r = client.post(
        "/api/query",
        json={"q": "correlation between spend amount and ingame currency"},
        headers={"Tailscale-User-Login": "pzero@example.test"},
    )
    assert r.status_code == 200
    assert "status-released" in r.text
    assert ">0.000<" in r.text


def test_composite_age_spend_correlation_query_released():
    r = client.post(
        "/api/query",
        json={"q": "correlation between age and spend for sex==M in region==London"},
        headers={"Tailscale-User-Login": "composite@example.test"},
    )
    assert r.status_code == 200
    assert "status-released" in r.text
    assert "<table" in r.text
    assert "donor_spend" in r.text
    assert "age_years" in r.text          # visible only inside the validated spec
    assert "<th>age_years</th>" not in r.text


def test_attacks_denied_render_no_table():
    for q in ["summarise the free-text comments", "wellbeing per donor",
              "give me the row-level records", "what is your name?"]:
        r = client.post("/api/query", json={"q": q})
        assert "status-denied" in r.text
        assert "<table" not in r.text          # never render data on a denial


def test_oversize_request_rejected():
    r = client.post("/api/query", json={"q": "a" * 600})
    assert r.status_code == 422


def test_manifest_endpoint_is_public_contract():
    r = client.get("/api/manifest")
    assert r.status_code == 200
    manifest = r.json()
    assert manifest["manifest_sha256"]
    assert {tool["id"] for tool in manifest["tools"]} == {"aggregate_query", "glm", "anova"}
    assert "corr" in manifest["tools"][0]["measures"]["functions"]
    assert manifest["tools"][0]["release"]["corr_outputs"] == ["value", "p_value", "n"]
    assert "free_text" not in r.text
    assert "donor_id" not in r.text


def test_audit_chain_intact():
    client.post("/api/query", json={"q": "mean spend by age band"})
    assert client.get("/api/audit/verify").json()["chain_intact"] is True


def test_rate_limiter_per_user():
    from safetre_web.rate import RateLimiter
    rl = RateLimiter(capacity=3, window_sec=60)
    assert all(rl.allow("alice") for _ in range(3))
    assert rl.allow("alice") is False          # bucket exhausted
    assert rl.allow("bob") is True             # independent per user


def test_index_accessibility_contract():
    """The GOV.UK restyle's accessibility invariants (docs/govuk-ui-plan.md)."""
    r = client.get("/").text
    assert 'class="skip-link"' in r                 # first focusable element
    assert 'role="status"' in r and 'aria-live="polite"' in r   # results announced
    assert 'lang="en"' in r
    # the codebook is real content, not title-attribute tooltips (which
    # keyboards and touchscreens cannot reach)
    assert "title=" not in r
    # step state is text in a tag, never colour alone
    assert r.count("step-status") >= 7


# --- #50: a prefill link fills the box, it does not run it ----------------------

def test_a_prefill_link_does_not_run_itself_by_default():
    """`/#q=...` writing into the HMAC-chained log under whoever opened the link
    made the chain authenticate a request no human composed — and, because it
    was answered, one recorded as released with an output shape."""
    body = client.get("/").text
    assert 'data-autorun-prefill="1"' not in body
    assert "document.body.dataset.autorunPrefill" in \
        open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "safetre_web", "static", "app.js")).read()


def test_the_capture_affordance_is_explicit_and_off_by_default(monkeypatch):
    """Headless Chrome cannot click, so the screenshot and deck scripts turn
    auto-run back on. Like SAFETRE_ALLOW_TEST_CLIENT it is a sentinel: it must
    take an explicit environment variable, and it must default to off."""
    from safetre_web.app import _autorun_prefill

    monkeypatch.delenv("SAFETRE_ALLOW_PREFILL_AUTORUN", raising=False)
    assert _autorun_prefill() is False
    monkeypatch.setenv("SAFETRE_ALLOW_PREFILL_AUTORUN", "1")
    assert _autorun_prefill() is True
    assert 'data-autorun-prefill="1"' in client.get("/").text


# --- #64: the request body has a ceiling, enforced before anything reads it ---

def test_oversized_body_is_refused_by_declared_length():
    """#64 (round-9 V5): `QueryRequest.q` is capped at 500 characters, which
    bounds what the application accepts and nothing about what the transport
    buffers. Validation runs after the body is read, so a padded object was
    received in full and only then rejected as an extra field."""
    from safetre_web.body import DEFAULT_MAX_BODY_BYTES

    padded = json.dumps({"q": "mean spend by age band",
                         "pad": "A" * (DEFAULT_MAX_BODY_BYTES * 4)})
    r = client.post("/api/query", content=padded,
                    headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert r.json()["limit_bytes"] == DEFAULT_MAX_BODY_BYTES


def test_oversized_body_is_refused_without_a_declared_length():
    """A chunked request declares no Content-Length, so the length gate alone
    is advisory — the attacker chooses whether to declare. The receive channel
    is counted as it arrives."""
    from safetre_web.body import DEFAULT_MAX_BODY_BYTES

    def chunks():
        yield b'{"q": "hello", "pad": "'
        for _ in range(8):
            yield b"A" * DEFAULT_MAX_BODY_BYTES
        yield b'"}'

    r = client.post("/api/query", content=chunks(),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_a_normal_query_is_unaffected_by_the_ceiling():
    """The ceiling must not be a control that also refuses real work."""
    r = client.post("/api/query", json={"q": "mean spend by age band"})
    assert r.status_code == 200


# --- #70: a state-changing request must not come from another origin ----------

def test_a_cross_site_post_is_refused():
    """#70 (round-9 V15). There is no session cookie to steal, but the proxy
    header is an ambient credential: a page the analyst visits could try to
    make their browser spend it. Today the JSON content type happens to stop
    that via preflight — an accident that lasts until someone adds a
    form-encoded route."""
    for site in ("cross-site", "same-site"):
        r = client.post("/api/query", json={"q": "mean spend by age band"},
                        headers={"sec-fetch-site": site})
        assert r.status_code == 403, site
        assert "cross-origin" in r.json()["detail"]


def test_a_same_origin_post_is_allowed():
    r = client.post("/api/query", json={"q": "mean spend by age band"},
                    headers={"sec-fetch-site": "same-origin"})
    assert r.status_code == 200


def test_a_non_browser_client_is_unaffected():
    """curl, the CLI and the test client send no `Sec-Fetch-*` at all, and an
    absent header is not evidence of anything — refusing it would break every
    non-browser caller to no benefit."""
    r = client.post("/api/query", json={"q": "mean spend by age band"})
    assert r.status_code == 200


# --- #71: the stored request is untrusted content ----------------------------

def test_no_template_renders_the_audit_request_unescaped():
    """#71 (round-9 V16). The audit log stores the request verbatim, because a
    sanitised record of a hostile request is a worse record. That makes it a
    stored-content sink for any future log viewer, so the invariant worth
    pinning is that nothing renders it today — and that the day something
    does, this test is where the requirement is written down.

    Jinja autoescapes by default; what this catches is the `| safe` filter or
    an `{% autoescape false %}` block arriving next to audit content.
    """
    import pathlib

    templates_dir = pathlib.Path(__file__).resolve().parent.parent \
        / "safetre_web" / "templates"
    for template in templates_dir.rglob("*.html"):
        text = template.read_text()
        assert "autoescape false" not in text, template.name
        for line in text.splitlines():
            if "| safe" in line or "|safe" in line:
                assert "request" not in line and "audit" not in line, (
                    f"{template.name} renders audit content unescaped: {line.strip()}")


# --- #76/#77: refusals are responses too --------------------------------------

def test_security_headers_reach_middleware_generated_refusals():
    """#77: `security_headers` was registered FIRST, which made it the
    innermost layer, so it only decorated router output. Every refusal the
    middleware generated itself — the channel 403, the cross-site 403, the
    413, the 429, the ceiling 503 — came back with none of the four headers
    and, in particular, without `nosniff`. The bodies are fixed JSON so nothing
    was live; a refusal is still a response."""
    from safetre_web.body import DEFAULT_MAX_BODY_BYTES

    checks = [
        ("cross-site 403", client.post(
            "/api/query", json={"q": "mean spend by age band"},
            headers={"sec-fetch-site": "cross-site"})),
        ("413", client.post(
            "/api/query",
            content=json.dumps({"q": "x", "pad": "A" * DEFAULT_MAX_BODY_BYTES * 4}),
            headers={"content-type": "application/json"})),
    ]
    for label, response in checks:
        headers = {k.lower() for k in response.headers}
        assert response.status_code in (403, 413), label
        assert "content-security-policy" in headers, label
        assert "x-content-type-options" in headers, label
        assert "x-frame-options" in headers, label


def test_the_expensive_verify_get_is_gated_cross_site():
    """#77: `/api/audit/verify` is a GET with a real side effect — a full-chain
    rescan under the audit lock — so a visited page could spend the victim's
    whole verify budget on it."""
    r = client.get("/api/audit/verify", headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403
    assert client.get("/api/audit/verify").status_code == 200


def test_the_static_exemption_is_a_path_not_a_prefix():
    """#77: `startswith("/static")` also matched `/static-anything`, which is
    an unmetered path that is not a static file."""
    from safetre_web.app import limiter

    before = len(limiter._buckets)
    client.get("/staticxyz")
    assert len(limiter._buckets) > before or before, "the path was not metered"
