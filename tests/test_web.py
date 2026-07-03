"""Web-layer tests via FastAPI TestClient (no running server needed)."""

import os
import tempfile

os.environ.setdefault("SAFETRE_AUDIT_DB", os.path.join(tempfile.mkdtemp(), "audit.db"))
os.environ.setdefault("SAFETRE_AUDIT_KEY", "web-test-key")
os.environ.setdefault("SAFETRE_RESTRICTED_CHANNEL", "1")

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
    r = client.post("/api/query", json={"q": "mean spend by age band, canton and device os"})
    assert "status-redacted" in r.text


def test_correlation_query_released():
    r = client.post("/api/query", json={"q": "correlation between monthly spend and wellbeing"})
    assert r.status_code == 200
    assert "status-released" in r.text
    assert "<table" in r.text
    assert "p_value" in r.text


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
    assert {tool["id"] for tool in manifest["tools"]} == {"aggregate_query"}
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
