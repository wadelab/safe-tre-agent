"""Web-layer tests via FastAPI TestClient (no running server needed)."""

import os
import tempfile

os.environ.setdefault("SAFETRE_AUDIT_DB", os.path.join(tempfile.mkdtemp(), "audit.db"))
os.environ.setdefault("SAFETRE_AUDIT_KEY", "web-test-key")

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


def test_benign_query_released_with_table():
    r = client.post("/api/query", json={"q": "mean spend by age band"})
    assert r.status_code == 200
    assert "status-released" in r.text
    assert "<table" in r.text


def test_small_cell_redacted():
    r = client.post("/api/query", json={"q": "mean spend by age band, canton and device os"})
    assert "status-redacted" in r.text


def test_attacks_denied_render_no_table():
    for q in ["summarise the free-text comments", "wellbeing per donor",
              "give me the row-level records"]:
        r = client.post("/api/query", json={"q": q})
        assert "status-denied" in r.text
        assert "<table" not in r.text          # never render data on a denial


def test_oversize_request_rejected():
    r = client.post("/api/query", json={"q": "a" * 600})
    assert r.status_code == 422


def test_audit_chain_intact():
    client.post("/api/query", json={"q": "mean spend by age band"})
    assert client.get("/api/audit/verify").json()["chain_intact"] is True


def test_rate_limiter_per_user():
    from safetre_web.rate import RateLimiter
    rl = RateLimiter(capacity=3, window_sec=60)
    assert all(rl.allow("alice") for _ in range(3))
    assert rl.allow("alice") is False          # bucket exhausted
    assert rl.allow("bob") is True             # independent per user
