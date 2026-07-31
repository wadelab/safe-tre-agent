"""Tests for local-first, model-agnostic LLM configuration."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

import pytest

from safetre.llm import (
    DEFAULT_LLM_BASE_URL,
    DEFAULT_LLM_MODEL,
    LLMClient,
    LLMConfig,
    real_llm_enabled,
)


LLM_ENV = [
    "SAFETRE_LLM_BASE_URL",
    "SAFETRE_LLM_MODEL",
    "SAFETRE_LLM_PROVIDER",
    "SAFETRE_LLM_API_KEY",
    "SAFETRE_LLM_TEMPERATURE",
    "SAFETRE_LLM_TIMEOUT",
    "SAFETRE_ALLOWED_LLM_HOSTS",
    "SAFETRE_ALLOW_REMOTE_LLM",
    "SAFETRE_LLM",
    "OPENAI_BASE_URL",
    "OPENAI_API_KEY",
    "SAFETRE_MODEL",
]


def clear_llm_env(monkeypatch):
    for name in LLM_ENV:
        monkeypatch.delenv(name, raising=False)


def test_llm_config_defaults_to_local_120b_profile(monkeypatch):
    clear_llm_env(monkeypatch)
    cfg = LLMConfig.from_env()
    assert cfg.base_url == DEFAULT_LLM_BASE_URL
    assert cfg.model == DEFAULT_LLM_MODEL
    assert cfg.api_key == "local"
    assert cfg.temperature == 0.0


def test_llm_config_prefers_safetre_env_over_legacy_openai_env(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "legacy-key")
    monkeypatch.setenv("SAFETRE_MODEL", "legacy-model")
    monkeypatch.setenv("SAFETRE_LLM_BASE_URL", "http://127.0.0.1:9000/v1")
    monkeypatch.setenv("SAFETRE_LLM_API_KEY", "pod-key")
    monkeypatch.setenv("SAFETRE_LLM_MODEL", "pod-120b")
    cfg = LLMConfig.from_env()
    assert cfg.base_url == "http://127.0.0.1:9000/v1"
    assert cfg.api_key == "pod-key"
    assert cfg.model == "pod-120b"


def test_llm_config_rejects_remote_endpoint_by_default(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("SAFETRE_LLM_BASE_URL", "https://openrouter.ai/api/v1")
    with pytest.raises(ValueError, match="not allowed"):
        LLMConfig.from_env()


def test_llm_config_allows_named_in_safepod_model_host(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("SAFETRE_LLM_BASE_URL", "http://model-gateway:8000/v1")
    monkeypatch.setenv("SAFETRE_ALLOWED_LLM_HOSTS", "localhost,127.0.0.1,model-gateway")
    cfg = LLMConfig.from_env()
    assert cfg.base_url == "http://model-gateway:8000/v1"


def test_llm_config_allows_remote_only_when_explicitly_enabled(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("SAFETRE_LLM_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setenv("SAFETRE_ALLOW_REMOTE_LLM", "1")
    assert LLMConfig.from_env().base_url == "https://openrouter.ai/api/v1"


def test_remote_endpoint_configured_via_generic_env(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("SAFETRE_LLM", "real")
    monkeypatch.setenv("SAFETRE_ALLOW_REMOTE_LLM", "1")
    monkeypatch.setenv("SAFETRE_LLM_BASE_URL", "https://remote.example/v1")
    monkeypatch.setenv("SAFETRE_LLM_MODEL", "provider/model-id")
    monkeypatch.setenv("SAFETRE_LLM_API_KEY", "remote-key")
    cfg = LLMConfig.from_env()
    assert cfg.base_url == "https://remote.example/v1"
    assert cfg.model == "provider/model-id"
    assert cfg.api_key == "remote-key"


def test_api_key_prefers_safetre_over_legacy_openai_env(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "legacy-key")
    monkeypatch.setenv("SAFETRE_LLM_API_KEY", "safetre-key")
    assert LLMConfig.from_env().api_key == "safetre-key"


def test_provider_profile_env_is_rejected_loudly(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("SAFETRE_LLM_PROVIDER", "some-provider")
    with pytest.raises(ValueError, match="no longer supported"):
        LLMConfig.from_env()


def test_planner_mode_real_and_mock(monkeypatch):
    clear_llm_env(monkeypatch)
    assert real_llm_enabled() is False          # unset -> offline mock (CLI default)
    monkeypatch.setenv("SAFETRE_LLM", "mock")
    assert real_llm_enabled() is False
    monkeypatch.setenv("SAFETRE_LLM", "real")
    assert real_llm_enabled() is True


def test_unknown_planner_mode_fails_loudly_not_silently(monkeypatch):
    clear_llm_env(monkeypatch)
    monkeypatch.setenv("SAFETRE_LLM", "some-old-profile")
    with pytest.raises(ValueError, match="unknown SAFETRE_LLM mode"):
        real_llm_enabled()


def test_llm_client_speaks_chat_completions_protocol(monkeypatch):
    clear_llm_env(monkeypatch)
    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen["path"] = self.path
            seen["auth"] = self.headers.get("Authorization")
            length = int(self.headers["Content-Length"])
            seen["body"] = json.loads(self.rfile.read(length))
            payload = {"choices": [{"message": {"content": "```python\nresult = 1\n```"}}]}
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}/v1"
        client = LLMClient(base_url=base_url, model="pod-120b", api_key="pod-key")
        assert client.complete("system", "user") == "result = 1"
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert seen["path"] == "/v1/chat/completions"
    assert seen["auth"] == "Bearer pod-key"
    assert seen["body"]["model"] == "pod-120b"
    assert seen["body"]["stream"] is False
    assert seen["body"]["messages"] == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]


def test_llm_client_accepts_data_wrapped_response(monkeypatch):
    """Some API gateways wrap the chat-completions payload in a data envelope."""
    clear_llm_env(monkeypatch)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers["Content-Length"])
            self.rfile.read(length)
            payload = {
                "success": True,
                "data": {"choices": [{"message": {"content": "{\"ok\":true}"}}]},
            }
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}/v1"
        client = LLMClient(base_url=base_url, model="pod-120b", api_key="pod-key")
        assert client.complete("system", "user") == "{\"ok\":true}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


# --- #80: the allowlist is checked on the URL we ask for --------------------

def test_a_redirect_cannot_move_the_request_off_the_allowlisted_host(monkeypatch):
    """#80 (round 11). `validate()` checks the CONFIGURED host once, and
    `urllib` then follows 301/302/303 on a POST by default — downgrading it to
    a GET and carrying every header except Content-Length and Content-Type to
    the new host, the `Authorization` bearer token included.

    The model runtime writes the response, and `docs/security.md` puts it in
    the UNTRUSTED zone, so it chose where the request went. Measured before the
    fix: a compliant `127.0.0.1` endpoint redirected to `127.0.0.2` — not on
    the default allowlist — the request arrived there as a GET carrying
    `Authorization: Bearer <key>`, and the attacker's reply was returned to the
    planner. That is the mitigation the threat model names for row 13, LLM
    endpoint egress / SSRF.
    """
    clear_llm_env(monkeypatch)
    arrived = []

    class Elsewhere(BaseHTTPRequestHandler):
        """A host that is NOT on the allowlist."""
        def do_GET(self):  # noqa: N802
            arrived.append(self.headers.get("Authorization"))
            raw = json.dumps({"choices": [{"message": {"content": "pwned"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_POST = do_GET

        def log_message(self, *_args):
            return

    elsewhere = ThreadingHTTPServer(("127.0.0.2", 0), Elsewhere)
    elsewhere_port = elsewhere.server_port
    elsewhere_thread = threading.Thread(target=elsewhere.serve_forever, daemon=True)
    elsewhere_thread.start()

    class Redirector(BaseHTTPRequestHandler):
        """The configured, allowlisted endpoint — which redirects."""
        def do_POST(self):  # noqa: N802
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.2:{elsewhere_port}/v1/chat/completions")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}/v1"
        client = LLMClient(base_url=base_url, model="pod-120b",
                           api_key="pod-key-must-not-egress")
        with pytest.raises(RuntimeError, match="redirect"):
            client.complete("system", "the research question")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        elsewhere.shutdown()
        elsewhere_thread.join(timeout=5)

    assert not arrived, (
        f"the request reached the off-allowlist host carrying {arrived!r}")


def test_a_non_object_response_is_a_schema_error_not_a_crash(monkeypatch):
    """The response body is untrusted. A bare JSON list reached `data.get`
    and raised `AttributeError` instead of the schema error beside it."""
    clear_llm_env(monkeypatch)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            raw = json.dumps([1, 2, 3]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = LLMClient(base_url=f"http://127.0.0.1:{server.server_port}/v1",
                           model="pod-120b", api_key="pod-key")
        with pytest.raises(RuntimeError, match="chat-completions schema"):
            client.complete("system", "user")
    finally:
        server.shutdown()
        thread.join(timeout=5)
