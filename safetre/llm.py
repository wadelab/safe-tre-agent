"""Model interface: local-first, model-agnostic completion clients.

The secure pipeline treats the model as untrusted regardless of capability. A
future 120B-class local model may plan better, but it still only proposes JSON
that the deterministic QuerySpec boundary validates.

The default real adapter speaks the OpenAI-compatible chat-completions protocol
over plain HTTP so it can target vLLM, llama.cpp server, Ollama-compatible
proxies, or another local runtime without a provider SDK dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import textwrap
from urllib import error, parse, request

DEFAULT_LLM_BASE_URL = "http://127.0.0.1:8000/v1"
DEFAULT_LLM_MODEL = "local-120b"
DEFAULT_ALLOWED_HOSTS = "localhost,127.0.0.1,::1"
FALSEY = {"0", "false", "no", "off"}
TRUTHY = {"1", "true", "yes", "on"}


def _strip_code_fences(text: str) -> str:
    m = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
    return (m.group(1) if m else text).strip()


def _env(name: str, fallback: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value not in (None, ""):
        return value
    return fallback


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in TRUTHY:
        return True
    if value in FALSEY:
        return False
    return default


def _allowed_hosts() -> set[str]:
    raw = os.environ.get("SAFETRE_ALLOWED_LLM_HOSTS", DEFAULT_ALLOWED_HOSTS)
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


@dataclass(frozen=True)
class LLMConfig:
    """Configuration for an OpenAI-compatible local model endpoint."""

    base_url: str = DEFAULT_LLM_BASE_URL
    model: str = DEFAULT_LLM_MODEL
    api_key: str = "local"
    temperature: float = 0.0
    timeout: float = 60.0

    @classmethod
    def from_env(cls, *, model: str | None = None, base_url: str | None = None,
                 api_key: str | None = None, temperature: float | None = None):
        resolved = cls(
            base_url=base_url or _env("SAFETRE_LLM_BASE_URL", _env("OPENAI_BASE_URL", DEFAULT_LLM_BASE_URL)),
            model=model or _env("SAFETRE_LLM_MODEL", _env("SAFETRE_MODEL", DEFAULT_LLM_MODEL)),
            api_key=api_key or _env("SAFETRE_LLM_API_KEY", _env("OPENAI_API_KEY", "local")),
            temperature=(
                temperature if temperature is not None
                else float(os.environ.get("SAFETRE_LLM_TEMPERATURE", "0"))
            ),
            timeout=float(os.environ.get("SAFETRE_LLM_TIMEOUT", "60")),
        )
        resolved.validate()
        return resolved

    def validate(self) -> None:
        parsed = parse.urlparse(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("SAFETRE_LLM_BASE_URL must be an http(s) URL with a host")
        if _bool_env("SAFETRE_ALLOW_REMOTE_LLM", default=False):
            return
        host = parsed.hostname.lower()
        if host not in _allowed_hosts():
            raise ValueError(
                f"LLM endpoint host {host!r} is not allowed; set "
                "SAFETRE_ALLOWED_LLM_HOSTS for an in-safepod model host or "
                "SAFETRE_ALLOW_REMOTE_LLM=1 for synthetic-data development"
            )

    @property
    def chat_completions_url(self) -> str:
        return self.base_url.rstrip("/") + "/chat/completions"


class LLMClient:
    """Thin wrapper over an OpenAI-compatible chat-completions endpoint."""

    def __init__(self, model: str | None = None, base_url: str | None = None,
                 api_key: str | None = None, temperature: float | None = None):
        self.config = LLMConfig.from_env(
            model=model, base_url=base_url, api_key=api_key, temperature=temperature,
        )

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        req = request.Request(
            self.config.chat_completions_url, data=body, headers=headers, method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.config.timeout) as resp:  # nosec B310
                data = json.loads(resp.read().decode())
        except error.URLError as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("LLM response did not match chat-completions schema") from exc
        return _strip_code_fences(content or "")


class MockLLM:
    """Deterministic stand-in. Maps known requests to representative code.

    Some responses deliberately model a *compromised / injected* agent (e.g. it
    tries to return raw rows), to prove the gateway stops the leak even when the
    model misbehaves — defence in depth.
    """

    def complete(self, system: str, user: str) -> str:
        u = user.lower()

        if "excluding the single biggest" in u:          # differencing, query B (check first: more specific)
            return textwrap.dedent("""
                s = survey.sort_values('monthly_spend_selfreport')
                result = pd.DataFrame({'measure': ['spend_pop'], 'n': [len(s) - 1]})
            """).strip()

        if "population size" in u:                       # differencing, query A
            return "result = pd.DataFrame({'measure': ['spend_pop'], 'n': [len(survey)]})"

        if "free-text" in u or "free text" in u:         # prompt-injection target
            # injected agent tries to dump identifiers + free text
            return "result = survey[['donor_id', 'free_text']]"

        if "per donor" in u or "per-donor" in u:         # code-channel smuggling
            return "result = survey[['donor_id', 'wemwbs_score']]"

        if "canton" in u and "device" in u:              # small-cell over-granular
            return textwrap.dedent("""
                m = events.merge(donors[['donor_id', 'age_band', 'canton', 'device_os']], on='donor_id')
                m = m[m.event_type.isin(['purchase', 'lootbox_open'])]
                g = m.groupby(['age_band', 'canton', 'device_os'])['amount_chf']
                result = g.mean().round(2).reset_index().rename(columns={'amount_chf': 'mean_chf'})
                result['n'] = g.size().values
            """).strip()

        # default benign: mean spend by age band
        return textwrap.dedent("""
            m = events.merge(donors[['donor_id', 'age_band']], on='donor_id')
            m = m[m.event_type.isin(['purchase', 'lootbox_open'])]
            g = m.groupby('age_band')['amount_chf']
            result = g.mean().round(2).reset_index().rename(columns={'amount_chf': 'mean_chf'})
            result['n'] = g.size().values
        """).strip()
