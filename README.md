# safe-tre-agent

**A safe-outputs gateway for an AI analyst inside a Trusted Research Environment.**

Classical statistical disclosure control (SDC) — minimum cell sizes, suppression,
output checking — assumes a **human** analyst. Putting an **LLM agent** between the
analyst and the data adds a new attack surface: the agent can be prompt-injected
*by the data itself*, can orchestrate many individually-"safe" queries to
triangulate an individual, or can emit code that smuggles raw rows into an
"aggregate". This prototype asks a concrete question:

> Does putting an AI between the analyst and sensitive data break the disclosure
> guarantee — and can a safe-outputs gateway plus human-in-the-loop restore it?

It runs entirely on **synthetic** data and is **model-agnostic** (OpenAI-compatible
client → OpenRouter, local vLLM/Ollama, or any compatible endpoint). A deterministic
`MockLLM` lets the whole pipeline and the red-team run offline.

> **📄 Full write-up with architecture, enclave and sequence diagrams, threat
> model and results: [`docs/writeup.md`](docs/writeup.md).**

## Where it sits

The agent runs **inside** the enclave; only outputs cross a gateway. The model
never needs raw data to leave — which is *why* a production deployment must use a
**local** model (a remote API would itself be an egress channel). Remote models are
fine here only because the data is synthetic.

```
NL request
  → vetting          intent / blocked-purpose check, per-session budget
  → agent (LLM)      writes pandas; model swappable via OpenAI-compatible config
  → static check     no imports / IO / network; must assign `result`
  → sandbox          restricted exec against copies of the synthetic tables
  → safe-outputs     ACRO-style: min cell size, suppression, identifier/free-text egress
  → session auditor  differencing / triangulation / query budget   ← agentic-novel
  → human-in-loop    medium findings escalate; high findings deny
  → released aggregate
```

## What it builds on

- **OpenSAFELY** (Bennett Institute, Oxford) — the code-to-data, outputs-checked
  TRE model. Their output checking is still **two humans**; this explores the
  automated, agent-aware layer above it.
- **ACRO / SACRO** (DARE UK) — open-source semi-automated output SDC. Production
  would wrap ACRO; `safetre/disclosure.py` is a lightweight stand-in so the demo
  needs no extra dependency.
- **Five Safes** — vetting = Safe Projects/People; gateway = Safe Outputs; local
  model = Safe Settings.

## Quick start (uv, offline, no API key)

```bash
uv sync --all-extras                              # pinned env from uv.lock
uv run python scripts/make_data.py                # synthetic SDDS-style data -> ./data
uv run python scripts/demo.py "mean spend by age band"
uv run python redteam/run_redteam.py              # gateway OFF vs ON, leakage table
uv run pytest -q
```

Use a real model by setting the OpenAI-compatible env vars in `.env` (see
`.env.example`) and `SAFETRE_LLM=real`.

## Web interface (Phase 1 — security-first)

```bash
uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port 8800   # or scripts/run_web.sh
# expose to your tailnet:  tailscale serve --bg 8800
```

The web layer is built security-first (the model is treated as untrusted):

- **No code execution.** The LLM only proposes a **`QuerySpec`** (Pydantic,
  `extra="forbid"`); anything off the allowlisted catalogue is rejected before it
  runs. A read-only **DuckDB** engine compiles the validated spec to
  **parameterised** SQL — no SQL-injection surface, no arbitrary code.
- **Identity = Safe People.** Behind `tailscale serve` the authenticated tailnet
  login is used for access control (`SAFETRE_ALLOWLIST`) and the audit trail.
- **Hash-chained audit log** (`safetre/audit.py`) — every request, spec and
  decision, tamper-evident (`GET /api/audit/verify`).
- **Hardened headers** (strict CSP `script-src 'self'`, no CDN JS) and a
  **least-privilege systemd unit** (`deploy/safetre-web.service`).
- Binds `127.0.0.1` only; per-user `SessionAuditor` makes differencing/budget
  controls persist across a session.

## The dataset (synthetic)

Four linked tables modelled on loot-box / in-app-spend + psychometric data
(the shape of the Lemanic Life Sciences Hackathon 2025 dataset — synthetic, not
the real data): `donors` (quasi-identifiers), `apps` (reference), `events`
(spend behaviour), `survey` (PGSI / wellbeing + free text). Column roles
(DI/QI/S/R) drive the disclosure rules. See `safetre/schema.py`.

## Threat model / red-team

`redteam/attacks.yaml` exercises: small-cell over-granularity, prompt-injection
planted in `free_text`, code-channel smuggling of identifiers, a two-query
differencing attack, and a direct re-identification request. `run_redteam.py`
replays each with the gateway OFF and ON and reports what actually leaked.

![Red-team: gateway off vs on](docs/figures/redteam_results.png)

**5/5 attacks neutralised; 3/6 would leak row-level data with the gateway off.**
Benign analysis flows through; small-cell queries are redacted and released.

## Two execution paths

- **Secure (web / Phase 1):** validated `QuerySpec` → read-only DuckDB. No code
  runs; this is the default and what the web interface uses.
- **Legacy / escalation (CLI):** the original "LLM writes pandas" path
  (`safetre/analyst.py` + `guards.py`) is retained for the red-team narrative and
  as the human-reviewed escalation route for analyses the DSL can't express. Its
  sandbox is **defence-in-depth illustration, not a secure jail** — that path
  would need real container isolation (gVisor/Firecracker) before real data.

Remaining for production either way: ACRO proper, a trained output-checker model,
and DP accounting for the session budget.

## Layout

```
safetre/      query (QuerySpec), engine (DuckDB), planner, service,   ← secure path
              disclosure gateway, session auditor, audit (hash-chain),
              schema, synthetic data, analyst+guards (legacy/escalation), llm
safetre_web/  FastAPI app, identity (Safe People), session, templates, static
scripts/      make_data.py, demo.py, make_figures.py, run_web.sh
redteam/      attacks.yaml, run_redteam.py
deploy/       safetre-web.service (hardened systemd unit)
docs/         writeup.md + figures
tests/        pytest (37): disclosure, pipeline, secure (QuerySpec/engine/audit), web
```
