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

## Quick start (offline, no API key)

```bash
pip install -r requirements.txt
python scripts/make_data.py                       # synthetic SDDS-style data -> ./data
python scripts/demo.py "mean spend by age band"   # one guarded request, end to end
python redteam/run_redteam.py                      # gateway OFF vs ON, leakage table
pytest -q
```

Use a real model by setting the OpenAI-compatible env vars in `.env` (see
`.env.example`) and `SAFETRE_LLM=real`.

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

## Status & honesty

Prototype / work-in-progress. The sandbox is **defence-in-depth illustration, not
a secure jail** — production needs real container isolation (gVisor/Firecracker),
ACRO proper, a trained output-checker model, and DP accounting for the session
budget. The point here is to make the *agentic* disclosure problem concrete and
measurable, and to show the control surface that addresses it.

## Layout

```
safetre/     schema, synthetic data, guards (static+sandbox), disclosure gateway,
             session auditor, HITL, LLM client (+ MockLLM), analyst loop
scripts/     make_data.py, demo.py
redteam/     attacks.yaml, run_redteam.py
tests/       pytest unit tests
```
