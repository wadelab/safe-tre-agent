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

It runs entirely on **synthetic** data and is **model-agnostic** at the protocol
boundary (local OpenAI-compatible `/v1/chat/completions` from vLLM, llama.cpp,
Ollama-compatible proxies, or a site-specific adapter). The operating assumption
is that local models will become strong enough for planning — roughly a good
120B-class model — while still being treated as untrusted. A deterministic
`MockLLM` lets the whole pipeline and the red-team run offline.

> **📚 Documentation:** [`docs/`](docs/index.md). The canonical technical
> report is the [research write-up](docs/writeup.md); start there, then the
> [specification](docs/specification.md) (what it must and must not do), the
> [security model](docs/security.md) and the [roadmap](docs/roadmap.md).
> Guides for installing, deploying, and certifying the prototype — and the
> hardening/red-team record — are grouped in the [docs index](docs/index.md).
> Browse as a site with `uv run --group docs mkdocs serve`.

## Where it sits

The agent runs **inside** the enclave; only outputs cross a gateway. For real
data, the data and server sit inside a **safepod** and researchers communicate
through a **restricted channel**. The model never needs raw data to leave —
which is *why* a production deployment must use a **local** model (a remote API
would itself be an egress channel). Remote models are fine here only because the
data are synthetic.

```
NL request
  → vetting          intent / blocked-purpose check, per-session budget
  → planner (LLM)    proposes QuerySpec JSON; local model runtime is swappable
  → validation       strict Pydantic allowlist; anything else is rejected
  → engine           read-only DuckDB views; parameterised SQL
  → safe-outputs     ACRO-style: min cell size, suppression, identifier/free-text egress
  → session auditor  differencing / triangulation / query budget   ← agentic-novel
  → human-in-loop    medium findings escalate; high findings deny
  → released aggregate
```

Statistical procedures are **registered contracts** (spec R14): the five
aggregate measures plus two model tools — a **GLM** (gaussian / logistic /
Poisson over categorical terms) and a **one-way ANOVA** — fitted
*exclusively from gateway-vetted cell tables*: any suppressed design cell
denies the whole model, a release carries the cell table it was fitted from,
and refitting from the released artifacts reproduces the coefficients
bit-for-bit. The safety boundary is machine-checked: the query boundary is
proved in **Lean 4** (identifier non-membership, internal-only containment,
parameterised single-SELECT SQL — pinned to the live engine byte-for-byte)
and the release path and differencing rule are model-checked in **Alloy**,
all replayed in CI. See [`formal/`](formal/README.md) and
[verifiable extensions](docs/verifiable-extensions.md).

```bash
uv run python scripts/demo_query.py "regress total spend on age band"
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

## Research core vs demo shell

The claim this repo makes lives entirely in **`safetre/`**: the validated
`QuerySpec`, the read-only engine, the disclosure gateway, the session auditor,
and the hash-chained audit log. That is the research artifact, and it is
installable (`pip install .` / `uv build`) so a TRE team can wrap the gateway
in their own infrastructure without adopting anything else here.

**`safetre_web/`** and **`deploy/`** are a demo shell: a reference deployment
for synthetic-data test drives. A production TRE would replace them with its
own identity, network boundary, and service management — none of the security
claim depends on them. They are kept working and red-teamed, but they are not
the research: the shell is frozen (fixes only), and new effort goes to the core
in the order set out in the [roadmap](docs/roadmap.md) — ACRO integration,
then the formal model, then a DP accountant.

## Quick start (uv, offline, no API key)

```bash
uv sync --all-extras                              # pinned env from uv.lock
uv run python scripts/make_data.py                # synthetic behavioural data -> ./data
uv run python scripts/demo.py "mean spend by age band"
uv run python redteam/run_redteam.py              # gateway OFF vs ON, leakage table
uv run pytest -q
```

Or as an installed package (MIT-licensed; see `CHANGELOG.md` for releases):

```bash
pip install .            # or: uv build && pip install dist/*.whl  ('.[web]' adds the shell)
safetre-demo             # scripted tour of the secure pipeline, synthetic data
safetre-demo "regress total spend on age band"
```

Use a real local model by setting the generic `SAFETRE_LLM_*` env vars in `.env`
(see `.env.example`) and `SAFETRE_LLM=real`. Remote model endpoints require an
explicit synthetic-data-only opt-in.

## Public demo route

The repo is the demo — there is no hosted server, and the primary demo path
needs no network exposure at all. The docs walk a reviewer from clone to
understanding in under fifteen minutes:

- [Demo in 5 minutes](docs/demo-5-minutes.md) — pinned env, synthetic data,
  the web app on loopback, three smoke checks. Offline planner mode
  (`SAFETRE_LLM=mock`, no key) or a synthetic-data-only remote model profile.
- [Screenshot tour](docs/screenshot-tour.md) — home, released, redacted,
  denied, audit verify: what each state shows and how to reproduce the images.
- [Evidence checklist](docs/evidence-checklist.md) — record commit, lock hash,
  check results and audit verification so a demo run is citable.

If you do need to show it to someone remotely, keep the app on loopback and
use the restricted-channel topology in [deployment](docs/deployment.md)
(`tailscale serve` into localhost); remote model endpoints remain
synthetic-data-only either way.

## Web interface (Phase 1 — security-first)

```bash
uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port 8800   # or scripts/run_web.sh
# expose to your tailnet:  tailscale serve --bg 8800
```

The interface follows the [GOV.UK Design System](https://design-system.service.gov.uk/)
(unbranded) and is WCAG 2.2 AA. Recent work includes a normative
[specification](docs/specification.md), the GLM and ANOVA tools, the
Lean/Alloy formal layer ([`formal/`](formal/README.md)), a safe
schema-disclosure endpoint, and a planner-quality
[evaluation](docs/planner-eval.md).

The web layer is built security-first (the model is treated as untrusted):

- **No code execution.** The LLM only proposes a **`QuerySpec`** (Pydantic,
  `extra="forbid"`); anything off the allowlisted catalogue is rejected before it
  runs. A read-only **DuckDB** engine compiles the validated spec to
  **parameterised** SQL — no SQL-injection surface, no arbitrary code.
- **Identity = Safe People.** Behind `tailscale serve` the authenticated tailnet
  login is used for access control (`SAFETRE_ALLOWLIST`) and the audit trail.
- **Restricted channel.** The app rejects requests whose real peer address is
  outside `SAFETRE_CHANNEL_ALLOW_NETS` (loopback by default), making the
  `tailscale serve` → localhost topology an enforced safepod boundary.
- **Hash-chained audit log** (`safetre/audit.py`) — every request, spec and
  decision, tamper-evident (`GET /api/audit/verify`).
- **Hardened headers** (strict CSP `script-src 'self'`, no CDN JS) and a
  **least-privilege systemd unit** (`deploy/safetre-web.service`).
- Binds `127.0.0.1` only; per-user `SessionAuditor` makes differencing/budget
  controls persist across a session.

## The dataset (synthetic)

Four linked synthetic tables model a UK loot-box / in-app-spend donation study:
`donors` (quasi-identifiers across all 12 UK ITL1 regions), `apps` (a named,
genre-coherent catalogue — *Lucky Lorry Slots*, *Penalty Kings*, …), `events`
(App-Store price-point spend with weekend/evening rhythm), and `survey`
(two-wave PGSI / IGDS / WEMWBS + free text). Column roles (DI/QI/S/R) drive the
disclosure rules. See `safetre/schema.py`.

The data are not noise: a latent per-donor propensity makes the invited analyses
find real effects (loot-box spend correlates with PGSI, total spend negatively
with wellbeing, self-report under-reports observed spend), while deterministic
disclosure anchors keep the suppression and differencing demos honest across
seeds — Northern Ireland and sex `X` pinned below the min-cell threshold, and
three regions whose spend is concentrated in one or two donors so the
*dominance* rules have something to bite on (sampled spend, being merely
heavy-tailed, left them dead code). See `synth.DOMINANCE_ANCHORS` and
[the ACRO comparison](docs/acro-comparison.md), where the anchors separate the
stand-in's dominance rule from ACRO's.

## Threat model / red-team

`redteam/attacks.yaml` holds 33 scenarios (28 attacks, 5 benign baselines):
small-cell over-granularity, prompt-injection planted in `free_text`,
code-channel smuggling of identifiers, differencing pairs, direct
re-identification, grouping-fidelity probes, GLM-specific attacks (suppressed
cells recovered through a saturated design, internal-variable predictors,
residual requests, model differencing pairs), literal-spec entries, the
band-edge and double-differencing probes from round 8, and adversarial data
payloads (negative dominance, non-finite values, undeclared categories, a
hyperactive donor). `run_redteam.py` replays each with the gateway OFF and ON
and reports what actually leaked; it is a CI gate that exits nonzero on any
failure.

![Red-team: gateway off vs on](docs/figures/redteam_results.png)

**28/28 attacks neutralised; 13/33 scenarios would leak row-level data with the
gateway off.** Benign analysis flows through; small-cell queries are redacted
and released.

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
safetre/      RESEARCH CORE — query (QuerySpec), engine (DuckDB), planner,
              service, disclosure gateway + session auditor, audit (hash-chain),
              procedures (registered contracts), glm, anova, stats,
              config (policy loader), schema, synthetic data,
              analyst+guards (legacy/escalation), llm
safetre_web/  DEMO SHELL — FastAPI app, identity (Safe People), session,
              channel, rate limit, templates, static
formal/       machine-checked layer (R16) — Lean 4 proofs, Alloy models,
              skeleton.json, run_checks.py; generated + pinned to the code
scripts/      make_data.py, demo_query.py, make_figures.py,
              gen_alloy_catalogue.py, gen_lean_catalogue.py, make_decks.py,
              make_demo_screenshots.py, measure_rounding_distortion.py,
              measure_dispersion_sensitivity.py, gen_policy_catalogue.py,
              gen_decision_log.py, gen_assurance_case.py,
              measure_composite_cost.py, measure_timing_channel.py,
              restart_web.sh, run_web.sh
redteam/      attacks.yaml, run_redteam.py
evals/        planner-quality corpus + runner
paper/        preprint.tex (builds with make)
deploy/       safetre-web.service (hardened systemd unit)
docs/         mkdocs site — specification, roadmap, hardening log, security
              model, demo tours + figures
tests/        pytest suite: disclosure, pipeline, secure QuerySpec/engine/audit,
              hardening regressions, stats cross-validation, GLM/ANOVA
              conformance + properties, formal sync hops, web, local-model
              config, manifest, and query invariants
```
