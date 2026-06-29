# Test deployment runbook

This runbook prepares a **synthetic-data test deployment**. It is not approval to
load real data. Treat it as the rehearsal environment for a later safepod
deployment review.

## Goal

At the end of this runbook you should have:

- a pinned local environment from `uv.lock`;
- synthetic data generated or loaded;
- the web app bound to `127.0.0.1`;
- a visible test UI;
- a passing test, security, dependency, docs, and red-team check set;
- a short evidence bundle recording the commit and verification results.

## Test host assumptions

Use a Linux host or VM with:

- Python 3.11 or newer;
- `uv`;
- Git;
- enough memory for DuckDB, tests, and a local model if enabled;
- loopback access to port `8800`;
- optional `tailscale` if you want to rehearse restricted-channel access.

Use synthetic data only unless a formal safepod review has approved the host,
model runtime, access channel, audit-key handling, and physical controls.

## 1. Checkout and pin the environment

```bash
git clone https://github.com/wadelab/safe-tre-agent.git
cd safe-tre-agent
git rev-parse HEAD
uv sync --all-extras --frozen
```

Record the commit SHA in your test notes.

## 2. Generate synthetic data

```bash
uv run python scripts/make_data.py
```

Expected output lists four CSV files under `data/`: `donors`, `apps`, `events`,
and `survey`. These files are generated artifacts and should not be committed.

## 3. Run the required checks

```bash
uv run pytest -q
uv run bandit -q -r safetre safetre_web
uv run pip-audit
uv run python redteam/run_redteam.py
uv run --group docs mkdocs build
```

The red-team writes `redteam/results.csv`; the docs build writes `site/`. Both
are ignored generated artifacts.

The current docs build may warn about documentation pages linking to source files
outside `docs/`; this is known for the non-strict build. Treat new or changed
warnings as regressions.

## 4. Run the web interface locally

```bash
uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port 8800
```

Open:

```text
http://127.0.0.1:8800
```

For a smoke test:

```bash
curl http://127.0.0.1:8800/healthz
curl http://127.0.0.1:8800/api/manifest
curl http://127.0.0.1:8800/api/audit/verify
```

The UI should look like this:

![Desktop screenshot of the test web UI](figures/web-ui-home.png)

## 5. Rehearse restricted-channel access

For a synthetic-data tailnet rehearsal:

```bash
tailscale serve --bg 8800
```

Then open the generated `https://...ts.net` URL from an allowed device. The app
must still bind only to loopback.

For a stricter rehearsal, set:

```bash
SAFETRE_RESTRICTED_CHANNEL=1
SAFETRE_CHANNEL_ALLOW_NETS=127.0.0.1/32,::1/128
SAFETRE_REQUIRE_IDENTITY=1
SAFETRE_ALLOWLIST=researcher@example.ac.uk
```

Only use real Safe People identities and an approved allowlist for production.

## 6. Optional local model rehearsal

The default test mode uses `MockPlanner` and needs no model server. To rehearse a
local model endpoint:

```bash
SAFETRE_LLM=real
SAFETRE_LLM_BASE_URL=http://127.0.0.1:8000/v1
SAFETRE_LLM_API_KEY=local
SAFETRE_LLM_MODEL=local-120b
SAFETRE_ALLOWED_LLM_HOSTS=localhost,127.0.0.1,::1
```

The endpoint must implement OpenAI-compatible `/v1/chat/completions`.

Remote model endpoints require:

```bash
SAFETRE_ALLOW_REMOTE_LLM=1
```

Remote endpoints are synthetic-data-only because they are data-egress channels.

## 7. Evidence bundle

For each test deployment, record:

- commit SHA;
- `uv.lock` hash;
- host name and OS;
- whether the planner was `mock` or `real`;
- check results from step 3;
- red-team summary;
- audit DB path and audit verification result;
- whether restricted-channel rehearsal was run;
- known deviations from this runbook.

Do not include generated CSVs, `.venv/`, `site/`, or `redteam/results.csv` in a
commit.

## Promotion gate

A test deployment is ready for review when:

- all checks pass;
- the UI and API smoke tests work;
- denied requests return no data;
- the red-team output says all checks passed;
- the safepod/operator has a plan for identity, audit key storage, off-pod audit
  anchoring, and rollback.

See [Deployment](deployment.md) for the production topology and
[Safepod model](safepod.md) for physical and operational controls.
