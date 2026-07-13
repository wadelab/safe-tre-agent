# Demo in 5 minutes

This is the minimal local run: pinned environment, synthetic data, the web app
on loopback, and three smoke checks. It needs no hosted service, no network
exposure, and — in the offline variant — no model endpoint or API key. For the
fuller rehearsal with the complete check set, use the
[test deployment runbook](test-deployment.md).

You need a Linux or macOS host with Python 3.11+, [uv](https://docs.astral.sh/uv/)
and Git.

## 1. Clone and pin the environment

```bash
git clone https://github.com/wadelab/safe-tre-agent.git
cd safe-tre-agent
git rev-parse HEAD        # record this — see the evidence checklist
uv sync --all-extras --frozen
```

## 2. Generate synthetic data

```bash
uv run python scripts/make_data.py
```

This writes four CSVs under `data/` (`donors`, `apps`, `events`, `survey`).
They are generated artifacts; do not commit them.

## 3. Run the web app

The app plans queries with an LLM. Pick a planner mode; there is no silent
fallback between them — if the configured model is unreachable, requests fail
loudly rather than quietly degrading.

**Variant A — offline, deterministic (no model, no key).** Set
`SAFETRE_LLM=mock` explicitly. This is the planner the tests and CI use: it
handles the demo phrasings on this page but deliberately lacks the nuance of a
real model. The gateway does not care — every safety property you will see is
enforced at the boundary, not by the planner.

```bash
SAFETRE_LLM=mock uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port 8800
```

**Variant B — remote model, synthetic-data-only.** Any hosted
OpenAI-compatible endpoint gives the full planning experience. Remote
endpoints are egress channels, so they require an explicit opt-in and must
never be used with real data:

```bash
export SAFETRE_LLM=real
export SAFETRE_ALLOW_REMOTE_LLM=1        # synthetic-data-only opt-in
export SAFETRE_LLM_BASE_URL=https://<provider>/v1
export SAFETRE_LLM_API_KEY=...           # never commit this
export SAFETRE_LLM_MODEL=<model-id>
uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port 8800
```

`scripts/run_web.sh` does the same, sourcing the variables from `.env.local`.
A local OpenAI-compatible endpoint (vLLM, llama.cpp) needs no opt-in; see
[test deployment § local model](test-deployment.md#6-optional-local-model-rehearsal).

Either way the app binds `127.0.0.1` only. Open <http://127.0.0.1:8800>.

## 4. Smoke-test the public endpoints

```bash
curl http://127.0.0.1:8800/healthz            # {"ok": true}
curl http://127.0.0.1:8800/api/manifest       # the public tool manifest (JSON)
curl http://127.0.0.1:8800/api/audit/verify   # {"chain_intact": true}
```

The manifest is what an outside model would plan against; the audit endpoint
re-verifies the hash chain over every request made so far.

## 5. Run the three demo queries

In the UI, run these in order — or follow the
[screenshot tour](screenshot-tour.md), which shows each expected result:

- `mean spend by age band` → **released**;
- `mean spend by age band, region and device os` → **redacted** (small cells
  suppressed, the rest released);
- `show mean wellbeing per donor` → **denied**, with the reason and no table.

Then re-run the audit check from step 4: the chain now covers those requests,
including the denial.

## 6. Stop cleanly

Stop the server with `Ctrl-C`. The run leaves only generated, gitignored
artifacts (`data/*.csv`, `audit.db*`); nothing needs cleaning up, and none of
it belongs in a commit.

## Going further

- The full check set (tests, SAST, dependency audit, red-team, strict docs
  build): [test deployment § required checks](test-deployment.md#3-run-the-required-checks).
- The red-team replay on its own: `uv run python redteam/run_redteam.py`.
- Recording what you just did as evidence: [evidence checklist](evidence-checklist.md).
