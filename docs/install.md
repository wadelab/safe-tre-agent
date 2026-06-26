# Install

This guide covers a local development install and the controlled safepod install
path. Use `uv` for every Python command so the lockfile is the source of truth.

## Requirements

- Python 3.11 or newer
- `uv`
- Git
- For the web UI: loopback access to port `8800`
- For production: a safepod or equivalent controlled host, no automatic updates,
  and an approved deployment process

## Local development

```bash
git clone git@github.com:wadelab/safe-tre-agent.git
cd safe-tre-agent
uv sync --all-extras
```

Generate synthetic data and run the checks:

```bash
uv run python scripts/make_data.py
uv run pytest -q
uv run bandit -q -r safetre safetre_web
uv run pip-audit
uv run python redteam/run_redteam.py
```

Run the web app locally:

```bash
uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port 8800
```

Open:

```text
http://127.0.0.1:8800
```

Build the documentation:

```bash
uv run --group docs mkdocs build
uv run --group docs mkdocs serve
```

## Model runtime

Offline mode needs no model server. It uses deterministic mock planning.

For a local model runtime:

```bash
SAFETRE_LLM=real
SAFETRE_LLM_BASE_URL=http://127.0.0.1:8000/v1
SAFETRE_LLM_API_KEY=local
SAFETRE_LLM_MODEL=local-120b
SAFETRE_ALLOWED_LLM_HOSTS=localhost,127.0.0.1,::1
```

The endpoint must implement OpenAI-compatible `/v1/chat/completions`. Remote
model endpoints require `SAFETRE_ALLOW_REMOTE_LLM=1` and are for synthetic-data
development only.

## Safepod install

The safepod host should not pull arbitrary updates at runtime. Do not run
automatic package updates, unattended `git pull`, or unreviewed dependency
refreshes against a real data pod.

Use a controlled release bundle:

1. Review the code diff and dependency lockfile outside the safepod.
2. Run the full check suite on a test host.
3. Record the commit SHA, `uv.lock` hash, and manifest hash.
4. Transfer the approved artifact through the site-approved path.
5. Install or update the safepod from that reviewed artifact.
6. Run smoke tests and verify the audit chain.
7. Keep a rollback artifact.

The shipped systemd unit is `deploy/safetre-web.service`.

```bash
uv sync --all-extras
sudo cp deploy/safetre-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now safetre-web
systemctl status safetre-web
```

Production defaults:

```bash
SAFETRE_REQUIRE_IDENTITY=1
SAFETRE_RESTRICTED_CHANNEL=1
SAFETRE_CHANNEL_ALLOW_NETS=127.0.0.1/32,::1/128
SAFETRE_ALLOWLIST=researcher@example.ac.uk
SAFETRE_AUDIT_DB=/var/lib/safetre/audit.db
```

Expose the app only through the approved restricted channel, such as the
site-managed gateway or `tailscale serve` for the current prototype.

## Verify after install

```bash
uv run pytest -q
uv run python redteam/run_redteam.py
curl http://127.0.0.1:8800/healthz
curl http://127.0.0.1:8800/api/audit/verify
```

For production, also verify the external channel, identity header handling,
allowlist behavior, off-pod audit anchoring, and systemd hardening.
