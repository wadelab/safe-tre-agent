# AGENTS.md

Guidance for coding agents working in this repository.

## Operating rules

- Use `uv` for Python commands: `uv run pytest -q`, `uv run bandit -q -r safetre safetre_web`, `uv run pip-audit`, and `uv run python ...`.
- Keep changes tightly scoped. Do not weaken security controls to make tests pass.
- If the user says `CAP=commit and push`, stop at committing and pushing the branch. Do not open a PR unless explicitly asked.
- Do not commit generated or ignored artifacts such as `.venv/`, `.pytest_cache/`, `site/`, `data/*.csv`, `redteam/results.csv`, or `__pycache__/`.

## Security invariants

- Treat the LLM, researcher input, and row-level data as untrusted.
- The secure web path must remain: natural-language request -> planner proposes `QuerySpec` -> strict validation -> read-only DuckDB engine -> disclosure gateway -> session auditor -> audit log.
- The model must not execute code, write SQL, read files, open sockets, or directly inspect raw rows in the web path.
- Real-model integrations must stay local-first and model-agnostic. Prefer `SAFETRE_LLM_*` settings and the `complete(system, user)` adapter boundary over provider SDK assumptions.
- Remote LLM endpoints require explicit `SAFETRE_ALLOW_REMOTE_LLM=1` and are synthetic-data-only.
- Outside planners may use the public tool manifest, but the manifest is not authorization. The safepod must validate every proposed tool call independently.
- Statistical tools (the shipped GLM and one-way ANOVA, and any future additions) must be fixed-function schemas with deterministic validators and disclosure checks, not arbitrary generated code; new procedures register declared conformance obligations in `safetre/procedures.py` (see `docs/adding-a-statistical-tool.md`).
- Keep direct identifiers, free text, raw timestamps, and high-granularity fields out of the public catalogue and public DuckDB views.
- All filter values must remain bound parameters. Identifiers must come only from allowlists and pass identifier validation.
- Do not lower disclosure thresholds, dominance controls, correlation influence controls, count rounding, query-budget checks, or differencing checks without explicit security review.
- Denied requests must never render or return data.
- Audit logs must remain HMAC chained. Production guidance must keep the audit key and audit-head anchor off the data host.

## Safepod requirements

- Real data belongs inside a safepod: the data host, local model, and raw data are physically controlled, and only aggregate outputs leave.
- Plan for capable local models, roughly 120B-class, but never rely on model capability for safety.
- The restricted channel is a security boundary. Keep `SAFETRE_RESTRICTED_CHANNEL=1` by default and keep `SAFETRE_CHANNEL_ALLOW_NETS` narrow.
- Channel decisions must use the real peer address reported by ASGI, not `X-Forwarded-For` or other caller-controlled forwarding headers.
- Production deployments must require identity (`SAFETRE_REQUIRE_IDENTITY=1`) and an explicit Safe People allowlist.
- Uvicorn should bind loopback and be exposed through the approved restricted-channel gateway, such as `tailscale serve`.
- Physical controls are part of the system: locked or tamper-evident enclosure, disabled unused ports/radios, disk encryption, maintenance logs, and off-pod audit anchoring.

## Required checks before publishing

Run these before committing security-relevant work:

```bash
uv run pytest -q
uv run bandit -q -r safetre safetre_web
uv run pip-audit
uv run python redteam/run_redteam.py
```

For docs changes, also run:

```bash
uv run --group docs mkdocs build --strict
```

The strict build passes and is a CI gate; treat any new warning as a regression.

On each new build, update a version tag visible in the webpage so that we can see which version of the code produced the interface we are using and also which verison goes with which docs.
