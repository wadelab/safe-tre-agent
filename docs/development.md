# Development

## Environment (uv)

The project is managed with [uv](https://docs.astral.sh/uv/). Dependencies are
pinned in `uv.lock`.

```bash
uv sync --all-extras          # runtime + web + llm + dev tools
uv run pytest -q
uv run python scripts/demo.py "mean spend by age band"
uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port 8800
```

Dependency groups: `web` (FastAPI stack), `llm` (kept for command compatibility;
the real model adapter uses stdlib HTTP), and the default `dev` group
(`pytest`, `matplotlib`, `bandit`, `pip-audit`). The project itself is not
packaged (`tool.uv.package = false`); `pytest`'s `pythonpath = ["."]` puts
`safetre` / `safetre_web` on the path.

## Repository layout

```
safetre/            secure path: query (QuerySpec), engine (DuckDB), planner,
                    service, disclosure gateway + session auditor, audit (hash chain),
                    schema, synth; legacy/escalation: analyst + guards; llm client
safetre_web/        FastAPI app, identity, session, templates/, static/
scripts/            make_data.py, demo.py, make_figures.py, run_web.sh
redteam/            attacks.yaml, run_redteam.py
deploy/             safetre-web.service (hardened systemd unit)
docs/               this documentation + writeup.md + figures/
tests/              test_disclosure, test_pipeline, test_secure, test_web
```

## Tests

```bash
uv run pytest -q
```

| File | Covers |
|---|---|
| `test_secure.py` | QuerySpec validation, engine injection-safety, end-to-end service, audit chain tamper-evidence |
| `test_llm.py` | local-first model endpoint config and chat-completions protocol adapter |
| `test_manifest.py` | public tool manifest safety and executable/planned tool separation |
| `test_web.py` | FastAPI endpoints, security headers, denial renders no table, oversize → 422 |
| `test_disclosure.py` | gateway rules (min cell, egress, differencing) |
| `test_pipeline.py` | legacy guarded analyst path and sandbox isolation |

## Security checks

```bash
uv run bandit -r safetre safetre_web    # SAST
uv run pip-audit                        # dependency CVEs
```

`# nosec <id>` annotations carry a justification; review them when changing the
engine or the legacy sandbox.

## Extending the catalogue

The catalogue is the security boundary, so changes are deliberate and reviewed.
To add a queryable dimension, measure, or tool:

1. Add the column to the relevant dataset in `CATALOGUE` (`safetre/query.py`),
   with its type (`cat` / `bool` / `int`) for dimensions.
2. Make sure the column is **selected by the corresponding view** in
   `safetre/engine.py` (and only safe columns — never `donor_id`, `free_text`,
   raw ages or timestamps).
3. Update the public manifest in `safetre/manifest.py` only if the capability is
   safe to publish outside the safepod. Fixed-function extensions such as
   `corr` must stay schema-validated and deterministic.
4. Add a validation test in `tests/test_secure.py` (accept the new valid spec;
   confirm anything off-allowlist is still rejected).

Never widen a view to expose an identifier or free-text column — that is the one
invariant the whole design rests on.

Future stats tools (GLM, regression, ANOVA, etc.) must enter as fixed-function
tool schemas plus deterministic validators. Listing a tool in
`planned_tool_classes` does not make it executable; only `tools[]` entries with
`status: "available"` may be proposed.

## Adding a disclosure control

Controls live in `safetre/disclosure.py`:

- output checks (per-result) → extend `leak_detector` / `DisclosurePolicy`;
- session checks (cross-query) → extend `SessionAuditor`.

Add a finding `rule`, wire it into `QueryService` if it needs a new decision, and
cover it in `tests/test_disclosure.py` and the red-team (`redteam/attacks.yaml`).

## HTTP API

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/` | – | the web UI |
| POST | `/api/query` | `{"q": "<=500 chars"}` | HTML result partial (released / redacted / denied) |
| GET | `/healthz` | – | `{"ok": true}` |
| GET | `/api/audit/verify` | – | `{"chain_intact": bool}` |

Interactive API docs are disabled by default (`docs_url=None`) to reduce surface;
re-enable in `safetre_web/app.py` for local development if needed.

## Conventions

- The model is untrusted: never let planner output reach execution unvalidated.
- A denied/blocked response must never carry data (`output is None`) — there's a
  test for it; keep it true.
- Keep new code covered; run `pytest`, `bandit` and `pip-audit` before pushing.
