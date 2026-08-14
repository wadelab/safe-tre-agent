# Development

For contributors: how to set up the environment, run the checks, and change
the code without weakening a control.

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
(`pytest`, `matplotlib`, `bandit`, `pip-audit`). The project is packaged
(hatchling; `pip install .`), and `pytest`'s `pythonpath = ["."]` puts
`safetre` / `safetre_web` on the path.

## Repository layout

```
safetre/            secure path: query (QuerySpec), engine (DuckDB), planner,
                    service, disclosure gateway + session auditor, audit (hash chain),
                    schema, synth; analyst (intent vetting + fidelity checks); llm client
safetre_web/        FastAPI app, identity, session, templates/, static/
scripts/            make_data.py, demo.py, make_figures.py, run_web.sh
redteam/            attacks.yaml, run_redteam.py, legacy/ (the quarantined
                    code-writing sandbox — illustration, not a secure jail)
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

## Docs screenshots

The demo-state images in the docs (`docs/figures/demo-*.png`) are generated,
not hand-captured: `uv run python scripts/make_demo_screenshots.py` starts a
throwaway mock-planner server on port 8801 and screenshots the four gateway
states (home, released, redacted, denied) plus a mobile-width capture of the
home page, with headless Chrome. Regenerate them after any UI change and check
the diff.
The states and queries are documented in the
[screenshot tour](screenshot-tour.md#reproducing-the-captures).

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

1. Add the column to the relevant dataset in the active dataset definition
   (`safetre/demo_dataset.yaml` by default, overridable via `SAFETRE_DATASET`),
   with its type (`cat` / `bool` / `int`) for dimensions. The catalogue mirror
   in `safetre/query.py` is populated from the definition, not edited by hand.
2. Make sure the column is **selected by the corresponding view** in
   `safetre/engine.py`. Public views must never expose `donor_id`, `free_text`,
   raw ages or timestamps. Internal unit views may carry internal analysis
   variables such as raw age only for fixed, validator-approved tools.
3. Update the public manifest in `safetre/manifest.py` only if the capability is
   safe to publish outside the safepod. Fixed-function extensions such as
   `corr` must stay schema-validated and deterministic.
4. Add a validation test in `tests/test_secure.py` (accept the new valid spec;
   confirm anything off-allowlist is still rejected).

Never widen a view to expose an identifier or free-text column — that is the one
invariant the whole design rests on.

Stats tools enter as fixed-function tool schemas plus deterministic validators,
never as arbitrary generated code. GLM and ANOVA are already live; the next
planned tool is `regression` (continuous-predictor linear models). Listing a
tool in `planned_tool_classes` does not make it executable; only `tools[]`
entries with `status: "available"` may be proposed.

## Adding a disclosure control

Controls live in `safetre/disclosure.py`:

- per-cell rules (is this cell releasable?) → a `CellVetter`. `StandinVetter`
  holds the prototype's own; `CompositeVetter` runs several and suppresses if
  any of them does. A vetter only ever *decides* — suppression, finalization
  and released-value shaping stay the policy's, which is what keeps the
  release-equality property true whatever rules run
  ([the seam](acro-integration.md));
- what a released table may contain at all (identifiers, free text) →
  `leak_detector`, which is also the red-team's ground-truth oracle;
- session checks (cross-query) → extend `SessionAuditor`.

A new vetter's findings must say whether suppressing the offending cells
resolves them (`Finding.suppressable`). One that does not has every query it
touches escalated and denied — which is exactly what happened the first time
an external checker ran end to end.

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
