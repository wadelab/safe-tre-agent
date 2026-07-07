# Maintenance guidelines

How to change this system without breaking its claim. Each section is a
per-change-type checklist: the rule, the steps, and the automated tripwires
that catch a skipped step. The detailed rationale lives in the linked pages —
this page is the playbook.

Two principles govern every change:

1. **The [specification](specification.md) leads.** A change to what the
   system must or must not do starts as a clause amendment (with a
   traceability row), lands as code + tests that cite the clause, and only
   then updates the prose docs. If the spec doesn't change, the behaviour
   doesn't get to change.
2. **Refuse loudly, never repair silently.** Any change that would make the
   system answer a *different* question than the one asked — a merged
   category, a dropped cell, a quietly substituted planner — is wrong even
   when it is "safe". Denials are part of the product.

## The gate list

Every change, whatever its type, is green on all of these before it merges.
CI runs them; run them locally first:

| Gate | Command |
|---|---|
| Lint (zero-findings baseline) | `uv run ruff check safetre safetre_web tests scripts evals redteam formal` |
| Tests | `uv run pytest -q` |
| Exhaustive skeleton passes | `uv run pytest -q -m slow` |
| Red-team, gateway off vs on | `uv run python redteam/run_redteam.py` |
| SAST + dependency CVEs | `uv run bandit -q -r safetre safetre_web` · `uv run pip-audit` |
| Docs (strict) | `uv run --group docs mkdocs build --strict` |
| Formal sync + model check | `uv run python scripts/gen_alloy_catalogue.py` · `python3 formal/run_checks.py --jar <alloy.jar>` (see [formal/README.md](https://github.com/wadelab/safe-tre-agent/blob/main/formal/README.md)) |
| Accessibility (UI changes) | pa11y against the four demo states (see [CI](https://github.com/wadelab/safe-tre-agent/blob/main/.github/workflows/ci.yml)) |

Changes to `safetre/query.py`, `engine.py`, `procedures.py`, `disclosure.py`,
`audit.py`, or `safetre_web/identity.py` are **boundary changes**: CODEOWNERS
requires explicit human review, whoever (or whatever) authored the diff.

## Adding a statistical procedure

The worked, as-built example is
[verifiable-extensions §5](verifiable-extensions.md) (how `glm` was
admitted). The short form:

1. **Decide the architecture first.** If the statistic is computable from
   *catalogued aggregates* (cells, moments), make it a **cells-first model
   procedure**: plan ordinary QuerySpecs, fit only on gateway-finalized
   tables, inherit every disclosure rule, discharge O5 (reproducibility)
   instead of a bespoke influence witness. Only a statistic that genuinely
   needs row-level access gets an engine-side implementation — and that route
   waits for ACRO ([roadmap](roadmap.md) item 1). When in doubt: if you can
   write the estimator as a function of released-equivalent tables, you must.
2. **Spec first.** Amend/add R/P clauses and traceability rows (status
   *Planned*, flipped when implemented).
3. **Register the contract** in `safetre/procedures.py` — aggregate
   (`validate_measure`, `select_exprs`, `witness_plans`, `output_contract`,
   `measure_configs`) or model (`validate`, `plan_aggregates`,
   `preconditions`, `fit`, `output_contract`, `skeleton`, `model_key`).
   Procedures supply *fragments*; the SafeSQL shape stays centralised in
   `engine.compile_query`. Fitting code must be a pure function of the
   finalized frames: stdlib-only numerics in `safetre/stats.py`, no
   engine/duckdb imports (the AST noninterference tests enforce this).
4. **Declare the obligations** in `tests/test_procedure_conformance.py`
   (`PROCEDURES` / `MODEL_PROCEDURES`). This is deliberate double-entry
   bookkeeping: the build fails until the independent declaration matches the
   registry's self-declaration.
5. **Regenerate the formal artifacts**:
   `uv run python scripts/gen_alloy_catalogue.py --write` (skeleton.json and
   the generated Alloy block); extend the model's assertions if the new
   procedure adds a release path.
6. **Extend every verification layer** — none is optional:
   exhaustive enumeration over the procedure's finite skeleton (bounds
   asserted); Hypothesis strategies; for model procedures the refit-equality
   reproducibility test; a dev-only **oracle** cross-validation
   (scipy/statsmodels); **red-team attacks** in `redteam/attacks.yaml`
   (benign baseline + one per failure mode, each blocked by a *named*
   control); planner-eval corpus items.
7. **Advertise last, in one isolated commit**: the manifest bump + planner
   prompt change together (see below). Update the docs
   (traceability flips, tool-manifest, hardening log if applicable) and
   `CHANGELOG.md`.

**Never** emit per-observation outputs (residuals, fitted values, leverage —
P20), never round/suppress inside the procedure (the gateway owns
disclosure), and never let an unregistered `fn`/`tool` fall through to
another procedure's behaviour (R14).

## Adding or changing datasets, columns, thresholds

- **Catalogue/columns** (`safetre/query.py` CATALOGUE, `safetre/schema.py`
  roles + declared domains, `safetre/engine.py` views): every column gets a
  DI/QI/S/R role and, if categorical, a declared domain; identifiers, free
  text and raw timestamps go in **no** allowlist and no public view. Internal
  variables go in `internal_filters`/`internal_measures` only. Update both
  the public view and the `_*_u` unit view. Then regenerate the formal
  artifacts (step 5 above) — the skeleton sync tests fail CI until you do —
  and check the enumeration-bound assertions in the formal tests still hold.
- **Synthetic data** (`safetre/synth.py`): keep the pinned disclosure anchors
  (sub-threshold Northern Ireland and sex-X groups, the hostile injected
  string values) — tests and the red-team depend on them. Regenerate
  `./data` (`scripts/make_data.py`) and restart the server after dataset
  changes.
- **Thresholds/policy** (`config.yaml`, env): the loader precedence is
  defaults < config.yaml < env, and `tests/test_invariants.py` pins floors
  (min cell ≥ 5, rounding base ≥ 5, dominance ≤ 0.5). Never weaken a floor to
  make a demo nicer. Anything unresolved fails **closed** (P7) — preserve the
  `+inf` fill pattern in new safety columns.

## Changing the manifest or planner prompt

The manifest is **part of the safepod contract**
([tool-manifest](tool-manifest.md)): its hash is embedded in the planner
prompt and published to analysts. A tool becomes live only by moving from
`planned_tool_classes` into `tools[]`. Treat any manifest or `PLANNER_SYSTEM`
change as a mini release: one isolated commit, version string bumped
(`MANIFEST_VERSION`), contract pins in `test_manifest.py`/`test_web.py`
updated deliberately (never loosened to "whatever it is"), security review,
and in a real safepod the same process as a code deployment — review, signed
artifact, audit trail. The planner is untrusted, so prompt changes carry
**no safety obligation** — but they carry a quality one: run
`uv run python evals/run_planner_eval.py` before and after, and extend the
corpus for new phrasings.

## Changing the UI (e.g. when GOV.UK guidance changes)

The shell is **frozen — fixes only** ([roadmap](roadmap.md)): a real TRE
supplies its own identity and boundary, so shell features do not advance the
research. A GOV.UK Design System update, an accessibility fix, or rendering
an already-released artifact all count as fixes. New controls, new pages, and
new data surfaces do not.

When you do touch it:

- Stay **unbranded**: GOV.UK layout and components, but no GDS Transport
  typeface, no crown, no claim to be a government service (the footer says
  so). See [govuk-ui-plan](govuk-ui-plan.md) for the original mapping.
- Keep the hardened posture: CSP stays `script-src 'self'` — **no CDN
  assets, ever**; all CSS/JS ships from `safetre_web/static/`. The identity
  and channel modules are boundary files; a UI change has no business in
  them.
- P18 holds in the template: a denial renders **no** data table.
- Gate on **pa11y (WCAG 2.2 AA)** against all four demo states (home,
  released, redacted, denied) — the CI job shows the exact invocation.
- Regenerate the deck screenshots afterwards
  (`scripts/make_decks.py`; capture needs a temporarily allow-all identity —
  restart with a copy of `.env.local` that empties `SAFETRE_ALLOWLIST`,
  capture, then restart with the real file).

## Installing and deploying

Full guides: [install](install.md), [deployment](deployment.md),
[certification & hardware](certification.md). The non-negotiables:

- **Pinned environments only**: `uv sync --all-extras --frozen` (exactly
  `uv.lock`). The runtime dependency set is part of the audit surface — keep
  it at the five runtime packages; oracles (scipy/statsmodels) and tooling
  stay dev-only. `pip-audit` and `bandit` run in CI; GitHub Actions and the
  Alloy jar are pinned by SHA.
- **A real deployment runs a local model** inside the safepod (A5). A remote
  endpoint is an egress channel: synthetic data only, behind the explicit
  `SAFETRE_ALLOW_REMOTE_LLM` opt-in. If the configured model is unreachable
  the system fails loudly — the mock planner is a tests/CI opt-in, never a
  fallback (R13).
- **Fail-closed identity and channel**: the identity header is trusted only
  on loopback, or behind an explicitly asserted trusted proxy
  (`SAFETRE_TRUST_FORWARDED_IDENTITY`, optional shared secret). Widening
  `SAFETRE_CHANNEL_ALLOW_NETS` without that assertion turns the header into
  an auth bypass — the code refuses, don't fight it.
- **The audit key lives off-box** (`SAFETRE_AUDIT_KEY`, systemd
  `LoadCredential`), and the chain head is anchored off-box
  (`SAFETRE_AUDIT_HEAD_ANCHOR`); verify via `GET /api/audit/verify`.
- Run under the least-privilege systemd unit (`deploy/safetre-web.service`),
  bind loopback, expose via `tailscale serve` (or your TRE's equivalent).

## Releasing a version

The v0.2.0 recipe: update `CHANGELOG.md`; bump `[project] version` (the
package reads `__version__` from distribution metadata — one place only);
run the full gate list; `uv build`; **install the wheel into a fresh venv
outside the repo** and smoke it (`safetre-demo "regress total spend on age
band"` must release with identical coefficients); tag `vX.Y.Z`; push with the
tag; create a **draft** GitHub release attaching the sdist, wheel, and the
regenerated decks (binary decks are distributed via releases, not git —
`artifacts/*.pptx` is ignored; only the committed `.ppt` explainers are
tracked). Publishing the release — and any PyPI upload — is a deliberate,
human decision.

## When something goes wrong

A security finding gets a numbered entry in the
[hardening log](hardening-log.md) (finding, severity, fix, where), a
regression test that pins it, and — if it reveals a class of gap — a
framework change that makes the class inexpressible (hardening #25 →
declared output contracts is the model). Never fix a leak silently.
