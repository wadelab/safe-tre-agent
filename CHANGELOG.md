# Changelog

All notable changes to safe-tre-agent. The normative record of safety
behaviour is [docs/specification.md](docs/specification.md); security findings
and fixes are in [docs/hardening-log.md](docs/hardening-log.md).

## Unreleased

### Security

- **Fixed a p-value side channel on `corr` (hardening #26):** released-value
  shaping (`postprocess`) ran in the engine, before gateway finalization, so
  a released correlation's `p_value` was computed from the exact pre-rounding
  cell count — fine-grained information about the `n` that base-5 rounding
  exists to blur. Shaping now runs on the gateway-finalized frame on both the
  plain and the model path: the released `(value, p_value, n)` triple is
  self-consistent, and every released number is recomputable from numbers
  already released.

### Added

- **One-way ANOVA (`anova`), the second registered model procedure.** Fits
  from the same gateway-vetted mean/`sum_sq`/`n` group cells the gaussian GLM
  already plans, so the disclosure machinery (allowlisted design-cell
  queries, fail-closed denial, reproducibility from the released cell table)
  is inherited unchanged. Stdlib-only F-tail (`stats.f_sf`) cross-validated
  against scipy; manifest v5 promotes `anova` to available; 49 new
  model-skeleton points; a worked example of the registry recipe in
  [docs/adding-a-statistical-tool.md](docs/adding-a-statistical-tool.md).
- **Literal spec entry (spec R17).** A request that is a single JSON object
  is taken as the spec itself, bypassing the planner and the
  natural-language gates (intent vetting, fidelity checks) — every
  downstream control (validation, budget, gateway, lineage, audit) applies
  unchanged. Malformed JSON is refused loudly, never handed to the planner
  as text. Red-team: a benign literal baseline plus a literal small-cell
  attack pin the path.
- **Formal round 2 (roadmap item 2, spec R16).** A Lean 4 model of the query
  boundary, generated from and pinned to the live code: no valid QuerySpec
  references an identifier, free-text, or timestamp column (P3);
  internal-only columns never reach a group-by or a release (P4); compiled
  SQL is one read-only SELECT over the declared view with every filter value
  a bound parameter (P9); DI/QI/S/R labels are consistent, with a
  column-level noninterference corollary end to end. Pinned by a 414-case
  byte-exact render-equality check against `compile_query` and a third sync
  hop (`test_formal_lean_sync.py`); the proofs are replayed in the CI
  `formal` job (Lean pinned by sha256). A second Alloy model
  (`formal/disclosure_policy.als`) checks the session auditor's simulatable
  differencing rule (P11) and machine-exhibits its two documented residuals.
- **Public-repo-first demo package.** The repo is the demo surface:
  [docs/public-demo.md](docs/public-demo.md), a five-minute tour, a
  screenshot tour and an evidence checklist, with
  `scripts/make_demo_screenshots.py` regenerating the demo figures against a
  throwaway mock server.
- **Decks and generators.** A maintenance-playbook deck and doc
  ([docs/maintenance.md](docs/maintenance.md)), a component & trust-map
  generator (`scripts/make_component_map.py`), and a plain-language
  explainer deck for the formal layer (`artifacts/ELIF-FORMAL.ppt`, built by
  `build_formal_elif()` in `scripts/make_decks.py`).

### Changed

- **Model/provider identities redacted repo-wide:** tracked files use the
  generic `SAFETRE_LLM_*` endpoint recipe and neutral "automated planner"
  language (decks and web UI regenerated to match).
- **Preprint** brought up to date with the GLM / procedure-framework round.

## 0.2.0 — 2026-07-07

The GLM / statistical-procedure-framework round. Plain-language account in
[docs/elif.md](docs/elif.md).

### Security

- **Fixed a count-rounding bypass (hardening #25):** released count queries
  carried the exact count in `value` beside the rounded `n`, making base-5
  count rounding a no-op. Counts now release `n` alone.

### Added

- **Statistical procedures as registered contracts (spec R14).**
  `safetre/procedures.py` holds the aggregate and model registries; the three
  former `if fn == …` dispatch sites delegate to it and fail loudly on an
  unregistered function. Adding a procedure without declared conformance
  obligations fails the build.
- **A `glm` tool (spec R15), cells-first.** Gaussian / binomial (logit) /
  Poisson models over up to three categorical terms, fitted **exclusively
  from gateway-finalized design-cell aggregates** by a stdlib-only IRLS.
  Any suppressed design cell denies the whole model (P19); per-observation
  outputs are not expressible (P20); a release carries the coefficient table,
  the model block, and the vetted cell table it was fitted from, and
  `safetre.glm.refit_from_artifact` reproduces the release bit-for-bit (P21).
  Estimability refusals are decided from the finalized tables alone and name
  terms, never quantities (P22).
- **`sum_sq`** as a fifth registered aggregate (second-moment cells; the
  gaussian dispersion input and the L2 moment-cell groundwork).
- **Formal layer (spec R16).** The registries export their finite request
  space (`formal/skeleton.json`); a bounded Alloy model generated from it
  checks P19/P21 over every vetting outcome and P4-admissibility over the
  exact catalogue atoms; two pytest sync hops pin code → skeleton → model;
  a CI `formal` job runs the solver (sha256-pinned Alloy 6.2.0).
- **Verification:** exhaustive enumeration of all 718 model skeleton points;
  a reproducibility meta-test (refit-equality, exhaustive at ≤ 2 terms,
  full skeleton under `pytest -m slow`); AST noninterference checks;
  statsmodels as a dev-only oracle (row-level fits match to 1e-8); nine new
  red-team attacks (20 total, all blocked by named controls); GLM items in
  the planner-eval corpus.
- **Measured, not asserted:** `scripts/measure_rounding_distortion.py`
  quantifies the finalized-weights (rounded-count) fitting distortion
  (`artifacts/rounding_distortion.json`).
- `safetre-demo` console script (the packaged face of
  `scripts/demo_query.py`); MIT license; ruff lint baseline.

### Changed

- Manifest v4: `glm` promoted from planned to available; the aggregate tool's
  function list is derived from the registry; planner prompt carries the
  GLMSpec shape and examples. Spec amended: R4 reworded; new clauses R14–R16
  and P19–P22, all Implemented in the traceability table.

## 0.1.0 — 2026-07-06

Initial research prototype: the validated QuerySpec boundary (count / mean /
sum / Pearson corr), read-only DuckDB engine, ACRO-style disclosure gateway
with simulatable session auditing, HMAC-chained audit log, GOV.UK-styled demo
shell, red-team harness, synthetic UK dataset, specification (R1–R13,
P1–P18), and three rounds of hardening.
