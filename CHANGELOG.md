# Changelog

All notable changes to safe-tre-agent. The normative record of safety
behaviour is [docs/specification.md](docs/specification.md); security findings
and fixes are in [docs/hardening-log.md](docs/hardening-log.md).

## 0.4.0 — 2026-07-25

The release-equality round: the query path's released output is now proved to
be a function of the table the gateway approved, and two of this release's
entries are leaks that proof found. The dataset gained the concentration its
dominance rules had never been tested against, which turned the ACRO
comparison from a one-sided result into a two-sided one, and the integration
design was written from those numbers.

### Security

- **Complementary suppression no longer picks its victim by the exact count
  (hardening #27).** `_secondary_suppress` sacrificed the cell with the
  smallest pre-rounding count, so of two cells that both release as `n = 10`
  the analyst learned which was smaller. The victim is now ranked on the
  released (rounded) count and tie-broken on the public cell key.
- **Released rows are no longer ordered by the exact count (hardening #28).**
  The engine hands the gateway cells in `ORDER BY n DESC` on the exact count
  and the gateway preserved that order, so a released table ranked cells more
  finely than its own released counts did. `_finalize` now re-sorts on the
  rounded count, then the cell key — which also makes a release reproducible
  run to run, as `ORDER BY` over tied counts is not. Suppression decisions and
  released numbers are unchanged; only which cell is sacrificed and what order
  rows appear in.

### Added

- **ACRO integration design (roadmap item 1, slice 2 — the design, not the
  code).** [docs/acro-integration.md](docs/acro-integration.md) fixes what to
  build from the first slice's measurements: the seam is a `CellVetter`
  protocol *inside* the gateway's vetting step, so complementary suppression,
  finalization (which owns hardening #27 and #28) and released-value shaping
  stay ours and the release-equality proof survives; the three rule sets
  compose as a union, because the measurements show none subsumes another;
  the checker runs out of process on its own pinned environment (C3) and
  fails closed and loudly on any error, with its version recorded per release
  in the audit chain; and the dominance parameters become a function of the
  output contract's disclosure class, so the second-moment cell's treatment
  is a stated policy rather than an accident. Compatibility shims carry
  explicit removal conditions, and the rollout starts with a
  behaviour-preserving refactor the existing suites regress.
- **CI runs the exhaustive skeleton passes.** A new `exhaustive` job runs the
  `-m slow` suite — every query-skeleton point through the release-equality
  properties and every model-skeleton point through the P21 reproducibility
  meta-test — so "exhaustive, not sampled" is checked rather than asserted.
- **Measured: the dispersion cell, not the frequency threshold, is what
  refuses a cells-first model.** A gaussian model needs group means *and*
  group sums of squares, and P19 denies it if either is suppressed — but
  squaring is not share-preserving, so the same 50% dominance bound is far
  tighter on the second moment (an equal-rest cell of `k` donors crosses it at
  a linear share of `1/(1+√(k−1))` — 0.19 at twenty donors, 0.09 at a
  hundred). `scripts/measure_dispersion_sensitivity.py` →
  `artifacts/dispersion_sensitivity.json` quantifies it at both levels: 355 of
  the 2650 design cells that pass the bound on the linear scale fail once
  squared (none the other way), and 36 gaussian skeleton points are refused by
  the dispersion cell alone against 47 that release — 43% of the
  otherwise-available models. Not a defect, but a ceiling on the extension
  route that nothing stated: written up in
  [verifiable-extensions §5.1](docs/verifiable-extensions.md), with the
  consequence for ACRO integration (whether the second-moment cell is checked
  on the same parameters as the first is now a deliberate decision).
- **Release equality for the query path (roadmap item 2).**
  `tests/test_release_equality.py` discharges, for the aggregate path, what
  the P21 reproducibility meta-test discharges for the model path: over the
  enumerated skeleton (a spread sample by default, all 2622 points under
  `-m slow`), a verifier holding the gateway-finalized table and the spec
  recomputes the released frame bit for bit, and perturbing the engine's frame
  in ways finalization erases — counts moved inside their rounding bucket, the
  internal donor count and the dominance/influence witnesses moved inside
  their verdict, tied rows reordered — leaves the release byte-identical. This
  is the factoring `release = postprocess ∘ finalize ∘ vet` that hardening #26
  established, now pinned; it found hardening #27 and #28.
- **Planted dominance anchors in the synthetic data
  (`synth.DOMINANCE_ANCHORS`).** Sampled spend is heavy-tailed but not
  concentrated — no cell of ten donors or more reached 0.35 single-donor
  share — so both the stand-in's and ACRO's dominance rules were dead code on
  the whole corpus and the comparison measured nothing on that axis. Three
  regions are now concentrated to shapes that separate the two rule sets
  (Scotland 62% in one donor, Wales 46% + 46%, East Midlands 60% + 35%), by
  redistribution within the region and with leaders capped at the largest
  donor total the sampler already produced, so no event, donor or count moves
  and no spend outside the observed range is introduced.
  `tests/test_dataset_anchors.py` pins the shares, the invariants and the
  divergence. The dataset-derived artifacts were regenerated against it:
  `artifacts/rounding_distortion.json` (57 releasable models, down from 61 —
  a few design cells are now concentrated enough to refuse) and the demo
  screenshots.
- **The ACRO comparison now measures dominance divergence in both
  directions.** Six `acro_stricter` cells (the first found): ACRO's NK-rule
  suppresses a cell whose top two donors hold 90%, which the stand-in's
  single-contributor 50% bound releases — a real gap in the stand-in. Ten
  of the 21 `standin_stricter` cells are the converse: one donor over 50%,
  which neither of ACRO's default dominance rules catches. Neither rule set
  subsumes the other, so the integration keeps both; results and the corrected
  reading in [docs/acro-comparison.md](docs/acro-comparison.md). New targeted
  fixtures, and the harness now generates the documented 800-donor dataset
  when `data/` is absent instead of a smaller one, so CI and the published
  numbers describe the same dataset.
- **ACRO decision-comparison harness (roadmap item 1, first slice).**
  `redteam/run_acro_compare.py` replays every plain QuerySpec in the
  service-path red-team corpus (model specs expanded to their planned
  design-cell aggregates) through both the stand-in gateway and ACRO
  0.4.12's own check implementations, feeding ACRO one row per donor per
  cell so its threshold counts donors (P5/D4). Numbers, method and
  compatibility findings in
  [docs/acro-comparison.md](docs/acro-comparison.md); the headline is that
  complementary suppression is a rule ACRO does not have, so
  `_secondary_suppress` stays in force on top of it (the roadmap's contrary
  claim is corrected). New CI job `acro-compare` gates on harness integrity;
  ACRO lives in a separate dependency group because 0.4.x pins `pandas < 3`.
- **Temporal session model (roadmap item 2, third slice).**
  `formal/temporal_session.als` model-checks the auditor's
  `observe → apply → record` event order in Alloy 6 temporal logic: spend is
  monotone and the entry prechecks keep it inside the budget under the
  per-Session lock, exhaustion short-circuits every later request before
  engine work (P17), the fail-closed gate releases only unflagged
  release/redact verdicts (P7), a differencing pair can never fully release
  under the lock (P16), and the cohort history equals the released cohorts
  at every instant. The lock is an explicit assumption, not a fact: a
  mandatory-satisfiable run exhibits the hardening #18 TOCTOU once it is
  dropped. Wired into the CI `formal` job via `run_checks.py`; a new sync
  test pins the live service's trace order and record-only-on-release to
  the model.

## 0.3.0 — 2026-07-17

The formal round: the query boundary proved in Lean 4, the differencing rule
model-checked in Alloy, one-way ANOVA as the worked registry example, and a
p-value side channel closed. Plain-language account in the ELIF-FORMAL deck
(`artifacts/ELIF-FORMAL.ppt`).

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
