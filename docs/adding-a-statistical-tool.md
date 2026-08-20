# Adding a statistical tool: one-way ANOVA, end to end

This is a worked example. It walks through the actual change that added the
`anova` tool — a one-way analysis of variance — to show how a new statistical
capability is introduced without hand-auditing "three files and hoping." It is
the concrete companion to the architectural argument in
[Verifiable extensions](verifiable-extensions.md); read that first for *why* the
seams are where they are.

The headline: **a new model tool is almost entirely new *numerics* and a new
*output contract*.** The disclosure machinery — allowlisted design-cell
queries, the safe-outputs gateway, the fail-closed model path, reproducibility —
is inherited unchanged, because ANOVA fits from the same gateway-vetted cell
aggregates the GLM already uses. Nothing new touches row-level data.

## The one idea that makes it cheap

A one-way ANOVA of a gaussian response `Y` across the levels of a categorical
factor `A` is a function of the per-group first two moments — the group means,
group sums-of-squares, and group sizes. Those are **exactly** the aggregates the
gaussian GLM already plans (`mean` and `sum_sq` grouped by the factor). So the
ANOVA tool plans the identical design-cell `QuerySpec`s, lets each pass the
ordinary gateway, and then does its own arithmetic on the finalized cells:

```
N          = Σ n_g                    grand_mean ȳ = Σ n_g ȳ_g / N
SS_between = Σ n_g (ȳ_g − ȳ)²                       df_between = k − 1
SS_within  = Σ (S_g − n_g ȳ_g²)                     df_within  = N − k
F          = (SS_between/df_between) / (SS_within/df_within)
p          = P(F_{df_between, df_within} > F)
```

Every quantity is a deterministic function of released-equivalent cells, so the
disclosure claim is *inherited*, not re-argued: an analyst outside the safepod
holding only the released cell table reproduces the whole ANOVA table
(reproducibility is machine-checked). Because the cells are identical to the
gaussian GLM's, you can see it directly — run `regress total spend on age band`
and `one-way anova of total spend by age band` and the `cells` artifact is the
same table.

## The obligations, and where each is discharged

A new model procedure implements the `ModelProcedure` interface
(`safetre/procedures.py`). Each method is where one obligation is discharged:

| Obligation | Method | How ANOVA discharges it |
|---|---|---|
| **O1 admissibility** | `validate` → `AnovaSpec` | Pydantic allowlist: gaussian responses only, exactly one factor, factor ≠ response, no internal variables expressible. |
| **O2 compile safety** | `plan_aggregates` | Emits ordinary `QuerySpec`s (`group_by=[factor]`); the proven SafeSQL shape stays in the engine — the tool cannot deviate from it. |
| **O3 influence bound** | *(inherited)* | The planned `mean`/`sum_sq` aggregates carry the standard dominance witness; the tool adds none of its own. |
| **O4 lineage identity** | *(inherited)* | Cohorts flow through the standard `QuerySpec.filters`. |
| **Contribution** | `contribution_expr`, `checker_aggfunc` | How one donor contributes to a cell, and how those contributions aggregate — what an external output checker decides on, since a threshold counts donors and a dominance rule needs shares, neither of which survives aggregation. Declared with the procedure because it knows the *scale* its rule works on: `sum_sq` contributes squared. `None` where there is no donor-additive contribution. |
| **Optional tables** *(model procedures)* | `optional_roles` | Planned tables the model can be fitted without, costing part of the output rather than the fit. Today only the gaussian dispersion. Everything else is required, and a suppressed required cell denies the model (P19). |
| **Output contract** | `output_contract` | Every released column of every frame (`output`, `cells`, `model`) is classified — the gateway's treatment is declared, not inferred. |
| **P19 fail-closed** | *(inherited from `service._handle_model`)* | Any suppressed group cell denies the whole model, loudly. |
| **P21 noninterference** | `fit` signature `(finalized, spec)` | The fitter consumes finalized tables and nothing else; `safetre/anova.py` never imports the engine, database, or service. |
| **P22 estimability** | `preconditions` | Single-level factor / no-residual-d.f. refusals are decided from the finalized tables and name the factor, never a quantity. |
| **R16 enumerability** | `skeleton` | Exports the finite ANOVA request space into `formal/skeleton.json`. |

Note that `service._handle_model` never learned the word "anova." It speaks the
GLM's `response`/`terms` vocabulary, so `AnovaSpec` exposes a one-element
`terms` property that is a view of `factor`. That bridge is the reason the whole
secure pipeline drives the new tool with **zero changes to the service**.

## The steps (the actual diff)

1. **A numeric primitive — `stats.f_sf`** (`safetre/stats.py`). The omnibus
   p-value is the F-distribution upper tail, which is just the incomplete beta
   already in the module — no new special function, and the stdlib-only boundary
   (the P21 physical guarantee) is preserved. Cross-validated against
   `scipy.stats.f.sf` in `tests/test_stats.py`.

2. **A typed request boundary — `AnovaSpec`** (`safetre/query.py`). The security
   boundary: gaussian response, one factor, allowlisted filters. Anything
   off-allowlist is rejected before any execution.

3. **The procedure — `AnovaProcedure`** (`safetre/anova.py`). Implements the
   `ModelProcedure` methods above and self-registers into `MODEL_REGISTRY`. It
   reuses the GLM's `_term_levels` helper and produces the same-shaped `cells`
   artifact, so the two tools' vetted tables coincide by construction.

4. **Wiring** so the untrusted planner can *request* it and the vetting layer
   lets the request through:
   - `manifest.py` — promote `anova` from `planned_tool_classes` to `tools[]`
     (bump `MANIFEST_VERSION`); this publishes the capability the planner sees.
   - `planner.py` — a paragraph of `AnovaSpec` guidance for the real LLM planner,
     and a deterministic `MockPlanner` branch for offline/testing.
   - `analyst.py` — add "anova" / "analysis of variance" to the analysis cues so
     `vet_request` recognises the request as in-scope. (The planner is untrusted,
     so this changes *what can be asked*, never *what is safe*.)

5. **Regenerate the formal artifact**:
   `uv run python scripts/gen_alloy_catalogue.py --write`. This rewrites
   `formal/skeleton.json` to include the ANOVA request space. The Alloy model's
   generated block is untouched here, because ANOVA reuses existing gaussian
   responses and adds no catalogue atoms — the correspondence chain
   (code → skeleton → model) stays in sync and CI proves it.

6. **Tests** — the same bar every procedure meets:
   - `tests/test_anova.py` — release contract, reproducibility-from-cells,
     fail-closed denial on a suppressed cell, estimability refusals, and an
     oracle check of F and p against `scipy.stats.f_oneway`.
   - Meta-tests updated so the registry stays self-describing:
     `test_procedure_conformance.py` (declares ANOVA's obligation),
     `test_skeleton_sync.py` (bounds the new model space),
     `test_glm_noninterference.py` (the P21 import boundary now also guards
     `safetre.anova`), and the manifest/web contract tests.

## What was *not* touched

`engine.py`, `disclosure.py`, and `service.py` — the trusted core — are
unchanged. That is the whole claim of the design working: a new statistical
capability is a small, enumerable, testable addition at the registry seam, not a
cross-cutting edit to the parts that carry the disclosure proof.

## Limits of this tool (deliberate)

One factor, gaussian response, main effect only, treatment of the omnibus F —
no two-way ANOVA, interactions, post-hoc contrasts, or non-parametric variants.
Those are further tools, each a similar-sized addition. A multi-factor request
is routed to the `glm` tool (whose coefficient t-tests are the model-form of the
same analysis); a request naming two factors to `anova` is refused by the term
coherence check rather than silently reduced to one.


## A second example, one round later: the `series` tool

The ANOVA walk-through above was written to show that a new tool is "almost
entirely new numerics and a new output contract". The `series` tool
(`safetre/series.py`, 2026-08-15, for the [inside analyst](inside-analyst.md)'s
phase 2) is the second pass through the same checklist, and the first tool
that is not a regression — which is what makes it a real test of the claim.

A **time series** here is a vetted per-window aggregate: the mean or sum of
one measure grouped by a dimension the dataset definition declares to be an
ordered time axis (`month`, `wave`; `time_dims:` on the view — declared, not
inferred, because an integer dimension is not necessarily a time). That
window table is *one ordinary `QuerySpec`*, so O2/O3/O4 are inherited as
literally as for ANOVA, and it passes the ordinary gateway cell by cell. The
tool's own arithmetic runs on the finalized windows and nothing else:

```
trend        OLS of value on window index: slope, intercept, R²
acf          autocorrelation at lags 1..L, L = min(4, n_windows // 3)
periodogram  |DFT of the demeaned series|² at frequencies 1..⌊n/2⌋,
             the dominant period and its share of the spectral power
```

Every output is a deterministic function of released-equivalent cells
(stdlib `cmath`, no dependency), so an analyst holding the released `cells`
frame — the series itself — reproduces every diagnostic bit for bit
(`refit_from_artifact`, pinned in `tests/test_series.py`). What is different
from ANOVA, and where the checklist earned its keep:

- **A request-decided refusal.** An axis that declares fewer than four
  windows can never carry a series, whatever the cohort, and its domain is
  public — so `SeriesSpec` refuses it at validation, naming the axis, rather
  than letting it reach the data and come back as a canonical refusal. The
  demo's `wave` (two windows) is exactly that case, which is why the demo's
  series skeleton is empty and the tool is exercised on the NIGHTPLAY study.
- **A gap is a P22 refusal that must not name the window.** A missing window
  inside the requested range means "no rows in that window for this cohort",
  which is an existence fact; the refusal says the series is not contiguous
  and does not say where.
- **The service was untouched, again.** `SeriesSpec` exposes `terms` as the
  one-element time axis, so `_handle_model` drives it as it drives ANOVA.

The steps were the ANOVA steps: `time_dims` on the definition and in the
catalogue; `SeriesSpec` in `query.py`; the procedure; the manifest entry and
version bump (`v13`), the planner paragraph and mock branch, the analysis
cues; the conformance obligation, skeleton bound, noninterference guard and
manifest pins; the formal artifacts regenerated. `tests/test_series.py` adds
the tool's own bar — contract, reproducibility, fail-closed on a suppressed
window, request-decided and finalized-table refusals, an exhaustive pass over
the NIGHTPLAY series skeleton, and the numerics against numpy.

## A third example: assumption tests and multiplicity, below the skeleton

The `anova` and `series` tools each added a request to the finite skeleton. The
next round added two things that are safe *without touching the skeleton at all*,
because they are functions of quantities the pipeline had already vetted or
released — the strongest form of "inherited, not re-argued".

- **Bartlett's homogeneity-of-variance test**, reported alongside the ANOVA
  table (`safetre/anova.py`). ANOVA already computes the per-group variances and
  the pooled variance (`ms_within`) from the finalized `mean`/`sum_sq` cells, so
  Bartlett's χ² and its p-value are *more arithmetic on the same finalized
  cells*: no new `QuerySpec`, no new catalogue atom, and `formal/skeleton.json`
  regenerates byte-identical. The output contract classifies the three new
  columns (`bartlett_chi2`/`bartlett_df` as `statistic`, `bartlett_p` as
  `p_value`), and `refit_from_artifact` reproduces them from the released cells,
  so P21 holds unchanged. (It is Bartlett, not Levene: Levene needs a row-level
  `|x − mean|` transform, which would be a new vetted aggregate; Bartlett is the
  moment-native homogeneity test that rides the cells ANOVA already vetted. A
  moment-based normality test, Jarque–Bera, would need the 3rd/4th moments the
  measure allowlist stops short of, and so is a heavier, separate round.)
- **Benjamini–Hochberg multiplicity correction** (`safetre/stats.benjamini_hochberg`,
  applied by the safe analysis engine in `Dossier.correct_multiplicity`). It is a
  pure function of *already-released* p-values — it touches no data, no cell and
  no gateway — so it is safe wherever those p-values were safe to release. It
  controls the false-discovery rate across the multiple tests one research
  question ran, and it excludes assumption diagnostics like `bartlett_p` from the
  family, because those are not the hypotheses under test.

Both stay inside the stdlib-only `safetre/stats.py` boundary (the chi-square tail
is `regularized_gamma_q(df/2, x/2)`, already present), cross-validated against
`scipy.stats.bartlett`, `scipy.stats.chi2.sf` and
`scipy.stats.false_discovery_control`. The formal layer needed no change: the
skeleton is byte-identical and `formal/` is untouched, so the existing Lean and
Alloy proofs cover the round unchanged — the addition is genuinely below the
surface they check.
