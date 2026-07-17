# Verifiable extensions: structuring modules so new procedures and queries carry their proofs

This document answers a specific design question: **how do we structure the
system so that adding a new statistical procedure (regression, quantiles,
ANOVA) or supporting a new kind of natural-language query is
verifiable-by-construction, rather than a hand-audited change to three files?**

It is the architectural companion to [Formal methods analysis](FORMAL_METHODS_ANALYSIS.md),
which catalogues *what* to prove about the current system. This one is about
*where the seams should be* so that each new thing you add comes with a fixed,
enumerable set of obligations — and so that you cannot wire it in until those
obligations are discharged.

The motivating example is real. Adding the `corr` procedure (round 2d) touched
`query.py` (schema), `engine.py` (compilation), and `disclosure.py` (a new
control), and its most important obligation — *no single donor may dominate a
released correlation* — was **nearly missed**, because nothing in the structure
*required* a new procedure to answer "how much can one individual move this
output?" (see [hardening log](hardening-log.md) #15). The fix worked; the
process that let it slip is the thing to fix here.

---

## 1. The trusted computing base, and two kinds of extension

Draw one line. Everything on the untrusted side may be arbitrary, adversarial,
or wrong; everything on the trusted side is deterministic, least-privilege, and
must be verified.

```
        UNTRUSTED                        │            TRUSTED (the TCB)
  researcher text, the LLM planner,      │   QuerySpec validation · engine
  row-level data (may carry injection)   │   compilation · disclosure gateway
                                         │   · session auditor · audit log
```

The two kinds of extension you named sit on **opposite sides of this line**, and
that is the whole point:

- **A new statistical procedure extends the TCB.** `corr` added trusted code
  that reads sensitive per-individual values and emits a released number. It
  therefore carries **proof obligations**: it must not be expressible over a
  forbidden column, must compile to safe read-only SQL, and must bound
  single-individual influence.

- **A new natural-language query does *not* extend the TCB.** The planner is
  untrusted by construction. A new phrasing (“break spend down by region”) is
  just a new path into the *same* `QuerySpec` space. It carries **no proof
  obligation at all** — only test obligations (does it map to the intended
  spec? does the mapping drift?). If the spec space is safe for *every* value,
  then every natural-language request that maps into it is safe, whatever the
  model does.

Keeping these separate is the key structural decision. It means the verification
frontier is the `QuerySpec` boundary, the procedure registry behind it is small
and finite, and the unbounded, fuzzy, model-driven part stays outside the things
you prove.

---

## 2. A procedure as a contract

Today a procedure is implicit: a `fn` value in a `Literal`, plus `if fn == …`
branches scattered across validation, compilation, and disclosure. Make it an
explicit unit with four obligations, each of which maps to a verification
technique. A procedure is *admissible* only when all four are discharged.

| # | Obligation | What it means | How it is discharged | Current status for `corr` |
|---|------------|---------------|----------------------|---------------------------|
| O1 | **Admissibility** | its arguments range only over allowlisted columns of the right kind; identifiers/free-text/raw-non-approved columns are not expressible | finite membership check → property test now, Lean `decide` later | `_check_allowlist` requires `x`,`y ∈ measures ∪ internal_measures`; `test_query_properties` fuzzes it |
| O2 | **Compilation safety** | it compiles to a read-only `SELECT` over a *declared* source view, bound parameters only, fixed shape | inspect the `SQLPlan`; property test over generated specs; grammar proof later | `compile_query` corr branch; shape asserted in `test_query_properties` |
| O3 | **Individual-influence bound** | no single donor may dominate the released statistic; if one can, the cell is suppressed | an internal per-donor influence plan on the unit view + a gateway threshold | **the obligation that was nearly missed**: leave-one-donor-out `influence` (round 2d) |
| O4 | **Lineage identity** | its released cohort is registered so cross-query differencing is caught | reuse `QuerySpec.normalized_filters()` + `SessionAuditor` | inherited for free — corr routes filters through the standard path |
| O5 | **Reproducibility** *(model procedures)* | the released model is a deterministic function of the released artifacts alone — the fitter can see nothing an analyst could not | refit from the released cell table, assert exact equality (`refit_from_artifact` + the meta-test in `test_glm_properties.py`); AST noninterference checks; Alloy `P21` | discharged for `glm` |
| O6 | **Skeleton export** | the procedure's finite request space is exported as data, so the exhaustive check and the formal model quantify over the space the code actually exposes | `skeleton()` / `measure_configs()` → `formal/skeleton.json` + sync tests + the generated Alloy catalogue | discharged for all registered procedures |

Two observations make this tractable:

- **O4 is free** as long as a procedure expresses its cohort through the standard
  `filters`. Differencing defence is *dataset-and-cohort* level, not
  procedure-specific, so procedures inherit it. (The round 2e real-model
  red-team confirmed lineage firing on a real correlation query.)
- **O3 is the load-bearing, procedure-specific obligation** and the one with no
  natural home today. Every procedure that reads a sensitive per-individual
  value needs an *influence witness*: a deterministic function `spec → (per
  group) max single-donor effect on the released number`, computed on the
  internal unit view and never released. `sum`/`mean` have it as the
  p%-**dominance** share; `corr` now has it as leave-one-donor-out **|Δr|**; a
  future `regression` would need leverage / Cook's distance; `quantile` would
  need a rank-based analogue. `count` reads no per-individual value and needs
  none.

---

## 3. The module structure that makes this hold

### 3.1 A procedure registry, and a pipeline generic over it

Replace the scattered `if fn == …` branches with a registry of procedure
objects, each carrying its own four obligations:

```python
class Procedure(Protocol):
    fn: str
    reads_individual_values: bool
    def validate_measure(self, m: Measure, cat: CatalogueEntry) -> None: ...   # O1
    def compile(self, spec: QuerySpec) -> SQLPlan: ...                          # O2
    def influence_plan(self, spec: QuerySpec) -> SQLPlan | None: ...            # O3 (None iff not reads_individual_values)
    def output_columns(self, spec: QuerySpec) -> tuple[str, ...]: ...

REGISTRY: dict[str, Procedure] = {"count": Count(), "mean": Mean(), "sum": Sum(), "corr": Corr()}
```

- `QuerySpec._check_allowlist` dispatches the measure check to
  `REGISTRY[fn].validate_measure` (O1).
- `QueryEngine.run` calls `REGISTRY[fn].compile` and, when
  `reads_individual_values`, `REGISTRY[fn].influence_plan` — attaching the
  helper column the gateway then drops (O2, O3).
- The disclosure gateway stays generic: it suppresses on whichever
  influence/dominance helper is present and drops it before release.

The refactor is mechanical and behaviour-preserving; its value is that the
`Procedure` interface becomes the **checklist you cannot skip**. There is no way
to register a procedure that reads individual values without providing an
`influence_plan`, because the type says so and the pipeline calls it.

> **Status.** Implemented in `safetre/procedures.py` (a CODEOWNERS boundary
> file), with one deliberate refinement over the sketch above: a procedure
> supplies only its aggregate *select-expression fragments* and witness plans —
> the proven SafeSQL shape (single SELECT over one declared view, bound
> parameters, `ORDER BY n DESC LIMIT` cap) stays centralised in
> `engine.compile_query`, so a procedure cannot deviate from the shape, only
> inject `_ident`-checked expressions. Each procedure also declares an **output
> contract** (released columns with disclosure classes — see spec R14) and a
> finite skeleton export (`measure_configs`). The conformance suite below still
> enforces the obligations *from outside*, and now additionally cross-checks
> its declarations against the registry's.

### 3.2 The conformance suite (implemented — the executable first step)

`tests/test_procedure_conformance.py` is the design above expressed as a test,
and it works against the current code with no refactor:

- It reads the supported functions **from the source of truth**
  (`get_args(Measure.model_fields["fn"])`) and asserts each has a declared
  obligation. *Add a `fn` to the schema without declaring its obligation and the
  build fails.*
- For every procedure that reads individual values, it asserts the engine
  attaches the declared influence control (`dominance`/`influence`) and the
  gateway drops it before release. *This is the check that would have caught the
  corr gap.*
- It re-runs the universal release invariant (no identifier/free-text/raw-age/
  sensitive columns, no sub-threshold or unrounded cells) per procedure.
- It asserts each procedure compiles to the safe read-only SQL shape.

This is the cheapest possible version of “new procedures carry their proofs”: a
single parametrised battery every procedure is held to, enumerated so you can’t
forget one.

---

## 4. Natural-language queries need no proof — they need a corpus

Because the planner is outside the TCB, a *new NL query* is verified the moment
it maps to an admissible `QuerySpec`: the spec-space safety proof (O1–O4) already
covers every value it could produce. So the structure for NL is deliberately
*not* a proof pipeline:

1. **The typed boundary is the frontier.** The planner returns only a
   `QuerySpec`; malformed or off-allowlist output is rejected with no execution.
   Nothing about a new phrasing can widen the reachable spec space.
2. **A golden NL→spec corpus** (regression fixtures) pins the *intended*
   translation for representative requests, so planner or prompt changes that
   silently drift are caught — a quality obligation, not a safety one.
3. **The real-model red-team** (`redteam/realmodel_results.txt`, round 2e) is the
   empirical safety check: adversarial phrasings through the *real* untrusted
   model, with a strict output invariant. It found 0 disclosures across 22
   queries precisely because the safety argument never depended on the model.

So: proofs and conformance for the finite procedure space; corpus and red-team
for the infinite NL space. Do not try to verify the planner — verify what it is
allowed to say.

---

## 5. Worked example — how the `glm` procedure was admitted (as built)

An earlier draft of this section sketched a `regression` procedure fitted on
row-level data, discharging O3 with a leverage/Cook's-distance witness and a
residual-degrees-of-freedom floor. The `glm` procedure that actually landed
takes a strictly stronger route — **cells-first**: it never touches rows, so
O3 is *inherited* rather than re-proven, and a new obligation (O5) replaces it.

1. **Schema (O1).** `GLMSpec` is a parallel typed boundary (`tool: "glm"`,
   family, response, ≤ 3 categorical terms), not a `Measure` extension: a
   model is a multi-query procedure, and `QuerySpec` stays the frozen, proven
   single-query space. The catalogue gained a `glm_responses` per-column
   family allowlist. *`test_formal_glm_enumeration` exhaustively checks all
   718 skeleton points and that off-allowlist perturbations fail.*
2. **Compilation (O2) — by inheritance.** `plan_aggregates` emits ordinary
   `QuerySpec`s (mean + sum_sq cells for gaussian; trials + successes counts
   for binomial; sums with exposure for poisson). Every one compiles through
   the same proven SafeSQL shape as any hand query. *The conformance and
   enumeration suites assert every planned aggregate is a valid QuerySpec.*
3. **Influence (O3) — by inheritance.** The gateway vets every design cell
   with the standard threshold/dominance/fail-closed rules **before** the fit
   exists; any suppression denies the whole model (P19). No model-specific
   influence witness is needed because no released number is computed from
   anything the gateway did not already pass.
4. **Lineage (O4).** Free, as designed: each underlying aggregate routes its
   cohort through `normalized_filters()`, so model differencing is caught by
   the same auditor (red-team `glm_differencing_pair`). Budget is charged per
   underlying aggregate.
5. **Reproducibility (O5) + output contract.** The fitter is a pure stdlib
   function of the finalized tables (P21); a release carries the coefficient
   table, the model block, and the vetted cell table it was fitted from, and
   `refit_from_artifact` reproduces the release bit-for-bit — machine-checked
   over the skeleton. Per-observation outputs (residuals, fitted values,
   leverage) are not expressible and are refused at intent (P20).
6. **Skeleton export (O6).** `skeleton()` feeds `formal/skeleton.json`, the
   exhaustive enumeration, and the generated Alloy and Lean catalogues; the
   pytest sync hops (listed in `formal/README.md`) pin the chain.

The engine-side route (row-level fitting with leverage witnesses and a
dof floor) remains the template for procedures whose sufficient statistics are
**not** catalogued aggregates — non-gaussian models with continuous
predictors — and is deliberately parked behind ACRO integration (roadmap
item 1), which would supply production-grade output checking to lean on.

---

## 6. How this maps onto the roadmap

| Phase | Step | Status |
|-------|------|--------|
| done | Conformance suite enumerated from the schema; per-procedure influence obligation | `tests/test_procedure_conformance.py` |
| done | `Procedure` registry refactor; delete the `if fn == …` branches | `safetre/procedures.py` (aggregate + model registries) |
| done | First model procedure (`glm`, cells-first) with O5 reproducibility + O6 skeleton export | `safetre/glm.py`, `test_glm*` suites |
| done | Bounded Alloy model of the model release path (P19/P21/P4), generated from the skeleton, CI-gated | `formal/`, CI `formal` job |
| done | Golden NL→spec corpus and scored planner evaluation | `evals/corpus.yaml`, `evals/run_planner_eval.py`, [planner evaluation](planner-eval.md) |
| next | Commit a runnable (key-gated) real-model red-team harness | partial (round 2e run recorded) |
| done | Lean proofs of the O1/O2 boundary over the whole spec space | `formal/lean/` (P3/P4/P9, label consistency, the 414-case engine pin) |
| done | Temporal model of the auditor's sequential composition (`observe → apply → record`) | `formal/temporal_session.als` (P7/P16/P17; hardening #18 race machine-exhibited) |

The through-line: make the **procedure interface the proof-obligation
checklist**, keep **natural language outside the proofs**, and let a single
conformance battery hold every present and future procedure to the same bar.
```
