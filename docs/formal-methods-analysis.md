# Formal Methods Analysis for safe-tre-agent

## Executive Summary

**This system is unusually well-suited for formal verification.** The query space is finite and enumerable — a small set of datasets, dimensions, measures, fixed aggregate functions, operators, and bounded group-by/filter counts — making security properties decidable in ways that would not work for arbitrary SQL systems.

This document catalogues the existing lightweight formal guarantees, identifies six concrete opportunities for stronger formal methods, proposes a phased roadmap, and notes the inherent limits of what formal methods can achieve in this context.

> **Source of truth:** the properties to prove are stated normatively in the [specification](specification.md) as the `P` (prohibition) and `R` (requirement) clauses. This document is about *how* to prove them; the specification is *what* must hold.

> **Companion:** [Verifiable extensions](verifiable-extensions.md) covers the *structural* side of the same problem — how to lay out modules so that adding a new statistical procedure or natural-language query comes with a fixed, enforced set of verification obligations, rather than a hand-audited change. It introduces the procedure-contract model (O1–O4) and the executable conformance suite (`tests/test_procedure_conformance.py`) that holds every present and future procedure to the same bar.

---

## 1. Existing Lightweight Formal Guarantees

The system already employs several techniques that border on formal guarantees:

| Layer | File(s) | Technique | Guarantee |
|-------|---------|-----------|-----------|
| Query schema | `safetre/query.py` | Pydantic `extra="forbid"` + `Literal` types | The LLM cannot invent new JSON fields — any extra keys are rejected at parse time |
| Catalogue allowlist | `safetre/query.py` (`CATALOGUE`) | Finite dictionary of permitted public and internal-only columns | Direct identifiers (`donor_id`), free text (`free_text`), and timestamps (`ts`) are **absent by construction**; high-granularity variables such as `age_years` are internal-only and cannot be grouped or returned |
| Identifier validation | `safetre/engine.py` (`_ident()`) | Regex `^[a-z_][a-z0-9_]*$` on all column names | SQL injection through identifiers is impossible — only valid bare names pass |
| Filter value binding | `safetre/engine.py` (`_where()`) | Bound `?` parameters in DuckDB | SQL injection through filter values is impossible |
| View separation | `safetre/engine.py` (`_VIEWS` / `_UNIT_VIEWS`) | Public views exclude `donor_id`, `free_text`, and raw age; internal unit views exist only for fixed tools and disclosure machinery | Identifiers cannot be reached through the public query path |
| Static regression guards | `tests/test_invariants.py` | Static code inspection at test time | Catches regressions if someone adds identifiers to the catalogue or weakens disclosure thresholds |
| Pydantic value typing | `safetre/query.py` (`_check_value()`) | Per-column type checking (str for `cat`, bool for `bool`, int for `int`) | Filter values match the expected column type, preventing type-confusion attacks |

These are not formal proofs in the theorem-prover sense, but they **constrain the system enough that full formal verification is tractable**. The query space is small, the validation logic is deterministic, and the data flow is linear (planner → validation → engine → disclosure → release).

---

## 2. Formal Methods Opportunities

### A. Type-Level Proofs: "No Valid QuerySpec Can Reference an Identifier"

**Impact:** ★★★★★ (highest value, easiest to implement)

**Current state:** The Pydantic `_check_allowlist` validator in `query.py` rejects queries with non-catalogued columns at runtime. This is tested in `test_invariants.py` but not *proven* — a proof would hold even if the test suite were deleted.

**Approach:** Extract `CATALOGUE` and `QuerySpec` into a proof assistant (Lean 4 recommended for its automation) and prove:

```lean
theorem no_identifier_leakage (q : QuerySpec) :
  ∀ col ∈ q.groupBy ∪ q.filters.columns ∪ {q.measure.column},
    col ∉ identifierColumns
```

**Why it's tractable:** The catalogue has a small finite number of public and internal-only entries, and the forbidden identifier/text/timestamp set is explicit. The proof is essentially a set-membership check over a small finite domain — Lean 4's `decide` or `simp` tactic handles it automatically.

**CI integration:** Install `elan` (the Lean toolchain manager) and run `lean --check formal/QuerySpec.lean` as a CI step. If the proof fails, the build fails.

**2026-07-14 update — implemented.** `formal/lean/` holds a Lean 4 model of the catalogue and QuerySpec validity (`SafeTre/Spec.lean`), generated from the live code by `scripts/gen_lean_catalogue.py` (`SafeTre/Catalogue.lean`: dims, measures, internal columns, disclosure-role labels via `schema.role_of`, and the engine's *live* view columns read back from DuckDB). The proved theorems (`SafeTre/Proofs.lean` — no `sorry`; standard axioms only, checked with `#print axioms`):

- `no_identifier_reference` — over the whole (unbounded) spec space, a valid spec references only allowlisted columns, and every allowlist is disjoint from `{donor_id, free_text, ts}` (P3);
- `internal_never_grouped` and `end_to_end_release_safe` — internal-only columns are never group-by keys, and a released frame carries only group-by keys and fixed payload names: never an identifier, internal, or witness column (P4; P2's column-level form);
- label consistency — every referencable column carries an explicit role, none is DI, group-by keys are never sensitive, all public measures are sensitive, and the live public views expose no DI column (`test_invariants.py` additionally forbids any catalogue column from falling back to `role_of`'s permissive default).

CI replays the proofs with a sha256-pinned Lean toolchain (`lake build` of `formal/lean` in the `formal` job — the roadmap's `lean --check` in its Lake form); `tests/test_formal_lean_sync.py` regenerates the artifacts and fails on drift, closing the model↔code gap the same way the Alloy skeleton sync does.

---

### B. SQL Generation Correctness: "The Engine Only Produces Safe SQL"

**Impact:** ★★★★☆ (high security value)

**Current state:** `engine.run()` builds SQL via string concatenation from a validated `QuerySpec`. It works, but there is no proof that the generated SQL is always a simple read-only `SELECT ... FROM public_view WHERE ... GROUP BY ...`.

**Approach:** Define a grammar for "safe SQL":

```
SafeSQL := SELECT <agg_fn>(<ident>) AS value, COUNT(*) AS n
           FROM <public_view>
           [WHERE <conditions_with_bound_params>]
           [GROUP BY <ident_list>]
           ORDER BY n DESC LIMIT ROW_CAP
```

Then prove:

```lean
theorem sql_is_readonly (spec : QuerySpec) :
  let sql := engine.generate spec
  in sql ∈ SafeSQL ∧ sql.references ⊆ publicViewColumns
```

**Why it's tractable:** The `run()` method is ~15 lines of deterministic code. The SQL template is fixed — only column names and parameter values vary, both constrained by the validated `QuerySpec`. A symbolic execution or direct translation to a proof assistant is straightforward.

**What it rules out:** SQL injection, DDL/DML execution, cross-view joins, subquery nesting (beyond the predefined dominance query), and reference to internal unit views through the public path.

**2026-06-27 update:** SQL compilation is now separated from execution. `safetre.engine.compile_query()` returns an immutable `SQLPlan` for the public aggregate query, and `compile_dominance_query()` returns the separate internal donor-level dominance plan used only for mean/sum disclosure checks. `tests/test_query_properties.py` asserts the public plan:

- reads only from the public dataset view;
- contains no internal unit-view names, identifiers, free-text fields, semicolons, or DDL/DML verbs;
- uses bound placeholders for every filter value;
- preserves the fixed `ORDER BY n DESC LIMIT ROW_CAP` shape.

This is not a machine-checked grammar proof yet, but it makes the SQL safety contract directly inspectable in CI.

**2026-07-14 update — proved.** `formal/lean/SafeTre/Sql.lean` defines the SafeSQL grammar as an inductive type — one SELECT over one declared view, WHERE atoms that carry values only as `?`-placeholder counts, the fixed `ORDER BY n DESC LIMIT` tail — and an abstract compiler mirroring `engine.compile_query`. The type has no constructor for DDL, DML, joins, or subqueries, and no field of any value type, so read-only-ness and never-interpolating-values (P9) hold by construction. Proved on top (`SafeTre/Proofs.lean`): `compile_mentions_no_identifier` (nothing selected, filtered, or guarded is a forbidden column), `compile_single_declared_view` (the public view, or the unit view exactly when the spec uses declared internal columns — `engine._source_view`; the roadmap line's "public views only" was the imprecise form), `compile_mentions_on_view` (every mentioned column exists on the source view; on the public branch nothing internal is mentioned), and `compile_param_accounting` (exactly one bound parameter per filter value). The model is pinned to the engine by `cases_pin_engine`: 414 generated cases — every registered measure configuration crossed with group-by depths and filter shapes — where the Lean-rendered SQL must equal `compile_query`'s output byte for byte and the parameter counts must agree. That one theorem is checked by `native_decide` (compiled evaluation — the only theorem with a larger trusted base), and the same pairs are independently regenerated from the live engine by the pytest sync hop.

---

### C. Information-Flow Analysis: "No Identifier-Labeled Data Can Reach Release"

**Impact:** ★★★★★ (highest security value, most effort)

**Current state:** `schema.py` already labels every column with a role (`DI` = direct identifier, `QI` = quasi-identifier, `S` = sensitive, `R` = reference, `meta` = metadata). The disclosure gateway in `disclosure.py` checks for identifier egress at the output boundary. But this is checked *after* computation, not proven as a property of the data flow itself.

**Approach:** Assign security labels to data elements:

| Label | Columns | Policy |
|-------|---------|--------|
| **Secret** | `donor_id`, `free_text`, `ts` | Never released in any form |
| **Internal-only** | `age_years` | Usable only inside fixed validator-approved tools; never grouped or returned |
| **Sensitive** | `amount_gbp`, `ingame_currency`, `pgsi_score`, `igds_score`, `wemwbs_score`, `monthly_spend_selfreport` | Released only as aggregates (count/mean/sum/correlation) with suppression and rounding |
| **Public** | `age_band`, `sex`, `region`, `income_band`, `device_os`, `genre`, `contains_lootboxes`, `price_tier`, `event_type`, `age_rating`, `wave` | Releasable as grouping dimensions (with cell-size thresholds) |

Prove noninterference: **Secret data cannot affect the Public/Sensitive output** except through the allowed aggregation functions (count, mean, sum, correlation) with the specified disclosure controls (threshold ≥ 10, dominance ≤ 50%, rounding to base 5).

**Two implementation paths:**

1. **Lightweight (1–2 weeks):** Annotate the `CATALOGUE` entries with their security label and add a compile-time check that no `DI`-labeled column appears in any queryable view. This is what `test_invariants.py` already does for `donor_id` and `free_text` — formalize it as a type-level property.

2. **Full (research-grade, 3–6 months):** Use a labelled type system (e.g., encode in Lean 4 or use a language-level information-flow type system like Jif/FlowCaml) to type-check the entire data pipeline: view projection → engine aggregation → disclosure filtering → rounding.

**2026-07-14 design note — what is now mechanized, and the honest shape of the rest.** The lightweight path is done (§A): every catalogue column carries a DI/QI/S/R label generated from `schema.role_of`, label consistency is proved in Lean, a strict-coverage test forbids silent default labels, and the *column-level* noninterference corollary is a theorem — a valid spec's released frame cannot name a Secret or Internal-only column, end to end through validation, compilation, and the gateway's finalize step (`end_to_end_release_safe`).

What column-level reasoning cannot give is *value-level* noninterference: that the numbers in a released aggregate are insensitive, up to the disclosure controls, to any one donor's data. Three observations shape the practical route:

1. **The right statement is conditional declassification, not classical noninterference.** Aggregates *must* depend on sensitive values — that is their purpose. The provable form is: released values are a function of gateway-finalized cells only, and each release channel is an approved aggregate whose declared disclosure class (`cell_key` / `count` / `magnitude` / `statistic` / `p_value`) has its control applied (threshold, dominance, influence). The procedure output contract (R14) is exactly this declassification policy, already stated in code.
2. **The GLM path already has the strongest witness.** `refit_from_artifact` reproduces a released model bit-for-bit from the released artifacts alone (P21, machine-checked over the enumerated skeleton): released model outputs provably carry no information beyond the vetted cells. The web query path's analogue is a release-equality test — recompute the released frame from the finalized table alone and require bit-equality — with `postprocess` (contractually "no new data") as the step to pin. *2026-07-17:* the factoring `release = postprocess ∘ finalize ∘ vet` this test needs now holds in the code — `postprocess` was moved after gateway finalization (hardening #26), which also closed the one place it was false in substance: corr's `p_value` was computed from the exact pre-rounding `n`. ***2026-07-25: delivered*** as `tests/test_release_equality.py`, in both directions — the released frame is recomputed from the finalized table over the enumerated skeleton (exhaustively under `-m slow`), and perturbing the engine's frame in ways finalization erases (counts moved inside their rounding bucket, the internal donor count and the dominance/influence witnesses moved inside their verdict, tied rows reordered) must leave the release byte-identical. The perturbation direction is what has teeth: it found two further channels where released output was still a function of exact counts — the cell complementary suppression sacrifices, and the order of the released rows (hardening #27, #28). What the test does *not* establish is value-level insensitivity to any one donor's data: that is the quantitative claim, and it needs the accountant, not another equality.
3. **Language-level IFC for Python is not the tractable route.** Jif/FlowCaml-style labelled type systems do not usefully exist for Python, and porting the pipeline defeats the demo. The tractable mechanization is a Lean model of the *service composition* — labelled tables flowing validation → engine → witnesses → gateway → finalize — proving every value that reaches release passed through an output-contract channel, pinned to the code by the existing generated-artifact sync discipline plus the release-equality tests above.

Remaining open, in order of value: ~~the temporal session model (budget and `observe → apply → record` — the natural TLA+/Alloy 6 next slice)~~ *delivered 2026-07-17 as `formal/temporal_session.als` (P7/P16/P17, with the hardening #18 race machine-exhibited when the lock assumption is dropped)*, then the quantitative step: replacing "insensitive up to controls" with a DP accountant (roadmap item 3), where value-level guarantees become theorems rather than control descriptions.

---

### D. Model Checking the Disclosure Policy

**Impact:** ★★★★☆ (high value for edge cases)

**Current state:** The `SessionAuditor` tracks query history and detects differencing attacks (two queries on the same measure returning totals that differ by less than the threshold). The `DisclosurePolicy` applies threshold suppression, dominance suppression, and rounding. These interact in complex ways — an attacker might craft a *sequence* of queries that, after rounding and suppression, reveals an individual's data.

**Approach:** Model the system as a finite state machine:

- **States:** Set of released aggregates (each rounded to base 5, with threshold ≥ 10, limited to budget = 20 queries per session)
- **Transitions:** New query → engine execution → disclosure filtering → (release | redact | deny)
- **Safety property:** For any individual record *r*, the set of possible released values is the same regardless of *r*'s actual values (within the rounding and threshold bounds)

**Tools:**

- **[Alloy](https://alloytools.org/):** Particularly well-suited because you can directly model the data relationships (donors, events, aggregations) and use the Alloy Analyzer to search for counterexamples to your privacy property. With a bounded model (e.g., 5 donors, 10 events, 20 queries), the search is exhaustive.
- **[TLA+](https://lamport.azurewebsites.net/tla/tla.html):** Better for the sequential composition aspect — modeling the session auditor's query history and proving that no sequence of 20 queries can violate the privacy property.

**What it catches:** Differencing attacks that exploit rounding asymmetry, triangulation across multiple group-by dimensions, and budget-exhaustion strategies.

**2026-07-14 update — first slice.** `formal/disclosure_policy.als` models the session auditor's cohort-lineage rule as implemented (`disclosure.simulatable_cohort_bound`): cohorts as per-dimension value selections, the true symmetric difference, and the simulatable marginal upper bound. Checked (a counterexample fails CI): `MarginalBoundSound` — the docstring's soundness claim, the marginal bound dominates the true symmetric difference on a single differing dimension; `RareCategoryIsolationBlocked` — the canonical add/remove-a-rare-category attack cannot pass the auditor (P11's decision rule). Machine-exhibited as satisfiable runs (unsatisfiability fails CI): the *interaction residual* (a large marginal hiding a small true difference) and the *multi-dimension sentinel* — the two gaps the code's docstring documents, now demonstrated rather than asserted, and covered by the per-cell donor threshold and the DP roadmap item. The auditor's temporal behaviour (budget, `observe`/`record` ordering) remains the open slice.

---

### E. Differential Privacy Formalization

**Impact:** ★★★☆☆ (medium value, significant effort)

**Current state:** The system uses cell suppression (n < 10), dominance suppression (p% > 50%), and rounding (base 5). These provide *ad hoc* privacy but not formally proven differential privacy (DP).

**Correction:** Deterministic rounding to base 5 is **not** differential privacy. It reduces precision and can help statistical disclosure control, but because it is deterministic, neighbouring datasets can still produce different released values with probability 1 versus 0. In the usual DP definition, that means there is no finite ε guarantee from rounding alone. The same caveat applies even more strongly to mean/sum queries, where one person's value can change a released aggregate unless bounded sensitivity and calibrated random noise are part of the mechanism.

**Approach:**

1. Treat the current threshold/dominance/rounding controls as SDC controls, not DP controls.
2. If DP becomes a requirement, define neighbouring datasets, contribution bounds, and sensitivity for each supported aggregate.
3. Add calibrated random noise and track the privacy budget compositionally across the session query budget.
4. Prefer integrating [OpenDP](https://github.com/opendp/opendp) or an equivalent vetted DP library over a bespoke proof of an ad hoc mechanism.

**Caveats:** A full DP integration would change the disclosure gateway's semantics: released values would become randomized, reproducibility would need an auditable randomness policy, and budget accounting would become part of the session auditor.

---

### F. Guard Sandbox Formalization

**Impact:** ★★☆☆☆ (low priority — this is a legacy path)

**Current state:** `guards.py` is explicitly marked "PROTOTYPE-GRADE" and the docstring notes it is "defence-in-depth illustration, not a secure sandbox." The main web path uses `QuerySpec` (declarative, validated) rather than `guards.py` (code execution with static checks).

**If needed:** Replace the `FORBIDDEN` string-matching list with proper abstract interpretation — parse the code into an AST (Python's `ast` module), build a control-flow graph, and prove no I/O, network, or file operations are reachable. This is a well-studied problem in program analysis.

**Recommendation:** Do not invest in formalizing this layer. Instead, ensure the main web path never routes through it (which is already the case), and consider removing or clearly deprecating it to reduce attack surface.

---

## Implemented Executable Invariants

**2026-06-27 update:** The first practical step is executable formalism rather than a theorem-prover artifact. `tests/test_query_properties.py` uses Hypothesis to generate valid `QuerySpec` instances over the finite catalogue and checks that:

- generated valid specs stay within the dataset catalogue and never touch identifier or free-text columns;
- valid specs execute through `QueryEngine` and `DisclosurePolicy` without releasing unsafe columns or unrounded/under-threshold counts;
- forbidden columns are rejected in group-by, filter, and measure positions;
- empty `in` filters and duplicate group-by dimensions are rejected at validation time.
- compiled public SQL keeps the fixed safe aggregate-query shape and uses bound parameters for filter values.

This does not replace Lean/Alloy, but it gives CI a broad executable approximation of the same invariants before investing in machine-checked proofs.

---

## 3. Recommended Roadmap

### Phase 1 — Quick Wins (1–2 weeks)

- [x] **(2026-07-14)** Formalize `CATALOGUE` and `QuerySpec` in Lean 4 — `formal/lean/SafeTre/`, catalogue/labels/view columns generated from the live code
- [x] **(2026-07-14)** Prove identifier non-membership (`no_identifier_reference`) and internal-only non-release (`internal_never_grouped`, `end_to_end_release_safe`) — over the whole spec space, `sorry`-free
- [x] **(2026-07-14)** Add CI step — `lake build` of `formal/lean` in the `formal` job, toolchain sha256-pinned
- [x] Add Hypothesis property-based testing in `tests/test_query_properties.py` to fuzz-generate valid `QuerySpec` instances and verify executable boundary invariants
- [x] **(2026-07-14)** Add security labels (`DI`, `QI`, `S`, `R`) — the generated `roleOf?` map plus the label-consistency theorems and a strict-coverage invariant test (no silent default role)

### Phase 2 — Stronger Guarantees (1–2 months)

- [x] **First Alloy artifact (2026-07-07):** a bounded model of the GLM release
      path — admissibility over the real generated catalogue at exact bounds,
      nondeterministic per-cell vetting, and the service rule — checking
      P19/P21/P4 in CI, with two pytest sync hops pinning
      code → `formal/skeleton.json` → model (see `formal/README.md`). The
      disclosure-policy/differencing model below remains open.
- [x] **(2026-07-14)** Model the disclosure policy in Alloy (`formal/disclosure_policy.als`): lineage-rule soundness and rare-category isolation checked; the documented residuals found and kept as satisfiable runs. Static and pairwise — the temporal session model is the open remainder
- [x] **(2026-07-28)** Rebuild that model over ROWS as well as donors, the arity hardening #40 turned on: `RowDifferenceAlwaysBounded` and `RowLayerSubsumesDonorLayer` checked, and the #40 attack, the total-delta over-count and the exact leg's non-simulatable bit exhibited as satisfiable runs
- [x] **(2026-07-28)** Extend the temporal model to the RESTART path (`ReplayEquivalence`, `AuditCompleteness`, `PolicyPrecedesEveryRecord`), with the log modelled as a security-critical *input* and an attacker who can delete rows; the three round-9 restart attacks are satisfiable runs once their assumptions are dropped
- [x] **(2026-07-28)** Prove band alignment in Lean (`internal_range_cuts_no_finer_than_bands`): over the whole spec space, an internal range predicate cannot separate two values in the same declared band, so every expressible cohort is a union of whole bands. Generalises hardening #39 from the patched instance to the class
- [x] Extract SQL compilation into inspectable plans and add property tests for the safe public SQL shape
- [x] **(2026-07-14)** Prove SQL generation correctness in a proof assistant — the SafeSQL type + compiler theorems in `SafeTre/Sql.lean`/`Proofs.lean`, pinned to the engine by the 414-case byte-equality check (§B update; \"declared view\" is the precise form of \"public views\")
- [x] Formalize noninterference for the model-fitting path: the fitter is
      statically stdlib-only and structurally fed only gateway-finalized
      tables; machine-checked by refit-equality over the enumerated skeleton
      (`tests/test_glm_properties.py`, `tests/test_glm_noninterference.py`).
      The full web-path label lattice remains open.
- [x] **(2026-07-29)** Formalize information-flow labels and prove noninterference for the web query path, at the column/cell level — `SafeTre/Release.lean`: a released cell is a function of key, payload, verdict and rounded count, so witnesses and exact counts reach it only through those. The VALUE-level claim (insensitivity to one donor) stays open and is the DP accountant's
- [x] **(2026-07-29)** Parametrise the models over the policy dials (F5): the Alloy threshold and budget range over every admissible value, and `SatisfiesFloors` states what `policy_floor_problems` enforces
- [x] **(2026-07-14)** Prove that the composition of `QuerySpec` validation + engine + disclosure gateway maintains the identifier-free invariant end-to-end — `end_to_end_release_safe` (column-level; value-level is the §C programme)

### Phase 3 — Research-Grade (3–6 months)

- [x] **(2026-07-29)** Formalise the vetting arithmetic (`SafeTre/Arith.lean`):
      the dominance witness is a share, is sign-invariant, and agrees with the
      naive share on non-negative data (#41); unresolved witnesses and
      non-finite payloads fail closed (#42); rounding blurs by one base;
      tightening a dial never releases more. Pinned to the live vetter over
      864 generated cells
- [x] **(2026-07-29)** Make the model ↔ attack correspondence mechanical
      (`formal/correspondence.yaml`, `tests/test_formal_correspondence.py`):
      every model run is a classified guard, attack or priced residual, and
      every executable twin must exist
- [ ] Integrate OpenDP for formal ε-DP on count/mean/sum queries
- [ ] Prove compositional privacy budget tracking across the session query budget
- [ ] Publish the formalization as a machine-checked verification artifact
- [ ] Write up the methodology for publication (applicable to other TRE data-access gateways)

---

## 4. What Formal Methods Cannot Do

Formal methods have inherent limits in this context. Be clear about the boundaries:

| Domain | Why formal methods don't apply | Mitigation |
|--------|-------------------------------|------------|
| **LLM safety** | The LLM is always untrusted — formal methods cannot make it "safe" | Architecture already handles this: LLM output is unvalidated input to a typed boundary (`QuerySpec`) |
| **Side channels** | Timing, memory usage, and cache-based side channels are outside the scope of pure formal methods | Would require constant-time implementations and hardware-level analysis |
| **Physical security** | Safepod controls (encrypted disk, tamper-evident enclosure, disabled radios) are operational controls, not mathematical properties | Organisational policy and audit logs |
| **Synthetic data safety** | Formal methods can prove the *system* doesn't leak data, but cannot prove the *synthetic generation process* is safe | Requires separate statistical disclosure assessment of the synthetic data generator |
| **Social engineering** | An authorised analyst could share results outside the system | Human-in-the-loop (HITL) review, legal agreements, and output monitoring |

---

## 5. Key Files Reference

| File | Relevance to Formal Methods |
|------|-----------------------------|
| `safetre/query.py` | Primary formalization target — `CATALOGUE`, `QuerySpec`, validators |
| `safetre/schema.py` | Column role labels (DI/QI/S/R) — basis for information-flow types |
| `safetre/engine.py` | SQL generation from validated spec — target for correctness proof |
| `safetre/disclosure.py` | Disclosure policy and session auditor — target for model checking |
| `safetre/guards.py` | Legacy sandbox — low priority for formalization |
| `tests/test_invariants.py` | Existing regression guards — extend with property-based testing |
| `tests/test_disclosure.py` | Existing disclosure tests — extend with Alloy counterexample search |
| `tests/test_secure.py` | Query boundary tests — complement with type-level proofs |
