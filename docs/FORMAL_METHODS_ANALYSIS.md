# Formal Methods Analysis for safe-tre-agent

## Executive Summary

**This system is unusually well-suited for formal verification.** The query space is finite and enumerable — a small set of datasets, dimensions, measures, fixed aggregate functions, operators, and bounded group-by/filter counts — making security properties decidable in ways that would not work for arbitrary SQL systems.

This document catalogues the existing lightweight formal guarantees, identifies six concrete opportunities for stronger formal methods, proposes a phased roadmap, and notes the inherent limits of what formal methods can achieve in this context.

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

- [ ] Formalize `CATALOGUE` and `QuerySpec` in Lean 4
- [ ] Prove identifier non-membership (no valid query can reference `donor_id`, `free_text`, or `ts`) and internal-only non-release (`age_years` can affect only approved fixed-tool outputs)
- [ ] Add CI step: `lean --check formal/QuerySpec.lean`
- [x] Add Hypothesis property-based testing in `tests/test_query_properties.py` to fuzz-generate valid `QuerySpec` instances and verify executable boundary invariants
- [ ] Add security labels (`DI`, `QI`, `S`, `R`) to `CATALOGUE` entries and prove label consistency at the type level

### Phase 2 — Stronger Guarantees (1–2 months)

- [ ] Model the disclosure policy in Alloy; search for differencing/triangulation counterexamples
- [x] Extract SQL compilation into inspectable plans and add property tests for the safe public SQL shape
- [ ] Prove SQL generation correctness in a proof assistant (engine produces only read-only SELECT from public views)
- [ ] Formalize information-flow labels and prove noninterference for the web query path
- [ ] Prove that the composition of `QuerySpec` validation + engine + disclosure gateway maintains the identifier-free invariant end-to-end

### Phase 3 — Research-Grade (3–6 months)

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
| **Social engineering** | An authorised analyst could share results outside the system | HITL review, legal agreements, and output monitoring |

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
