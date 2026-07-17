# Formal artifacts (spec R16; roadmap item 2)

Machine-checked models of the safety boundary, generated from and pinned to
the live code. Two toolchains: **Lean 4** proofs over the query boundary
(unbounded spec space), and **Alloy 6** bounded model checks where instance
search is the right tool (nondeterministic vetting outcomes, counterexample
hunting).

## Files

| File | What it is |
|---|---|
| `skeleton.json` | The registries' finite request space exported as data (`safetre.procedures.registry_skeleton()`): the catalogue, every aggregate measure configuration, and all no-filter model skeleton points (718 GLM + 49 ANOVA). |
| `glm_gateway.als` | Alloy model of the GLM release path: GLMSpec admissibility, nondeterministic per-cell vetting, the service rule. Checks P19/P21 over every vetting outcome and P4-admissibility over the exact catalogue atoms. |
| `disclosure_policy.als` | Alloy model of the session auditor's cohort-lineage rule (`simulatable_cohort_bound`). Checks the marginal bound's soundness and that rare-category isolation is blocked (P11); machine-exhibits the two residuals the code documents, as satisfiable runs. |
| `run_checks.py` | Headless runner for both models: executes every command via the Alloy CLI and turns the receipts into a CI verdict (the CLI itself exits 0 even on a counterexample). Fails on any counterexample, any unsatisfiable run, or a missing command. |
| `lean/` | The Lean 4 package (`SafeTre`). `Types/Spec/Sql/Proofs.lean` are hand-written; `Catalogue.lean` (catalogue, DI/QI/S/R labels, live view columns) and `Cases.lean` (414 compiled-SQL pin pairs) are **generated** by `scripts/gen_lean_catalogue.py`. |

## What is proved (Lean, whole spec space)

All in `lean/SafeTre/Proofs.lean`, `sorry`-free:

- **P3** `no_identifier_reference` — a valid QuerySpec cannot reference
  `donor_id`, `free_text`, or `ts`: every referenced column is allowlisted
  and every allowlist is disjoint from the forbidden set.
- **P4** `internal_never_grouped`, `end_to_end_release_safe` — internal-only
  columns never appear in a group-by or a released frame; a release carries
  only group-by keys and fixed payload names (witness columns are dropped).
- **P9 / SafeSQL** — the `SafeSelect` type *is* the grammar: one SELECT over
  one declared view, no DDL/DML/join/subquery constructor, no value-typed
  field. `compile_mentions_no_identifier`, `compile_single_declared_view`,
  `compile_mentions_on_view`, `compile_param_accounting` prove the compiled
  statement mentions only referenced columns that exist on its source view
  and binds exactly one parameter per filter value.
- **Labels** — every referencable column has an explicit DI/QI/S/R role;
  none is DI; group-by keys are never sensitive; public measures are all
  sensitive; the engine's *live* public views (read back from DuckDB, not
  the source text) expose no DI column.
- **The engine pin** `cases_pin_engine` — for all 414 generated cases the
  Lean-rendered SQL equals `engine.compile_query`'s output byte for byte,
  with matching parameter counts.

Trusted base: Lean's kernel plus the standard axioms (`propext`,
`Classical.choice`, `Quot.sound`) — checked with `#print axioms`. The one
exception is `cases_pin_engine`, which uses `native_decide` (compiled
evaluation); the same pairs are independently regenerated from the live
engine by pytest, so a compiler bug would have to fool both.

## What is checked (Alloy, bounded)

- **P19/P21** over up to 6 specs / 18 cells / 6 fits, for every vetting
  outcome; **P4-admissibility** exhaustively over the real catalogue atoms;
  vacuity guards (`glm_gateway.als`).
- **P11**: `MarginalBoundSound` (the simulatable bound dominates the true
  symmetric difference on a single differing dimension — denials are sound)
  and `RareCategoryIsolationBlocked` (the canonical differencing attack
  cannot pass the auditor), for 6 donors / 6 values / 4 releases. The
  documented residuals — interaction hiding and the multi-dimension
  sentinel — are `run` commands that must stay satisfiable: if the model
  stops exhibiting them, it has drifted from the code it claims to describe
  (`disclosure_policy.als`).

## Correspondence discipline

The known weak point of model-based verification is drift between model and
code. Pytest-checked hops close it, none needing Java or Lean:

1. `tests/test_skeleton_sync.py` — `skeleton.json` equals the live
   `registry_skeleton()` export;
2. `tests/test_formal_alloy_sync.py` — the committed `.als` generated block
   equals `scripts/gen_alloy_catalogue.py`'s output, and both models still
   declare every command the verdict script expects;
3. `tests/test_formal_lean_sync.py` — the committed `Catalogue.lean` and
   `Cases.lean` equal `scripts/gen_lean_catalogue.py`'s output (catalogue,
   labels, live view columns, and the engine's actual SQL for every pin
   case), and the package root imports every module so `lake build` cannot
   silently skip the proofs.

After any catalogue, registry, schema-role, view, or compiler change:

```sh
uv run python scripts/gen_alloy_catalogue.py --write
uv run python scripts/gen_lean_catalogue.py --write
```

## Running the toolchains locally

```sh
# Alloy (both models)
curl -sL -o /tmp/alloy.jar https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v6.2.0/org.alloytools.alloy.dist.jar
echo "6b8c1cb5bc93bedfc7c61435c4e1ab6e688a242dc702a394628d9a9801edb78d  /tmp/alloy.jar" | sha256sum -c
python formal/run_checks.py --jar /tmp/alloy.jar

# Lean (the proofs)
curl -sL -o /tmp/lean.tar.zst https://github.com/leanprover/lean4/releases/download/v4.32.0/lean-4.32.0-linux.tar.zst
echo "fca846f3588724a38ad19ee40292c67cb7438d7555903372e3308eef795ba516  /tmp/lean.tar.zst" | sha256sum -c
mkdir /tmp/lean && tar --use-compress-program=unzstd -xf /tmp/lean.tar.zst -C /tmp/lean --strip-components=1
cd formal/lean && PATH=/tmp/lean/bin:$PATH lake build
```

CI runs exactly this (both downloads sha256-pinned, Temurin 21 for Alloy)
in the `formal` job.

## What this deliberately does not model (yet)

Filter *value* typing (covered by the parameter-binding property tests — the
Lean model carries values only as bound-parameter counts, by design), the
numeric fit itself (covered by the reproducibility meta-test and the
statsmodels oracle), rounding/dominance arithmetic (covered by the gateway's
own tests), value-level noninterference through the release path (designed
in the §C note of `docs/FORMAL_METHODS_ANALYSIS.md`), and the session
auditor's *temporal* behaviour — budget exhaustion and `observe → apply →
record` ordering — the natural next slice (TLA+/Alloy 6 temporal operators).
