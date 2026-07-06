# Formal artifacts (spec R16; roadmap item 2, first slice)

A bounded, machine-checked model of the GLM release path, generated from and
pinned to the live procedure registries.

## Files

| File | What it is |
|---|---|
| `skeleton.json` | The registries' finite request space exported as data (`safetre.procedures.registry_skeleton()`): the catalogue, every aggregate measure configuration, and all 718 no-filter GLM skeleton points. |
| `glm_gateway.als` | The Alloy 6 model. The catalogue block between the `GENERATED` markers is produced from `skeleton.json`; the hand-written part states GLMSpec admissibility, the gateway's nondeterministic per-cell vetting, the service rule (fit ⟺ every design cell released), and the checked assertions. |
| `run_checks.py` | Headless runner: executes every command via the Alloy CLI and turns `receipt.json` into a CI verdict (the CLI itself exits 0 even on a counterexample). Fails on any counterexample, on a vacuous model, or on missing commands. |

## What is proved, and within what bounds

- **P19** `noFitOnSuppressedCells` and **P21** `fitterSeesOnlyReleasedCells` —
  checked for up to 6 specs / 18 cells / 6 fits. These properties are
  per-fit-local, so small scopes are adequate in the usual small-scope-
  hypothesis sense; they verify the *service rule* implies the P-clauses, for
  every vetting outcome the gateway could produce.
- **P4** `internalNeverEntersAModel` and `AdmissibleSpaceMatchesCatalogue` —
  checked over the **real catalogue atoms at exact bounds** (every dataset,
  column, and family is a fixed `one sig`), so these are exhaustive over the
  actual catalogue, not samples. The vacuity guard fails if a catalogue edit
  ever makes the admissibility clauses hold emptily.
- `someAdmissibleSpec` — a satisfiable `run` proving the modelled space is
  inhabited (the checks are not vacuously true).

## Correspondence discipline

The known weak point of model-based verification is drift between model and
code. Two pytest-checked hops close it, neither needing Java:

1. `tests/test_skeleton_sync.py` — `skeleton.json` equals the live
   `registry_skeleton()` export;
2. `tests/test_formal_alloy_sync.py` — the committed `.als` generated block
   equals `scripts/gen_alloy_catalogue.py`'s output for that skeleton (and
   the model still declares every command the verdict script expects).

After any catalogue or registry change:

```sh
uv run python scripts/gen_alloy_catalogue.py --write
```

## Running the solver locally

```sh
curl -sL -o /tmp/alloy.jar https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v6.2.0/org.alloytools.alloy.dist.jar
echo "6b8c1cb5bc93bedfc7c61435c4e1ab6e688a242dc702a394628d9a9801edb78d  /tmp/alloy.jar" | sha256sum -c
python formal/run_checks.py --jar /tmp/alloy.jar
```

CI runs exactly this (pinned SHA download, Temurin 21) in the `formal` job.

## What this deliberately does not model (yet)

Filters and their value space (covered by parameter-binding property tests),
the numeric fit itself (covered by the reproducibility meta-test and the
statsmodels oracle), rounding/dominance arithmetic (covered by the gateway's
own tests), and the session auditor's temporal behaviour (the natural next
slice — TLA+/Alloy 6 temporal operators over `observe → apply → record`).
