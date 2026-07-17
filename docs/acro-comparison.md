# ACRO decision comparison

The first slice of [roadmap item 1](roadmap.md): before ACRO replaces the
stand-in gateway, measure where the two disagree. The harness
(`redteam/run_acro_compare.py`) is read-only — nothing in the release path
changes — and compares per-cell decisions, not values, over every plain
QuerySpec in the service-path red-team corpus plus five divergence-targeted
fixtures. Model specs are expanded to their planned design-cell aggregates,
the exact frames `_handle_model` vets (P19).

```sh
uv run --no-default-groups --group acro python redteam/run_acro_compare.py
```

The dedicated environment matters: ACRO 0.4.x pins `pandas < 3` while the
project runtime uses pandas 3, so the groups resolve separately
(`[tool.uv] conflicts` in `pyproject.toml`) and ACRO stays out of the
runtime install surface entirely.

## Method

- **Protection unit.** ACRO is fed one row per donor per cell — the donor's
  summed contribution from the dataset's unit view — so its frequency
  threshold counts donors exactly as the stand-in's `n_donors` check does
  (spec P5, best-practice D4). For `mean` this makes ACRO's cell *value* a
  mean of donor means; decisions stay comparable, values do not.
- **Decisions, not tables.** The harness consumes ACRO's own check masks
  (`create_crosstab_masks` — its real threshold/p%/NK implementations) and
  composes the per-cell verdict exactly as ACRO's `apply_suppression` would;
  see finding C1 for why it cannot use `ACRO.crosstab` directly.
- **Scope.** The session auditor (lineage, budget) is deliberately absent:
  those controls sit above ACRO in the integration design and have no ACRO
  analogue. `corr`/influence cells are recorded `not_comparable` (D6), never
  silently skipped; the harness exits nonzero on any translation failure
  (R13).
- **Caveat.** Donors whose every contribution is NULL are dropped from
  ACRO's frame (its dominance arithmetic has no value to work with); the
  stand-in's `n_donors` counts them, so on such cells ACRO sees one donor
  fewer.

## Results (2026-07-17, ACRO 0.4.12, seed-7 dataset)

| classification | cells |
|---|---|
| agree_release | 248 |
| agree_suppress | 46 |
| **acro_stricter** | **0** |
| standin_stricter | 16 |
| not comparable (corr, D6) | 1 |

**No candidate under-suppression: over 310 comparable cells, ACRO never
suppresses a cell the stand-in releases.** This is the number the preprint's
gateway section needs — the stand-in's decisions are, on this corpus, a
superset of ACRO's protections.

All 16 `standin_stricter` cells are explained by one rule ACRO does not
have: **complementary suppression**. The canonical example is `count` by
region: Northern Ireland (8 donors) is below threshold for both gateways,
but the stand-in also suppresses North East (11 donors — safe by itself)
because a margin with exactly one suppressed cell leaks it
(`_secondary_suppress`, spec R5); ACRO releases it. The GLM design-cell
rows in the list are the same effect inside saturated designs.

## Compatibility findings for the integration slice

- **C1 — ACRO 0.4.12 `crosstab` crashes on zero/empty categories.** Its
  values table drops empty and all-zero rows (`delete_empty_rows_columns`)
  but its masks are built from the raw series, and the misaligned frames
  make its own `apply_suppression` raise `ValueError` — with `suppress`
  either on or off, since the outcome frame is computed unconditionally.
  Triggered by the dataset's planted adversarial categories (one-donor,
  zero-sum cells). Reported to the maintainers (together with the
  underlying zero-sum-equals-empty deletion semantics); the harness
  sidesteps it by consuming the check masks directly.
- **C2 — no complementary suppression.** Confirmed against the source:
  ACRO masks the failing cells only. LP-based secondary suppression is
  τ-Argus/sdcTable territory. The stand-in's `_secondary_suppress` must
  stay in force on top of ACRO (the roadmap and `disclosure.py` were
  corrected accordingly).
- **C3 — `pandas < 3` pin.** ACRO 0.4.x cannot be imported into the
  project's runtime environment at all until upstream supports pandas 3;
  any integration slice must either vendor the checks or isolate ACRO
  behind a subprocess/service boundary.
- **D3 lens.** ACRO's dominance defaults (p% = 0.1, NK n=2 k=0.9) fired on
  no corpus cell that the stand-in's single-contributor 50% rule released —
  no observed divergence yet, so calibrating the bespoke rules against
  ACRO's needs sharper fixtures (planted dominant donors) in a later slice.

## Next

Slice 2 chooses the integration seam using these numbers: ACRO's checks
under the cells-first layer (`DisclosurePolicy` stays the protocol; ACRO
becomes an implementation that vets cell tables), with `_secondary_suppress`
and the session auditor retained on top. The red-team comparison then
becomes a CI regression: today's harness already gates on its own
integrity in the `acro-compare` job.
