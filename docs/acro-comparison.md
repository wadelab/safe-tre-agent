# ACRO decision comparison

The first slice of [roadmap item 1](roadmap.md): before ACRO replaces the
stand-in gateway, measure where the two disagree. The harness
(`redteam/run_acro_compare.py`) is read-only — nothing in the release path
changes — and compares per-cell decisions, not values, over every plain
QuerySpec in the service-path red-team corpus plus ten divergence-targeted
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
- **Dataset.** The demo dataset: 800 donors at seed 7, the defaults
  `scripts/make_data.py` writes into `data/`. The harness generates it when
  `data/` is absent (as in CI) rather than falling back to a smaller one, so
  the numbers below do not depend on who ran it.
- **Planted dominance.** Sampled spend is heavy-tailed but not
  *concentrated*: measured over the whole skeleton, no cell of ten donors or
  more reached even 0.35 single-donor share, so neither gateway's dominance
  rule could fire and the comparison measured nothing on that axis. The
  generator now plants three regions that separate the two rule sets
  (`synth.DOMINANCE_ANCHORS`, pinned by `tests/test_dataset_anchors.py`):
  Scotland with one donor at 62%, Wales with two at 46% each, East Midlands
  at 60% + 35%. Leaders are capped at the largest donor total the sampler
  already produced, so the plant introduces no spend outside the observed
  range.

## Results (2026-07-25, ACRO 0.4.12, 800-donor seed-7 dataset)

| classification | cells |
|---|---|
| agree_release | 239 |
| agree_suppress | 71 |
| **acro_stricter** | **6** |
| standin_stricter | 21 |
| not comparable (corr, D6) | 1 |

**The two rule sets are not ordered.** Over 337 comparable cells each
gateway suppresses cells the other releases, and the disagreements fall into
two clean groups.

**ACRO stricter (6 cells, all the Wales anchor, all `nk-rule`).** ACRO's
NK-rule suppresses a cell whose top two donors hold 90% or more of it. The
stand-in has no such rule: it bounds the *single* largest contributor at
50%, so two donors at 46% each pass. This is a real gap in the stand-in, and
the first candidate under-suppression the comparison has found — it appears
on `sum` and `mean` of the same cell, and on a corpus scenario as well as
the targeted fixtures.

**Stand-in stricter (21 cells), from two different rules:**

- *10 cells are the Scotland anchor* (`Scotland`, `Scotland|iOS`,
  `Scotland|Android` across the sum/mean specs): one donor holds 62%, over
  the stand-in's 50% bound. ACRO releases them — its NK-rule sees only 66%
  in the top two, and its p%-rule wants the spend outside the top two to
  fall below a tenth of the largest, which it does not. So the p%-rule as
  ACRO configures it by default is *weaker* here than the bespoke 50% bound.
- *11 cells are complementary suppression*, which ACRO does not implement at
  all (C2). The canonical example is `count` by region: Northern Ireland (8
  donors) is below threshold for both gateways, but the stand-in also
  suppresses North East (11 donors — safe by itself) because a margin with
  exactly one suppressed cell leaks it (`_secondary_suppress`, spec R5).

The integration reading: ACRO's checks belong underneath, and
`_secondary_suppress` stays on top of them (C2) — but the stand-in's
single-contributor bound must *also* stay, because ACRO's defaults do not
subsume it. The honest summary for the preprint's gateway section is that
neither rule set dominates the other, not that the stand-in is a superset.

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
- **D3 lens — measured.** With the dominance anchors in place, ACRO's
  defaults (p% = 0.1, NK n = 2, k = 0.9) and the stand-in's 50% bound
  disagree in *both* directions: the NK-rule catches a concentrated pair the
  50% bound releases (Wales), and the 50% bound catches a single dominant
  donor both of ACRO's rules release (Scotland). Neither is a superset of
  the other, so the integration keeps both.

## Next

Slice 2 chooses the integration seam using these numbers: ACRO's checks
under the cells-first layer (`DisclosurePolicy` stays the protocol; ACRO
becomes an implementation that vets cell tables), with `_secondary_suppress`
**and the single-contributor bound** retained on top — the D3 measurement
says ACRO's defaults do not cover the latter. The comparison then becomes a
CI regression: today's harness already gates on its own integrity in the
`acro-compare` job.
