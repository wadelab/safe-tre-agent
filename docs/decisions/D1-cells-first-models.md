---
id: D1
title: Models fit from vetted cells, not from rows
date: 2026-07-07
status: accepted
question: >
  Should a statistical model be fitted on row-level data behind an influence
  witness, or exclusively on cell tables the gateway has already vetted?
clauses: [R14, R15, P19, P21]
evidence:
  - docs/verifiable-extensions.md
revisit_when: >
  A model family arrives whose sufficient statistics are not catalogued
  aggregates — non-gaussian with continuous predictors is the standing
  example. That case needs either a new aggregate that IS vettable, or the
  row-level route with a leverage witness, and the row-level route is
  deliberately kept alive in the design for it.
---

An earlier draft planned a `regression` procedure fitted on rows, discharging
the individual-influence obligation with leverage and Cook's distance and a
residual-degrees-of-freedom floor. What shipped instead never touches a row:
models plan ordinary `QuerySpec` aggregates, the gateway vets each design cell
by its existing rules, and the fitter is a pure function of the finalized
tables.

**Why.** The row-level route needs a *new* safety argument per model family —
each with its own influence measure, each to be validated. The cells-first
route inherits the arguments already made: compilation safety, the influence
witnesses, lineage and budget all apply because every model input is literally
a `QuerySpec`. What would have been proof obligations became inheritance.

**What it cost.** Fitting from rounded, suppressed cells introduces a
distortion, which is measured rather than waved away
(`artifacts/rounding_distortion.json`). And any suppressed design cell refuses
the whole model (P19) — a bluntness that [D3](D3-second-moment-parameters.md)
later had to soften, because the dispersion cell turned out to be doing most
of the refusing.
