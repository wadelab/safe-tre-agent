# Decision log

Why the system is the way it is. The [hardening log](hardening-log.md) records
what went wrong and was fixed; this records what was *chosen* when more than
one answer was defensible.

Each record states the question, the evidence it rested on, what was rejected,
and **what would change our mind**. That last field is the one that makes a
record worth keeping: a decision whose conditions for revision are not written
down cannot be revisited honestly later, only defended or abandoned. Where a
question is still open, it is recorded as open rather than left out, so the
gaps in the argument are visible in the same place as the answers.

Records are immutable once accepted. A decision that changes gets a new record
superseding the old one, so the reasoning that applied at the time survives
alongside the reasoning that replaced it.


| | Decision | Status | Clauses |
|---|---|---|---|
| D1 | [Models fit from vetted cells, not from rows](decisions/D1-cells-first-models.md) | accepted | R14, R15, P19, P21 |
| D2 | [Rule sets compose as a union, and the checker runs out of process](decisions/D2-acro-composition.md) | accepted | R5 |
| D3 | [Second-moment cells get their own bound, and their own failure mode](decisions/D3-second-moment-parameters.md) | accepted | R5, R15, P19 |
| D4 | [Inference from a dispersion that cannot be released](decisions/D4-robust-dispersion.md) | **open** | R15, P21 |

## D1 — Models fit from vetted cells, not from rows

*2026-07-07 · accepted*

Should a statistical model be fitted on row-level data behind an influence witness, or exclusively on cell tables the gateway has already vetted?

**What would change our mind.** A model family arrives whose sufficient statistics are not catalogued aggregates — non-gaussian with continuous predictors is the standing example. That case needs either a new aggregate that IS vettable, or the row-level route with a leverage witness, and the row-level route is deliberately kept alive in the design for it.

[Read the record](decisions/D1-cells-first-models.md)

## D2 — Rule sets compose as a union, and the checker runs out of process

*2026-07-25 · accepted*

When an external output checker is brought in, does it replace the prototype's disclosure rules, sit beside them, or sit under them — and where does it run?

**What would change our mind.** The measurement stops holding. The union is justified by a specific finding — that neither rule set subsumes the other on this corpus — so a different checker, a different configuration of the same one, or a corpus that exercises the rules differently could change the answer. Re-run the comparison before assuming it still holds.

[Read the record](decisions/D2-acro-composition.md)

## D3 — Second-moment cells get their own bound, and their own failure mode

*2026-07-26 · accepted*

A dominance bound calibrated for sums is a far tighter rule on sums of squares, and the second moment is what decides whether a model may be released at all. Should both moments be checked on the same parameters, and what should happen when the dispersion cell cannot be released?

**What would change our mind.** Someone sets a second-moment bound in anger. The default deliberately changes nothing, so the interesting evidence — whether a stated relaxation is defensible to an output checker, and what it costs on real rather than synthetic concentration — does not exist yet. Also revisit if a robust dispersion lands ([D4](decisions/D4-robust-dispersion.md)), which would make the availability argument for relaxing the bound much weaker.

[Read the record](decisions/D3-second-moment-parameters.md)

## D4 — Inference from a dispersion that cannot be released

*2026-07-26 · open*

A coefficient without a standard error is rarely publishable. Can inference — an interval, or even a significance class — be restored when the second-moment cell is too concentrated to release?

**What would change our mind.** This is open, so what it needs is not a trigger but an answer to two questions. First, statistical: is a winsorised or trimmed dispersion something a researcher would publish, given it is optimistic unless corrected? Second, empirical: how much of the 36-model gap does it actually recover, which is measurable with the existing sweep once an estimator is chosen.

[Read the record](decisions/D4-robust-dispersion.md)


## Adding a record

Create `docs/decisions/D<n>-<slug>.md` with the header fields above — `status`
is `accepted`, `open` or `superseded` — and regenerate:

```sh
uv run python scripts/gen_decision_log.py --write
```

`tests/test_decision_log.py` fails the build on a missing field, a clause that
is not in the specification, evidence that does not exist, an empty
`revisit_when`, a duplicate or mismatched id, or a stale index.
