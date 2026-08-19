# Decision log

Why the system is the way it is. The [hardening log](hardening-log.md) records
what went wrong and was fixed; this records what was *chosen* when more than
one answer was defensible.

Each record states the question, the evidence it rested on, what was rejected,
and **what would change our mind**. That last field is the one that makes a
record worth keeping: a decision whose conditions for revision are not written
down cannot be revisited honestly later, only defended or abandoned. Where a
question is still unanswered it is recorded as such rather than left out, so
the gaps in the argument are visible in the same place as the answers.

Two kinds of unanswered. **Open** means nobody has done the work yet.
**Parked** means the work was scoped and the answer was *not to do it* — the
plan survives in the record, so unparking is cheap, but the reasoning for
leaving it alone is written down where the reasoning for doing it would have
been. A parked question is a decision, not an omission.

Records are immutable once accepted. A decision that changes gets a new record
superseding the old one, so the reasoning that applied at the time survives
alongside the reasoning that replaced it.


| | Decision | Status | Clauses |
|---|---|---|---|
| D1 | [Models fit from vetted cells, not from rows](decisions/D1-cells-first-models.md) | accepted | R14, R15, P19, P21 |
| D10 | [Authenticated release domains and deterministic accounting come before differential privacy](decisions/D10-authenticated-release-domains.md) | accepted | R6, R10, P11, P13, P24 |
| D2 | [Rule sets compose as a union, and the checker runs out of process](decisions/D2-acro-composition.md) | accepted | R5 |
| D3 | [Second-moment cells get their own bound, and their own failure mode](decisions/D3-second-moment-parameters.md) | accepted | R5, R15, P19 |
| D4 | [Inference from a dispersion that cannot be released](decisions/D4-robust-dispersion.md) | **parked** | R15, P21 |
| D5 | [What to do about the response-time channel](decisions/D5-timing-channel.md) | accepted | R3, R5, R6, R18 |
| D6 | [An external checker is used by default when one is configured](decisions/D6-checker-default.md) | accepted | R5 |
| D7 | [Auditor totals count donors, and internal range filters are band-aligned](decisions/D7-donor-totals-and-band-filters.md) | accepted | R5, R6 |
| D8 | [The inside analyst starts as a vetted loop, on the public side of the gateway](decisions/D8-inside-analyst-vetted-loop.md) | accepted | R19, P23 |
| D9 | [A published result is a verifiable research record, not an AI narrative](decisions/D9-verifiable-research-record.md) | accepted | R6, R8, R11, R19, R20 |

## D1 — Models fit from vetted cells, not from rows

*2026-07-07 · accepted*

Should a statistical model be fitted on row-level data behind an influence witness, or exclusively on cell tables the gateway has already vetted?

**What would change our mind.** A model family arrives whose sufficient statistics are not catalogued aggregates — non-gaussian with continuous predictors is the standing example. That case needs either a new aggregate that IS vettable, or the row-level route with a leverage witness, and the row-level route is deliberately kept alive in the design for it.

[Read the record](decisions/D1-cells-first-models.md)

## D10 — Authenticated release domains and deterministic accounting come before differential privacy

*2026-08-19 · accepted*

In an answer-level TRE, should cumulative disclosure be controlled primarily by a public-query-style differential-privacy budget, or by the fact that the service is a restricted research environment with strongly identified, authorised users and custodian-defined release domains?

**What would change our mind.** Deterministic shared accounting has been implemented and attacked with the collusion corpus. Add a DP mechanism only where a measured residual cannot be bounded cleanly enough by deterministic release rules, identity-aware limits, memoisation and shared lineage, or where a quantitative privacy guarantee is itself the research objective.

[Read the record](decisions/D10-authenticated-release-domains.md)

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

*2026-07-26 · parked*

A coefficient without a standard error is rarely publishable. Can inference — an interval, or even a significance class — be restored when the second-moment cell is too concentrated to release?

**What would change our mind.** A researcher is actually blocked by it — the availability gap is currently 36 gaussian points out of 539 on synthetic data, and a real cohort where the concentrated case is the common one rather than the rare one would change the arithmetic. Or a robust dispersion arrives from outside with its bias already characterised, so the correction does not have to be defended here. Or the wider question is settled by the DP accountant (roadmap item 3), which would supply intervals by a route that does not need this one. The plan below survives intact, so unparking is cheap.

[Read the record](decisions/D4-robust-dispersion.md)

## D5 — What to do about the response-time channel

*2026-07-26 · accepted*

Query latency tracks cohort size closely enough to put sub-threshold cells in size order within a session's query budget. Should responses be padded to a constant time, quantised to a coarse bucket, or documented and left?

**What would change our mind.** Quantisation attenuates rather than eliminates, and the residual is written below: a patient attacker across sessions can still order some pairs at 26-70 samples. Revisit if cross-session accounting arrives (roadmap item 4) and makes that bound meaningful rather than notional; if a deployment reports the ceiling refusing legitimate work, which would mean the quantum and ceiling need re-fitting to a larger dataset; or if anyone wants the channel closed rather than narrowed, which needs constant time — available today by setting the quantum equal to the ceiling, at the cost of every query paying it. If the system is ever pointed at real data, revisit the whole approach in favour of asynchronous delivery, which removes the channel instead of narrowing it (see the end of this record).

[Read the record](decisions/D5-timing-channel.md)

## D6 — An external checker is used by default when one is configured

*2026-07-26 · accepted*

Should the shipped default vet with the prototype's own rules alone, or compose them with an external output checker?

**What would change our mind.** The measured cost was 5% of gaussian model availability on synthetic data whose concentration was deliberately planted. Real data could be worse, and a deployment that finds the composite refusing analyses researchers need should re-run `scripts/measure_composite_cost.py` against its own data rather than assume these numbers transfer. Revisit also if a checker ever gains rules that are not monotone with ours — the whole argument rests on the union only ever suppressing more.

[Read the record](decisions/D6-checker-default.md)

## D7 — Auditor totals count donors, and internal range filters are band-aligned

*2026-07-28 · accepted*

An adversarial review (redteam/adver_report.md §2) showed the filter algebra is a differencing channel the auditor cannot see: a range sweep on exact age reads sub-band totals from individually safe releases, and two such slices with two common narrowing dimensions recover a 1-3 donor cell. Do we count donors in the auditor's delta check, restrict internal range filters to the public band edges, both, or something structural (DP)?

**What would change our mind.** A differential-privacy accountant (roadmap item 4) would make both rules redundant by bounding the answer rather than the query shape; revisit then. Also revisit if a new internal high-granularity filter variable is added — it needs its own declared edge set in query.INTERNAL_RANGE_RULES, or the same analysis repeated — and if analysts complain that band-aligned age windows cost real utility, because the alternative (publishing two- dimensional marginals so the lineage bound can see interactions) is a different disclosure trade, not a free one.

[Read the record](decisions/D7-donor-totals-and-band-filters.md)

## D8 — The inside analyst starts as a vetted loop, on the public side of the gateway

*2026-08-15 · accepted*

The next research phase moves the automated component from formatting one request at a time to answering a research question end to end. Where should the analyst's inputs come from — the released side of the gateway, or the raw side with new controls — and what must its output be so that the existing disclosure argument is inherited rather than re-argued?

**What would change our mind.** Phase 3 of docs/inside-analyst.md — the data-sighted tier, where the analyst sees unvetted intermediates — needs its own clauses (a locked, audit-committed plan; adaptivity metered by the DP accountant), because there selection is a channel and P23 as written cannot hold. Revisit also if the question bank shows the vetted loop cannot reach the truths the NIGHTPLAY study plants through released aggregates alone, which would be the argument for that tier.

[Read the record](decisions/D8-inside-analyst-vetted-loop.md)

## D9 — A published result is a verifiable research record, not an AI narrative

*2026-08-19 · accepted*

If an automated analyst performs increasingly rich and adaptive work inside the TRE, what must a researcher be able to show a reviewer so that the scientific result is inspectable and reproducible without exposing protected data or trusting the model's prose?

**What would change our mind.** The first implementation slice has produced a complete record and replay certificate for an end-to-end NIGHTPLAY question. At that point promote the stable parts into normative R/P clauses. Revisit earlier if public provenance itself proves disclosive, or if deterministic replay cannot be made stable enough for the registered procedure set.

[Read the record](decisions/D9-verifiable-research-record.md)


## Adding a record

Create `docs/decisions/D<n>-<slug>.md` with the header fields above — `status`
is `accepted`, `open` or `superseded` — and regenerate:

```sh
uv run python scripts/gen_decision_log.py --write
```

`tests/test_decision_log.py` fails the build on a missing field, a clause that
is not in the specification, evidence that does not exist, an empty
`revisit_when`, a duplicate or mismatched id, or a stale index.
