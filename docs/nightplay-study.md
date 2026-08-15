# The NIGHTPLAY study

*A second synthetic population, built for the [inside analyst](inside-analyst.md)
phase: linked sources, a person × month panel, planted truths that a competent
analyst should find, planted traps that an incompetent one falls into, and the
truth written down beside the data so a dossier can be marked. It lives in
`studies/nightplay/` and is served through the ordinary
[dataset definition](datasets.md) mechanism with no code change.*

## Why a second dataset

The packaged demo answers one question at a time, and its synthetic corpus was
chosen to be realistic — which, the round-11 audit showed, is the wrong
sampling for finding defects: a realistic corpus is chosen to be
unexceptional. An automated analyst needs the opposite in both directions.
There must be something genuine to discover across several sources, so that
multi-step analysis is worth doing; and there must be structure that breaks
careless arithmetic and careless inference, so that a good analyst can be
told from a bad one.

So the study is built backwards: decide what should be true, generate a
population in which it is true, record it. The headline question is the plan's
running example — *is late-night phone use linked to gambling?*

## What is in it

Six base tables, ~6,000 people by default (`studies/nightplay/generate.py`):

| Table | One row per | Carries |
|---|---|---|
| `people` | person | age, sex, region, employment, income, device, and `night_use_band` — the person's own late-night use, banded |
| `phone_sessions` | phone session | hour band, day type, month, app category, duration |
| `gambling_txns` | gambling transaction | hour band, month, product, stake, net loss (negative on wins, NULL while pending) |
| `person_month` | person × calendar month | that month's sessions, late-night sessions and minutes, gambling transactions, stake, net loss, giving |
| `questionnaire` | person × wave (three waves) | PGSI, sleep quality, WEMWBS, self-reported stake, free text |
| `donations` | donation | month, cause, amount |

Five public views (`studies/nightplay/nightplay.yaml`): `sessions`, `bets`,
`panel`, `wellbeing`, `giving`. Raw timestamps and free text are in no view;
`hour_band` and `month` are their declared coarsenings. Exact age is an
internal band-edge filter, as in the demo.

The panel and the cohort band are **derived from the event tables after every
plant is applied**, so the views agree with each other by construction — the
same property the demo's per-donor rollups have, materialised. That
consistency is also a live instance of the cross-view differencing surface
roadmap item 0.0 describes: `panel.stake_gbp` *is* the per-person-month sum
of `bets.stake_gbp`, and only a declared equivalence could tell the lineage
so.

## What is planted, and what is written down

Every truth is measured on the unvetted rows at generation time and written
to `nightplay_ground_truth.json` beside the CSVs, with the design parameters
that produced it. Those are oracle values — what a perfect analyst with row
access would find. A dossier assembled through the gateway is marked against
them.

**Truths.**

- **T1 dose–response.** Monthly stake rises monotonically with
  `night_use_band` (rare → heavy roughly five-fold at the default seed), as
  does the share who gamble at all.
- **T2 the confounder.** Shift workers use their phones at night more *and*
  gamble more for reasons of their own. The naive comparison overstates the
  effect; adjusting for `employment` shrinks it and keeps it positive. Nothing
  unobserved confounds — the latent night-owl trait acts on phone use only —
  so the manifest can say, truthfully, that the adjusted effect is the causal
  one.
- **T3 the planted null.** Late-night use has no effect on charitable
  giving, which follows income alone. An analyst who reports an association
  has found noise (any small marginal gradient is the income composition of
  the bands; the manifest carries the income-adjusted means too).
- **T4 heterogeneity.** The effect is carried by casino and slots; lottery
  stakes are flat across bands.
- **T5 time structure, twice.** Stakes peak in June and July with a smaller
  December rise, and the 2 a.m. bet is larger than the daytime one — an
  annual cycle and a within-day one, on a person × month panel that
  time-series procedures can later bite on.
- **T6 longitudinal.** PGSI rises wave over wave for heavy night users and
  stays flat for the rest; sleep quality falls with night use.

One deliberate subtlety: the panel correlation between late-night sessions
and stake is real but weak (r ≈ 0.08 over 72,000 zero-inflated, heavy-tailed
person-months) while the banded comparison shows a five-fold effect. An
analyst that dismisses the association on the correlation alone is wrong, and
the question bank marks that.

**Traps for the arithmetic** (each recorded under `adversarial` in the
manifest): item non-response in `sleep_quality`, `duration_min` and pending
`net_loss_gbp`; cancelling contributions, including one named cell whose net
loss sums to £0.37; a dominant contributor carrying 62% of a named
region × product cell; one person who single-handedly carries a
region × month correlation; sub-threshold subgroups (Northern Ireland 8, sex X
7, `armed_forces` 6); hostile strings in the free text and as *undeclared
category values* in `app_category` and `region`, so an undeclared value has to
be suppressed by name (hardening #43); and log-normal stakes with a long tail.

## The truths survive the gateway; the traps do not

A study that is rich on disk and empty at the boundary would justify nothing.
`studies/nightplay/verify.py` plays the reference analyst — literal
`QuerySpec`s, no planner, the same `QueryService` and `DisclosurePolicy` the
web app builds — and marks the *released* frames against the manifest. At the
default population all fourteen checks pass over sixteen requests: T1–T6 are
each recoverable from vetted releases; the whale cell, Northern Ireland and
`armed_forces` are suppressed; and no hostile string appears in any released
frame. `tests/test_nightplay_study.py` runs the same checks on a fresh 2,500-
person population in the ordinary suite, alongside pins that the generator is
deterministic, that the panel agrees with the events it was derived from, and
that every plant is present.

The one thing the gateway did *not* do at first pass is worth recording: the
GLM adjusted for employment is denied unless `armed_forces` (six people) is
filtered out, because any suppressed design cell denies the whole model
(P19) — and once released, it comes back coefficients-only, its dispersion
table withheld under the second-moment rule
([D3](decisions/D3-second-moment-parameters.md)). That is the framework
working, and it is the first thing a competent analyst has to notice; the
question bank marks whether the dossier says so.

## The question bank

`studies/nightplay/questions.yaml` is the marking scheme for a future
analyst: nine research questions, each naming the truth it is marked against,
the datasets and procedures a good answer uses, the expected verdict
(`supported` / `not_supported` / `null` / `not_answerable`) and the trap it
sets. Three of the nine are refusals — a per-person listing, a sub-threshold
region, the free text — where the mark is for refusing *and saying so* rather
than substituting a valid-looking aggregate. It is not yet an executable
evaluation; the reference analyses are run by hand in `verify.py`.

## Serving it

```sh
uv run python studies/nightplay/generate.py            # CSVs + manifest -> data/
SAFETRE_DATASET=studies/nightplay/nightplay.yaml scripts/restart_web.sh
```

The study's table names do not collide with the demo's, so both sets of CSVs
can sit in `data/` together; only the active definition decides which is
served. As for any non-demo study, the Lean and Alloy artifacts describe the
demo catalogue until regenerated ([datasets.md](datasets.md), step 4).
`--people` scales the population; the sub-threshold plants are absolute
counts, so they are present at any size.
