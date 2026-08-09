# Shadow data

A researcher cannot see the real rows. That is the point of the system, and it
is also the thing that makes the system awkward to use: you are asked to write
an analysis against data you have never looked at, submit it, and find out
afterwards whether the factor had the levels you assumed.

**Shadow data** are the answer to that. They carry the study's *shape* — column
names, types, factor levels — and none of its content, so a researcher can open
them in whatever tool they already use, get the analysis roughly working, and
submit only the finished spec to the gateway. The expensive, budget-consuming,
disclosure-checked run then happens once, deliberately.

```bash
uv run python scripts/make_shadow.py --out shadow/ \
    --persons 2000 --rows events=40000 \
    --range pgsi_score=0:27 --range wemwbs_score=14:70 \
    --derive age_band=age_years
```

This writes one CSV per public dataset — the exact columns an analyst sees —
plus the base tables, a `README.md` and a `MANIFEST.json`.

## Why they are safe

The generator's only input is the [dataset definition](datasets.md). It never
opens the real tables, never connects to the operator's database, and has no
parameter through which real rows could be passed. Everything it emits comes
from one of three places:

| Source | Example | Why publishing it is not a release |
|---|---|---|
| A **declared domain** | the twelve UK ITL1 regions | Design-time knowledge, authored and reviewed by the operator, already published in the catalogue the planner is given |
| A **declared kind or band edge** | `age_years` is `int`, banded at 13/16/18/25/35/50 | Same: operator configuration, independent of any participant |
| A **fixed fallback range** | 0–100 for an unbounded measure | Invented, and *reported as invented* — listed in the manifest and the README |

Nothing is fitted. That is the whole design.

### Why not fit a synthesiser to the real data?

Because the synthetic dataset would then itself be a release, and one this
gateway is not built to check.

- The gateway checks **frames of aggregates** against cell-size, dominance and
  influence rules. A synthesised table is thousands of correlated statistics
  arriving with no budget entry and no cell structure to check.
- **Measured value sets leak directly.** The existence of a rare category is
  disclosive — which is precisely what the demo fixture's eight Northern
  Ireland donors exist to demonstrate. A synthesiser that learns the levels of
  `region` from the data publishes that fact.
- The literature does not let you assume otherwise. Sequential-tree
  synthesisers can reproduce outlying records close to verbatim, and membership
  inference against synthetic data is an active attack area. "Synthetic" is a
  privacy property only when the fitting step is itself private.

Here there is no fitting step, so there is nothing to argue about.

### The property is enforced, not promised

`verify_shadow()` runs on **every** build and refuses to return a shadow
containing a value the definition does not account for: each column's values
must lie in its declared domain, in `{True, False}`, inside a bounded numeric
interval, in a generated key pool, or match the placeholder pattern. It also
re-checks that no public frame carries a direct identifier or a person id.

A failure means some code path invented a value from outside the definition —
exactly the situation in which "synthetic" would stop being a safety property.
It raises; the shadow is not written.

## What shadow data are useless for

Every column is drawn independently. There are no correlations, no realistic
marginals, no heavy tails, no small cells and no dominance.

- **Do not** test disclosure control against them. There is nothing to find, so
  a red-team run would pass while proving nothing. `safetre/synth.py` is the
  fixture for that, and it plants its hazards on purpose — sub-threshold
  cells, dominance anchors, an injection payload.
- **Do not** read effect sizes, power or model fit off a shadow run. An
  analysis that looks healthy here can be badly specified for the real data.
- **Do** use them to check that a model *runs*: that the factors have the
  levels you expected, that a contrast is estimable, that a GLM family suits
  the response, that your syntax is right.

## What the generator does guarantee

Within those limits, three properties are worth relying on, and each is held by
a test:

1. **The columns are the real columns.** Public datasets are built by running
   the definition's own `public_view_sql()` over the generated base tables, so
   the shadow's columns — including derived rollups like `total_spend_gbp` —
   cannot drift from the real view's.
2. **Every declared factor level is present.** Values are drawn with coverage
   rather than uniformly, and a table is never generated with fewer rows than
   its widest domain. A level missing from the shadow would make a contrast
   estimable here and not there, which is the surprise the whole exercise
   exists to prevent.
3. **Joins are non-empty.** Foreign keys are drawn from the owning table's
   generated pool, and every person appears in every table that carries the
   person key.

## Options

| Flag | Effect |
|---|---|
| `--dataset PATH` | Definition to shadow (default: the packaged demo) |
| `--persons N` | Distinct people (default 500) |
| `--rows TABLE=N` | Rows for one base table. Tables carrying the person key default to one row per person, so event tables usually want this set |
| `--range COL=LO:HI` | Bounds a numeric column the definition does not bound, instead of accepting the 0–100 fallback |
| `--derive BAND=SOURCE` | Compute a banded column from the numeric column it bands |
| `--seed N` | Same seed and definition always give the same files |

### Bands, and why they are opt-in

Independent draws mean a shadow row can carry age 51 in band `18-24`. Harmless
for checking that a query runs; confusing to look at. `--derive
age_band=age_years` computes the band from the value, using the source column's
declared range-rule edges and the banded column's declared domain.

It is never inferred. Two declarations that happen to be the same length are
not evidence that they describe the same banding, and pairing them up quietly
would be a guess dressed as configuration. The operator states the coupling,
both declarations are checked, and a mismatch is refused.

### Columns with no declared scale

A numeric column the definition does not bound gets uniform values on 0–100,
which are **not** on the real scale — a shadow WEMWBS score of 41.7 must not be
mistakable for one on the true 14–70 scale. Every such column is named on
stdout, in `MANIFEST.json` and in the generated `README.md`, and `--range`
fixes it.

### Columns no dataset exposes

Free text, timestamps and row ids are not groupable or aggregable by any
analyst, so the generator emits an obvious placeholder (`ts-000042`) rather
than a plausible fake. Person ids are stamped `SHADOW-P…` so an extract found
on a disk somewhere cannot be mistaken for a real one.

## Where this is going

Shadow data are the missing half of a front-end story. A GUI such as JASP is
already a spec-shaped interface — its forms emit a declarative options blob
much like a `QuerySpec` — but it assumes it holds the data. Point it at a
shadow instead and the whole tool works normally while the real run stays
behind the gateway, with the submit button as the auditable trust boundary.

That also fixes a security problem such a front end would otherwise create:
interactive tools re-run on every tick, and a stream of near-identical cohorts
is exactly the shape the [differencing controls](security.md) exist to catch. A
researcher who iterates on shadow data spends no budget and reveals nothing;
only the deliberate submit costs anything.

If independent columns prove too thin in practice, the next step is for the
operator to *declare* approximate marginals in the definition file alongside
the domains — reviewed configuration, the same trust status as the domains
themselves — rather than for anything to measure them. That keeps the boundary
where it is: the generator's inputs stay operator-authored and
analyst-independent.
