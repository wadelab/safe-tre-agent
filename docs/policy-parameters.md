# Policy parameters

Every dial that changes what this gateway releases. Each is declared where it
lives — on the `PolicyConfig` field itself — and this page is generated from
those declarations, so a parameter cannot exist here without an explanation or
exist in the code without appearing here.

Three things are worth knowing before turning anything.

**The defaults are the strict reading.** Where a parameter is optional,
leaving it unset selects the more conservative behaviour. Nothing here has to
be set for the gateway to be safe; the dials exist so a TRE can be *stricter*,
or can accept a stated, measured relaxation deliberately rather than by
accident.

**A number is not a policy until you know what it means.** A dominance bound
of 0.5 sounds like one rule and is two, depending on whether the cell holds a
sum or a sum of squares. Each parameter below says what its value means in
terms of donors and cells, which is the form an output checker can actually
reason about.

**Where a cost has been measured, it is linked.** Tightening a dial suppresses
more; loosening it releases more. Some of those trades have been quantified
against this project's synthetic data, and the evidence column points at the
measurement rather than an assertion. Where there is no link, the cost has not
been measured, and that is itself worth knowing.

Set any of them by environment variable (which wins) or in `config.yaml`
(which beats the built-in default). Both routes are tested against every
parameter listed here.


## `min_cell_size`

The minimum number of distinct donors a released cell may describe.

**What the value means.** a cell is suppressed unless at least this many DONORS (not rows) contribute to it. Ten is the SDC convention; raising it suppresses more small cells, which mostly costs fine-grained breakdowns.

| | |
|---|---|
| Default | `10` |
| Environment | `SAFETRE_MIN_CELL` |
| `config.yaml` | `disclosure.min_cell_size` |
| Clause | [R5](specification.md) |
| Pinned by | `tests/test_hardening.py` |
| Measured cost | *not measured* |

## `max_output_rows`

How many rows a result may have before it looks like a row dump.

**What the value means.** an un-aggregated result longer than this is flagged for human review rather than released automatically. It bounds granularity, not cell size.

| | |
|---|---|
| Default | `100` |
| Environment | `SAFETRE_MAX_OUTPUT_ROWS` |
| `config.yaml` | `disclosure.max_output_rows` |
| Clause | [R5](specification.md) |
| Pinned by | `tests/test_disclosure.py` |
| Measured cost | *not measured* |

## `query_budget`

How many aggregates one session may release.

**What the value means.** each released aggregate is individually differencable, so the budget bounds how much an analyst can accumulate in one sitting — including one per design cell table of a model. It is a cost bound, not a privacy bound: it does not compose across sessions or users.

| | |
|---|---|
| Default | `20` |
| Environment | `SAFETRE_QUERY_BUDGET` |
| `config.yaml` | `session.query_budget` |
| Clause | [R6](specification.md) |
| Pinned by | `tests/test_hardening.py` |
| Measured cost | *not measured* |

## `differencing_delta`

How similar two cohorts may be before the second is refused.

**What the value means.** if a new cohort differs from one already released by fewer than this many donors, the release is denied — the difference would isolate that few people. The bound is computed from PUBLISHED marginals, so the refusal itself leaks nothing.

| | |
|---|---|
| Default | `10` |
| Environment | `SAFETRE_DIFFERENCING_DELTA` |
| `config.yaml` | `session.differencing_delta` |
| Clause | [R6](specification.md) |
| Pinned by | `tests/test_hardening.py` |
| Measured cost | *not measured* |

## `dom_threshold`

How much of a cell one donor may account for.

**What the value means.** a sum or mean cell is suppressed when its largest contributor holds more than this share of the total — at 0.5, one donor may not be more than half the cell. ACRO's defaults express the same concern differently (p%- and NK-rules) and neither set subsumes the other, so a deployment running both keeps both.

| | |
|---|---|
| Default | `0.5` |
| Environment | `SAFETRE_DOM_THRESHOLD` |
| `config.yaml` | `disclosure.dom_threshold` |
| Clause | [R5](specification.md) |
| Pinned by | `tests/test_disclosure.py` |
| Measured cost | [docs/acro-comparison.md](acro-comparison.md) |

## `influence_threshold`

How far one donor may move a released correlation.

**What the value means.** a correlation cell is suppressed when removing any single donor would shift r by more than this. It is the corr analogue of dominance, and its value is bespoke rather than derived from a standard — see best-practice review D6.

| | |
|---|---|
| Default | `0.5` |
| Environment | `SAFETRE_INFLUENCE_THRESHOLD` |
| `config.yaml` | `disclosure.influence_threshold` |
| Clause | [R5](specification.md) |
| Pinned by | `tests/test_disclosure.py` |
| Measured cost | [docs/best-practice-review.md](best-practice-review.md) |

## `round_base`

The granularity released counts are rounded to.

**What the value means.** every released count is rounded to a multiple of this, so a count carries at most this much precision about how many people a cell describes. Everything else the release reveals must be a function of the ROUNDED value, which is what hardenings #26 to #28 were about.

| | |
|---|---|
| Default | `5` |
| Environment | `SAFETRE_ROUND_BASE` |
| `config.yaml` | `disclosure.round_base` |
| Clause | [R5](specification.md) |
| Pinned by | `tests/test_disclosure.py` |
| Measured cost | [artifacts/rounding_distortion.json](https://github.com/wadelab/safe-tre-agent/blob/main/artifacts/rounding_distortion.json) |

## `moment2_dom_threshold`

Dominance for second-moment cells (sums of squares), which back a model's standard errors.

**What the value means.** squaring is not share-preserving, so the same number is a much tighter rule here: a donor holding a fraction p of a cell holds p²/(p² + (1-p)²/(k-1)) of its squared total, crossing one half at p = 1/(1+√(k-1)). A bound of 0.5 therefore allows about 0.19 of a twenty-donor cell and 0.13 of a fifty-donor one; a bound of 0.8 allows 0.31 and 0.22. Because a model dies if either moment table is suppressed, this dial governs how often models are available at all.

| | |
|---|---|
| Default | unset — second moments are checked at `dom_threshold`, the stricter reading |
| Environment | `SAFETRE_MOMENT2_DOM_THRESHOLD` |
| `config.yaml` | `disclosure.moment2_dom_threshold` |
| Clause | [R5](specification.md) |
| Pinned by | `tests/test_second_moment.py` |
| Measured cost | [artifacts/dispersion_sensitivity.json](https://github.com/wadelab/safe-tre-agent/blob/main/artifacts/dispersion_sensitivity.json) |

## `vetter`

Which rules decide whether a cell may be released.

**What the value means.** `standin` uses this prototype's own rules. `standin+external` ALSO asks an external output checker and suppresses a cell if either says so — a union, so adding the checker can only suppress more. An external checker is never the only vetter: it has no egress rules and no complementary suppression.

| | |
|---|---|
| Default | `'standin'` |
| Environment | `SAFETRE_VETTER` |
| `config.yaml` | `disclosure.vetter` |
| Clause | [R5](specification.md) |
| Pinned by | `tests/test_cell_vetter.py` |
| Measured cost | [docs/acro-integration.md](acro-integration.md) |

## `checker_cmd`

The command that starts that external checker.

**What the value means.** a command line, run per vetted table, speaking the JSON contract in `safetre/external_checker.py`. Every failure — exit code, timeout, bad protocol, incomplete answer — denies the release rather than falling back to the built-in rules.

| | |
|---|---|
| Default | `''` — no external checker; required when `vetter` names one |
| Environment | `SAFETRE_CHECKER_CMD` |
| `config.yaml` | `disclosure.checker_cmd` |
| Clause | [R5](specification.md) |
| Pinned by | `tests/test_acro_boundary.py` |
| Measured cost | *not measured* |


## Adding a parameter

Declare it on `PolicyConfig` with `_dial(...)`, giving what it controls, what
the number means, its governing clause, its `config.yaml` key, and a test that
proves changing it changes a decision. Add its environment variable to
`_ENV_OVERRIDES`, then regenerate this page:

```sh
uv run python scripts/gen_policy_catalogue.py --write
```

`tests/test_policy_catalogue.py` will otherwise fail the build — for a missing
declaration, a clause that does not exist, evidence that has gone missing, a
`config.yaml` key or environment variable that does not actually take effect,
or a page that no longer matches the code.
