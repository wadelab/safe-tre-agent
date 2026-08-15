# Planner-quality evaluation

The gateway makes planner mistakes safe, not invisible: a valid but wrong
QuerySpec — a missing filter, the wrong dataset — releases a misleading answer.
`evals/run_planner_eval.py` measures that gap against a reference corpus
(`evals/corpus.yaml`): 24 answerable natural-language requests with acceptable
reference specs, plus 6 requests with **no legal answer**, where the correct
behaviour is a proposal that fails validation.

Scoring, after canonicalisation (order-insensitive group-by and filters):

- **valid** — the proposal passes QuerySpec validation
- **primary** — matches the intended reference spec
- **accepted** — matches any acceptable variant
- **cohort** — right dataset and filters, wrong measure or grouping
- **rejected** — for unanswerable requests, the proposal failed validation

```bash
uv run python evals/run_planner_eval.py                 # mock (offline)
uv run python evals/run_planner_eval.py --planner real  # SAFETRE_LLM_* env
```

## First results — 2026-07-06

| Planner | valid | primary | accepted | cohort | rejected (n=4) |
|---|---|---|---|---|---|
| MockPlanner (keyword stub) | 94% | 33% | 33% | 44% | 50% |
| Real planner (remote-hosted model†) | 94% | 50% | 67% | 72% | 0–25%* |

\* two runs; the model is sampled, so scores vary run to run.

† synthetic-data-only endpoint; the model is deliberately not named
([model runtime](model-runtime.md)) — naming the planner invites
model-targeted prompting, and the measurement is of the *class* of planner
the boundary must tolerate, not of one product.

Three observations worth keeping:

1. **The real model plans usefully but imprecisely.** Two-thirds of proposals
   match an acceptable reading; half match the intended one. The common miss is
   a dropped `event_type` filter — a valid spec whose mean is diluted by £0
   session events. The gateway releases it, correctly: it is safe, just not
   the question asked.
2. **The model almost never refuses.** On the four unanswerable requests it
   proposed a valid-looking spec nearly every time. Sometimes the spec named
   the forbidden column (`free_text`) and validation caught it; more often it
   **deflected** — for "wellbeing per donor" it proposed mean wellbeing by
   age band: valid, safe, and silently a different question. Refusal behaviour
   cannot be assumed from the planner; the boundary has to supply it.
3. **The mock out-scores the model on rejection (50%)** only because its
   canned attack branches deliberately propose off-allowlist specs. That is a
   property of the test fixture, not of keyword planning.

## Second measurement — 2026-08-15: a local-class model, and what its misses taught the prompt

Phase 0a of the [inside-analyst plan](inside-analyst.md) asked one question:
can a model of the class a TRE could host *locally* do the planning job at
all? A hosted **120B-class open-weight mixture-of-experts model** (about 12B
parameters active per token — the [model runtime](model-runtime.md) page's
own planning target) stood in for a local deployment, scored twice on the
corpus as it now stands (24 answerable, 6 unanswerable) beside a same-day
rerun of the remote planner the demo has used, first on the prompt as it was
and then on a revised prompt. Neither model is named, for the reason given
above; both were reached over a synthetic-data-only remote endpoint, which is
what `SAFETRE_ALLOW_REMOTE_LLM` exists for and the runtime otherwise refuses.

| Planner | prompt | valid | primary | accepted | cohort | rejected (n=6) |
|---|---|---|---|---|---|---|
| Incumbent remote planner | as of 2026-07 | 96% | 63–71% | 79–88% | 79–88% | **0%** (0/6, both runs) |
| 120B-class local-class stand-in | as of 2026-07 | 92–96% | 54–63% | 67–75% | 71–75% | 33–67% |
| Incumbent remote planner | revised | 100% | 96% | **100%** | 100% | 0–17% |
| 120B-class local-class stand-in | revised | 96% | 92–96% | **96%** | 96% | 33–50% |

Ranges are two runs each; the endpoints are not deterministic even at
temperature 0, and with 24 items one item is 4 points, so read differences
under ~8 points as noise.

Three things worth keeping:

1. **The model class is sufficient.** On the revised prompt the stand-in
   matches the intended reference spec on 22–23 of 24 answerable requests,
   within one item of the incumbent. Orchestrating a small, typed procedure
   menu is an easier job than open-ended code generation, and this is the
   number that says a modest local model can do it.

2. **Most of the misses were the prompt's, not the model's.** Reading the
   stand-in's failed proposals on the original prompt sorted them into three
   bins. The largest was *dataset semantics the prompt never stated*: it did
   not know that "total spend" means summing event-level `amount_gbp` over
   `purchase` and `lootbox_open` events, so it reached for the per-donor
   rollup or dropped the `event_type` filter — the incumbent's documented
   miss from July, now explained. The second was *format*: a filter object
   written as `{"column": ..., ">=": 18}`, and an age bound expressed as two
   equalities on `age_band`. Both facts now live in the demo definition's
   `planner_hints` and `planner_examples` (what a row of each dataset is;
   which filter a spend question needs; the exact filter shape; that age
   bounds snap *inward* to the declared edges, so "over 40" is `>= 50`).
   That revision moved the stand-in from 67–75% to 96% accepted and the
   incumbent from 79–88% to 100% — a prompt change with no safety obligation
   (the planner is untrusted) and a large quality one, which is exactly what
   the [maintenance guidelines](maintenance.md) say to measure before and
   after.

3. **The third bin is the one that matters for the next phase: deflection.**
   Both planners, on both prompts, turned "mean wellbeing per donor so I can
   see the distribution" into a valid overall mean and "regress wellbeing on
   region and give me the residuals" into a valid model with the residuals
   silently dropped — valid, safe, and *a different question*
   ([the Mirror](bestiary.md)). The stand-in does refuse outright when the
   request is plainly for rows or timestamps (it answers with an explicit
   error object, which the incumbent almost never did), which is why its
   rejection rate is higher; but it deflects on the subtler ones just as
   readily. The July conclusion therefore holds for the new model class:
   refusal must come from the boundary, not the planner — and for an analyst
   that assembles many answers into a dossier it becomes a requirement rather
   than an observation. The dossier must carry typed `not_answerable`
   verdicts; a silently substituted answer is the failure mode to design
   against.

The measurement turns the [model-runtime](model-runtime.md) assumption —
"local models will become strong enough for planning" — into a number that can
be tracked per model and per prompt revision. Raw proposals are kept in the
JSON output (`--json`) for qualitative review.
