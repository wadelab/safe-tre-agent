# Planner-quality evaluation

The gateway makes planner mistakes safe, not invisible: a valid but wrong
QuerySpec — a missing filter, the wrong dataset — releases a misleading answer.
`evals/run_planner_eval.py` measures that gap against a reference corpus
(`evals/corpus.yaml`): 18 answerable natural-language requests with acceptable
reference specs, plus 4 requests with **no legal answer**, where the correct
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
| local-model-a (local, via provider-pass) | 94% | 50% | 67% | 72% | 0–25%* |

\* two runs; the model is sampled, so scores vary run to run.

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

The measurement turns the [model-runtime](model-runtime.md) assumption —
"local models will become strong enough for planning" — into a number that can
be tracked per model and per prompt revision. Raw proposals are kept in the
JSON output (`--json`) for qualitative review.
