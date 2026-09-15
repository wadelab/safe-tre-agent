# Web interface walkthrough

A two-minute first look at the web interface for someone who has never used
it. It assumes the app is already running (see [Demo in 5 minutes](demo-5-minutes.md))
and walks through three simple questions, then the two ways a question can be
processed: **parse outside** and **parse inside**.

## What you are looking at

The page lets you ask questions of a sensitive dataset without ever seeing an
individual's record. The demo data are synthetic: app spending, loot boxes, age,
region and wellbeing. You type a question in plain English; the system turns it
into a calculation, runs it, and checks the answer before you see it.

## Look around first

The right-hand panel shows what you can ask about:

- **Datasets** — open one to see its *dimensions* (things you can group by, such
  as age band or region) and *measures* (things you can average or count, such
  as spend or wellbeing).
- **Disclosure policy** — groups must have at least 10 people, counts are
  rounded to 5, and raw rows are never released.

If you are stuck, open **Example queries** under the question box and click one.

## Query 1 — a simple question

Type `mean spend by age band` and select **Ask**.

Watch the **Gateway checks** strip: vetting, planner, validation, engine,
session auditor, safe outputs and human review light up in turn. All seven
complete, and a table comes back with an `n` (number of people) beside each
figure. Status: **released**.

## Query 2 — too specific

Now try `mean spend by age band, region and device os`.

Splitting three ways makes some groups too small. The **Safe outputs** step
reads **Redacted**: those cells are blanked, but the rest of the table still
comes back. The gateway removes only the risky cells.

## Query 3 — asking about individuals

Try `show mean wellbeing per donor`.

The request stops at step 1 and the result is **denied**, with a reason and no
table. A denial is the safety controls working, not a crash, and every request,
denied ones included, is recorded in the audit log.

## Beyond averages

The same box accepts statistical questions, such as
`correlation between age and spend` or `regress total spend on age band`. The
same checks apply.

## Parse outside and parse inside

When the operator has enabled the inside analyst, a small
**parse outside / parse inside** switch sits above the page title. Without it,
every question is processed outside.

![The ask box with the inside analyst enabled](figures/demo-inside-toggle.png)

| | Parse outside (default) | Parse inside |
|---|---|---|
| What happens | The planner turns your question into **one** calculation | The safe analysis engine plans and runs **several** analyses inside the environment |
| What you see | The seven-step gateway-check strip | One box per analysis step, each settling as released, redacted or denied |
| What comes back | One table, or a denial | A dossier of vetted releases and a summary written only from them |
| Speed | Well under a second | Tens of seconds to a minute |
| Good for | A single, well-formed aggregate question | A research question that needs several steps to answer |

Both modes use the same gateway. In parse inside, every step the engine takes is
a full pass through validation, the session auditor and the safe-outputs checks,
so it cannot release anything a single outside query could not. Its working
notes and the raw data never reach the browser.

Start with parse outside. Switch to parse inside when one table is not enough to
answer the question.

!!! note "Who controls the switch"
    Whether an inside analyst exists at all is an operator decision, set at
    deploy time with `SAFETRE_ANALYST=chimp`; a page visitor cannot turn it on.
    The per-question switch is a demo affordance and is intended to become an
    operator-level setting. Parse inside needs a model endpoint: the offline
    `mock` planner does not drive it. See [Deployment](deployment.md#the-inside-analyst-safe-analysis-engine)
    and [The inside analyst](inside-analyst.md).

## The one idea to remember

The planner suggests what to calculate; fixed rules decide what you are allowed
to see.
