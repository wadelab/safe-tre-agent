# User guide

This guide is for an external researcher using the analysis interface from a
remote site.

## Access

You receive access after project approval. The approval links:

- your identity;
- the project purpose;
- the datasets and tools you may use;
- the output rules for the project.

You open a secure HTTPS page and sign in through the approved identity provider.
You do not get shell access, database access, notebooks with raw rows, or data
downloads.

![Web interface before a query](figures/web-ui-home.png)

## What the assistant does

You ask for an aggregate analysis in plain language. The outside interface may
use a frontier model to help translate your request into a tool call. The model
does not run the analysis and does not see raw data.

The safepod receives the proposed tool call, validates it, runs only approved
fixed tools, checks the output for disclosure risk, and returns either a result
or a refusal.

## Asking questions

Good requests are specific about the outcome, grouping, and filters:

- `mean spend by age band`
- `mean wellbeing by region`
- `total spend by device os for purchases`
- `count by sex and age band`
- `correlation between monthly spend self report and wellbeing score`
- `correlation between age and spend for sex==M in region==London`

The current executable tool is `aggregate_query`: count, mean, sum, and Pearson
correlation over allowlisted datasets. Correlation is fixed-function: it can only
use two allowlisted measure columns from the same dataset and returns `value`,
`p_value`, and `n` after the normal disclosure and session checks. Future tools
such as GLM, regression, and ANOVA will appear in the manifest only after they
have fixed schemas and disclosure checks.

Composite filters such as `sex==M` and `region==London` are compiled as separate
validated predicates with bound parameters. Raw age can be used inside fixed
tools such as donor-level age/spend correlation, but it is an internal analysis
variable only: it cannot be grouped, rendered, or returned.

## Results

Every request returns one of three statuses:

| Status | Meaning |
|---|---|
| `released` | the aggregate passed validation and disclosure checks |
| `redacted` | some cells were suppressed, but the remaining aggregate is safe |
| `denied` | no data is returned |

Released tables include an `n` column. Counts may be rounded. Small cells,
dominated cells, and unsafe combinations are suppressed or denied.

## Why requests are denied

Common reasons:

- the request names a field outside the allowed catalogue;
- the request asks for row-level data or per-person output;
- the requested breakdown creates groups that are too small;
- a sequence of requests could isolate a person through differencing;
- the requested tool is only planned and not yet executable;
- the project or user is not approved for the request.

The refusal reason is part of the result. Denied requests do not include a table.

## What not to ask for

Do not ask for:

- raw rows;
- donor or participant identifiers;
- free-text comments;
- exact timestamps;
- rare subgroups designed to isolate a person;
- repeated variations intended to reconstruct a suppressed value;
- custom code or SQL.

Those requests are blocked by design.

## Tool manifest

The interface uses a public manifest that lists available tools, datasets,
dimensions, measures, and limits. The manifest helps the outside model plan a
valid request, but it does not authorize execution. The safepod validates every
request again before anything runs.

The current endpoint is:

```text
/api/manifest
```

## Session behavior

The system tracks your session budget and previous released aggregates. A later
request may be denied even if it looks harmless on its own, because it combines
with earlier outputs in a risky way.

## Getting better results

- Ask for a broader grouping before asking for a fine-grained grouping.
- Prefer planned project variables and predeclared contrasts.
- Use standard aggregate language: count, mean, total, grouped by, filtered to.
- If a query is redacted, ask for fewer grouping variables or a broader cohort.
- If a query is denied, treat the denial as final unless your project reviewer
  changes the approved analysis plan.
