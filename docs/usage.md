# Usage (researcher guide)

You ask for an **aggregate** in plain language. The system turns it into a
validated query, runs it on data you never see, and returns the result only if it
passes disclosure control. You will get one of three outcomes: **released**,
**redacted**, or **denied** — always with the reason.

## The interface

Open `https://d2-1.<tailnet>.ts.net`. You'll see who you're signed in as (your
tailnet identity), a query box, and the catalogue of what can be queried. Type a
request and press **Run**. The result card shows the status, the validated
`QuerySpec` that ran, the table (if released), any findings, and the full
pipeline trace.

## What you can ask for

You can request a **count**, **mean** or **sum**, grouped by up to three
dimensions, with filters — over two datasets:

| Dataset | Dimensions (group by / filter) | Measures (mean / sum) |
|---|---|---|
| `spend` | age_band, sex, canton, income_band, device_os, genre, contains_lootboxes, price_tier, event_type, age_rating | amount_chf, ingame_currency |
| `wellbeing` | age_band, sex, canton, income_band, device_os, wave | pgsi_score, igds_score, wemwbs_score, monthly_spend_selfreport |

Anything else — identifiers, free text, raw ages, timestamps, custom maths — is
**outside the catalogue and will be rejected**. Those analyses go through the
human-reviewed escalation route, not the live interface.

### Examples that work

- `mean spend by age band`
- `count of donors by canton`
- `mean wellbeing by canton` (mean `wemwbs_score`)
- `total spend by device os for purchases`

### Examples that get blocked

- `summarise the free-text comments` → **denied** (free text is not queryable)
- `wellbeing per donor` → **denied** (no per-individual output)
- `give me the row-level records` → **denied** (hostile intent)
- `mean spend by age band, canton and device os` → **redacted** (small cells
  suppressed, the rest released)

## Reading the result

**Released** — the aggregate passed every check. Each row includes an `n` column:
the number of individuals behind that cell.

**Redacted** — some cells were below the minimum group size (10) and were
suppressed; the rest is shown. This is normal and expected for fine-grained
breakdowns.

**Denied** — nothing is returned. The message says why:

| You'll see | Meaning |
|---|---|
| `query rejected: …` | the proposed query was off the allowlist |
| `intent_block` | the request asked for something disclosive by intent |
| `identifier_egress` / `free_text_egress` | output would contain identifying data |
| `small_cell` (as denial) | combined with other findings, too disclosive to release |
| `differencing` | this query, combined with an earlier one this session, could isolate an individual |
| `query budget … exceeded` | too many queries this session; pause and review |

## Why some safe-looking queries are refused

Two individually harmless queries can, **together**, reveal one person (a
"differencing" attack — e.g. a total, then the same total excluding one
subgroup). The session auditor tracks this across your session and will deny the
second query. It isn't a bug; it's the system protecting against inference.

## What gets denied or redacted

The red-team that ships with the project demonstrates the full set:

![Red-team: gateway off vs on](figures/redteam_results.png)

Every attack is neutralised; benign analysis flows through. See
[Security model](security.md#threats-and-controls) for the mechanism behind each.
