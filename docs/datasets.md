# Serving a different study: the dataset definition

The gateway contains no facts about the data it serves. Every dataset-specific
thing — table and column names, which columns are identifiers, which may be
grouped, which may be aggregated, how the public views are joined, what the
natural-language gates recognise, what the planner is shown — lives in one YAML
file. Point `SAFETRE_DATASET` at yours and the same machinery serves your study
with no code change.

This is the operational companion to
[adding a statistical tool](adding-a-statistical-tool.md): that one adds a new
*capability*, this one adds new *data*.

> **What "no code change" is worth.** It is not a convenience claim. Every
> disclosure control in the system — the frequency threshold, dominance,
> differencing lineage, the fail-closed gate, the model path — is written
> against the definition's vocabulary rather than the demo's, so a new study
> inherits all of them as they are. `tests/test_dataset_independence.py` drives
> a second, deliberately different study (two base tables, a `patient_id`
> person key, one event-level view and one per-person rollup) through spec
> validation, the engine, the gateway, the session auditor, GLM, the planner
> prompt and the manifest. If a demo column name creeps back into the
> machinery, that suite fails.

## The shape of a definition

Start from [`safetre/demo_dataset.yaml`](https://github.com/wadelab/safe-tre-agent/blob/main/safetre/demo_dataset.yaml),
which is a worked example of every field. The required parts:

| Field | What it is |
|---|---|
| `name`, `description` | Identify the study. The name is logged at startup and recorded in the audit chain's config row. |
| `person_key` | **The unit of privacy** — the column naming the person whose *distinct count* the frequency threshold protects. Not the row key. Everything downstream counts these, not rows. |
| `tables` | Base table → column → disclosure role: `DI` direct identifier, `QI` quasi-identifier, `S` sensitive, `R` reference, `meta` structural. This is the labelling the whole gateway reasons from. |
| `datasets` | One entry per public, pre-joined view an analyst may query. |

And the parts you will want in practice:

| Field | What it is |
|---|---|
| `columns` | Per-column `desc` and, for categoricals, `domain` — the declared value list. The domain is load-bearing: a released cell key must be a declared category, so an undeclared or hostile value is suppressed by name rather than printed (hardening #43). |
| `derived_roles` | Roles for columns a view computes rather than reads. |
| `internal_range_rules` | Band-aligned ranges for high-granularity filter variables — see below. |
| `lexicon` | Dimension and response synonyms, and domain cues, for the natural-language fidelity gates. |
| `planner_hints`, `planner_examples` | What the untrusted planner is shown. Wrong content here costs answer quality, never safety: every spec it proposes is validated against the allowlists regardless. |
| `ui_queries`, `tour` | The example buttons and the guided tour. |

### A view (`datasets` entry)

```yaml
datasets:
  visits:                       # the name an analyst queries
    base: visits                # base table
    joins:
      - {table: patients, key: patient_id}      # JOIN patients ON base.key = patients.key
    columns:                    # qualified table.column refs -> public view
      - patients.sex
      - visits.cost_gbp
    unit_columns: [patients.age_years]          # internal unit view only
    dims: {sex: cat, site: cat}                 # groupable + filterable
    measures: [cost_gbp, minutes]               # aggregable
    internal_filters: {age_years: int}          # filterable, NEVER grouped or returned
    internal_measures: []                       # readable by fixed tools (corr) only
    glm_responses: {cost_gbp: [gaussian]}       # what a model may regress
```

A per-person rollup adds `group_by` and derived conditional aggregates:

```yaml
    group_by: [patients.patient_id, patients.sex]
    columns:
      - name: total_cost_gbp
        sum_if: {column: visits.cost_gbp, when: visits.visit_type,
                 in: [consultation, procedure]}
      - name: consults
        count_if: {column: visits.visit_type, equals: consultation}
```

### Internal range rules, and why they exist

A high-granularity variable such as exact age is a differencing channel the
moment it can cut *finer than the public dimension it backs*: sweeping
`age_years >= v` reconstructs an age histogram the catalogue publishes only as
bands, out of releases that are each legitimately large (hardening #39). So an
internal range variable may only be compared against the **declared band
edges**, and equality on the raw value is not offered at all:

```yaml
internal_range_rules:
  age_years:
    ops: [">=", "<="]
    edges: {">=": [18, 40, 65], "<=": [39, 64, 89]}
```

The `>=` edges are the bands' lower bounds and the `<=` edges their upper
bounds, so the two lists must be the same length and describe the same bands.
Lean proves the consequence over the whole spec space
(`internal_range_cuts_no_finer_than_bands`): no predicate a valid spec can
express separates two values inside one band, so every expressible cohort is a
union of whole bands whose marginals are already public. **If your study has a
fine-grained variable you want filterable but not publishable, this is the
mechanism** — and if you declare edges that do not line up with your bands, the
proof fails rather than the property silently weakening.

## The procedure

**1. Write the definition.** Copy the demo YAML and work through it. The
validator refuses a great deal at load, so iterate against it early:

```sh
uv run python -c "from safetre.dataset import load_dataset; load_dataset('study.yaml')"
```

It rejects a person key that is not a column of a base table or is not labelled
`DI`; a `DI` column exposed on a public view; a dim that is not in the view's
columns; a column reference naming a table that is neither the base nor joined;
a join key missing from either side; a table joined to itself or twice; a range
rule for a column that does not exist; and any identifier that is not a legal
bare name.

**2. Put the data in `data/`** — one CSV per base table, named exactly as the
tables are (`patients.csv`, `visits.csv`). There is no generator except for the
packaged demo, and the app refuses to start rather than guess: a study whose
CSVs are missing is a configuration error, not a reason to serve something else.

**3. Point the process at it.**

```sh
export SAFETRE_DATASET=/etc/safetre/study.yaml
```

Resolution is lazy and process-wide, so it must be set *before* anything
imports `safetre`. In the shipped unit it is an `Environment=` line.

**4. Regenerate the formal artifacts.** The Lean and Alloy models are generated
*from the active catalogue*, so with a new study the committed ones describe
the demo, not yours. Regenerate them or your proofs are about somebody else's
columns:

```sh
SAFETRE_DATASET=/etc/safetre/study.yaml uv run python scripts/gen_lean_catalogue.py --write
SAFETRE_DATASET=/etc/safetre/study.yaml uv run python scripts/gen_alloy_catalogue.py --write
```

**5. Run the suite**, which regenerates both in-memory and fails on drift, then
replay the proofs and the model checks as CI does (see
[formal/README.md](https://github.com/wadelab/safe-tre-agent/blob/main/formal/README.md)).

**6. Set the production environment**, none of which is dataset-specific but
all of which a real deployment needs: `SAFETRE_AUDIT_KEY` from an
`EnvironmentFile` (production refuses to start without it — hardening #65),
`SAFETRE_PROXY_SHARED_SECRET`, `SAFETRE_ALLOWLIST`, and
`SAFETRE_AUDIT_HEAD_ANCHOR`. `deploy/safetre-web.service` carries all four with
the reasoning.

## What is still demo-shaped, stated plainly

- **The synthetic generator.** `safetre/synth.py` produces the demo's tables
  and nothing else. Any other study supplies CSVs; there is deliberately no
  fallback, because inventing data for a study whose files are missing is the
  wrong answer to a configuration mistake.
- **The offline planner stub.** `MockLLM` writes demo-shaped pandas code. It
  feeds the legacy code-writing path that the red-team harness keeps as a
  counter-example, not the secure path, so it does not affect a real
  deployment — but `SAFETRE_LLM=mock` on another study will not produce
  sensible plans.
- **The demo's own numbers** quoted throughout the hardening log and decision
  records are measurements of the demo data. They are evidence about the
  controls, not about your study; the measurement scripts in `scripts/` re-run
  against whatever is active.
