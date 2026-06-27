# Fellowship and research positioning

This page frames `safe-tre-agent` as a base project for a research fellowship
application, including the AI-safety fellows programme and adjacent AI safety /
secure research infrastructure calls.

## One-sentence project

Build and evaluate a safe-outputs gateway for AI-assisted analysis inside
Trusted Research Environments, where the model is useful for planning but never
trusted with raw data, code execution, SQL execution, or release authority.

## Why this matters

TREs already reduce harm from sensitive-data analysis by keeping data in a
controlled setting and releasing only checked outputs. AI agents change the
threat model:

- a model can be prompt-injected by row-level data;
- a model can attempt code or SQL that bypasses intended disclosure controls;
- a model can chain many apparently safe aggregate requests into a differencing
  attack;
- a model can create persuasive but unsafe outputs faster than human checkers can
  review them.

The project studies whether a deliberately narrow, formally inspectable
interface can keep the useful parts of AI assistance while preserving TRE
disclosure guarantees.

## Fit with AI-safety fellowship themes

The programme's [Fellows Program page](https://example.org/ai-safety-fellows-program/)
describes support for work on AI safety and alignment-relevant research. This
project is a concrete systems-safety case study: how to deploy capable models in
a high-stakes data setting while treating the model as untrusted infrastructure.

The work is not "make the model safe by prompting." The research claim is
stronger and more testable:

> Safety should come from deterministic boundaries, typed tool contracts,
> disclosure policy, auditability, and deployment controls, with the model
> confined to proposing actions that the safepod can independently validate.

Relevant fellowship outputs could include:

- a working open-source prototype;
- a red-team harness for agentic disclosure attacks;
- a formal model of the `QuerySpec -> engine -> disclosure -> audit` path;
- a lineage-aware auditor for multi-query differencing;
- a paper or technical report on AI agents inside TREs;
- deployment guidance for research infrastructure teams.

## Research questions

1. Can a small, typed query language preserve the useful planning role of an LLM
   while eliminating code and SQL execution from the model boundary?
2. Which disclosure attacks are specific to agentic workflows rather than normal
   human analyst workflows?
3. Can output-checking and session history be modeled as a finite-state safety
   system?
4. How should a safepod ration repeated queries: fixed budgets, lineage-aware
   disclosure budgets, or differential privacy budgets?
5. What does a credible audit trail look like when an AI planner is involved?

## Research dependencies and grounding

This project intentionally builds on existing research infrastructure rather
than inventing a new TRE model from scratch.

| Dependency | Role in this project |
|---|---|
| [OpenSAFELY documentation](https://docs.opensafely.org/) and the Bennett Institute/Oxford model | The code-to-data, outputs-checked TRE pattern: analysis runs near the data, and only approved outputs leave. |
| [Bennett Institute for Applied Data Science, University of Oxford](https://www.bennett.ox.ac.uk/) | Institutional and technical reference point for OpenSAFELY-style secure analytics at national scale. |
| [ACRO](https://github.com/AI-SDC/ACRO) | Target production-grade statistical disclosure control dependency; the current `safetre.disclosure` module is a lightweight stand-in. |
| [SACRO-ML](https://github.com/AI-SDC/SACRO-ML) | Reference point for safe release workflows around machine-learning outputs and TRE tooling. |
| [DARE UK](https://dareuk.org.uk/) | Broader UK programme context for trustworthy research environments and semi-automated output checking. |
| Five Safes framework | Governance model: Safe People, Safe Projects, Safe Settings, Safe Data, Safe Outputs. |
| Differential privacy / OpenDP-style accounting | Possible future release mode when a mathematically composable privacy budget is required. |
| Local OpenAI-compatible model runtimes | Deployment assumption for real data: model calls stay inside the safepod or fixed internal model host. |

## Current technical evidence

The prototype already demonstrates:

- strict `QuerySpec` validation with no extra fields;
- a finite public catalogue that omits direct identifiers, free text, raw
  timestamps, and high-granularity age fields;
- inspectable SQL plans over read-only DuckDB views;
- bound parameters for filter values;
- small-cell, dominance, count-rounding, and egress checks;
- per-session differencing and query-budget controls;
- HMAC-chained audit logs;
- a restricted-channel web deployment model;
- property-based tests over the finite query space;
- red-team scenarios showing row-level leaks with the gateway off and blocked
  outputs with the gateway on.

![Red-team summary](figures/redteam_results.png)

## Near-term fellowship work packages

### Work package 1: Lineage-aware disclosure auditing

Replace shallow total-based differencing with internal contributor-set lineage.
Each released aggregate gets an internal donor-set signature. The auditor blocks
small differences, intersections, and reconstructable suppressed cells.

Deliverables:

- bounded model-checking tests;
- lineage metadata in the engine/gateway;
- session auditor upgrade;
- red-team counterexamples before and after.

### Work package 2: Formal executable specification

Turn the finite `QuerySpec` and SQL-plan boundary into a machine-checkable
artifact.

Deliverables:

- generated finite catalogue model;
- Lean/Alloy/TLA+ model for selected invariants;
- CI check for proof/model artifacts;
- documentation mapping code to proof obligations.

### Work package 3: Real output-checking dependency

Replace the lightweight disclosure stand-in with ACRO-style output checking where
possible, while preserving the agent-specific session auditor.

Deliverables:

- ACRO integration design;
- comparison against current disclosure gateway;
- compatibility notes for TRE operators;
- tests for p%-dominance, secondary suppression, and model-output release.

### Work package 4: Deployment evidence

Package the prototype for repeatable synthetic-data test deployments and a
reviewed safepod path.

Deliverables:

- test-deployment runbook;
- screenshots and operator evidence bundle;
- systemd hardening review;
- audit anchoring plan;
- failure-mode table.

## What not to overclaim

This prototype does not prove that LLMs are safe analysts. It proves something
more modest and useful: an LLM can be placed behind a constrained, auditable,
non-authoritative boundary where deterministic code decides what runs and what
leaves.

It also does not yet provide differential privacy. Current controls are
statistical disclosure controls. A true epsilon budget would require randomized
mechanisms and a privacy accountant.

## Application summary paragraph

`safe-tre-agent` is an open-source research prototype for safely using AI agents
inside Trusted Research Environments. It treats the model as untrusted: the model
can only propose a typed aggregate query, while deterministic validation,
read-only execution, disclosure control, session auditing, and HMAC-chained logs
decide whether any output leaves the safepod. The fellowship work would turn
this prototype into a stronger research artifact by adding lineage-aware
multi-query disclosure auditing, formal verification of the query and SQL
boundary, integration with ACRO/OpenSAFELY-inspired output-checking practice, and
repeatable synthetic-data deployment evidence.
