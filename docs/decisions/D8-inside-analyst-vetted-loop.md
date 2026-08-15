---
id: D8
title: The inside analyst starts as a vetted loop, on the public side of the gateway
date: 2026-08-15
status: accepted
question: >
  The next research phase moves the automated component from formatting one
  request at a time to answering a research question end to end. Where should
  the analyst's inputs come from — the released side of the gateway, or the
  raw side with new controls — and what must its output be so that the
  existing disclosure argument is inherited rather than re-argued?
clauses: [R19, P23]
evidence:
  - safetre/inside_analyst.py
  - tests/test_inside_analyst.py
  - tests/test_inside_analyst_redteam.py
  - redteam/analyst_attacks.yaml
  - docs/inside-analyst.md
  - docs/planner-eval.md
revisit_when: >
  Phase 3 of docs/inside-analyst.md — the data-sighted tier, where the analyst
  sees unvetted intermediates — needs its own clauses (a locked, audit-committed
  plan; adaptivity metered by the DP accountant), because there selection is a
  channel and P23 as written cannot hold. Revisit also if the question bank
  shows the vetted loop cannot reach the truths the NIGHTPLAY study plants
  through released aggregates alone, which would be the argument for that tier.
---

**Status: accepted 2026-08-15 — the vetted loop, released side only (R19, P23).**

## The decision, stated once

The phase-1 analyst is a loop whose every step is an ordinary request through
`QueryService.handle` — a natural-language sub-question with the spec the
analyst proposes for it — under **one** session auditor for the whole
question, and whose policy (model or script) is shown **only what a human user
of that session would be shown**: status, canonical message, numberless
findings, released frames, the question, the remaining budget. Its output is
a typed dossier: claims with verdicts from a closed vocabulary, each citing
released steps; a claim about the data that cites none is downgraded to
`not_answerable`. The narrator writes from the dossier alone, and any figure
in its prose that no released table supports is recorded as unsupported.

## Why this and not the other thing

The question "can an LLM work inside the TRE?" decomposes on one distinction:
which side of the gateway the model's inputs come from. An analyst that reads
only released results is, informationally, where the human stands; its
adaptivity is bounded by the same budget and lineage (P11, P16, P17), and the
disclosure claim — released output is a function of vetted cells (P19–P22,
R15) — is inherited without a new argument. This is most of the value of an
analyst (multi-query, multi-source, follow-ups, honest refusals) and none of
the new risk.

The alternative — let the analyst see raw residuals, diagnostics, exploratory
looks — raises a genuinely hard problem: an adversarial or hijacked analyst
can encode private bits in its *choices* (which of seven analyses to report,
which cohort to compare), and the same mechanism done innocently is p-hacking
at machine speed. The answer to both is a plan locked and audit-committed
before the data are touched, with adaptivity metered by the DP accountant.
That is a research programme, not a phase-1 build, and it gets no clause here
because it is not built.

Two facts made the typed dossier a requirement rather than a nicety. First,
the planner evaluation's second measurement: both a remote planner and a
120B-class local stand-in **deflect** — asked for something forbidden they
propose a valid, safe, different question. An analyst assembling many answers
into one would launder that into a confident dossier unless refusal is a
first-class, typed outcome. Second, the red team's `fabricated_conclusion`
scenario: a model can simply assert claims citing steps that were denied or
never happened; grounding claims in released steps is what makes the dossier a
record of evidence rather than an opinion with footnotes.

## What the loop taught, on day one

- **The lineage binds across steps.** Asking the marginal by night-use band
  and then the model excluding a sub-threshold employment group is a
  differencing pair by the published-marginal bound, and the second step is
  denied inside the loop; model-first with a consistent exclusion releases
  both. The analyst lives in a human's lineage, and ordering matters to it as
  it would to a human — a fact the red-team corpus now states in a comment.
- **The known-open cross-view pair (#95) reproduces on the second study by
  construction**, because the NIGHTPLAY panel's monthly stake is the sum of
  its transaction-level stakes and the lineage is keyed on the dataset name.
  The red team carries it as `known_open` and fails if it ever *stops*
  reproducing unaudited (roadmap 0.2).
- **The narrative check earns its place.** On the first live run the model
  narrator wrote "n = 72 000" with a thin space; the check flagged "72" until
  it learned space-grouped thousands. Every other figure traced.

## What it does not decide

Nothing about the data-sighted tier, time-series procedures, or FHE. Nothing
about which model plays the analyst — the loop takes any `complete(system,
user)` client, and the first measurement used the same 120B-class open-weight
stand-in the planner evaluation did.
