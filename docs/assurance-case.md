# Assurance case

The safety argument as a structure rather than a narrative: what is claimed,
how the claim decomposes, what each part rests on, and — the part usually left
out — **where the argument is not finished**.

This page is generated. The clauses, what enforces them, what checks them and
their status come from the [specification](specification.md)'s traceability
table; the open questions come from the [decision log](decision-log.md); the
assumptions come from the specification's trust model. If the code and its
tests move, this moves with them, which is the only way an argument like this
stays worth reading.

## The claim

> Under the stated assumptions, an untrusted language model placed between an
> analyst and sensitive data does not weaken the disclosure guarantee: nothing
> leaves the enclave that discloses an individual, and every release is
> explicable and reproducible from what was released.

It is a *conditional* claim. The assumptions below are not hedges, they are
the boundary — outside them nothing here is claimed at all.

## Context: what is assumed


- **A1** — The planner is untrusted. It may be prompt-injected by the data, buggy, or adversarial. No requirement depends on the planner behaving.
- **A2** — The data may be hostile. Any string field may carry an injection, SQL/DDL, tool-call spoof, or spreadsheet-formula payload.
- **A3** — The operator supplies the network boundary and an upstream identity proxy. The app enforces the restricted channel and reads the proxy's identity header; it does not itself authenticate users.
- **A4** — The audit HMAC key and the off-box chain anchor live outside the app host.
- **A5** — A real deployment runs a **local** model inside the safepod. A remote model endpoint is an egress channel and is permitted for synthetic data only, behind an explicit opt-in.
- **A6** — The data in this repository is synthetic.

## Strategy: decompose by the Five Safes

The claim is argued by the framework TRE accreditation already uses, so a
reader can check it against the thing they know. Each Safe carries the clauses
that serve it, each clause names what enforces it and what checks it, and a
clause whose status is *Partial* is shown as an **undeveloped goal** — a place
the argument is honest about being incomplete rather than quiet about it.


### Safe projects

*Claim: the request is one this data may be used for at all.*

| Clause | Enforced by | Checked by | |
|---|---|---|---|
| P1 no code/SQL execution | `query.py`, `service.py` | `test_secure.py` | ✓ |
| P2 no row-level output | `engine.py` (aggregate-only views) | `test_secure.py`, `test_invariants.py` | ✓ |
| P10 non-numeric refusals | `disclosure.py` (`SessionAuditor`) | `test_hardening.py` | ✓ |
| R1 | — | — | **unevidenced** |
| R12 | — | — | **unevidenced** |

### Safe people

*Claim: the person asking is entitled to ask.*

| Clause | Enforced by | Checked by | |
|---|---|---|---|
| P13 identity/channel coupling | `identity.py`, `channel.py` | `test_hardening.py`, `test_web.py` | ✓ |
| P14 channel + allowlist gate | `channel.py`, `identity.py`, `app.py` | `test_web.py`, `test_schema.py` | ✓ |
| R10 | — | — | **unevidenced** |

### Safe settings

*Claim: the enclave the analysis runs in does not leak.*

| Clause | Enforced by | Checked by | |
|---|---|---|---|
| P8 strict allowlist validation | `query.py` (`extra="forbid"`) | `test_secure.py`, `test_query_properties.py` | ✓ |
| P9 parameterised SQL only | `engine.py` (`_ident`, bound params) | `test_secure.py`, `test_query_properties.py`, Lean `P9` | ✓ |
| P12 safe marginals & schema | `engine.py`, `manifest.py`, `schema.py` | `test_schema.py`, `test_hardening.py` | ✓ |
| P15 tamper-evident audit | `audit.py` (HMAC chain) | `test_secure.py` | ✓ |
| P16 concurrency serialisation | `session.py`, `app.py` | `test_hardening.py`, Alloy `temporal_session` | ✓ |
| R3 | — | — | **unevidenced** |
| R8 | — | — | **unevidenced** |
| R13 | — | — | **unevidenced** |

### Safe data

*Claim: what the analysis can reach is already limited.*

| Clause | Enforced by | Checked by | |
|---|---|---|---|
| P3 no identifiers/free-text/timestamps | `query.py`, `engine.py` `_VIEWS` | `test_invariants.py`, `test_web.py`, Lean `P3` | ✓ |
| P4 internal variables never leave | `query.py`, `engine.py` | `test_secure.py`, Lean `P4` | ✓ |
| P5 minimum donor count | `disclosure.py`, `engine.py` (`n_donors`) | `test_secure.py`, `test_disclosure.py` | ✓ |
| P6 dominance / influence | `disclosure.py`, `engine.py` | `test_secure.py`, `test_disclosure.py` | ✓ |
| R2 | — | — | **unevidenced** |
| R9 | — | — | **unevidenced** |
| R14 procedure registry | `procedures.py` | `test_procedure_conformance.py` | ✓ |

### Safe outputs

*Claim: what leaves the enclave discloses nothing about anyone.*

| Clause | Enforced by | Checked by | |
|---|---|---|---|
| P7 fail closed on unresolved check | `engine.py`, `disclosure.py` | `test_hardening.py`, Alloy `temporal_session` | ✓ |
| P11 simulatable differencing | `disclosure.py`, `service.py` | `test_secure.py`, `test_hardening.py`, Alloy `disclosure_policy` | **undeveloped** |
| P17 budget short-circuit | `service.py`, `disclosure.py` | `test_hardening.py`, Alloy `temporal_session` | ✓ |
| P18 no table on denial | `_result.html`, `service.py` | `test_web.py` | ✓ |
| P19 deny on incomplete cell table | `service.py` (`_handle_model`), `procedures.py` (`optional_roles`) | `test_glm.py`, `test_glm_properties.py`, `test_second_moment.py`, red-team, Alloy `P19` | ✓ |
| P20 no per-observation model output | `glm.py` (output contract), `analyst.py` (intent) | `test_glm.py`, `test_procedure_conformance.py` | ✓ |
| P21 fitter noninterference | `stats.py`, `glm.py` (pure fit) | reproducibility meta-test (`test_glm_properties.py`), `test_glm_noninterference.py`, Alloy `P21` | ✓ |
| P22 refusals from released-equivalent data | `glm.py` (`preconditions`), `service.py` | `test_glm.py` (non-numeric, term-naming refusals) | ✓ |
| R4 | — | — | **unevidenced** |
| R5 complementary suppression | `disclosure.py` (`_secondary_suppress`, `_finalize`) | `test_disclosure.py`, `test_release_equality.py` | **undeveloped** |
| R6 | — | — | **unevidenced** |
| R7 | — | — | **unevidenced** |
| R11 | — | — | **unevidenced** |
| R15 GLM from vetted cells | `glm.py`, `stats.py`, `service.py` | `test_glm.py`, `test_formal_glm_enumeration.py`, `test_glm_oracle.py`, `test_second_moment.py` | ✓ |
| R16 skeleton export + model check | `procedures.py`, `formal/` | `test_skeleton_sync.py`, `test_formal_alloy_sync.py`, `test_formal_lean_sync.py`, CI `formal` job | ✓ |
| R17 literal spec entry | `service.py` (`_literal_spec`) | `test_literal_spec.py` | ✓ |

## Where the argument is unfinished

**Partial clauses** — discharged, but not completely:

- P11 — simulatable differencing (Partial (one-bit residual, N1))
- R5 — complementary suppression (Partial (single-dim exact, multi-dim conservative))

**Clauses with no recorded evidence** — the traceability table is scoped to the prohibitions, so these requirements are claimed but not cited. Each is enforced somewhere and tested somewhere; what is missing is the record saying where, which is what an assurance argument needs:

- R1, R2, R3, R4, R6, R7, R8, R9, R10, R11, R12, R13

**Open decisions** — questions with acceptance criteria and no answer yet:

- **[D4](decisions/D4-robust-dispersion.md)** Inference from a dispersion that cannot be released — A coefficient without a standard error is rarely publishable. Can inference — an interval, or even a significance class — be restored when the second-moment cell is too concentrated to release?

## How to read a gap

An undeveloped goal is not a defect report. It says the claim at that point
rests on something weaker than proof — a documented residual, a control that
is exact in one dimension and conservative in others, a question with an
answer that has not been measured yet. The value of drawing the argument this
way is that those places are visible at the same resolution as the parts that
are finished, instead of being a sentence in a document nobody reaches.

Three kinds appear above. A *partial clause* is one the specification itself
marks as incompletely discharged. An *unevidenced clause* is one the
traceability table does not reach — it is enforced and tested somewhere, but
the record saying where does not exist, and an argument may not cite evidence
it cannot point at. An *open decision* is a question recorded in the decision
log with no answer yet, carrying its own acceptance criteria for what would
close it.

## Adding to the argument

A new clause must be assigned to a Safe in `scripts/gen_assurance_case.py`,
and `tests/test_assurance_case.py` fails the build until it is. Then:

```sh
uv run python scripts/gen_assurance_case.py --write
```
