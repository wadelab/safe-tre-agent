# safe-tre-agent documentation

A safe-outputs gateway that lets an **AI analyst** answer questions over
sensitive behavioural data held in a **Trusted Research Environment (TRE)**,
without any row-level data leaving and without trusting the model with code.

The model is treated as adversarial. Its only power is to propose a validated,
declarative query; a deterministic engine runs it; a disclosure gateway checks
every output; and every request is written to a tamper-evident audit log.

## Start here

The **[research write-up](writeup.md)** is the canonical technical report: the
problem, the design, the red-team results, and the simulatable-auditing
argument. Everything else supports it.

### The research argument

| If you want to… | Read |
|---|---|
| Read the canonical technical report | [Write-up](writeup.md) |
| See what it must and must not do (normative) | [Specification](specification.md) |
| Understand the threat model and controls | [Security model](security.md) |
| Understand how the system is built | [Architecture](architecture.md) |
| Understand the physical deployment boundary | [Safepod model](safepod.md) |
| Understand local model assumptions | [Model runtime](model-runtime.md) |
| Understand the two-LLM tool contract | [Tool manifest](tool-manifest.md) |
| See how well local models actually plan | [Planner evaluation](planner-eval.md) |
| See what has been built, most recent first | [Progress](progress.md) |
| See what comes next, in order | [Roadmap](roadmap.md) |

### Using the prototype

| If you want to… | Read |
|---|---|
| Understand the project from scratch | [Beginner guide](beginner.md) |
| Install or run the project | [How to install](install.md) |
| Use the interface as a researcher | [User guide](userguide.md) |
| Rehearse a synthetic-data deployment | [Test deployment runbook](test-deployment.md) |
| Run it on a host / tailnet | [Deployment](deployment.md) |
| Certify it for real data (SATRE, ISO 27001, hardware) | [Certification & hardware](certification.md) |
| Work on the code | [Development](development.md) |

### Engineering record (appendices)

| If you want to… | Read |
|---|---|
| See what's been red-teamed and fixed | [Hardening log](hardening-log.md) |
| See the conformance review against TRE practice | [Best-practice review](best-practice-review.md) |
| See the round-2 hardening plan (done) | [Round 2 plan](round2-plan.md) |
| See the GOV.UK interface restyle plan | [GOV.UK UI plan](govuk-ui-plan.md) |
| See the formal-methods analysis | [Formal methods](FORMAL_METHODS_ANALYSIS.md) |
| See candidate verifiable extensions | [Verifiable extensions](verifiable-extensions.md) |

### Positioning

| If you want to… | Read |
|---|---|
| Position it for fellowship funding | [Fellowship positioning](fellowship.md) |

## The one-paragraph version

A researcher asks a question in natural language. An (untrusted) LLM turns it
into a **`QuerySpec`** — a JSON object describing an aggregate over an
allowlisted catalogue. Pydantic validates it; anything off-allowlist is rejected
before anything runs. A read-only **DuckDB** engine compiles the validated spec
into **parameterised** SQL over views that expose only non-identifying columns.
The result passes a **safe-outputs gateway** (minimum cell size, suppression,
egress checks), a **session auditor** (differencing, query budget), and a
**human-in-the-loop** policy, and the whole transaction is appended to a
**hash-chained audit log**. The web interface is served on `localhost` and
exposed to a tailnet via `tailscale serve`.

## Status

Phase 1 (secure web interface) is built and tested. The data is **synthetic**.
See [Security model § Limitations](security.md#limitations-and-roadmap) for what
is and isn't production-ready, and the [roadmap](roadmap.md) for what comes
next (ACRO integration first, then the formal model, then a DP accountant).

> **Built on:** OpenSAFELY (Bennett Institute, Oxford) for the code-to-data,
> outputs-checked TRE model; ACRO/SACRO (DARE UK) for statistical disclosure
> control; the Five Safes framework for governance.

![safe-tre-agent web interface](figures/web-ui-home.png)
