# safe-tre-agent documentation

## What this is, simply

Hospitals, statistics agencies and universities hold data that are valuable
for research but too sensitive to hand out. The standard answer is a
**Trusted Research Environment (TRE)**: the data stay inside, researchers
send questions in, and only checked, aggregated answers come out.

This project asks what happens when an **AI helps with the asking** — and
builds the machinery that keeps the same guarantees when it does. The AI is
treated as untrusted: it never sees the raw data, never runs code or SQL,
and cannot release anything. All it may do is *propose* a query in a small,
fixed vocabulary. Ordinary, deterministic software then does everything that
matters: it validates the proposal against an allowlist, runs it read-only,
checks every number in the answer against statistical disclosure rules
(minimum group sizes, no dominant contributors, rounding, no
question-pairs that differ by one person), and writes the whole exchange to
a tamper-evident log. Nothing the checks did not pass ever reaches the
researcher.

Everything here runs on **synthetic data** — it is a research prototype,
not a production service. The plainest account of how it works is
[Explained simply](elif.md); the fastest way to see it is the
[five-minute demo](demo-5-minutes.md).

## Start here

The **[research write-up](writeup.md)** is the canonical technical report: the
problem, the design, the red-team results, and the simulatable-auditing
argument. Everything else supports it.

To see it run rather than read about it, take the **[public demo](public-demo.md)**
path: clone the repo, run the synthetic demo locally in five minutes, and check
what you see against the recorded screenshot tour and evidence checklist. No
hosted server is involved.

### The public demo

| If you want to… | Read |
|---|---|
| Understand the demo route and its scope | [Public demo](public-demo.md) |
| Run the synthetic demo locally, fast | [Demo in 5 minutes](demo-5-minutes.md) |
| See the five states that carry the argument | [Screenshot tour](screenshot-tour.md) |
| Record a run as citable evidence | [Evidence checklist](evidence-checklist.md) |

### The research argument

| If you want to… | Read |
|---|---|
| Read the plainest account of how it works | [Explained simply](elif.md) |
| Read the canonical technical report | [Write-up](writeup.md) |
| See what it must and must not do (normative) | [Specification](specification.md) |
| Understand the threat model and controls | [Security model](security.md) |
| Understand how the system is built | [Architecture](architecture.md) |
| Understand the physical deployment boundary | [Safepod model](safepod.md) |
| Understand local model assumptions | [Model runtime](model-runtime.md) |
| Understand the two-LLM tool contract | [Tool manifest](tool-manifest.md) |
| See how well local models actually plan | [Planner evaluation](planner-eval.md) |
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
| See the GOV.UK interface restyle record | [GOV.UK restyle record](govuk-ui-plan.md) |
| See the formal-methods analysis | [Formal methods](FORMAL_METHODS_ANALYSIS.md) |
| See candidate verifiable extensions | [Verifiable extensions](verifiable-extensions.md) |

### Positioning

| If you want to… | Read |
|---|---|
| Position it for fellowship funding | [Fellowship positioning](fellowship.md) |

## The one-paragraph technical version

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

Phase 1 (secure web interface) is built and tested. The data are **synthetic**.
See [Security model § Limitations](security.md#limitations-and-roadmap) for what
is and isn't production-ready, and the [roadmap](roadmap.md) for what comes
next (ACRO integration first, then the last slice of the formal model, then a
differential-privacy release mode).

> **Built on:** OpenSAFELY (Bennett Institute, Oxford) for the code-to-data,
> outputs-checked TRE model; ACRO/SACRO (DARE UK) for statistical disclosure
> control; the Five Safes framework for governance.

![safe-tre-agent web interface](figures/web-ui-home.png)
