# Public demo

This repository is the demo. There is no hosted server to visit: you clone the
repo, run it on synthetic data, and compare what you see against the recorded
evidence in these pages. A reviewer should get from `git clone` to understanding
the safety pipeline in under fifteen minutes, and should be able to check every
claim without asking anyone for access.

!!! note "Scope"
    Everything here runs on **synthetic data only**. These pages are a
    demonstration artifact, not a deployment guide: running the prototype on
    real data requires a [safepod](safepod.md) deployment with the physical,
    identity and channel controls in the [security model](security.md) and
    [deployment](deployment.md) pages. Remote model endpoints are
    synthetic-data-only, because a remote API is itself an egress channel.

## The path

1. **[Demo in 5 minutes](demo-5-minutes.md)** — clone, generate synthetic
   data, run the web app locally, and smoke-test the three public endpoints.
2. **[Screenshot tour](screenshot-tour.md)** — the five states that carry the
   safety argument (home, released, redacted, denied, audit verify), each with
   what to look for and the exact query that produces it.
3. **[Evidence checklist](evidence-checklist.md)** — what to record so a demo
   run becomes citable evidence: commit, lock hash, check results, red-team
   summary, audit verification.

## What you can check without running anything

The claims are enforced in CI on every push, so the repo state itself is
evidence:

- the test suite, SAST and dependency audit (`.github/workflows/ci.yml`);
- the red-team replay — the run fails CI if any attack leaks
  ([hardening log](hardening-log.md));
- a bounded model check of the prohibition clauses in Alloy
  ([formal methods](FORMAL_METHODS_ANALYSIS.md));
- this documentation, built `--strict` so broken links fail the build.

## Where the argument lives

The demo shows the pipeline working; the reasoning behind it is written up
separately. The [research write-up](writeup.md) is the canonical report, the
[specification](specification.md) states what the system must and must not do
as testable clauses, and the [security model](security.md) explains the threat
model the demo states illustrate.
