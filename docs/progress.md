# Progress

What has been built, most recent first. This is the backward-looking record;
the [roadmap](roadmap.md) is the forward plan, and the
[hardening log](hardening-log.md) has the red-team detail.

## July 2026

**Consolidated preprint.** A technical report (`paper/preprint.tex`) draws the
design, the specification, the red-team results and the planner evaluation
into one external-facing document. Builds with `make`; distributed via
releases.

**Planner-quality evaluation.** A scored corpus (`evals/corpus.yaml`) and
harness measure how well a planner turns requests into correct QuerySpecs
([planner evaluation](planner-eval.md)). First numbers: the local model plans
usefully (67% of proposals acceptable) but rarely refuses an unanswerable
request — evidence that refusal must come from the boundary, not the model.

**CI hardening.** The red-team suite (now exits nonzero on any failure), a
strict docs build, and pa11y accessibility checks against the four demo states
now run in continuous integration alongside the tests, SAST and dependency
audit.

**GOV.UK interface.** The web UI was restyled to the
[GOV.UK Design System](https://design-system.service.gov.uk/), unbranded (no
GDS Transport, no crown), and is WCAG 2.2 AA (pa11y reports no issues on home,
released, redacted and denied states). The gateway pipeline is now a
step-by-step list whose stage status is text, never colour alone; results are
notification banners and an error summary; the dark console theme was retired.
See the [GOV.UK UI plan](govuk-ui-plan.md).

**Safe schema disclosure.** A `GET /api/schema` data dictionary publishes the
study codebook — column roles, descriptions and declared value domains — as
design-time metadata only. Building it closed a real leak: the marginals
endpoint had published sub-threshold category *names* (including hostile
strings smuggled into fields), so published tables now drop any value outside
its declared domain rather than only nulling its count.

**Normative specification.** [`docs/specification.md`](specification.md) states
13 requirements and 18 prohibitions as testable clauses, with a traceability
table from each prohibition to the code that enforces it and the test that
checks it. It is the source of truth the formal-methods work will discharge; an
exhaustive enumeration of the query skeleton already machine-checks several
clauses.

**Comprehensive UK dataset.** The synthetic generator now models a plausible UK
loot-box study — all 12 ITL1 regions, a named app catalogue, a latent per-donor
propensity so the invited analyses find real effects — with disclosure anchors
(Northern Ireland, sex X) pinned below the threshold so suppression and
differencing demos hold across seeds.

**Round-3 hardening.** The stateful controls around the QuerySpec boundary were
hardened after an external red-team: a concurrency race on the session
controls, an inert policy config, fail-open suppression, identity/channel
coupling, and non-simulatable refusals. See the
[hardening log](hardening-log.md).

## Earlier

The [round 2 plan](round2-plan.md) records the differencing lineage auditor,
complementary suppression and the SSRF/egress lockdown; the
[hardening log](hardening-log.md) covers rounds 1–2. The
[research write-up](writeup.md) remains the canonical account of the design.
