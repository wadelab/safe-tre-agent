---
id: D6
title: An external checker is used by default when one is configured
date: 2026-07-26
status: accepted
question: >
  Should the shipped default vet with the prototype's own rules alone, or
  compose them with an external output checker?
clauses: [R5]
evidence:
  - artifacts/composite_cost.json
  - docs/acro-comparison.md
revisit_when: >
  The measured cost was 5% of gaussian model availability on synthetic data
  whose concentration was deliberately planted. Real data could be worse, and
  a deployment that finds the composite refusing analyses researchers need
  should re-run `scripts/measure_composite_cost.py` against its own data
  rather than assume these numbers transfer. Revisit also if a checker ever
  gains rules that are not monotone with ours — the whole argument rests on
  the union only ever suppressing more.
---

The claim this project makes is that automated output checking can be real
rather than a stand-in. Running the community's own implementation by default,
rather than as an opt-in nobody enables, is the strongest form of that claim
available — so the question was only ever what it costs and what "by default"
can honestly mean.

**What it costs, measured.** Over 4684 cells the union suppresses 23 more than
the stand-in alone. Of 102 available gaussian models, 5 stop being available.
Coefficients-only is unchanged at 42, which says the checker added no new
second-moment refusals at all: the five losses are mean cells, not the
dispersion cliff [D3](D3-second-moment-parameters.md) worried about. About 5%
of model availability, then, for the community's rules on every cell.

**What "by default" can mean.** Not "required". This is a library a TRE
embeds, and the checker cannot even be imported into the service environment —
so demanding one would make the software fail to start for everyone who has
not set it up, which is safe and useless. The default is therefore: **use an
external checker if one is configured, and not otherwise.** An operator who
wants it guaranteed names the vetter explicitly and gets a startup failure
when the command is missing.

**Why that is not a silent downgrade.** Because every release records which
rules decided it. `CellVetter.describe()` puts the vetter — and the checker's
reported version — in the pipeline trace, so a release reads
`gateway: redacted by standin+external(0.4.12)`, and one taken without a
checker says so. The rule this project holds to is not "a checker always ran";
it is "a release never implies checks that did not run". Recording satisfies
that; requiring would not have added to it.

The failure behaviour is unchanged and remains the strict one: once a checker
*is* configured, every way it can fail — exit, timeout, bad protocol, an
answer to the wrong request, a version that changes mid-session — denies. The
degradation is at startup, where an operator can see it, never mid-session
where a release might quietly claim more than it should.
