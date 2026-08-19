---
id: D10
title: Authenticated release domains and deterministic accounting come before differential privacy
date: 2026-08-19
status: accepted
question: >
  In an answer-level TRE, should cumulative disclosure be controlled primarily
  by a public-query-style differential-privacy budget, or by the fact that the
  service is a restricted research environment with strongly identified,
  authorised users and custodian-defined release domains?
clauses: [R6, R10, P13]
evidence:
  - docs/specification.md
  - docs/answer-level-release.md
  - docs/verifiable-research-record.md
  - docs/vrr-critical-review.md
revisit_when: >
  Deterministic shared accounting has been implemented and attacked with the
  collusion corpus. Add a DP mechanism only where a measured residual cannot be
  bounded cleanly enough by deterministic release rules, identity-aware limits,
  memoisation and shared lineage, or where a quantitative privacy guarantee is
  itself the research objective.
---

**Status: accepted 2026-08-19 — design direction for the post-v1.0 phase.**

## The decision

The Safe TRE is not an anonymous public statistical API. Access is restricted to
identified, authorised people or service principals operating under an approved
project/purpose. The current system already assumes an upstream identity proxy
and requires the restricted channel and Safe People allowlist on every request
path.

The next phase therefore makes **authenticated access context plus a shared,
deterministic release ledger** the primary composition control. Differential
privacy remains an optional quantitative backstop, not the architectural centre
or an inevitable destination.

## Access context

Every analysis/release has an internal `AccessContext` containing at least:

```text
actor_id                 # stable authenticated principal
project_id               # approved research project/purpose
role                      # researcher/service/operator role
release_domain_id         # custodian-defined disclosure-accounting scope
authentication_issuer
policy_version
```

`actor_id` and detailed identity metadata are internal unless the release policy
explicitly makes them public. A VRR can normally state that the analysis was
**authorised under project X / release domain Y** without publishing an internal
login identifier.

Authentication is supplied by the TRE/upstream identity system. The research
core consumes the resulting principal; it should not grow its own password or
identity-provider implementation.

## Release domains, not sessions or usernames

A session remains useful for immediate lineage, rate limiting and concurrency,
but it is not a disclosure boundary. Logging out, opening a new session, using a
second approved account or collaborating with another researcher must not create
a fresh information budget where the releases concern the same protected
quantity/population.

The custodian therefore defines a `ReleaseDomain` for cumulative accounting.
Possible inputs include:

```text
data product / protected population
quantity or estimand family
approved project or purpose
policy epoch
```

The correct scope is policy-dependent. It may be broader than one project where
cross-project releases over the same population can compose.

The important invariant is:

> **A change of actor or session cannot, by itself, reset the disclosure state
> governing an equivalent protected release.**

## Three layers of limits

Use several reinforcing controls rather than pretending one counter solves the
problem.

### 1. Access/authorisation limits

- only approved principals can submit work;
- principals are bound to approved projects/purposes and datasets;
- service principals are explicit rather than anonymous shared identities;
- access revocation is enforced by the upstream TRE boundary.

### 2. Actor/project operational limits

- request/rate limits;
- finite outstanding analyses;
- per-project release quotas where useful;
- auditability and operator escalation;
- human governance consequences for deliberate misuse.

These reduce Sybil/probing capacity and make abuse attributable. They are not a
mathematical privacy proof.

### 3. Release-domain disclosure controls

- cell/output SDC;
- shared cohort/quantity lineage across actors and sessions;
- deterministic differencing rules;
- stable/reused answers where the **executed release semantics** are identical;
- finite release budgets where policy calls for them;
- data-dependent selection metering when a private choice itself creates a
  channel.

This is the layer that protects against an authorised insider or colluding
researchers. Identity strengthens it but does not replace it.

## Do not make natural-language equivalence load-bearing

Question canonicalisation is useful for user experience and exact-repeat
memoisation, but an LLM or heuristic deciding that two scientific questions are
"the same" is too fragile to be a disclosure control.

Safety accounting binds to the executed semantics instead:

```text
release_domain
population / cohort lineage
quantity / estimand identity
registered procedure / release class
public parameterisation relevant to the release
```

A `QuestionSpec` may help derive those objects, but a canonical question ID is
never the sole reason two releases do or do not compose.

## Where DP still belongs

Differential privacy is valuable when it buys a guarantee the deterministic
system cannot supply cleanly, for example:

- a genuinely high-volume adaptive aggregate interface;
- private-data-dependent selection that needs a quantitative bound;
- public statistics intended for broad repeated reuse;
- a residual composition class for which deterministic lineage becomes
  unmanageably conservative or incomplete.

In those modes, the DP accountant is itself part of the release-domain policy
and its events belong in the VRR. It does not need to be present for the first
answer-level or Verifiable Research Record implementation.

## What authenticated access does not solve

A valid credential does not make a researcher benign. Two valid researchers can
collude. A compromised account is still an attacker. A project may intentionally
probe its permitted data. The operator may also be dishonest, which remains
outside the current trust model.

So the claim is deliberately modest:

> **Strong identity and authorisation make the threat model more realistic,
> reduce cheap Sybil/probing attacks, support project limits and governance, and
> let disclosure state follow the real research context. The statistical
> release boundary must still be safe against an authorised adversarial user.**
