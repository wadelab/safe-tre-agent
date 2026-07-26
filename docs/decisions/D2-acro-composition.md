---
id: D2
title: Rule sets compose as a union, and the checker runs out of process
date: 2026-07-25
status: accepted
question: >
  When an external output checker is brought in, does it replace the
  prototype's disclosure rules, sit beside them, or sit under them — and where
  does it run?
clauses: [R5]
evidence:
  - docs/acro-comparison.md
  - docs/acro-integration.md
revisit_when: >
  The measurement stops holding. The union is justified by a specific finding
  — that neither rule set subsumes the other on this corpus — so a different
  checker, a different configuration of the same one, or a corpus that
  exercises the rules differently could change the answer. Re-run the
  comparison before assuming it still holds.
---

The obvious reading before measuring was that a production checker's rules
would *replace* the prototype's. The comparison says otherwise: over 337
comparable cells, ACRO's NK-rule suppresses concentrated pairs that the
single-contributor bound releases, and that bound suppresses single dominant
donors both of ACRO's default rules release. Neither is a superset.

**The decision.** Rules compose as a **union** — a cell is suppressed if any
vetter says so. The union is monotone, so adding a checker can only suppress
more, which means bringing one in cannot regress protection even if its rules
are wrong. Replacing rather than composing would have quietly *lost*
protection that had been measured.

**Where it runs.** Out of process, in its own pinned environment, because the
checker cannot be imported into the service environment at all. Every failure
— exit code, timeout, malformed answer, protocol mismatch, an answer that does
not cover the table — denies. There is deliberately no fallback to the
built-in rules: a release claims the checks that ran, and a checker that is
down is not a checker that approved.

**What it cost.** A second engine query per vetted table (only when a vetter
reads it), a process boundary to maintain, and over-suppression relative to
either rule set alone — the price of the monotonicity that makes it safe.
