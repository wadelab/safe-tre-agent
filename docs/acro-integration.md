# ACRO integration: the design

The second slice of [roadmap item 1](roadmap.md). The first slice measured
where ACRO's decisions and the stand-in's differ ([ACRO
comparison](acro-comparison.md)); this page fixed what to build from those
numbers, before any of it was built, so the decisions could be argued with
while they were still cheap.

*Most of it now exists.* The seam, the rules, the out-of-process boundary and
the configuration switch have all landed — see the rollout in §6 for what each
step delivered and what it cost. The default is still the stand-in's rules
alone; turning an external checker on is an operator's decision, and §3's
second-moment parameters are the part that remains theirs to set.

Two measurements from the first slice drive almost every choice below, and
both cut against the obvious implementation:

- **Neither dominance rule set subsumes the other.** ACRO's NK-rule suppresses
  a cell whose top two donors hold 90%, which the stand-in's
  single-contributor 50% bound releases; the 50% bound suppresses a cell with
  one donor at 62%, which both of ACRO's default rules release. Replacing the
  bespoke rule with ACRO's would *lose* protection.
- **The dominance bound bites far harder on the second moment than the
  first**, and the second moment is what gates model release
  ([verifiable-extensions §5.1](verifiable-extensions.md)). Whatever rules the
  cell layer applies, applying them unchanged to a `sum_sq` cell is a decision
  with a measured cost, not a default.

## 1. Where ACRO goes: the seam

Today `DisclosurePolicy.apply` does four separable things in one method: it
runs the per-cell rules (`leak_detector`), suppresses the failing cells, adds
complementary suppression, and finalizes (drops internal helpers, rounds
counts, orders rows). Only the first is ACRO's business.

The seam is therefore *inside* `apply`, not around it:

```
       cell table (exact values + internal witnesses)
                     |
   [ CellVetter ] ---+---> per-cell verdicts + findings      <- ACRO goes HERE
                     |
       primary suppression (drop failing cells)
                     |
       complementary suppression (margins)                    <- stays ours (C2)
                     |
       finalize: drop helpers, round counts, order rows       <- stays ours (#27, #28)
                     |
       postprocess: released-value shaping                    <- stays ours
```

`CellVetter` is the new protocol: given a cell table and the policy
parameters, return a verdict per cell and the findings that explain it. Three
implementations are wanted from the start — the stand-in's rules, ACRO's, and
a **composite** that runs both and suppresses a cell if *either* does. The
composite is not a transitional device; §2 says it is the intended
end state.

Everything below the vetter stays exactly where it is. That is not
conservatism: the release-equality property proved in this round
(`tests/test_release_equality.py`) is a statement about the composition
`release = postprocess ∘ finalize ∘ vet`, and it holds however `vet` decides,
provided `vet` only ever *decides* and never computes released values. Putting
ACRO inside `vet` keeps that proof intact and keeps hardening #27 and #28 —
which live in `finalize` — out of a third party's hands.

Above the seam, the agent-specific layer is untouched: session lineage, the
differencing bound, the query budget, the audit chain and the human-in-the-loop
step have no ACRO analogue and sit where they are.

## 2. Rule composition: what runs, and why nothing can be dropped

| rule | stand-in | ACRO | after integration |
|---|---|---|---|
| frequency threshold | on distinct donors (`n_donors`) | on rows, fed one row per donor | ACRO's, on the donor frame |
| dominance — single contributor > 50% | yes | no | **kept** (measured: ACRO releases cells this catches) |
| dominance — p%-rule, NK-rule | no | yes | **added** (measured: catches cells the 50% bound releases) |
| complementary suppression | yes | no (C2) | **kept**, on top of both |
| missing/negative value checks | no | yes | added |
| class disclosure | no | yes | added |
| residual dof floor | via the donor threshold | `safe_dof_threshold` | adopt ACRO's for model cells (best-practice D4) |

The composite's rule is the union: **a cell is suppressed if any vetter
suppresses it.** This is the only composition the measurements support, and it
is monotone — adding a rule can never release a cell that was suppressed
before, so the integration cannot regress protection by construction.

The cost is over-suppression relative to either alone, and the honest way to
report it is the comparison harness itself: after integration it stops being a
research instrument and becomes a regression test that says how much each rule
set contributes.

## 3. The decision this round forced: the second-moment cell

A gaussian model is refused if either its mean cells or its `sum_sq` cells are
suppressed, and the dominance bound is far tighter on the squared scale — a
donor at 19% of a twenty-donor cell already holds half its sum of squares.
Measured, the current 50% bound on `sum_sq` alone costs 43% of the otherwise
available gaussian models. Adding ACRO's NK-rule to that cell on the same
parameters would cost substantially more, and nobody has decided that it
should.

Three options:

1. **Same rules, same parameters, both moments.** Simplest to explain and to
   certify; strictly the safest; likely leaves gaussian models rarely
   available on realistic (heavy-tailed) data.
2. **ACRO's rules on the first moment, the existing bound on the second.**
   Keeps today's model availability exactly, at the cost of a rule set that
   differs by disclosure class — harder to explain to an output checker.
3. **Parameterise by disclosure class.** The output contract (R14) already
   labels every released column `cell_key` / `count` / `magnitude` /
   `statistic` / `p_value`. Dominance parameters become a function of that
   label, so "the second moment is checked at *k* = 0.95" is a stated policy
   rather than an accident.

**Recommendation: option 3**, with option 1's parameters as the default and
the second-moment relaxation stated explicitly in the specification. It costs
one indirection, it makes the choice visible to a certifier instead of buried,
and it is the only option under which the answer can be *changed* by a TRE
operator without editing the vetting code. The measured availability cost of
each setting should ship with it — `scripts/measure_dispersion_sensitivity.py`
already produces exactly that number.

**Decided 2026-07-26: options 3 and 4, together.** They are complements, not
alternatives — one makes the rule sayable, the other makes its cost bearable.

*Option 3, as built.* `sum_sq` no longer labels its value `magnitude`; R14
gained a `moment2` class, because the vocabulary could not previously express
the distinction the rule turns on. `VettingParameters.dominance_for` selects
the bound by that class, and `PolicyConfig.moment2_dom_threshold` (unset by
default, so nothing changes) is where an operator states it. What a stated
bound *means* is now something they can reason about: a bound *s* on the
squared share corresponds to a linear-scale share of *p* = *r*/(1+*r*) with
*r* = √(*s*/((1−*s*)(*k*−1))), so `moment2: 0.8` says "one donor may hold
about a third of a twenty-donor cell, or a fifth of a fifty-donor one".

| squared bound | *k* = 20 | *k* = 50 |
|---|---|---|
| 0.5 (the default, unchanged) | 0.19 | 0.13 |
| 0.8 | 0.31 | 0.22 |
| 0.9 | 0.41 | 0.30 |

*Option 4, as built.* A gaussian model's `sum_sq` tables are declared
**optional** (`ModelProcedure.optional_roles`). If the gateway cannot release
them completely, the fit proceeds from the vetted mean cells alone and the
release carries coefficients with no standard error, t, p or R²; the model
block records `dispersion_released: False` and the analyst gets a finding
saying so. Nothing derived from the withheld table leaves, the released cell
table has no `sum_sq` column at all, and P21 still holds — `refit_from_artifact`
reproduces the degraded release bit-for-bit from what was released. An
optional table is used only if it releases *completely*: a partly-suppressed
one would silently change the number it feeds. This is confined to the
gaussian dispersion — binomial and poisson cannot be fitted without their
tables, and ANOVA *is* a variance decomposition, so both still refuse.

Measured on the demo dataset, gaussian skeleton points now split 47 full fits
/ 36 coefficients-only / 456 refused, against 47 / 0 / 492 before: exactly the
36 that the dispersion cell alone was refusing.

**Not done, and deliberately:** significance stars from a withheld dispersion.
A star is a function of the standard error, so computing one from a suppressed
`sum_sq` would release a coarsened function of an unvetted cell — breaking the
invariant that everything released is a function of vetted cells (P21,
release-equality), and leaking weakly, since β and *n* are released and a star
bounds the SE, which bounds Σx², which bounds the dominant donor. The version
that would work is a **robust dispersion** — winsorise or trim the top
contributor so the cell is not dominated by construction, vet *that*, and
derive inference from it. It is a statistical question rather than an
engineering one (a winsorised SE is optimistic unless corrected, which is the
wrong direction for a disclosure tool) and is left open.

## 4. The process boundary

ACRO 0.4.x pins `pandas < 3` and the runtime uses pandas 3 (C3), so ACRO
cannot be imported into the service at all. Rather than vendor its checks —
which would fork code we do not maintain and quietly lose upstream fixes —
run it **out of process**, and treat that as the design rather than the
workaround:

- ACRO lives in its own environment, pinned independently of the service
  (`[tool.uv] conflicts` already models this for the comparison harness).
- **The checker is started once and stays up**, taking one request per line
  and answering one per line. A process per vetted table cost a second or two
  of interpreter and import time each — enough that an external checker could
  not sensibly be anyone's default. Measured on the demo dataset: 0.82s for
  the first query, 0.03s for each after it.
- Every request carries an id the response must echo, because a reused pipe
  can desynchronise: a late answer to an abandoned request would otherwise be
  read as the answer to the next one, and a cell would be vetted against
  verdicts computed for a different table. Any timeout or protocol error
  discards the process rather than reusing it in a state nobody can
  characterise, and a checker whose reported version changes mid-session
  denies — a release must not claim checks from a version that did not run
  them.
- The service sends a cell table and the policy parameters; the checker
  returns per-cell verdicts and rule names. The payload is aggregate cells and
  a donor-level contribution frame — data that have not yet passed the gateway,
  so the boundary is *inside* the safepod and crosses no trust boundary.
- **Fail closed, loudly.** A non-zero exit, a timeout, a malformed response or
  a version mismatch suppresses everything and denies the request. There is no
  "ACRO unavailable, fall back to the stand-in" path: silently applying
  different rules from the ones the release claims is precisely the failure
  mode the project refuses elsewhere.
- The checker's version and parameter set are recorded per release in the
  audit chain. "Which rules did this output pass?" is an output-checker
  question, and a TRE has to be able to answer it a year later.

This also has a governance benefit worth naming: a TRE can upgrade or pin its
output checker independently of the agent, which is what an operator running
accredited software will want anyway.

## 5. Compatibility shims, and how they leave

- **C1 — the `crosstab` crash on zero/empty categories.** The harness drives
  `create_crosstab_masks` directly because 0.4.12's `crosstab` raises on
  planted zero-sum cells. The integration inherits that shim. Its removal
  condition is explicit: when a release containing the upstream fix (their PR
  #347, on main and unreleased at the time of writing) is pinned, the shim
  goes and the checker calls the public API. Until then the shim is documented
  where it is used, not just here.
- **C3 — the pandas pin.** Removal condition: ACRO supports pandas 3 *and*
  there is a reason to bring it in-process. Note that §4 argues the out-of-process
  boundary is worth keeping on its own merits, so this shim may outlive its
  cause.

## 6. Rollout

1. ~~Extract `CellVetter` and move the existing rules behind it, with no
   behaviour change.~~ **Delivered 2026-07-25.** `CellVetter`,
   `StandinVetter` and `CompositeVetter` live in `disclosure.py`;
   `DisclosurePolicy` carries a `vetter` field and reads its thresholds at
   call time, so a policy built from `config.yaml` cannot vet on stale ones.
   Behaviour preservation was checked directly rather than inferred: the
   pre-seam `apply` was run beside the new one over all 2622 skeleton points,
   and the action, the released frame and the finding sequence were identical
   on every one. `tests/test_cell_vetter.py` pins the seam's two properties —
   the stand-in vetter suppresses exactly what the old filtering dropped, and
   composition is a monotone union.
2. ~~Add the ACRO vetter and the composite, defaulted **off**.~~ **Rules
   delivered 2026-07-25; the boundary is not.** `redteam/acro_vetter.py`
   wraps ACRO's real check implementations in the seam, and the comparison
   harness drives its ACRO side through it — reproducing the published
   numbers exactly (337 cells, 6 `acro_stricter`, 21 `standin_stricter`),
   which is the regression that says the rule mapping is faithful. It lives
   in `redteam/` rather than `safetre/` on purpose: ACRO cannot be imported
   into the service environment at all (C3), so the production path is the
   §4 boundary calling this logic out of process, and **that boundary is
   what remains of this step**. Two limits are recorded in the module: ACRO
   decides with its own configuration rather than ours (§3 is not done), and
   it never denies a whole table — egress checks stay the stand-in's.
   `tests/test_acro_vetter.py` covers the mapping, the rule attribution and
   the fail-closed treatment of a cell ACRO returned no verdict for, without
   needing ACRO installed.

   **The boundary followed the same day.** `redteam/acro_checker.py` is the
   checker process — it reads one request on stdin, calls the same rule
   implementation, and writes one response, printing nothing else to stdout so
   a stray `print` cannot corrupt the contract. `redteam/acro_boundary.py`
   holds the versioned JSON contract and the client, which imports nothing
   from ACRO and is therefore constructible in the service environment. Every
   failure denies: non-zero exit, crash, timeout, unstartable command,
   malformed or non-JSON response, protocol mismatch, a reported error, and a
   verdict list that does not cover the table — each is a case in
   `tests/test_acro_boundary.py`, driven by fake checkers so the suite needs
   neither ACRO nor its environment. The checker's reported version is kept
   for the release to record.

   Cross-environment operation is proved where it can be: every comparison run
   now calls the real checker through `uv run --no-default-groups --group
   acro` and requires the out-of-process verdicts to equal the in-process
   ones, failing the harness if they ever diverge. Otherwise the numbers this
   project publishes would describe rules the gateway does not apply.

   What is left before a TRE could switch this on: the engine must be able to
   produce the donor-level contribution frame per spec (it is not derivable
   from a cell table, which is why both vetters take it by construction), the
   client needs a home in `safetre/` once something there calls it, and the
   choice needs a configuration switch. Those are steps 3–5.
3. ~~Run both in shadow.~~ **Delivered.** The comparison harness runs in CI on
   every push (`acro-compare`), and now also verifies the real
   out-of-process checker against the in-process rules on each run.
4. **Switchable, not switched.** `PolicyConfig.vetter` selects `standin` (the
   default) or `standin+external`, and `checker_cmd` says how to start the
   checker; asking for an external checker without a command fails at startup
   rather than at the first query. End to end on the demo dataset, `sum` by
   region releases nine regions under the stand-in alone and eight with ACRO
   composed in — Wales, the NK-rule cell, is the difference, exactly as the
   comparison predicted. **What is not decided is §3**: the second-moment
   parameters. That needs an operator's judgement against the availability
   cost, and turning ACRO on for models before deciding it would refuse far
   more than anyone has agreed to.
5. Rewrite the preprint's gateway section once the default flips. It now
   describes the stand-in, the measured comparison and the seam, which is
   what is true today.

### What wiring it up cost, and what it caught

Two defects surfaced only when the whole thing ran end to end, and both would
have been invisible to unit tests of the pieces:

- **A configured vetter has no query in it.** A vetter built at startup and
  reused knows nothing about the table in front of it, so an external checker
  given only a cell frame vetted every table as a single `total` cell and
  released everything. Cell keys and the aggregation now travel with the
  contributions in a `CellContext` — a `mean` cell and a `sum` cell over the
  same contributions are different tables, and a checker told the wrong one
  checks the wrong numbers.
- **Suppressability was a list of the stand-in's own rule names.** The
  human-in-the-loop step escalates whatever the gateway did not resolve by
  suppression, and it recognised that set by name — so ACRO's findings, which
  *had* been resolved by suppressing their cells, read as unresolved
  residuals and denied every query they touched. A finding now declares
  whether suppression resolves it, which is a property of the finding rather
  than of a hard-coded vocabulary the next vetter would also have missed.

## 7. Open questions

- **Does ACRO's threshold count what we think?** The harness feeds one row per
  donor so ACRO's frequency check counts donors. That is the right protection
  unit (P5, best-practice D4), but it makes ACRO's *values* means of donor
  means. For vetting this is immaterial; if ACRO's output tables are ever
  surfaced rather than just its verdicts, it stops being immaterial.
- **Class disclosure and missing-value checks are new rules**, not
  replacements. They have no stand-in analogue and no measurement yet; they
  should be measured on the corpus before they are switched on, the same way
  dominance was.
- **Does the composite need a rule-attribution channel?** A suppressed cell
  currently yields a finding naming the rule. With three rule sets the finding
  should name which one fired — useful to an operator, but it is also a
  slightly finer signal about the data than the current message. It needs the
  same simulatability argument the auditor's refusals got.
