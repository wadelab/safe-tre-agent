# Best-practice review: deviations and recommendations

This review compares safe-tre-agent against published best practice in three
fields it straddles: statistical disclosure control (SDC) for trusted research
environments, the security of LLM agents against prompt injection, and the
theory of query auditing and differential privacy. It records where the
prototype already follows best practice, where it departs from it, and what to
change. Sources are listed at the end; every claim below cites one.

The method was a literature search (July 2026) across the ACRO/SACRO tooling and
the SDC Handbook, the OpenSAFELY and Five Safes governance guidance, the OWASP
LLM Top 10 (2025) and the recent design-patterns work on securing LLM agents,
and the query-auditing and differential-privacy literature. Findings were then
mapped onto the code.

## Summary

The architecture is sound and, in one respect, ahead of the field: treating the
model as untrusted and letting it emit only a validated `QuerySpec` is a
published secure-agent pattern, not an ad-hoc choice. The gaps are in the
disclosure layer, where several controls are simpler than the ACRO reference
they intend to become, and in the session auditor, whose design has a known
theoretical weakness. None of the gaps is a working-tree bug; they are places
where a production system on real data would need to change.

**Update (2026-07-04).** D4 and D1 are implemented (hardening
[round 2h](hardening-log.md)): the frequency threshold now counts distinct
donors, not rows, and the differencing auditor now decides from published donor
marginals rather than the live donor sets (simulatable auditing). D7 is
reassessed below — the prototype is already stricter than the OpenSAFELY rule it
was measured against. D5 and D6 are addressed as documentation and configuration
below. D3 (dominance parameterisation) is now *measured* against ACRO's own
rules and stays open, with a corrected reading — neither rule set subsumes the
other; D2 (a DP accountant) remains planned.

| # | Deviation | Field | Severity | Recommendation |
|---|-----------|-------|----------|----------------|
| D1 | Auditor decides denials from the real data, so a refusal can itself leak | Auditing theory | Medium | Make the auditor *simulatable* — decide from queries and public metadata, not realised donor sets |
| D2 | Per-session, ad-hoc differencing control; no cumulative bound or cross-user budget | DP theory | High (for real data) | A differential-privacy accountant with global budget; state the limit until then |
| D3 | Dominance uses a single-contributor 50% rule, not the standard (n,k)/p% rules | SDC | Medium | Adopt configurable (n,k) and p% rules to match ACRO |
| D4 | No residual-degrees-of-freedom floor for `corr`/future regression; event-level `corr` counts events, not donors | SDC | Medium | Add a distinct-donor floor (ACRO `safe_dof_threshold = 10`); count donors, not rows |
| D5 | One automated gateway where the standard is two human output checkers | Governance | Medium | Position the gateway as a pre-filter; keep two-human review on real releases |
| D6 | The correlation influence control is bespoke and its threshold is unvalidated | SDC | Low | Validate 0.5 against ACRO behaviour; keep it as a complement to D4, not a substitute |
| D7 | Rounding to base 5 after suppressing n<10 permits narrow inference | SDC | Low | Follow OpenSAFELY: redact counts ≤7, then round to 5 |

## Where the prototype already follows best practice

**The untrusted-model boundary is a named, published pattern.** Beurer-Kellner
et al. (2025) catalogue six design patterns for securing LLM agents against
prompt injection. The first, the Action-Selector pattern, is "an LLM-modulated
switch statement" in which the model maps a request onto predefined actions and
"any feedback from these actions" cannot influence what runs; the authors call
this strong immunity to prompt injection. The planner here is exactly that: it
emits a `QuerySpec` chosen from a fixed catalogue, never sees tool output fed
back as instructions, and cannot name anything off the allowlist. The real-model
red-team (round 2e) is the empirical check — 22 adversarial requests through a
live model, no disclosure. The prototype implements a documented pattern rather
than trusting the model to behave.

**The security posture matches the OWASP LLM guidance.** OWASP's 2025 Top 10
keeps prompt injection at number one and recommends defence-in-depth,
least-privilege tooling, treating model output as untrusted input, human
approval for high-risk actions, and regular adversarial testing. The prototype
does each: validation plus gateway plus auditor, a read-only engine, output
disclosure checks, human escalation on medium findings, and a standing red-team.

**The core SDC rules are the right ones.** The threshold, (n,k)/p% dominance,
secondary suppression, and rounding controls in `disclosure.py` mirror the ACRO
check set and the SDC Handbook. The frequency threshold of 10 is at or above the
handbook's 3–5 and OpenSAFELY's redact-≤7, so it is conservative rather than
lax.

**The governance framing is honest.** The system is synthetic-only, maps its
layers onto the Five Safes, keeps an HMAC-chained audit log, and states its
limits plainly. Honesty about what a control does not do is itself best practice
in this field.

## Deviations and recommendations

### D1 — The auditor is not simulatable

The session auditor decides whether to release a query by computing the true
symmetric difference of two cohorts' donor sets on the real data
(`engine.cohort_symdiff`). Kenthapadi, Mishra and Nissim (2005) showed that an
auditor whose allow/deny decision depends on the private answers can leak
through the decisions themselves: a refusal tells the analyst that the two
cohorts differ by fewer than the threshold, which is information about the data.
Their fix is *simulatable* auditing, where the decision depends only on the
queries and public parameters, so the analyst learns nothing from a refusal that
they could not have computed alone.

Recommendation: base the lineage decision on public structure — the normalised
filter predicates and catalogue-level cardinalities — rather than the realised
donor sets, or randomise the threshold. This weakens the check slightly and is
subsumed by D2's differential-privacy route, which is simulatable by
construction.

**Status: implemented (round 2h).** The auditor now decides from a published
donor-frequency table (`engine.marginal_donor_counts`) via a pure bound function
(`disclosure.simulatable_cohort_bound`); the service no longer calls the live
`cohort_symdiff` on the decision path. For two cohorts differing on one
dimension, the whole-population marginal of the differing values is an upper
bound on the symmetric difference, so a denial is sound and the refusal is
reproducible from public metadata. The trade-off, stated in the code: this
version can miss differencing that isolates a small group through the
interaction of a common category with an otherwise-narrow cohort. That residual
is largely covered by D4 (a narrow cohort's cells are suppressed for having too
few donors) and fully by D2. Removing the refusal leak is the point; full
coverage is DP's job.

### D2 — Ad-hoc auditing cannot bound cumulative disclosure

The auditor is per-session and heuristic. Two results bound what that can
achieve. Dinur and Nissim (2003) showed that enough accurate answers to counting
queries reconstruct the data — the Fundamental Law of Information Recovery — and
online query auditing is co-NP-hard for counting queries. A per-session budget
also does not compose across sessions or colluding users, so the guarantee is
local, not global.

Recommendation: for any real-data deployment, add a differential-privacy
accountant (for example OpenDP) with a budget composed across the session, and
account for it globally per data subject. The prototype already defers this to a
later round and says so; the recommendation is to keep that boundary explicit in
any claim about protection, because the deterministic controls are SDC, not DP.

### D3 — Dominance departs from the standard rules

The gateway suppresses a sum or mean cell when one donor contributes more than
50% of the total. ACRO and the SDC Handbook instead use the (n,k) rule (the n
largest contributors exceed k% of the total; a common default is n=2, k=90) and
the p% rule, both configurable. The single-contributor 50% rule is a reasonable
person-level proxy but is neither of the standard rules, so a production system
that claims ACRO-grade control would answer to a different test than it applies.

Recommendation: replace the fixed 50% rule with configurable (n,k) and p% rules.
This matters because the stated plan is to wrap ACRO in production; matching its
parameters now avoids a silent change in what "dominated" means later.

**Status: measured, not yet closed (2026-07-25).** The deviation now has
numbers rather than an argument. The dataset was carrying no concentrated
cells at all — no cell of ten donors or more reached 0.35 single-donor share —
so neither rule could fire and the difference was untestable; three regions
are now planted with shapes that separate the two rules
(`synth.DOMINANCE_ANCHORS`). Against ACRO 0.4.12's own implementations, the
rules disagree in **both** directions: the (n,k) rule suppresses a cell whose
top two donors hold 92% and the 50% rule releases it, and the 50% rule
suppresses a cell with one donor at 62% that both of ACRO's default rules
release. So this is not simply a laxer rule to be replaced — adopting (n,k)
and p% alone would *lose* protection the current rule provides, and the
integration must keep both. Numbers in the
[ACRO comparison](acro-comparison.md).

### D4 — No degrees-of-freedom floor for correlation or regression

ACRO's default `safe_dof_threshold` is 10: a model or correlation output is
unsafe unless its residual degrees of freedom exceed 10. The prototype's `corr`
relies on the frequency threshold (n ≥ 10) instead. For a donor-level
correlation this coincides with a distinct-donor count, but for an event-level
correlation `n` counts events, so ten events could come from one donor — the
frequency check does not then bound the number of individuals. (The leave-one-
donor-out influence control added in round 2d covers the dominating-donor case,
but not the count.)

Recommendation: add a distinct-donor floor to `corr` and to any future
regression tool, aligned to ACRO's `safe_dof_threshold = 10`, and compute it on
distinct donors rather than rows. This is the standard model-output check and
the natural home for the "how many people is this really about" question.

**Status: implemented (round 2h).** The engine now attaches an internal
`n_donors` (distinct-donor count per cell, on the unit view) to every result and
the gateway enforces the threshold on it, so a cell with many rows but fewer
than ten donors is suppressed. This makes the threshold rule count individuals
across all procedures, not just `corr`, and drops the helper before release.

### D5 — One automated checker where the standard is two humans

OpenSAFELY and SACRO require two trained human output checkers before release,
and SACRO's stated design philosophy is to assist checkers rather than replace
them. The prototype auto-denies high findings and escalates medium findings to a
single human. Automating the check is the project's novel contribution, but it
should not be presented as meeting the two-human standard.

Recommendation: position the agent gateway as a pre-filter that reduces checker
load — which DARE UK identifies as the bottleneck for scaling TREs — and keep
two-human review on any real release. This aligns the framing with SACRO and
turns the automation into a throughput gain rather than a governance downgrade.

**Status: documented.** The [security model](security.md) now states that on
real data the gateway is a pre-filter that reduces human-checker load, not a
replacement for the two-human standard.

### D6 — The influence control is bespoke and its threshold is unvalidated

The leave-one-donor-out correlation control (round 2d) has no direct counterpart
in ACRO, and its threshold (a released r may not move by more than 0.5 when one
donor is removed) was set by judgement, not calibration. The control is
defensible and arguably stronger than ACRO's handling of correlation, but an
unvalidated threshold can over- or under-suppress.

Recommendation: calibrate the threshold against ACRO behaviour on matched
outputs, and keep the influence control as a complement to the degrees-of-
freedom floor in D4, not a replacement for it.

**Status: configurable; calibration pending.** The threshold is the
`influence_threshold` field on `DisclosurePolicy` (default 0.5), so it can be set
per deployment. It now sits alongside the D4 distinct-donor floor, as
recommended. Empirical calibration against ACRO is still open.

### D7 — Rounding permits narrow inference

The gateway suppresses counts below 10 and rounds the rest to base 5. OpenSAFELY
moved away from plain rounding after finding that a rounded 5 could be inferred
as a 6 or 7; it now redacts counts ≤7 and then rounds. The prototype's
suppress-then-round has the same class of residual inference near the threshold.

Recommendation: adopt OpenSAFELY's rule — redact ≤7, then round to 5 — or
midpoint rounding, for closer alignment with current NHS-TRE practice.

**Status: reassessed — already conservative.** The prototype suppresses counts
below 10 and then rounds, so released counts start at 10; this is stricter than
OpenSAFELY's redact-≤7. The residual near-threshold inference is minor and no
code change is made now. Midpoint rounding remains an optional refinement if
exact alignment with a specific NHS-TRE policy is required.

## A note on the future two-LLM deployment

The docs anticipate an outside planner proposing tool calls and an inside model
reviewing them. When that is built, follow the Dual LLM / CaMeL pattern
(Beurer-Kellner et al. 2025; Willison 2023): the privileged model manipulates
untrusted results only symbolically, as opaque references it never dereferences,
and a non-model orchestrator enforces policy and tracks data provenance before
each tool call. The existing tool manifest is a start; the missing piece is
capability and provenance tracking, which is what makes the pattern sound.

## References

- OWASP Gen AI Security Project. *LLM01:2025 Prompt Injection.* <https://genai.owasp.org/llmrisk/llm01-prompt-injection/>
- Beurer-Kellner L, et al. (2025). *Design Patterns for Securing LLM Agents against Prompt Injections.* arXiv:2506.08837. <https://arxiv.org/abs/2506.08837>
- Willison S (2023). *The Dual LLM pattern for building AI assistants that can resist prompt injection.* <https://simonwillison.net/2023/Apr/25/dual-llm-pattern/>
- Green E, Ritchie F, Smith J, et al. (2022). *A multi-language toolkit for the semi-automated checking of research outputs (ACRO/SACRO).* arXiv:2212.02935. <https://arxiv.org/abs/2212.02935>
- AI-SDC / Eurostat. *ACRO safe defaults* (`safe_threshold = 10`, `safe_dof_threshold = 10`, `safe_nk_n = 2`). <https://github.com/AI-SDC/ACRO>, <https://github.com/eurostat/ACRO/blob/main/safe_globals.ado>
- sdctools. *Handbook on Statistical Disclosure Control* (threshold, (n,k) and p% rules, secondary suppression). <https://sdctools.github.io/HandbookSDC/>
- Bennett Institute (2023). *"Safe Outputs" and Statistical Disclosure Control in OpenSAFELY* (redact ≤7, round to 5, two output checkers). <https://www.bennett.ox.ac.uk/blog/2023/03/safe-outputs-and-statistical-disclosure-control-in-opensafely/>
- GOV.UK. *The Five Safes Framework.* <https://www.gov.uk/data-ethics-guidance/the-five-safes-framework>
- Dinur I, Nissim K (2003). *Revealing information while preserving privacy* (reconstruction). PODS.
- Kenthapadi K, Mishra N, Nissim K (2005). *Simulatable auditing.* PODS.
- Dwork C, Roth A (2014). *The Algorithmic Foundations of Differential Privacy* (Fundamental Law of Information Recovery; composition).
- DARE UK. *Output-checking capacity as a barrier to scaling TREs.* <https://dareuk.org.uk/>
