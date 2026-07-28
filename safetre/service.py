"""GuardedQueryService — the secure pipeline (no code execution).

request → intent vetting → planner (untrusted) → QuerySpec validation
       → read-only engine → safe-outputs gateway → session auditor → audit log
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pandas as pd
from pydantic import ValidationError

from . import disclosure as D
from .analyst import check_grouping_coherence, check_term_coherence, vet_request
from .disclosure import simulatable_cohort_bound
from .engine import QueryEngine, compile_query
from .procedures import get_procedure, model_registry
from .query import QuerySpec


# The single answer every data-derived refusal gives. A refusal decided from
# the REQUEST — a spec that would not validate, an intent the gates block, an
# exhausted budget — may be explained in full, because the analyst holds the
# request and could reach the same verdict themselves. A refusal decided from
# the DATA may not, because everything distinguishing one such refusal from
# another is a fact about records the gateway has just withheld.
#
# Red-teamed 2026-07-26. Removing the row count from the trace was not enough:
# a cohort matching nobody came back `released` with an empty table, while a
# cohort matching one person came back `redacted` with a `small_cell` finding.
# The status word alone answered "does anyone match this predicate?", and with
# five filter slots over the catalogue that is a re-identification oracle. The
# fix has to be that nothing released means one answer, not several.
WITHHELD_MESSAGE = "blocked by safe-outputs gateway: nothing from this query " \
                   "can be released"
WITHHELD_TRACE = "gateway: nothing released"


def _withheld() -> list:
    return [D.Finding("high", "nothing_released", suppressable=True,
                      detail="no part of this result passed the disclosure checks")]


def _donor_total(df: pd.DataFrame) -> float:
    """The distinct-donor size of a raw engine frame, for the session auditor.

    Every engine result carries the internal `n_donors` helper (dropped by the
    gateway before release). Falling back to the row count keeps the auditor
    correct for frames that did not come through the engine.
    """
    if "n_donors" in df.columns:
        return float(df["n_donors"].sum())
    if "n" in df.columns:
        return float(df["n"].sum())
    return float(len(df))


def _literal_spec(request: str) -> dict | None:
    """A request that is a single JSON object is an analyst-authored spec
    (R17): it bypasses the planner and the natural-language gates, and is
    treated as untrusted input by everything downstream, exactly as a
    planner-proposed spec would be. Returns None for natural-language
    requests. A request that starts as JSON but does not parse raises —
    refused loudly, never re-routed to the planner as text.
    """
    text = request.strip()
    if not text.startswith("{"):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"literal spec is not valid JSON: {exc}") from None


@dataclass
class Result:
    status: str                       # released | redacted | denied | review
    output: pd.DataFrame | None = None
    message: str = ""
    spec: dict | None = None
    findings: list = field(default_factory=list)
    trace: list = field(default_factory=list)
    # released companion frames (e.g. a model's vetted cell table and summary
    # block, R15). Always None unless status is released.
    artifacts: dict[str, pd.DataFrame] | None = None
    # the compiled SQL the request would run — one entry, or one per design
    # cell table for a model. R11 requires a decision to be inspectable, and
    # the plan is the part of it the caller could not otherwise reconstruct.
    # Safe to show: the SafeSQL shape carries no values, only bound-parameter
    # placeholders, and every identifier in it is already public catalogue.
    plans: list[str] = field(default_factory=list)


class QueryService:
    def __init__(self, tables, policy: D.DisclosurePolicy | None = None):
        self.engine = QueryEngine(tables)
        self.policy = policy or D.DisclosurePolicy()

    def _difference_bound(self, dataset: str, marginals: dict):
        """The differencing test the session auditor decides with.

        Two layers, and the smaller wins because either denying is a denial:

        - `simulatable_cohort_bound` — decided from published marginals alone,
          so it costs no query and catches rare-category isolation without
          touching the data. Kept as the cheap early-out.
        - `QueryEngine.row_symdiff_donors` — the donors behind the rows exactly
          one of the two queries aggregated. Exact, and it is the quantity that
          actually governs the disclosure: a released value is a function of the
          rows it counted, not of the cohort that produced them. The bound alone
          overstated the true difference by 13x on the attack it was meant to
          catch, and missed entirely the case where two cohorts hold the *same
          people* but aggregate different rows (hardening #40).

        The exact leg runs only when the cheap one has not already denied.
        """
        def bound(a: tuple, b: tuple) -> int:
            cheap = simulatable_cohort_bound(marginals, dataset, a, b)
            if cheap < self.policy.threshold:
                return cheap
            return self.engine.row_symdiff_donors(dataset, a, b)

        return bound

    def _context(self, spec: QuerySpec):
        """What a vetter needs to know about this query: the disclosure class
        of its released value (which selects the dominance bound) and its cell
        keys, always; the donor-level contributions only when a vetter reads
        them, since those cost a second engine query."""
        return self.engine.cell_context(
            spec, with_contributions=self.policy.needs_contributions())

    def handle(self, request: str, planner, auditor: D.SessionAuditor | None = None,
               audit_log=None, user: str = "anon") -> Result:
        """The audited, fail-closed entry point.

        Any exception below — a planner failure, an engine error, a fit that
        raises — must not escape as an un-audited 500 (hardening #37): it is
        recorded with status "error" and the exception TYPE only (an exception
        message may carry data), and the caller receives the canonical
        withheld response, so a crash is neither an audit gap nor an oracle.
        """
        auditor = auditor or D.SessionAuditor()
        try:
            return self._handle_inner(request, planner, auditor=auditor,
                                      audit_log=audit_log, user=user)
        except Exception as exc:                  # noqa: BLE001 - audited boundary
            findings = [D.Finding(
                "high", "pipeline_error",
                "the query pipeline failed before a release decision",
                audit_detail=type(exc).__name__)]
            if audit_log is not None:
                audit_log.append(
                    user=user, request=request, spec=None, status="error",
                    findings=[f.__dict__ for f in findings], output_shape=None)
            return Result("denied", message=WITHHELD_MESSAGE,
                          findings=_withheld(), trace=[WITHHELD_TRACE])

    def _handle_inner(self, request: str, planner, auditor: D.SessionAuditor,
                      audit_log=None, user: str = "anon") -> Result:
        auditor = auditor or D.SessionAuditor()
        trace: list[str] = []

        def record(status, spec, findings, output):
            if audit_log is not None:
                audit_log.append(
                    user=user, request=request, spec=spec, status=status,
                    findings=[f.__dict__ for f in findings],
                    output_shape=(list(output.shape) if output is not None else None))

        try:
            literal = _literal_spec(request)
        except ValueError as exc:
            f = [D.Finding("high", "spec_rejected", str(exc))]
            trace.append(f"literal spec: REJECTED ({exc})")
            record("denied", None, f, None)
            return Result("denied", message=f"query rejected: {exc}",
                          findings=f, trace=trace)

        if literal is None:
            ok, why = vet_request(request)
            trace.append(f"vetting: {why}")
            if not ok:
                f = [D.Finding("high", "intent_block", why)]
                record("denied", None, f, None)
                return Result("denied", message=why, findings=f, trace=trace)
        else:
            # R17: no natural-language question, so the NL gates (intent
            # vetting, fidelity checks) have nothing to check; the typed
            # validation below is the stronger admissibility gate.
            trace.append("vetting: literal spec entered by analyst (R17)")

        # Budget short-circuit: once the session has spent its query budget, deny
        # before doing planner/engine work at all (bounds cost and the per-session
        # state a flood can accumulate).
        if auditor.over_budget():
            f = [D.Finding("high", "query_budget",
                           f"session query budget {auditor.budget} exceeded")]
            trace.append("auditor: query budget exhausted")
            record("denied", None, f, None)
            return Result("denied", message="session query budget exceeded",
                          findings=f, trace=trace)

        if literal is not None:
            raw = literal
            trace.append("planner: bypassed (literal spec)")
        else:
            raw = planner.plan(request)

        # model procedures route by the explicit `tool` key; a plain QuerySpec
        # cannot carry one (extra="forbid"), so the dispatch is unambiguous.
        if isinstance(raw, dict) and "tool" in raw:
            return self._handle_model(request, raw, auditor, trace, record,
                                      literal=literal is not None)
        trace.append("planner: QuerySpec proposed (untrusted)")

        try:
            spec = QuerySpec(**raw)
        except (ValidationError, TypeError) as exc:
            msg = "; ".join(e.get("msg", str(exc)) for e in exc.errors()) \
                if isinstance(exc, ValidationError) else str(exc)
            f = [D.Finding("high", "spec_rejected", msg)]
            trace.append(f"validation: REJECTED ({msg})")
            record("denied", raw, f, None)
            return Result("denied", message=f"query rejected: {msg}",
                          spec=raw, findings=f, trace=trace)
        trace.append(f"validation: ok ({spec.measure_key()}, group_by={spec.group_by})")

        # Fidelity gate: the spec validated, but does it answer the question that
        # was asked? Refuse when the planner grouped by a dimension the request
        # did not ask for, or asked for a breakdown this dataset cannot provide,
        # rather than silently returning an answer to a substituted question.
        # A literal spec IS the question, so there is no fidelity to check (R17).
        if literal is not None:
            trace.append("grouping: literal spec — fidelity gate not applicable")
        else:
            gok, gwhy = check_grouping_coherence(request, spec.dataset, spec.group_by)
            trace.append(f"grouping: {gwhy}")
            if not gok:
                f = [D.Finding("high", "grouping_mismatch", gwhy)]
                record("denied", spec.model_dump(), f, None)
                return Result("denied", message=gwhy, spec=spec.model_dump(),
                              findings=f, trace=trace)

        plans = [compile_query(spec).sql]
        df = self.engine.run(spec)
        # No row count here, and none in the model path below. The trace is
        # shown to the analyst for DENIED queries too, so a count of the cells
        # the engine found is a number about data the gateway then withheld —
        # and it is enough on its own: filter to a narrow cohort, group by a
        # dimension, and "0" versus "1" answers "does anyone match?" for any
        # predicate the catalogue can express. Red-teamed 2026-07-26: eight
        # such queries, every one of them refused, recovered a unique donor's
        # region, sex, income band and device. When a result IS released the
        # analyst can count its rows; when it is not, they may not.
        trace.append("engine: aggregate computed")

        # The auditor's totals are DONORS, not rows: two cohorts that differ
        # by a few individuals must trip the delta check however many rows
        # separate them — on an event-level view a hyperactive donor inflates
        # n without adding people, which is exactly the gap a double-
        # differencing pair exploits (hardening #38; completes D4's
        # individuals-not-rows reading in the auditor, not just the threshold).
        total = _donor_total(df)
        audit_findings = auditor.observe(spec.measure_key(), total)
        # lineage: does this release differ from an earlier one by too few
        # people? The published marginals decide it where they can, and the
        # exact row-level difference decides it where they cannot — see
        # `_difference_bound` and hardening #40.
        cohort = spec.normalized_filters()
        marginals = self.engine.marginal_donor_counts()
        audit_findings += auditor.observe_cohort(
            spec.dataset, cohort, self._difference_bound(spec.dataset, marginals))

        released, action, findings = self.policy.apply(df, self._context(spec))
        findings = findings + audit_findings

        # Fail closed: any auditor flag, an explicit deny, an unrecognised
        # action — or a result with no rows left in it. The last of those is
        # the one that is easy to miss: an empty frame is not a release, and
        # treating it as one told an analyst that their predicate matched
        # nobody, which is a sub-threshold fact like any other. Every branch
        # here produces the SAME status, message, findings and trace; the audit
        # log keeps the real findings, so an output checker still sees which
        # rule fired and on how many cells.
        if (audit_findings or action not in ("release", "redacted")
                or released is None or len(released) == 0):
            trace.append(WITHHELD_TRACE)
            record("denied", spec.model_dump(), findings, None)
            return Result("denied", message=WITHHELD_MESSAGE,
                          spec=spec.model_dump(), findings=_withheld(), trace=trace,
                          plans=plans)

        trace.append(f"auditor: {[f.rule for f in audit_findings]}")
        trace.append(f"gateway: {action} by {self.policy.vetter.describe()} "
                     f"({[f.rule for f in findings]})")

        # Human-in-the-loop: suppression-resolved findings are settled, but any
        # residual medium/high finding escalates (and a residual high denies).
        # This keeps the documented HITL step present in the secure path — today
        # nothing medium can reach here, so it is future-proofing + fail-closed.
        residual = [f for f in findings if not D.is_suppressable(f)]
        decision = D.hitl_decision(residual)
        trace.append(f"hitl: {decision}")
        if decision == "deny":
            record("denied", spec.model_dump(), findings, None)
            return Result("denied", message="blocked at human-in-the-loop",
                          spec=spec.model_dump(), findings=findings, trace=trace,
                          plans=plans)
        if decision == "human":
            record("review", spec.model_dump(), findings, None)
            return Result("review", message="escalated to human output checker",
                          spec=spec.model_dump(), findings=findings, trace=trace,
                          plans=plans)

        auditor.record_cohort(spec.dataset, cohort)
        # Released-value shaping runs on the FINALIZED frame: corr's p_value is
        # computed from the rounded n, never the exact one, so every released
        # number is a function of numbers already released (hardening #26).
        released = get_procedure(spec.measure.fn).postprocess(released, spec)
        status = "redacted" if action == "redacted" else "released"
        record(status, spec.model_dump(), findings, released)
        return Result(status, output=released, spec=spec.model_dump(),
                      findings=findings, trace=trace, plans=plans)

    def _handle_model(self, request: str, raw: dict, auditor: D.SessionAuditor,
                      trace: list[str], record, literal: bool = False) -> Result:
        """Model procedures (R15): plan cell aggregates → vet EACH through the
        standard gateway → fit only when every one releases cleanly.

        Fail-closed rules specific to models: any redacted/denied underlying
        aggregate denies the whole model (P19); estimability refusals are
        decided from the finalized tables alone (P22); the fitter receives the
        finalized frames and nothing else (P21).
        """
        registry = model_registry()
        proc = registry.get(raw.get("tool"))
        if proc is None:
            msg = f"unknown tool {raw.get('tool')!r}"
            f = [D.Finding("high", "spec_rejected", msg)]
            trace.append(f"validation: REJECTED ({msg})")
            record("denied", raw, f, None)
            return Result("denied", message=f"query rejected: {msg}",
                          spec=raw, findings=f, trace=trace)
        trace.append(f"planner: {proc.tool} spec proposed (untrusted)")

        try:
            spec = proc.validate(raw)
        except (ValidationError, TypeError) as exc:
            msg = "; ".join(e.get("msg", str(exc)) for e in exc.errors()) \
                if isinstance(exc, ValidationError) else str(exc)
            f = [D.Finding("high", "spec_rejected", msg)]
            trace.append(f"validation: REJECTED ({msg})")
            record("denied", raw, f, None)
            return Result("denied", message=f"query rejected: {msg}",
                          spec=raw, findings=f, trace=trace)
        trace.append(f"validation: ok ({proc.model_key(spec)})")

        # bound before `deny` can be called: a fidelity refusal happens before
        # any aggregate is planned, and the closure must not read an unset name
        plans: list[str] = []

        def deny(findings: list[D.Finding], message: str,
                 public: list[D.Finding] | None = None) -> Result:
            """`findings` is the truth, for the audit log. `public` is what the
            analyst is shown: for a refusal decided from the DATA it is the one
            canonical finding, because which rule fired on which role is a fact
            about cells that were withheld."""
            record("denied", spec.model_dump(), findings, None)
            return Result("denied", message=message, spec=spec.model_dump(),
                          findings=public if public is not None else findings,
                          trace=trace, plans=list(plans))

        # Fidelity gate: does the model answer the question that was asked?
        # A literal spec IS the question, so there is no fidelity to check (R17).
        if literal:
            trace.append("terms: literal spec — fidelity gate not applicable")
        else:
            cok, cwhy = check_term_coherence(request, spec.dataset,
                                             spec.response, spec.terms)
            trace.append(f"terms: {cwhy}")
            if not cok:
                return deny([D.Finding("high", "term_mismatch", cwhy)], cwhy)

        aggregates = proc.plan_aggregates(spec)
        roles = proc.table_roles(spec)
        plans.extend(compile_query(a).sql for a in aggregates)

        # Budget precheck: each underlying aggregate is individually a
        # differencable release, so each individually counts — and an
        # unaffordable model does no engine work at all (P17).
        if auditor.spent + len(aggregates) > auditor.budget:
            f = [D.Finding("high", "query_budget",
                           f"session query budget {auditor.budget} exceeded")]
            trace.append("auditor: query budget insufficient for model")
            return deny(f, "session query budget exceeded")

        marginals = self.engine.marginal_donor_counts()
        optional = proc.optional_roles(spec)
        finalized: dict[str, pd.DataFrame] = {}
        cohorts: list[tuple[str, tuple]] = []
        notes: list[D.Finding] = []
        for role, agg in zip(roles, aggregates, strict=True):
            df = self.engine.run(agg)
            trace.append(f"engine[{role}]: aggregate computed")

            # Donor totals, as on the plain path (hardening #38). The auditor
            # key is qualified by the aggregate's ROLE: a model's roles are
            # one joint release — a binomial's successes table is released
            # alongside its trials table, so the two differing by a few
            # donors is not a differencing signal, it's the model. Two
            # models (or two hand-issued counts on the plain path) still
            # compare role-for-role as before.
            total = _donor_total(df)
            audit_findings = auditor.observe(f"{agg.measure_key()}#{role}", total)
            cohort = agg.normalized_filters()
            audit_findings += auditor.observe_cohort(
                agg.dataset, cohort,
                self._difference_bound(agg.dataset, marginals))
            if audit_findings:
                trace.append(WITHHELD_TRACE)
                return deny(audit_findings, WITHHELD_MESSAGE, public=_withheld())

            released, action, findings = self.policy.apply(
                df, self._context(agg))
            if action == "release" and (released is None or len(released) == 0):
                # an empty design-cell table is not a table this model can be
                # fitted from, and saying so per role would name which one
                action = "redacted"
            # P19: the model fits on a complete vetted table or not at all. A
            # redaction means some design cell is unsafe to release, so the
            # message names the aggregate role only — never which cell or why.
            if action != "release":
                trace.append(f"gateway[{role}]: withheld")
                if role in optional:
                    # the fit goes ahead without it, and the output says so:
                    # a coefficient computed from vetted means is releasable
                    # even when the dispersion behind its standard error is
                    # not. Nothing derived from this table is released.
                    trace.append("the model releases without what it would "
                                 "have provided")
                    notes.append(D.Finding(
                        "low", "model_table_withheld", suppressable=True,
                        detail=f"the {role!r} table could not be released; the "
                               "model omits what it supplies"))
                    continue
                f = [D.Finding("high", "model_incomplete_cell_table",
                               "an underlying design-cell table cannot be fully "
                               "released for this model",
                               audit_detail=f"role {role!r} came back {action!r}")]
                return deny(f, WITHHELD_MESSAGE, public=_withheld())
            # value shaping on the finalized cells, as on the plain path
            # (hardening #26): the fitter and the released artifact consume
            # identical finalized-then-shaped frames (P21)
            trace.append(f"gateway[{role}]: released by "
                         f"{self.policy.vetter.describe()}")
            finalized[role] = get_procedure(agg.measure.fn).postprocess(released, agg)
            cohorts.append((agg.dataset, cohort))

        problems = proc.preconditions(finalized, spec)
        if problems:
            trace.append(f"preconditions: {problems}")
            f = [D.Finding("high", "model_unestimable", p) for p in problems]
            return deny(f, "; ".join(problems))
        trace.append("preconditions: ok")

        output, artifacts = proc.fit(finalized, spec)
        trace.append(f"fit: {len(output)} coefficient(s) from "
                     f"{len(artifacts['cells'])} vetted cell(s)")

        # Output contract (R14): released frames carry declared columns only.
        contract = proc.output_contract(spec)
        frames = {"output": output, **artifacts}
        for name, frame in frames.items():
            undeclared = [c for c in frame.columns if c not in contract.get(name, {})]
            if undeclared:
                f = [D.Finding("high", "contract_violation",
                               f"frame {name!r} carries undeclared columns "
                               f"{undeclared!r}")]
                trace.append(f"contract: VIOLATION in {name!r}")
                return deny(f, "blocked: model output violates its declared contract")
        trace.append("contract: ok")

        for dataset, cohort in cohorts:
            auditor.record_cohort(dataset, cohort)
        spec_dict = spec.model_dump() | {
            "aggregates": [a.measure_key() for a in aggregates]}
        record("released", spec_dict, notes, output)
        return Result("released", output=output, spec=spec_dict, plans=plans,
                      findings=notes, trace=trace, artifacts=artifacts)
