"""GuardedQueryService — the secure pipeline (no code execution).

request → intent vetting → planner (untrusted) → QuerySpec validation
       → read-only engine → safe-outputs gateway → session auditor → audit log
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd
from pydantic import ValidationError

from . import disclosure as D
from .analyst import check_grouping_coherence, check_term_coherence, vet_request
from .disclosure import simulatable_cohort_bound
from .engine import QueryEngine
from .procedures import model_registry
from .query import QuerySpec


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


class QueryService:
    def __init__(self, tables, policy: D.DisclosurePolicy | None = None):
        self.engine = QueryEngine(tables)
        self.policy = policy or D.DisclosurePolicy()

    def handle(self, request: str, planner, auditor: D.SessionAuditor | None = None,
               audit_log=None, user: str = "anon") -> Result:
        auditor = auditor or D.SessionAuditor()
        trace: list[str] = []

        def record(status, spec, findings, output):
            if audit_log is not None:
                audit_log.append(
                    user=user, request=request, spec=spec, status=status,
                    findings=[f.__dict__ for f in findings],
                    output_shape=(list(output.shape) if output is not None else None))

        ok, why = vet_request(request)
        trace.append(f"vetting: {why}")
        if not ok:
            f = [D.Finding("high", "intent_block", why)]
            record("denied", None, f, None)
            return Result("denied", message=why, findings=f, trace=trace)

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

        raw = planner.plan(request)

        # model procedures route by the explicit `tool` key; a plain QuerySpec
        # cannot carry one (extra="forbid"), so the dispatch is unambiguous.
        if isinstance(raw, dict) and "tool" in raw:
            return self._handle_model(request, raw, auditor, trace, record)
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
        gok, gwhy = check_grouping_coherence(request, spec.dataset, spec.group_by)
        trace.append(f"grouping: {gwhy}")
        if not gok:
            f = [D.Finding("high", "grouping_mismatch", gwhy)]
            record("denied", spec.model_dump(), f, None)
            return Result("denied", message=gwhy, spec=spec.model_dump(),
                          findings=f, trace=trace)

        df = self.engine.run(spec)
        trace.append(f"engine: {len(df)} aggregate row(s) computed")

        total = float(df["n"].sum()) if "n" in df.columns else float(len(df))
        audit_findings = auditor.observe(spec.measure_key(), total)
        # lineage: is this cohort a near-duplicate of one already released?
        # The bound is computed from PUBLISHED donor marginals, not the live
        # donor sets, so the deny/allow decision is simulatable — an analyst with
        # the same public marginals could reproduce it, and a refusal leaks
        # nothing (see disclosure.simulatable_cohort_bound).
        cohort = spec.normalized_filters()
        marginals = self.engine.marginal_donor_counts()
        audit_findings += auditor.observe_cohort(
            spec.dataset, cohort,
            lambda a, b: simulatable_cohort_bound(marginals, spec.dataset, a, b))
        trace.append(f"auditor: {[f.rule for f in audit_findings]}")

        released, action, findings = self.policy.apply(df)
        findings = findings + audit_findings
        trace.append(f"gateway: {action} ({[f.rule for f in findings]})")

        # Fail closed: any auditor flag, an explicit deny, or an unrecognised
        # action withholds all data.
        if audit_findings or action not in ("release", "redacted"):
            record("denied", spec.model_dump(), findings, None)
            return Result("denied", message="blocked by safe-outputs gateway",
                          spec=spec.model_dump(), findings=findings, trace=trace)

        # Human-in-the-loop: suppression-resolved findings are settled, but any
        # residual medium/high finding escalates (and a residual high denies).
        # This keeps the documented HITL step present in the secure path — today
        # nothing medium can reach here, so it is future-proofing + fail-closed.
        residual = [f for f in findings if f.rule not in D.SUPPRESSABLE]
        decision = D.hitl_decision(residual)
        trace.append(f"hitl: {decision}")
        if decision == "deny":
            record("denied", spec.model_dump(), findings, None)
            return Result("denied", message="blocked at human-in-the-loop",
                          spec=spec.model_dump(), findings=findings, trace=trace)
        if decision == "human":
            record("review", spec.model_dump(), findings, None)
            return Result("review", message="escalated to human output checker",
                          spec=spec.model_dump(), findings=findings, trace=trace)

        auditor.record_cohort(spec.dataset, cohort)
        status = "redacted" if action == "redacted" else "released"
        record(status, spec.model_dump(), findings, released)
        return Result(status, output=released, spec=spec.model_dump(),
                      findings=findings, trace=trace)

    def _handle_model(self, request: str, raw: dict, auditor: D.SessionAuditor,
                      trace: list[str], record) -> Result:
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

        def deny(findings: list[D.Finding], message: str) -> Result:
            record("denied", spec.model_dump(), findings, None)
            return Result("denied", message=message, spec=spec.model_dump(),
                          findings=findings, trace=trace)

        # Fidelity gate: does the model answer the question that was asked?
        cok, cwhy = check_term_coherence(request, spec.dataset,
                                         spec.response, spec.terms)
        trace.append(f"terms: {cwhy}")
        if not cok:
            return deny([D.Finding("high", "term_mismatch", cwhy)], cwhy)

        aggregates = proc.plan_aggregates(spec)
        roles = proc.table_roles(spec)

        # Budget precheck: each underlying aggregate is individually a
        # differencable release, so each individually counts — and an
        # unaffordable model does no engine work at all (P17).
        if auditor.spent + len(aggregates) > auditor.budget:
            f = [D.Finding("high", "query_budget",
                           f"session query budget {auditor.budget} exceeded")]
            trace.append("auditor: query budget insufficient for model")
            return deny(f, "session query budget exceeded")

        marginals = self.engine.marginal_donor_counts()
        finalized: dict[str, pd.DataFrame] = {}
        cohorts: list[tuple[str, tuple]] = []
        for role, agg in zip(roles, aggregates, strict=True):
            df = self.engine.run(agg)
            trace.append(f"engine[{role}]: {len(df)} aggregate row(s) computed")

            total = float(df["n"].sum()) if "n" in df.columns else float(len(df))
            audit_findings = auditor.observe(agg.measure_key(), total)
            cohort = agg.normalized_filters()
            audit_findings += auditor.observe_cohort(
                agg.dataset, cohort,
                lambda a, b: simulatable_cohort_bound(marginals, agg.dataset, a, b))
            if audit_findings:
                trace.append(f"auditor[{role}]: {[f.rule for f in audit_findings]}")
                return deny(audit_findings, "blocked by safe-outputs gateway")

            released, action, findings = self.policy.apply(df)
            trace.append(f"gateway[{role}]: {action} ({[f.rule for f in findings]})")
            # P19: the model fits on a complete vetted table or not at all. A
            # redaction means some design cell is unsafe to release, so the
            # message names the aggregate role only — never which cell or why.
            if action != "release":
                f = [D.Finding("high", "model_incomplete_cell_table",
                               "an underlying design-cell table cannot be fully "
                               "released for this model")]
                return deny(f, "blocked by safe-outputs gateway: the model's "
                               "design-cell table cannot be fully released")
            finalized[role] = released
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
        record("released", spec_dict, [], output)
        return Result("released", output=output, spec=spec_dict,
                      findings=[], trace=trace, artifacts=artifacts)
