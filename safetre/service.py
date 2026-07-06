"""GuardedQueryService — the secure pipeline (no code execution).

request → intent vetting → planner (untrusted) → QuerySpec validation
       → read-only engine → safe-outputs gateway → session auditor → audit log
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd
from pydantic import ValidationError

from . import disclosure as D
from .analyst import vet_request
from .disclosure import simulatable_cohort_bound
from .engine import QueryEngine
from .query import QuerySpec


@dataclass
class Result:
    status: str                       # released | redacted | denied
    output: pd.DataFrame | None = None
    message: str = ""
    spec: dict | None = None
    findings: list = field(default_factory=list)
    trace: list = field(default_factory=list)


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
