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

        total = float(df["n"].sum()) if "n" in df.columns else float(len(df))
        audit_findings = auditor.observe(spec.measure_key(), total)
        trace.append(f"auditor: {[f.rule for f in audit_findings]}")

        released, action, findings = self.policy.apply(df)
        findings = findings + audit_findings
        trace.append(f"gateway: {action} ({[f.rule for f in findings]})")

        if audit_findings or action == "deny":
            record("denied", spec.model_dump(), findings, None)
            return Result("denied", message="blocked by safe-outputs gateway",
                          spec=spec.model_dump(), findings=findings, trace=trace)

        status = "redacted" if action == "redacted" else "released"
        record(status, spec.model_dump(), findings, released)
        return Result(status, output=released, spec=spec.model_dump(),
                      findings=findings, trace=trace)
