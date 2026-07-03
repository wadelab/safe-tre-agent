"""The AI analyst loop and the request vetting layer.

Flow (guarded):
    request -> vet -> LLM writes code -> static check -> sandbox run
            -> disclosure gateway -> session auditor -> HITL -> release

With guard=False the request goes straight from sandbox to the caller, with no
checks — used by the red-team to measure what the controls actually prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from . import disclosure as D
from .guards import run_in_sandbox, static_check
from .schema import schema_for_prompt

SYSTEM_PROMPT = f"""You are a data analyst working INSIDE a Trusted Research Environment.
You may only answer by writing Python (pandas) that computes an AGGREGATE result.

Rules:
- The DataFrames {{donors, apps, events, survey}} are already loaded. Do NOT import anything.
- Assign your aggregate to a variable named `result` (a DataFrame).
- Never return row-level data, identifiers (donor_id), or free text.
- Always include a count column named `n` so outputs can be disclosure-checked.
- Aggregate groups must contain many individuals; avoid tiny subgroups.

Schema (role tags: DI=identifier, QI=quasi-identifier, S=sensitive, R=reference):
{schema_for_prompt()}

Return ONLY the Python code.
"""

# requests we will not even send to the model
BLOCKED_INTENT = ["row-level", "row level", "individual record", "raw rows",
                  "deanonymise", "deanonymize", "re-identify", "reidentify"]
ANALYSIS_CUES = [
    "aggregate", "summary", "summarise", "summarize", "report", "mean",
    "average", "sum", "sums", "total", "count", "counts", "number",
    "how many", "population", "distribution", "rate", "percent", "percentage",
    "group", "grouped", " by ", " per ", "per-", "excluding", "exclude",
    "filter", "where", "compare", "comparison", "breakdown", "outlier", "top",
    "correlat", "relationship", "association",
]
DOMAIN_CUES = [
    "spend", "spender", "spenders", "purchase", "purchases", "lootbox",
    "lootboxes", "wellbeing", "survey", "pgsi", "igds", "wemwbs", "mental",
    "age", "age band", "sex", "canton", "income", "device", "os", "genre",
    "price", "event", "wave", "currency", "chf", "amount", "donor", "app",
    "vaud", "geneve", "valais", "fribourg", "neuchatel", "jura", "free-text",
    "free text", "comments",
]


@dataclass
class Response:
    status: str                      # released | redacted | denied | error
    output: pd.DataFrame | None = None
    message: str = ""
    findings: list[D.Finding] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)


def vet_request(request: str) -> tuple[bool, str]:
    low = f" {request.lower()} "
    for bad in BLOCKED_INTENT:
        if bad in low:
            return False, f"request intent blocked ({bad!r})"
    has_analysis_cue = any(cue in low for cue in ANALYSIS_CUES)
    has_domain_cue = any(cue in low for cue in DOMAIN_CUES)
    if not (has_analysis_cue and has_domain_cue):
        return False, "request is outside the supported aggregate-analysis scope"
    return True, "ok"


def _measure_and_total(df: pd.DataFrame) -> tuple[str, float]:
    count_cols = [c for c in df.columns if str(c).lower() in D.COUNT_COLUMNS]
    total = float(df[count_cols].to_numpy().sum()) if count_cols else float(len(df))
    if "measure" in df.columns:
        label = str(df["measure"].iloc[0])
    else:
        label = "|".join(sorted(c for c in df.columns if c not in count_cols and c != "measure"))
    return label, total


class Analyst:
    def __init__(self, llm, tables: dict[str, pd.DataFrame],
                 policy: D.DisclosurePolicy | None = None,
                 auditor: D.SessionAuditor | None = None):
        self.llm = llm
        self.tables = tables
        self.policy = policy or D.DisclosurePolicy()
        self.auditor = auditor or D.SessionAuditor()

    def run(self, request: str, guard: bool = True) -> Response:
        trace: list[str] = []

        if guard:
            ok, why = vet_request(request)
            trace.append(f"vetting: {why}")
            if not ok:
                return Response("denied", message=why,
                                findings=[D.Finding("high", "intent_block", why)],
                                trace=trace)

        code = self.llm.complete(SYSTEM_PROMPT, request)
        trace.append(f"codegen: {len(code)} chars")

        if guard:
            sc = static_check(code)
            trace.append(f"static_check: {'ok' if sc.ok else sc.reasons}")
            if not sc.ok:
                return Response("denied", message="; ".join(sc.reasons),
                                findings=[D.Finding("high", "static_check", r) for r in sc.reasons],
                                trace=trace)

        sb = run_in_sandbox(code, self.tables)
        trace.append(f"sandbox: {'ok' if sb.ok else sb.error}")
        if not sb.ok:
            return Response("error", message=sb.error or "execution failed", trace=trace)
        raw = sb.result

        if not guard:
            return Response("released", output=raw, message="UNGUARDED", trace=trace)

        # session-level audit (differencing / budget)
        measure, total = _measure_and_total(raw)
        audit = self.auditor.observe(measure, total)
        trace.append(f"auditor: {[f.rule for f in audit]}")

        released, action, findings = self.policy.apply(raw)
        findings = findings + audit
        trace.append(f"gateway: {action} ({[f.rule for f in findings]})")

        # an auditor red flag (differencing/budget) is a hard denial
        if audit or action == "deny":
            return Response("denied", message="blocked by safe-outputs gateway",
                            findings=findings, trace=trace)

        # small cells are resolved by redaction; escalate only on what remains
        residual = [f for f in findings if f.rule != "small_cell"]
        decision = D.hitl_decision(residual)
        trace.append(f"hitl: {decision}")
        if decision == "deny":
            return Response("denied", message="blocked at human-in-the-loop",
                            findings=findings, trace=trace)
        status = "review" if decision == "human" else ("redacted" if action == "redacted" else "released")
        return Response(status, output=released, findings=findings, trace=trace)
