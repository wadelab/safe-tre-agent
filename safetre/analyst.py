"""The AI analyst loop and the request vetting layer.

Flow (guarded):
    request -> vet -> LLM writes code -> static check -> sandbox run
            -> disclosure gateway -> session auditor -> HITL -> release

With guard=False the request goes straight from sandbox to the caller, with no
checks — used by the red-team to measure what the controls actually prevent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import pandas as pd

from . import disclosure as D
from .guards import run_in_sandbox, static_check
from .query import CATALOGUE
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

# Requests we will not even send to the model. This is a cheap defence-in-depth
# pre-filter, NOT the security boundary — the QuerySpec allowlist is. Cues are
# broad paraphrases of "give me the microdata"; the real guarantee is that
# identifiers/free-text/raw-age are not expressible in a QuerySpec at all.
BLOCKED_INTENT = [
    # microdata / re-identification paraphrases
    "row-level", "row level", "line level", "line-level",
    "individual record", "individual-level", "unit record",
    "microdata", "micro-data", "raw row", "raw record",
    "raw event", "raw data row", "record-level", "record level",
    "deanonymise", "deanonymize", "re-identify", "reidentify",
    # per-individual / one-row-per-subject enumeration. The safe interface only
    # exposes per-donor results as AGGREGATES over grouped dimensions, never a
    # row per subject. This is caught deterministically here, BEFORE the planner,
    # so a capable model cannot quietly "repair" a disclosive request into a
    # permitted overall aggregate and release that instead — a silent downgrade
    # in which the user asked for row-level data and got a single number with no
    # signal their request was refused. Fail loudly instead.
    "per donor", "per-donor", "per participant", "per-participant",
    "per respondent", "per-respondent", "per individual", "per-individual",
    "each donor", "each participant", "each respondent", "each individual",
    "by row", "one row per", "row per donor", "row per participant",
    "row per respondent",
]
BLOCKED_TEXT_INTENT = [
    "free-text", "free text", "raw text", "verbatim",
    "open-ended", "open ended", "qualitative response",
    "qualitative responses", "comments", "comment field",
]
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
    "age", "age band", "sex", "region", "income", "device", "os", "genre",
    "price", "event", "wave", "currency", "gbp", "amount", "donor", "app",
    "london", "south east", "north west", "scotland", "wales", "northern ireland", "free-text",
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
    for bad in BLOCKED_TEXT_INTENT:
        if bad in low:
            return False, f"free-text request blocked ({bad!r})"
    has_analysis_cue = any(cue in low for cue in ANALYSIS_CUES)
    has_domain_cue = any(cue in low for cue in DOMAIN_CUES)
    if not (has_analysis_cue and has_domain_cue):
        return False, "request is outside the supported aggregate-analysis scope"
    return True, "ok"


# Phrases that introduce a grouping/breakdown in a request.
GROUPING_KEYWORDS = [
    "broken down by", "break down by", "grouped by", "group by", "split by",
    "breakdown by", "breakdown of", "for each ", " per ", " by ", " across ",
]

# Natural-language term -> the catalogue dimension it names. Longer, more
# specific phrases are matched first so "age band" wins over "age", etc.
DIMENSION_SYNONYMS = {
    "age band": "age_band", "age group": "age_band", "age bracket": "age_band",
    "age range": "age_band", "age": "age_band",
    "gender": "sex", "sex": "sex",
    "region": "region", "area": "region", "location": "region",
    "nation": "region", "country": "region",
    "income band": "income_band", "income bracket": "income_band",
    "income": "income_band", "earnings": "income_band", "salary": "income_band",
    "device os": "device_os", "operating system": "device_os",
    "device": "device_os", "platform": "device_os", "os": "device_os",
    "genre": "genre", "game type": "genre",
    "lootbox": "contains_lootboxes", "lootboxes": "contains_lootboxes",
    "loot box": "contains_lootboxes", "loot boxes": "contains_lootboxes",
    "loot-box": "contains_lootboxes", "crate": "contains_lootboxes",
    "price tier": "price_tier", "price": "price_tier", "pricing": "price_tier",
    "event type": "event_type",
    "age rating": "age_rating", "content rating": "age_rating", "pegi": "age_rating",
    "survey wave": "wave", "wave": "wave", "timepoint": "wave",
}


# Words that end a grouping clause and begin a filter/condition, so a breakdown
# ("by region for age > 40") is not mistaken for a request to group by the
# filtered column.
FILTER_TERMINATORS = [
    " for ", " where ", " excluding ", " exclude ", " with ", " in ",
    " between ", " over ", " under ", " above ", " below ", " during ",
    " among ", " if ", " that ", " who ", " having ", " restricted to ",
]


def _dims_mentioned(text: str) -> set[str]:
    """Catalogue dimensions named (by synonym) in `text`.

    Longest synonyms match first and consume their span, so "age rating" names
    age_rating only — not also age_band via the "age" inside it.
    """
    low = text.lower()
    consumed = [False] * len(low)
    found = set()
    for term in sorted(DIMENSION_SYNONYMS, key=len, reverse=True):
        dim = DIMENSION_SYNONYMS[term]
        for m in re.finditer(rf"(?<!\w){re.escape(term)}(?:s|es)?(?!\w)", low):
            if not any(consumed[m.start():m.end()]):
                found.add(dim)
                for i in range(m.start(), m.end()):
                    consumed[i] = True
    return found


def _grouping_clause(request: str) -> str | None:
    """The breakdown clause: text from the first grouping keyword up to the next
    filter keyword (or end). None if the request asks for no explicit breakdown."""
    low = f" {request.lower()} "
    start = None
    for kw in GROUPING_KEYWORDS:
        idx = low.find(kw)
        if idx != -1 and (start is None or idx < start[0]):
            start = (idx, idx + len(kw))
    if start is None:
        return None
    clause = low[start[1]:]
    cut = len(clause)
    for term in FILTER_TERMINATORS:
        t = clause.find(term)
        if t != -1:
            cut = min(cut, t)
    return clause[:cut]


def check_grouping_coherence(request: str, dataset: str,
                             group_by: list[str]) -> tuple[bool, str]:
    """Deterministic request<->spec fidelity check for grouping.

    The untrusted planner can emit a spec that VALIDATES (every group_by dim is
    on the dataset's allowlist) yet answers a *different* question than the one
    asked. Rather than release an answer to a substituted question, refuse.
    Three ways the spec can be unfaithful to an explicit breakdown request:
      A. a breakdown this dataset cannot provide ("wellbeing per lootbox");
      B. a group_by dimension the request never named (hallucination);
      C. a requested, valid breakdown the planner silently dropped (omission).
    Runs after validation, before the engine, independent of the planner.

    Lenient by design: it only fires when the request names a groupable concept,
    so it does not flag differencing follow-ups ("same, excluding ...") or
    requests with no explicit breakdown.
    """
    dims = CATALOGUE[dataset]["dims"]
    clause = _grouping_clause(request)
    if clause is None:
        return True, "no explicit grouping requested"
    clause_dims = _dims_mentioned(clause)
    if not clause_dims:
        return True, "no recognised grouping dimension in request"
    grouped = set(group_by)

    # Rule A: a requested breakdown this dataset cannot provide.
    unsupported = sorted(d for d in clause_dims if d not in dims)
    if unsupported:
        where = "; ".join(
            f"{d!r} is available on "
            f"{', '.join(sorted(ds for ds, i in CATALOGUE.items() if d in i['dims'])) or 'no dataset'}"
            for d in unsupported)
        return False, (
            f"cannot break {dataset!r} down by {', '.join(unsupported)}: {where}. "
            f"valid breakdowns for {dataset!r}: {', '.join(sorted(dims))}")

    # Rule C: a requested, valid breakdown the planner silently dropped.
    missing = sorted(d for d in clause_dims if d in dims and d not in grouped)
    if missing:
        return False, (
            f"request asks to break {dataset!r} down by {', '.join(missing)}, but the "
            f"query {'omits it' if len(missing) == 1 else 'omits them'} "
            f"(group_by={sorted(grouped)})")

    # Rule B: the planner grouped by a dimension the request never mentioned.
    referenced = _dims_mentioned(request)
    hallucinated = sorted(g for g in grouped if g not in referenced)
    if hallucinated:
        return False, (
            f"query groups by {', '.join(hallucinated)}, which was not part of the "
            f"request; valid breakdowns for {dataset!r}: {', '.join(sorted(dims))}")
    return True, "grouping matches request"


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
