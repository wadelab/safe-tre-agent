"""The inside analyst, phase 1: the vetted loop (spec R19, P23).

An automated analyst that answers a research QUESTION rather than a single
request — planning sub-requests, sending each through the ordinary service,
reading what came back, following up, and concluding with a typed dossier.

The safety argument does not change shape, and this module is built so that
it cannot. The analyst's inputs come from the PUBLIC side of the gateway:

- Every sub-request is an ordinary request through `QueryService.handle`
  (a natural-language sub-question plus the spec the analyst proposes for
  it, so intent vetting, the fidelity gates, typed validation, the gateway,
  the session auditor's budget and differencing lineage, and the audit log
  all apply exactly as they do to a human at the web page).
- The only things the analyst policy is ever shown are the things a human
  user is shown: the status, the canonical message, the numberless findings,
  and the RELEASED frames. Nothing else exists in `LoopState`, and
  `tests/test_inside_analyst.py` pins that a policy sees no more.
- The loop's output is a `Dossier`: the steps, the released frames, and typed
  claims whose verdicts come from a closed vocabulary. A refusal is a typed
  `not_answerable`, never a substituted answer.
- The narrator writes prose from the dossier ALONE, and `check_narrative`
  flags any figure in the prose that does not appear in a released table —
  a validity control against invention, not a disclosure control (there is
  nothing to disclose in a context that holds only released numbers).

The analyst POLICY — what to ask next — is pluggable, so the loop is testable
offline: `ScriptedPolicy` follows a fixed plan; `LLMAnalystPolicy` asks a
model over the same `complete(system, user)` interface the planner uses.
Under A1 the model is untrusted, and here it is untrusted in the same way
the planner is: it proposes, the boundary decides.

Phase 1 deliberately does NOT let the analyst see unvetted intermediates.
That is the data-sighted tier (docs/inside-analyst.md, phase 3), a research
problem this module does not attempt.
"""

from __future__ import annotations

import io
import json
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Protocol

import pandas as pd

from . import disclosure as D
from .planner import _extract_json, planner_system

VERDICTS = ("supported", "not_supported", "null", "not_answerable")
DEFAULT_MAX_STEPS = 12
FRAME_ROWS_SHOWN = 60


# --------------------------------------------------------------------------- #
# The dossier                                                                 #
# --------------------------------------------------------------------------- #

def _frame_records(df: pd.DataFrame | None) -> list[dict] | None:
    if df is None:
        return None
    out = df.copy()
    # NaN is not JSON; a suppressed value is shown as null, as the web page does
    return json.loads(out.to_json(orient="records", date_format="iso"))


@dataclass
class Step:
    """One sub-request and what the gateway released for it. Everything here
    is what a web user would have seen for the same request."""
    id: int
    sub_question: str
    spec: dict | None
    status: str                       # released | redacted | denied | review
    message: str = ""
    findings: list[dict] = field(default_factory=list)   # rule + detail only
    output: list[dict] | None = None                     # the released frame
    artifacts: dict[str, list[dict]] | None = None       # released companions
    cost: int = 0                                        # budget units spent

    def released(self) -> bool:
        return self.status in ("released", "redacted") and self.output is not None


@dataclass
class Claim:
    text: str
    verdict: str
    evidence: list[int] = field(default_factory=list)    # step ids
    reason: str = ""                                     # for not_answerable


@dataclass
class Dossier:
    question: str
    dataset: str
    steps: list[Step] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    verdict: str = "not_answerable"
    notes: str = ""
    budget: int = 0
    budget_spent: int = 0
    stopped_because: str = ""
    narrative: str = ""
    unsupported_figures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, **kw) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str, **kw)

    def released_numbers(self) -> set[float]:
        """Every numeric value in every released frame and companion — and
        every number written inside a released string cell key ("20-35k",
        "18-24"), since a band label quoted in prose is not a figure."""
        out: set[float] = set()
        for s in self.steps:
            for rows in ([s.output or []] + list((s.artifacts or {}).values())):
                for row in rows:
                    for v in row.values():
                        if isinstance(v, bool) or v is None:
                            continue
                        if isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v)):
                            out.add(float(v))
                        elif isinstance(v, str):
                            for tok in re.findall(r"\d+\.?\d*", v):
                                try:
                                    out.add(float(tok))
                                except ValueError:
                                    pass
        return out

    def check_narrative(self, text: str) -> list[str]:
        """Figures in `text` that appear in no released frame.

        A validity control: the narrator sees only released numbers, so an
        unsupported figure is an invention, not a leak. A figure is accepted
        when some released number ROUNDS TO IT at the figure's own precision
        — to its decimal places, or to its number of significant digits, so
        "about 49" stands for 48.66 and "10,000" for 10,200, but 9,999 does
        not. Percentages of released shares in [0, 1] are accepted, and so
        are small integers up to 12, which are months, waves, step counts
        and ordinal noise rather than quantities, and the conventional
        significance thresholds 0.05, 0.01 and 0.001.
        """
        released = self.released_numbers()
        derived: set[float] = set()
        for r in released:
            derived.add(r)
            if 0 <= r <= 1:
                derived.add(r * 100)
        bad: list[str] = []
        # "72 000" (thin, no-break or plain space as the thousands separator)
        # is one figure, not two; and a typographic minus (U+2212, U+2011,
        # U+2013) is a sign, so "‑0.1266" is the released -0.1266, not 0.1266
        text = re.sub(r"(?<=\d)[\u202f\u00a0 ](?=\d{3}\b)", "", text)
        text = re.sub(r"[\u2212\u2011\u2013\u2010]", "-", text)
        for tok in re.findall(r"(?<![\w.])[-+]?\d[\d,]*\.?\d*(?![\w.])", text):
            raw = tok.replace(",", "")
            try:
                val = float(raw)
            except ValueError:
                continue
            if val.is_integer() and 0 <= val <= 12:
                continue
            if val in (0.05, 0.01, 0.001):        # conventional significance thresholds
                continue
            decimals = len(raw.split(".")[1]) if "." in raw else 0
            digits = raw.lstrip("-+").replace(".", "").lstrip("0").rstrip("0") or "0"
            sig = max(1, len(digits))
            ok = any(_rounds_to(x, val, decimals, sig) for x in derived)
            if not ok:
                bad.append(tok)
        return bad


def _rounds_to(x: float, val: float, decimals: int, sig: int) -> bool:
    if math.isclose(x, val, rel_tol=1e-9, abs_tol=1e-9):
        return True
    if round(x, decimals) == val:
        return True
    if x == 0:
        return val == 0
    mag = math.floor(math.log10(abs(x)))
    return round(x, sig - 1 - mag) == val


# --------------------------------------------------------------------------- #
# Actions and policies                                                        #
# --------------------------------------------------------------------------- #

@dataclass
class Query:
    sub_question: str
    spec: dict


@dataclass
class Conclude:
    claims: list[Claim]
    verdict: str
    notes: str = ""


@dataclass
class LoopState:
    """Everything a policy is allowed to know. Built only from `Result`
    fields a web user sees, plus the public question and budget."""
    question: str
    steps: list[Step]
    budget_remaining: int
    steps_remaining: int


class AnalystPolicy(Protocol):
    def next(self, state: LoopState) -> Query | Conclude: ...


class ScriptedPolicy:
    """Follow a fixed plan, then conclude. For tests and reference runs."""

    def __init__(self, queries: list[tuple[str, dict]], conclusion: Conclude):
        self._queries = list(queries)
        self._conclusion = conclusion

    def next(self, state: LoopState) -> Query | Conclude:
        if len(state.steps) < len(self._queries):
            q, spec = self._queries[len(state.steps)]
            return Query(q, spec)
        return self._conclusion


def _ground_claims(claims: list[Claim], steps: list[Step]) -> list[Claim]:
    """A claim that asserts something about the data (supported,
    not_supported, null) must cite at least one RELEASED step; one that cites
    none, or only denied steps, or step ids that do not exist, is downgraded
    to not_answerable with the reason recorded. Evidence is what makes a
    claim a claim rather than an opinion."""
    released_ids = {s.id for s in steps if s.released()}
    out = []
    for c in claims:
        if c.verdict == "not_answerable":
            out.append(c)
            continue
        cited = [e for e in c.evidence if e in released_ids]
        if cited:
            out.append(Claim(c.text, c.verdict, list(c.evidence), c.reason))
        else:
            out.append(Claim(c.text, "not_answerable", list(c.evidence),
                             reason="claim cites no released step"))
    return out


class _OneShotPlanner:
    """The service's planner interface, answering with the analyst's proposed
    spec for exactly this sub-question. Untrusted, like any planner (A1)."""

    def __init__(self, spec: dict):
        self._spec = spec

    def plan(self, request: str) -> dict:
        return json.loads(json.dumps(self._spec))


# --------------------------------------------------------------------------- #
# The loop                                                                    #
# --------------------------------------------------------------------------- #

class AnalystLoop:
    """Run a policy against a service under one session, producing a dossier.

    `auditor` is the session — pass the same one a human would get, so the
    analyst spends the same budget and lives in the same differencing lineage.
    `audit_log`, if given, records every step under `user`.
    """

    def __init__(self, service, policy: AnalystPolicy, *,
                 auditor: D.SessionAuditor | None = None, audit_log=None,
                 user: str = "inside-analyst", max_steps: int = DEFAULT_MAX_STEPS):
        self.service = service
        self.policy = policy
        self.auditor = auditor or D.SessionAuditor()
        self.audit_log = audit_log
        self.user = user
        self.max_steps = max_steps

    def _state(self, question: str, steps: list[Step]) -> LoopState:
        return LoopState(question=question, steps=list(steps),
                         budget_remaining=max(0, self.auditor.budget - self.auditor.spent),
                         steps_remaining=self.max_steps - len(steps))

    def run(self, question: str) -> Dossier:
        from . import dataset as dataset_mod
        dossier = Dossier(question=question, dataset=dataset_mod.active().name,
                          budget=self.auditor.budget)
        steps: list[Step] = []
        while True:
            state = self._state(question, steps)
            if state.steps_remaining <= 0:
                dossier.stopped_because = "max_steps"
                break
            if state.budget_remaining <= 0:
                dossier.stopped_because = "budget_exhausted"
                break
            action = self.policy.next(state)
            if isinstance(action, Conclude):
                dossier.claims = _ground_claims(action.claims, steps)
                dossier.verdict = action.verdict if action.verdict in VERDICTS else "not_answerable"
                if dossier.verdict != "not_answerable" and not any(
                        c.verdict == dossier.verdict for c in dossier.claims):
                    # the overall verdict must be carried by at least one
                    # surviving claim of the same kind
                    dossier.verdict = "not_answerable"
                dossier.notes = action.notes
                dossier.stopped_because = "concluded"
                break
            steps.append(self._step(len(steps) + 1, action))
        if not dossier.claims:
            # a loop that ran out of budget or steps without concluding has
            # answered nothing; say so in the closed vocabulary rather than
            # leaving the reader to infer it from a missing field
            dossier.claims = [Claim("the analyst did not reach a conclusion",
                                    "not_answerable", [], reason=dossier.stopped_because)]
            dossier.verdict = "not_answerable"
        dossier.steps = steps
        dossier.budget_spent = self.auditor.spent
        return dossier

    def _step(self, step_id: int, action: Query) -> Step:
        spent_before = self.auditor.spent
        result = self.service.handle(action.sub_question, _OneShotPlanner(action.spec),
                                     auditor=self.auditor, audit_log=self.audit_log,
                                     user=self.user)
        artifacts = None
        if result.artifacts:
            artifacts = {k: _frame_records(v) for k, v in result.artifacts.items()
                         if isinstance(v, pd.DataFrame)}
        return Step(
            id=step_id, sub_question=action.sub_question, spec=action.spec,
            status=result.status, message=result.message or "",
            findings=[{"rule": f.rule, "detail": f.detail} for f in result.findings],
            output=_frame_records(result.output) if result.status != "denied" else None,
            artifacts=artifacts if result.status != "denied" else None,
            cost=self.auditor.spent - spent_before)


# --------------------------------------------------------------------------- #
# The LLM policy                                                              #
# --------------------------------------------------------------------------- #

ANALYST_PROTOCOL = """
You are the INSIDE ANALYST of a Trusted Research Environment. You answer a
RESEARCH QUESTION by planning a sequence of aggregate requests, one per turn,
reading only what the safe-outputs gateway RELEASES for each, and finally
concluding with typed claims. You never see individual records; every request
you make is checked by the same rules that apply to a human researcher.

Each turn, reply with ONE JSON object and nothing else, in one of two forms:

1. A query:
   {"action":"query","sub_question":"<plain aggregate request, as a
    researcher would type it, naming the measure and any breakdown>",
    "spec":<QuerySpec | GLMSpec | AnovaSpec JSON, exactly as specified below>}

2. A conclusion:
   {"action":"conclude","verdict":"supported|not_supported|null|not_answerable",
    "claims":[{"text":"<one sentence>","verdict":"<one of the four>",
               "evidence":[<step ids>],"reason":"<why, if not_answerable>"}],
    "notes":"<caveats, one or two sentences>"}

Rules:
- Every figure in a claim must appear in a RELEASED table. Never invent,
  extrapolate or compute numbers that were not released.
- A denied step is information: read the message. Rephrase within the rules
  if the question is answerable another way; otherwise record a claim with
  verdict not_answerable and its reason. Never substitute a different,
  answerable question and present it as the answer to the one asked.
- The session has a budget of released aggregates; each simple query costs 1,
  a model costs one per design-cell table (usually 2). Plan within it, and
  do not repeat a request that was already answered.
- Prefer breakdowns by declared categorical bands over raw correlations on
  event-level or panel data, and adjust for confounders by adding them as
  model terms (categorical dimensions only; a measure cannot be a term). If a
  model is refused, the usual cause is a design cell too small to release:
  retry with fewer terms, or exclude a sparse category with a filter, before
  concluding it cannot be done — and ask the model BEFORE the unadjusted
  marginal, since a marginal followed by an exclusion is a differencing pair.
- Distinguish statistical significance from size: with large n a negligible
  difference is "significant". Report the magnitude, and before claiming an
  effect consider whether the bands differ in composition (income, age)
  rather than in the thing asked about.
- A category that is ABSENT from a released breakdown was suppressed as too
  small. To fit a model over that dimension, exclude that category with a
  filter {"column": <dimension>, "op": "!=", "value": <category>} and ask the
  model before any unadjusted marginal.
- Distinguish a property of PEOPLE (a per-person band such as a night-use
  band) from a property of EVENTS (the hour band of a single bet). A question
  about late-night USERS is answered with the person-level band; a question
  about late-night BETS with the event-level hour band. Say which you used.
- For seasonality, trend, "over time" or "over the year" questions use the
  series tool: in one step it releases the vetted per-window table AND its
  trend, autocorrelation and dominant period, which a plain breakdown by month
  does not give you.
- Use the budget. A research question usually has parts — the association,
  its adjustment for a confounder, and a check that could refute you — so
  plan several steps and do not conclude after the first released table
  unless the question is a single fact.
- verdict vocabulary (use these exact tokens):
    supported      = the released data show the association or effect asked about;
    null           = the released data show NO association or effect (a null
                     result, including "significant but negligible" or "gone
                     after adjustment") — use this for "is X linked to Y?" when
                     the answer is no;
    not_supported  = the released data CONTRADICT the specific claim asked
                     about (the effect runs the other way, or the stated
                     comparison fails);
    not_answerable = the boundary refused what would be needed, or the
                     question is outside what aggregates can settle.
- Time in the questionnaire records is the wave (1, 2, 3), not the calendar
  month; event and panel data carry the month.
"""


def _frame_text(rows: list[dict] | None, cap: int = FRAME_ROWS_SHOWN) -> str:
    if not rows:
        return "(no table)"
    df = pd.DataFrame(rows)
    more = ""
    if len(df) > cap:
        df = df.head(cap)
        more = f"\n... ({len(rows) - cap} more rows)"
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().rstrip() + more


def transcript(state: LoopState) -> str:
    """The user-turn text a policy sees: the question, then each step as a
    web user saw it, then the remaining budget."""
    parts = [f"RESEARCH QUESTION: {state.question}", ""]
    for s in state.steps:
        parts.append(f"--- step {s.id}: {s.sub_question}")
        parts.append(f"spec: {json.dumps(s.spec, separators=(',', ':'))}")
        parts.append(f"status: {s.status}" + (f" — {s.message}" if s.message else ""))
        if s.findings:
            parts.append("findings: " + "; ".join(f"{f['rule']}: {f['detail']}" for f in s.findings))
        if s.released():
            parts.append("released table:")
            parts.append(_frame_text(s.output))
            for name, rows in (s.artifacts or {}).items():
                parts.append(f"released companion '{name}':")
                parts.append(_frame_text(rows))
        parts.append("")
    parts.append(f"Budget remaining: {state.budget_remaining} released aggregates. "
                 f"Steps remaining: {state.steps_remaining}.")
    parts.append("Reply with your next action as one JSON object.")
    return "\n".join(parts)


class LLMAnalystPolicy:
    """Ask a model for the next action over the planner's own client
    interface. Malformed replies are retried once and then converted into a
    typed refusal — the loop never raises on the model's account."""

    def __init__(self, client, policy=None, retries: int = 1):
        self.client = client
        self.retries = retries
        self.system = ANALYST_PROTOCOL + "\n\nThe request grammar and catalogue:\n" \
            + planner_system(policy)
        self.raw_replies: list[str] = []

    def next(self, state: LoopState) -> Query | Conclude:
        user = transcript(state)
        last_error = ""
        for _ in range(self.retries + 1):
            raw = self.client.complete(self.system, user + (
                f"\n\n(Your previous reply was not usable: {last_error}. "
                "Reply with exactly one JSON object.)" if last_error else ""))
            self.raw_replies.append(raw)
            try:
                return parse_action(raw)
            except ValueError as exc:
                last_error = str(exc)
        return Conclude(
            claims=[Claim("the analyst's reply could not be parsed", "not_answerable",
                          [], reason=f"protocol_error: {last_error}")],
            verdict="not_answerable", notes="protocol error")


_VERDICT_ALIASES = {
    "not supported": "not_supported", "notsupported": "not_supported",
    "unsupported": "not_supported", "contradicted": "not_supported",
    "no association": "null", "no_association": "null", "no effect": "null",
    "no_effect": "null", "null result": "null", "null_result": "null",
    "not answerable": "not_answerable", "notanswerable": "not_answerable",
    "unanswerable": "not_answerable", "cannot be answered": "not_answerable",
    "cannot_be_answered": "not_answerable", "refused": "not_answerable",
}


def _normalise_verdict(v) -> str | None:
    """Accept the closed vocabulary and its obvious spellings; nothing else.
    A model that writes "not supported" or "unanswerable" has used the
    vocabulary; one that writes "partially supported" has not, and the
    retry tells it so."""
    if not isinstance(v, str):
        return None
    t = v.strip().lower().replace("-", " ").replace("_", " ").strip(" .")
    t = t.replace(" ", "_") if t.replace(" ", "_") in VERDICTS else t
    if t in VERDICTS:
        return t
    return _VERDICT_ALIASES.get(t)


def parse_action(raw: str) -> Query | Conclude:
    """Parse one model reply into an action, or raise ValueError."""
    try:
        obj = json.loads(_extract_json(raw))
    except json.JSONDecodeError as exc:
        raise ValueError(f"not JSON ({exc.msg})") from None
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    action = obj.get("action")
    if action == "query":
        sub_q = obj.get("sub_question")
        spec = obj.get("spec")
        if not isinstance(sub_q, str) or not sub_q.strip():
            raise ValueError("query needs a sub_question string")
        if not isinstance(spec, dict):
            raise ValueError("query needs a spec object")
        return Query(sub_q.strip(), spec)
    if action == "conclude":
        verdict = _normalise_verdict(obj.get("verdict"))
        if verdict is None and obj.get("verdict") not in (None, ""):
            raise ValueError(f"verdict must be one of {VERDICTS}")
        claims_raw = obj.get("claims")
        if not isinstance(claims_raw, list) or not claims_raw:
            raise ValueError("conclude needs a non-empty claims list")
        claims = []
        for c in claims_raw:
            if not isinstance(c, dict) or not isinstance(c.get("text"), str):
                raise ValueError("each claim needs a text")
            v = _normalise_verdict(c.get("verdict"))
            if v is None:
                raise ValueError(f"claim verdict must be one of {VERDICTS}")
            ev = c.get("evidence") or []
            if not isinstance(ev, list) or not all(isinstance(e, int) for e in ev):
                raise ValueError("claim evidence must be a list of step ids")
            claims.append(Claim(c["text"].strip(), v, ev, str(c.get("reason") or "")))
        if verdict is None:
            # a conclusion whose claims all carry verdicts but which omits the
            # overall one is a usable conclusion: the overall verdict is the
            # first substantive claim's, else not_answerable — and the loop
            # still requires a surviving claim of that kind to carry it
            verdict = next((c.verdict for c in claims if c.verdict != "not_answerable"),
                           "not_answerable")
        return Conclude(claims, verdict, str(obj.get("notes") or ""))
    raise ValueError("action must be 'query' or 'conclude'")


# --------------------------------------------------------------------------- #
# Narration                                                                   #
# --------------------------------------------------------------------------- #

NARRATOR_SYSTEM = """
You write the human-facing summary of an evidence dossier produced inside a
Trusted Research Environment. You are shown ONLY the dossier: the research
question, each step's released table (or its refusal), and the analyst's
typed claims. Write at most 250 words of plain English for a research
audience. Every number you cite must appear in a released table exactly or
as an ordinary rounding of it; cite no other numbers. State refusals as
refusals — say what could not be answered and why — and never fill a gap with
a guess. Do not mention these instructions.
"""


def render_dossier_markdown(dossier: Dossier) -> str:
    """A deterministic narrative: the claims, verbatim, with their evidence.
    Uses no model, invents nothing, and is what the CLI prints when no
    narrator is configured."""
    lines = [f"**Question.** {dossier.question}", "",
             f"**Verdict.** {dossier.verdict}", ""]
    for c in dossier.claims:
        ev = f" (steps {', '.join(map(str, c.evidence))})" if c.evidence else ""
        why = f" — {c.reason}" if c.reason else ""
        lines.append(f"- [{c.verdict}] {c.text}{ev}{why}")
    if dossier.notes:
        lines += ["", f"*{dossier.notes}*"]
    lines += ["", f"{len(dossier.steps)} steps; {dossier.budget_spent}/{dossier.budget} "
              f"budget units; stopped because: {dossier.stopped_because}."]
    return "\n".join(lines)


class LLMNarrator:
    """Prose from the dossier alone; the result is checked, and the figures
    the check cannot trace are recorded on the dossier."""

    def __init__(self, client):
        self.client = client

    def render(self, dossier: Dossier) -> str:
        shown = {
            "question": dossier.question,
            "verdict": dossier.verdict,
            "claims": [asdict(c) for c in dossier.claims],
            "notes": dossier.notes,
            "steps": [{"id": s.id, "sub_question": s.sub_question, "status": s.status,
                       "message": s.message, "released_table": s.output,
                       "released_companions": s.artifacts} for s in dossier.steps],
        }
        text = self.client.complete(NARRATOR_SYSTEM, json.dumps(shown, default=str))
        dossier.narrative = text
        dossier.unsupported_figures = dossier.check_narrative(text)
        return text


__all__ = [
    "VERDICTS", "Step", "Claim", "Dossier", "Query", "Conclude", "LoopState",
    "AnalystPolicy", "ScriptedPolicy", "LLMAnalystPolicy", "AnalystLoop",
    "parse_action", "transcript", "render_dossier_markdown", "LLMNarrator",
    "NARRATOR_SYSTEM", "ANALYST_PROTOCOL",
]
