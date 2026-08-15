"""Locked analysis plans (spec R20, P24) — the data-sighted tier, made safe.

This is the phase-3 core of the inside analyst ("Chimp"). Phase 1 kept the
analyst on the PUBLIC side of the gateway: it read only released results, so
its every choice was one a human at the web page could have made, and the
disclosure argument was inherited unchanged (P23). The value it left behind is
the choices a *data-sighted* analyst would make — above all: "the adjusted
model was refused because one category is too sparse; drop that category and
refit." In a cells-first system there are no row residuals, so "unvetted
intermediate" means precisely *the cells the gateway withheld* — and a model
that any suppressed design cell denies (P19) gives the analyst NO cell table,
so *which* level was sparse is hidden on purpose. The canonical refusal is a
cohort-structure oracle exactly so that it cannot be read (hardening #30, #66).

So a data-sighted decision cannot be made ad hoc by a model in the loop. It
can only be made if it is:

  1. DECLARED IN ADVANCE. A `Plan` is a typed, finite program — ordered
     stages, each an ordinary spec, some guarded by an earlier stage's vetting
     OUTCOME (public: the analyst saw it anyway), at most one carrying a
     data-sighted contingency.
  2. COMMITTED before it runs. The plan's canonical hash is written to the
     audit chain (`status="plan"`) before any stage executes, so the plan a
     release came from is fixed and attributable — selection cannot be
     conditioned on results the plan has not yet seen.
  3. EXECUTED by deterministic code, never a model. `PlanExecutor` runs the
     stages through the unchanged `QueryService`; the one contingency rewrites
     a filter by a rule, and no free choice enters.
  4. METERED. The only data-sighted operation is `exclude_sparse`: it runs a
     PRIVILEGED probe (`engine.sparse_levels`) for the levels of a dimension
     whose cells fall below the threshold in the cohort, excludes them, and
     charges ONE BIT PER REVEALED LEVEL to the session's selection ledger
     (`SessionAuditor.charge_selection`) against `selection_budget_bits`
     (default 4; the round-8 existence attack recovered a unique donor with
     eight). Over budget → the stage is refused and nothing is spent, because
     the fact that a contingency was unaffordable is a fact about the plan,
     not the data.

Every released stage still passes the whole gateway, so no VALUE escapes that
a single query could not have released. What R20 adds is a bounded, logged,
replayable channel for the SELECTION a data-sighted analyst needs — an interim
the differential-privacy accountant (roadmap 3) is the principled replacement
for. The exact sparse counts are never released; only the branch taken shows,
in the executed spec, and it is paid for.

The plan is data, not code: `Plan` is a Pydantic model with a closed
vocabulary, as enumerable and inert as a QuerySpec. `PlanExecutor` is the only
new trusted surface and makes no disclosure decision of its own — it charges
bits, rewrites one filter, and calls the service.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Literal

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import dataset as _dataset
from . import disclosure as D
from .service import Result, frame_digest  # noqa: F401  (frame_digest re-exported for callers)

# A guard is decided from an earlier stage's VETTING OUTCOME — which a human
# analyst sees for free — never from a withheld number.
GUARD_STATUSES = ("released", "redacted", "denied", "review")


class ExcludeSparse(BaseModel):
    """The one data-sighted contingency: before running this stage, exclude
    the levels of `dimension` whose cells are below the threshold in this
    stage's own cohort. Charged one bit per excluded level (P24)."""
    model_config = ConfigDict(extra="forbid")
    kind: Literal["exclude_sparse"] = "exclude_sparse"
    dimension: str


class Guard(BaseModel):
    """Run this stage only if an earlier stage ended in one of `statuses`."""
    model_config = ConfigDict(extra="forbid")
    from_stage: str
    statuses: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _known(self):
        bad = [s for s in self.statuses if s not in GUARD_STATUSES]
        if bad:
            raise ValueError(f"guard statuses {bad!r} not in {GUARD_STATUSES}")
        return self


class Stage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    sub_question: str
    spec: dict
    guard: Guard | None = None
    contingency: ExcludeSparse | None = None

    @model_validator(mode="after")
    def _ident(self):
        if not self.id or not self.id.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"stage id {self.id!r} must be alphanumeric")
        return self


class Plan(BaseModel):
    """A locked analysis plan: ordered stages with unique ids, where every
    guard names an EARLIER stage."""
    model_config = ConfigDict(extra="forbid")
    question: str
    stages: list[Stage] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def _wellformed(self):
        seen: set[str] = set()
        for st in self.stages:
            if st.id in seen:
                raise ValueError(f"duplicate stage id {st.id!r}")
            if st.guard is not None and st.guard.from_stage not in seen:
                raise ValueError(
                    f"stage {st.id!r} guard names {st.guard.from_stage!r}, "
                    "which is not an EARLIER stage")
            seen.add(st.id)
        return self

    def canonical_hash(self) -> str:
        """A stable digest of the plan, committed to the audit chain before
        execution (R20). Order-sensitive, whitespace-insensitive."""
        payload = json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# execution                                                                   #
# --------------------------------------------------------------------------- #

@dataclass
class StageResult:
    id: str
    sub_question: str
    status: str                       # released | redacted | denied | review | skipped
    spec: dict | None = None
    message: str = ""
    findings: list[dict] = field(default_factory=list)
    output: list[dict] | None = None
    artifacts: dict[str, list[dict]] | None = None
    output_sha256: str | None = None   # stage commitment (R20)
    selection_bits: int = 0            # bits this stage spent (P24)
    excluded: list[str] = field(default_factory=list)   # levels the contingency dropped

    def released(self) -> bool:
        return self.status in ("released", "redacted") and self.output is not None


@dataclass
class PlanRun:
    question: str
    plan_hash: str
    stages: list[StageResult] = field(default_factory=list)
    selection_spent: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, **kw) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str, **kw)


def _records(df: pd.DataFrame | None) -> list[dict] | None:
    if df is None:
        return None
    return json.loads(df.to_json(orient="records", date_format="iso"))


class _OneShotPlanner:
    def __init__(self, spec: dict):
        self._spec = spec

    def plan(self, request: str) -> dict:
        return json.loads(json.dumps(self._spec))


class PlanExecutor:
    """Run a committed plan against a service under one session. Deterministic:
    no model, no free choice. Guards read prior vetting outcomes; the one
    contingency runs a privileged sparseness probe, charges its cost in bits,
    and rewrites a filter; every stage goes through the unchanged gateway.
    """

    def __init__(self, service, *, auditor: D.SessionAuditor | None = None,
                 audit_log=None, user: str = "chimp"):
        self.service = service
        self.auditor = auditor or D.SessionAuditor()
        self.audit_log = audit_log
        self.user = user

    def run(self, plan: Plan) -> PlanRun:
        # commit the plan BEFORE any stage runs (R20): the hash is in the chain
        # so the plan a release came from cannot be chosen after the fact
        plan_hash = plan.canonical_hash()
        if self.audit_log is not None:
            self._commit(plan, plan_hash)
        run = PlanRun(question=plan.question, plan_hash=plan_hash)
        by_id: dict[str, StageResult] = {}
        for st in plan.stages:
            sr = self._stage(st, by_id)
            run.stages.append(sr)
            by_id[st.id] = sr
        run.selection_spent = self.auditor.selection_spent
        return run

    def _commit(self, plan: Plan, plan_hash: str) -> None:
        # a metadata record, not a release: status "plan" carries no output and
        # spends no query budget; it fixes the plan in the chain
        self.audit_log.append(
            user=self.user, request=f"[plan] {plan.question}",
            spec={"plan_hash": plan_hash, "stage_ids": [s.id for s in plan.stages]},
            status="plan", findings=[], output_shape=None,
            accounting={"cost": 0, "plan_hash": plan_hash})

    def _stage(self, st: Stage, by_id: dict[str, StageResult]) -> StageResult:
        if st.guard is not None:
            src = by_id.get(st.guard.from_stage)
            if src is None or src.status not in st.guard.statuses:
                return StageResult(st.id, st.sub_question, "skipped",
                                   message=f"guard on {st.guard.from_stage!r} not met")

        spec = dict(st.spec)
        bits, excluded = 0, []
        if st.contingency is not None:
            spec, bits, excluded, refusal = self._apply_contingency(st, spec)
            if refusal is not None:
                return refusal

        res = self.service.handle(st.sub_question, _OneShotPlanner(spec),
                                  auditor=self.auditor, audit_log=self.audit_log,
                                  user=self.user, selection_bits=bits)
        return StageResult(
            id=st.id, sub_question=st.sub_question, status=res.status, spec=spec,
            message=res.message or "",
            findings=[{"rule": f.rule, "detail": f.detail} for f in res.findings],
            output=_records(res.output) if res.status != "denied" else None,
            artifacts=({k: _records(v) for k, v in res.artifacts.items()
                        if isinstance(v, pd.DataFrame)}
                       if (res.artifacts and res.status != "denied") else None),
            output_sha256=frame_digest(res.output) if res.status != "denied" else None,
            selection_bits=bits, excluded=excluded)

    def _apply_contingency(self, st: Stage, spec: dict):
        """Probe for the sparse levels of the contingency's dimension WITHIN
        this stage's own cohort, charge one bit per level, and exclude them.
        Returns (spec, bits, excluded, refusal|None). The probe is privileged
        and its result never released; only the bits and the executed filter
        are observable."""
        dim = st.contingency.dimension
        dataset = spec.get("dataset")
        cat = _dataset.active().catalogue().get(dataset, {})
        if dim not in cat.get("dims", {}):
            return spec, 0, [], StageResult(
                st.id, st.sub_question, "denied",
                message=f"exclude_sparse names {dim!r}, not a dimension of {dataset!r}")

        filters = list(spec.get("filters") or [])
        cohort = _normalized_triples(filters)
        threshold = self.service.policy.threshold
        sparse = self.service.engine.sparse_levels(dataset, dim, cohort, threshold)
        bits = len(sparse)

        if bits and not self.auditor.charge_selection(bits):
            # unaffordable: a fact about the PLAN, not the data — a plain
            # refusal, nothing spent, no numbers
            return spec, 0, [], StageResult(
                st.id, st.sub_question, "denied",
                message="plan's selection budget is exhausted (P24)",
                findings=[{"rule": "selection_budget",
                           "detail": f"contingency needs {bits} bit(s); "
                                     f"{self.auditor.selection_remaining()} remain"}])
        if not sparse:
            return spec, 0, [], None      # nothing sparse, nothing to charge

        for level in sparse:
            filters.append({"column": dim, "op": "!=", "value": level})
        return dict(spec, filters=filters), bits, [str(x) for x in sparse], None


def _normalized_triples(filters: list[dict]) -> tuple:
    """(column, op, value) triples from a stage's raw filter dicts, for the
    privileged cohort probe (mirrors QuerySpec.normalized_filters shape)."""
    out = []
    for f in filters:
        out.append((f["column"], f.get("op", "=="), f.get("value")))
    return tuple(out)


__all__ = ["Plan", "Stage", "Guard", "ExcludeSparse", "PlanExecutor",
           "PlanRun", "StageResult", "GUARD_STATUSES"]
