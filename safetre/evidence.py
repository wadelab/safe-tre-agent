"""Evidence lineage: giving every released number a machine identity (M3).

*A manuscript says "stake rose from £8.97 to £45.20 across night-use bands". A
reviewer cannot check that against a private dataset, and should not have to
take the sentence's word for which query produced it. An `EvidenceItem` is the
number, the cell it belongs to, the stage that computed it and the audit row
that released it — one object, one stable identity.*

Four kinds come from the build plan and a fifth is added here:

    GroupStatistic       one cell of a released aggregate
    ModelCoefficient     one estimated coefficient of a released fit
    ConfidenceInterval   an interval released alongside an estimate
    NotAnswerable        the gateway released nothing for this sub-question
    ModelFit             the released fit block (n, cells, parameters, df)

`ModelFit` is a deliberate addition, not drift. Milestone 3's acceptance test is
that *every released numeric claim maps to an evidence item*, and the model path
releases a summary block as well as coefficients; filing those numbers under
"provenance metadata" would have satisfied the type list by putting released
numbers somewhere the lineage checks do not look. A number that left the
gateway is evidence, whatever it is evidence of.

## Identity, and why the figure label is not part of it

`manuscript_ref` ("Figure 2b") is metadata. `identity_digest` covers the kind,
the stage, the procedure, the keys, the values and the precision — and not the
label — so moving a result from Figure 2b to Figure 3a leaves the scientific
artifact identical, which is what it is. The bundle's evidence ids are derived
from that digest, so the same analysis over the same snapshot yields the same
ids on any machine.

## What an evidence item may cite

Not a denied stage, and not a privileged probe. Both rules live in
`ResearchRecord.validate_record`, because they are properties of the record as a
whole; what lives here is the extraction that never creates such an item in the
first place. `NotAnswerable` is the one kind that may cite a stage that released
nothing, because that is precisely its claim — and it carries no values, so
there is no withheld number inside it to leak.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from .research_record import (
    EvidenceItem, EvidenceKind, RecordError, StageRecord, StageType,
)

GROUP_STATISTIC = EvidenceKind.GROUP_STATISTIC
MODEL_COEFFICIENT = EvidenceKind.MODEL_COEFFICIENT
CONFIDENCE_INTERVAL = EvidenceKind.CONFIDENCE_INTERVAL
NOT_ANSWERABLE = EvidenceKind.NOT_ANSWERABLE
MODEL_FIT = EvidenceKind.MODEL_FIT

KINDS = tuple(EvidenceKind)

# Columns a released aggregate frame uses for the measured value and its cell
# size. Everything else in the row is a cell key.
_VALUE_COLUMNS = ("value", "mean", "estimate")
_SIZE_COLUMNS = ("n", "n_donors")

# Suffix -> unit, for the one thing a bare number cannot say about itself.
_UNITS = {"_gbp": "GBP", "_minutes": "minutes", "_pct": "percent"}


def _units_for(column: str | None) -> str | None:
    if not column:
        return None
    for suffix, unit in _UNITS.items():
        if column.endswith(suffix):
            return unit
    return None


def _precision_of(value: Any) -> int | None:
    """Decimal places in a released value, as released.

    Read off the value rather than off the policy, because the policy's rounding
    base is what the gateway *may* apply and this is what it *did*: a reviewer
    reproducing "45.2" needs to know the number was released to one decimal, and
    reading that from the value cannot disagree with the value.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    exponent = Decimal(str(value)).as_tuple().exponent
    return -int(exponent) if isinstance(exponent, int) and exponent < 0 else 0


def _evidence_id(item: EvidenceItem) -> str:
    return "ev-" + item.identity_digest()[:16]


def _finish(kind: EvidenceKind, stage: StageRecord, keys: dict[str, Any],
            values: dict[str, Any], *, procedure: str, units: str | None,
            precision: int | None) -> EvidenceItem:
    draft = EvidenceItem(
        evidence_id="pending", kind=kind, source_stage=stage.stage_id,
        audit_ref=stage.audit_ref, procedure=procedure, keys=keys, values=values,
        precision=precision, units=units)
    return draft.model_copy(update={"evidence_id": _evidence_id(draft)})


def _measure_column(stage: StageRecord) -> str | None:
    params = stage.public_parameters
    if params.get("response"):
        return str(params["response"])
    measure = params.get("measure") or {}
    return measure.get("column")


def _split_row(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """A released aggregate row, split into what it is about and what it says."""
    keys, values = {}, {}
    for column, cell in row.items():
        if column in _VALUE_COLUMNS or column in _SIZE_COLUMNS:
            values[column] = cell
        else:
            keys[column] = cell
    return keys, values


def _primary(values: dict[str, Any]) -> Any:
    for column in _VALUE_COLUMNS:
        if column in values:
            return values[column]
    return None


def from_aggregate(stage: StageRecord, rows: list[dict[str, Any]]) -> list[EvidenceItem]:
    column = _measure_column(stage)
    units = _units_for(column)
    out = []
    for row in rows:
        keys, values = _split_row(row)
        out.append(_finish(GROUP_STATISTIC, stage, keys, values,
                           procedure=stage.procedure, units=units,
                           precision=_precision_of(_primary(values))))
    return out


def from_coefficients(stage: StageRecord, rows: list[dict[str, Any]]) -> list[EvidenceItem]:
    units = _units_for(_measure_column(stage))
    out = []
    for row in rows:
        keys = {k: v for k, v in row.items() if k in ("term", "level")}
        values = {k: v for k, v in row.items() if k not in ("term", "level")}
        kind = (CONFIDENCE_INTERVAL if {"ci_low", "ci_high"} <= set(values)
                else MODEL_COEFFICIENT)
        out.append(_finish(kind, stage, keys, values, procedure=stage.procedure,
                           units=units, precision=_precision_of(values.get("estimate"))))
    return out


def from_fit_block(stage: StageRecord, rows: list[dict[str, Any]]) -> list[EvidenceItem]:
    return [_finish(MODEL_FIT, stage, {}, dict(row), procedure=stage.procedure,
                    units=None, precision=None)
            for row in rows]


def not_answerable(stage: StageRecord, reason: str = "") -> EvidenceItem:
    """A claim that the gateway released nothing here.

    Carries `reason` only as a key, and callers must pass a REQUEST-decided one
    or nothing at all. The gateway's own message for a data-derived refusal is
    already the single canonical sentence for exactly this reason: what
    distinguishes one withheld cohort from another is a fact about the records
    it withheld.
    """
    return _finish(NOT_ANSWERABLE, stage, {"reason": reason or "nothing released"},
                   {}, procedure=stage.procedure, units=None, precision=None)


def extract(stage: StageRecord, *, output: list[dict[str, Any]] | None,
            artifacts: dict[str, list[dict[str, Any]]] | None = None,
            include_not_answerable: bool = False) -> list[EvidenceItem]:
    """Every released number of one stage, as evidence.

    Takes the released rows from the caller rather than reading them off the
    stage record: a `StageRecord` deliberately does not carry released values —
    it carries commitments to them — and having the extractor reach for values
    that are not there would have been the reason to put them there.
    """
    if stage.stage_type is StageType.PROBE:
        raise RecordError(
            f"stage {stage.stage_id!r} is a privileged probe; its result is "
            "what the gateway withheld, and it is not evidence of anything")
    if not stage.released():
        if include_not_answerable:
            return [not_answerable(stage)]
        return []

    items: list[EvidenceItem] = []
    artifacts = artifacts or {}
    if stage.stage_type is StageType.MODEL:
        items += from_coefficients(stage, output or [])
        items += from_aggregate(stage, artifacts.get("cells", []))
        items += from_fit_block(stage, artifacts.get("model", []))
    else:
        items += from_aggregate(stage, output or [])
        for name, rows in sorted(artifacts.items()):
            items += from_aggregate(stage, rows)
    return items


def extract_run(trace_stages: list[StageRecord], released: dict[str, dict[str, Any]],
                *, include_not_answerable: bool = False) -> list[EvidenceItem]:
    """Evidence for a whole run.

    `released` maps stage id -> {"output": rows, "artifacts": {...}}. Ids are
    checked for collisions rather than deduplicated: two distinct released
    numbers hashing to one identity would mean the identity is not covering
    something that distinguishes them, and quietly dropping one would hide that.
    """
    out: list[EvidenceItem] = []
    seen: set[str] = set()
    for stage in trace_stages:
        if stage.stage_type is StageType.PROBE:
            continue
        bundle = released.get(stage.stage_id, {})
        for item in extract(stage, output=bundle.get("output"),
                            artifacts=bundle.get("artifacts"),
                            include_not_answerable=include_not_answerable):
            if item.evidence_id in seen:
                raise RecordError(
                    f"two released values share evidence id {item.evidence_id!r}; "
                    "the identity is not distinguishing them")
            seen.add(item.evidence_id)
            out.append(item)
    return out


def render(item: EvidenceItem) -> str:
    """The reported number, rendered deterministically from the evidence alone.

    Milestone 3's last acceptance test: a reviewer regenerating the reported
    figure from the bundle must get the number that was released. Rendering
    from `values` at the recorded `precision` is the whole mechanism — there is
    no path here back to the data.
    """
    if item.kind is NOT_ANSWERABLE:
        return "not answerable"
    value = _primary(item.values)
    if value is None:
        value = item.values.get("estimate")
    if value is None:
        return ", ".join(f"{k}={v}" for k, v in sorted(item.values.items()))
    if isinstance(value, (int, float)) and not isinstance(value, bool) and item.precision:
        text = f"{value:.{item.precision}f}"
    else:
        text = str(value)
    return f"{text} {item.units}" if item.units else text


def label(item: EvidenceItem, manuscript_ref: str) -> EvidenceItem:
    """Attach a publication label without changing what the evidence IS."""
    return item.model_copy(update={"manuscript_ref": manuscript_ref})


__all__ = ["CONFIDENCE_INTERVAL", "GROUP_STATISTIC", "KINDS", "MODEL_COEFFICIENT",
           "MODEL_FIT", "NOT_ANSWERABLE", "extract", "extract_run", "from_aggregate",
           "from_coefficients", "from_fit_block", "label", "not_answerable", "render"]
