"""QuerySpec — the security boundary.

The (untrusted) LLM never writes code or SQL. It may only propose a QuerySpec:
a declarative aggregate query over an allowlisted catalogue. Pydantic validates
it; anything off-allowlist is rejected before any execution. This makes the
entire query space enumerable and auditable, and removes the code/SQL-injection
surface by construction.

Deliberately absent from every allowlist: direct identifiers (donor_id),
free text, and high-granularity fields (raw age, timestamps) — they cannot be
named in a query at all.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# Fixed catalogue of pre-joined, read-only datasets. dim type -> allowed ops.
CATALOGUE: dict[str, dict[str, Any]] = {
    "spend": {
        "dims": {
            "age_band": "cat", "sex": "cat", "canton": "cat", "income_band": "cat",
            "device_os": "cat", "genre": "cat", "contains_lootboxes": "bool",
            "price_tier": "cat", "event_type": "cat", "age_rating": "int",
        },
        "measures": {"amount_chf", "ingame_currency"},
    },
    "wellbeing": {
        "dims": {
            "age_band": "cat", "sex": "cat", "canton": "cat", "income_band": "cat",
            "device_os": "cat", "wave": "int",
        },
        "measures": {"pgsi_score", "igds_score", "wemwbs_score", "monthly_spend_selfreport"},
    },
}

CAT_OPS = {"==", "!=", "in"}
NUM_OPS = {"==", "!=", "<", "<=", ">", ">=", "in"}
MAX_GROUP_BY = 3
MAX_FILTERS = 5
MAX_IN_VALUES = 50      # cap `in` lists to bound query cost (DoS)


class Measure(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fn: Literal["count", "mean", "sum"]
    column: str | None = None


class Filter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    column: str
    op: Literal["==", "!=", "<", "<=", ">", ">=", "in"]
    value: Any


class QuerySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")   # reject unknown fields from the model
    dataset: Literal["spend", "wellbeing"]
    measure: Measure
    group_by: list[str] = []
    filters: list[Filter] = []

    @field_validator("group_by")
    @classmethod
    def _limit_groupby(cls, v):
        if len(v) > MAX_GROUP_BY:
            raise ValueError(f"at most {MAX_GROUP_BY} group-by dimensions")
        return v

    @field_validator("filters")
    @classmethod
    def _limit_filters(cls, v):
        if len(v) > MAX_FILTERS:
            raise ValueError(f"at most {MAX_FILTERS} filters")
        return v

    @model_validator(mode="after")
    def _check_allowlist(self):
        cat = CATALOGUE[self.dataset]
        dims, measures = cat["dims"], cat["measures"]

        # measure
        if self.measure.fn == "count":
            if self.measure.column is not None:
                raise ValueError("count takes no column")
        else:
            if self.measure.column not in measures:
                raise ValueError(
                    f"measure column {self.measure.column!r} not allowed for "
                    f"dataset {self.dataset!r} (allowed: {sorted(measures)})")

        # group-by must be allowlisted dimensions
        for g in self.group_by:
            if g not in dims:
                raise ValueError(f"group-by {g!r} is not a permitted dimension")

        # filters: allowlisted dims, op valid for type, value type-checked
        for f in self.filters:
            if f.column not in dims:
                raise ValueError(f"filter column {f.column!r} is not a permitted dimension")
            kind = dims[f.column]
            allowed = CAT_OPS if kind in ("cat", "bool") else NUM_OPS
            if f.op not in allowed:
                raise ValueError(f"operator {f.op!r} not allowed on {f.column!r}")
            self._check_value(f, kind)
        return self

    @staticmethod
    def _check_value(f: Filter, kind: str):
        vals = f.value if f.op == "in" else [f.value]
        if f.op == "in" and not isinstance(f.value, list):
            raise ValueError("`in` requires a list value")
        if f.op == "in" and len(f.value) > MAX_IN_VALUES:
            raise ValueError(f"`in` list too long (max {MAX_IN_VALUES})")
        for v in vals:
            if kind == "cat" and not isinstance(v, str):
                raise ValueError(f"{f.column!r} expects string value(s)")
            if kind == "bool" and not isinstance(v, bool):
                raise ValueError(f"{f.column!r} expects boolean value(s)")
            if kind == "int" and (not isinstance(v, int) or isinstance(v, bool)):
                raise ValueError(f"{f.column!r} expects integer value(s)")

    def measure_key(self) -> str:
        return f"{self.dataset}:{self.measure.fn}:{self.measure.column or '*'}"
