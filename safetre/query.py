"""QuerySpec — the security boundary.

The (untrusted) LLM never writes code or SQL. It may only propose a QuerySpec:
a declarative aggregate query over an allowlisted catalogue. Pydantic validates
it; anything off-allowlist is rejected before any execution. This makes the
entire query space enumerable and auditable, and removes the code/SQL-injection
surface by construction.

Direct identifiers (donor_id), free text, and raw timestamps are deliberately
absent from every allowlist. Some high-granularity variables, such as raw age,
may appear only in internal analysis allowlists for fixed tools. They cannot be
grouped, selected, or returned.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# Fixed catalogue of pre-joined, read-only datasets. dim type -> allowed ops.
# - dims: public dimensions; may be filtered, grouped, and returned as group keys
# - measures: public numeric measures; may be aggregated and used in corr
# - internal_filters: internal-only predicates; may filter but never group/output
# - internal_measures: internal-only numeric variables for fixed tools such as corr
CATALOGUE: dict[str, dict[str, Any]] = {
    "spend": {
        "dims": {
            "age_band": "cat", "sex": "cat", "region": "cat", "income_band": "cat",
            "device_os": "cat", "genre": "cat", "contains_lootboxes": "bool",
            "price_tier": "cat", "event_type": "cat", "age_rating": "int",
        },
        "measures": {"amount_gbp", "ingame_currency"},
        "internal_filters": {"age_years": "int"},
        "internal_measures": set(),
    },
    "donor_spend": {
        "dims": {
            "age_band": "cat", "sex": "cat", "region": "cat", "income_band": "cat",
            "device_os": "cat",
        },
        "measures": {"total_spend_gbp", "purchase_events", "lootbox_events"},
        "internal_filters": {"age_years": "int"},
        "internal_measures": {"age_years"},
    },
    "wellbeing": {
        "dims": {
            "age_band": "cat", "sex": "cat", "region": "cat", "income_band": "cat",
            "device_os": "cat", "wave": "int",
        },
        "measures": {"pgsi_score", "igds_score", "wemwbs_score", "monthly_spend_selfreport"},
        "internal_filters": {"age_years": "int"},
        "internal_measures": set(),
    },
}

CAT_OPS = {"==", "!=", "in"}
NUM_OPS = {"==", "!=", "<", "<=", ">", ">=", "in"}
MAX_GROUP_BY = 3
MAX_FILTERS = 5
MAX_IN_VALUES = 50      # cap `in` lists to bound query cost (DoS)


class Measure(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fn: Literal["count", "mean", "sum", "sum_sq", "corr"]
    column: str | None = None
    x: str | None = None
    y: str | None = None


class Filter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    column: str
    op: Literal["==", "!=", "<", "<=", ">", ">=", "in"]
    value: Any


class QuerySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")   # reject unknown fields from the model
    dataset: Literal["spend", "donor_spend", "wellbeing"]
    measure: Measure
    group_by: list[str] = []
    filters: list[Filter] = []

    @field_validator("group_by")
    @classmethod
    def _limit_groupby(cls, v):
        if len(v) > MAX_GROUP_BY:
            raise ValueError(f"at most {MAX_GROUP_BY} group-by dimensions")
        if len(v) != len(set(v)):
            raise ValueError("group-by dimensions must be unique")
        return v

    @field_validator("filters")
    @classmethod
    def _limit_filters(cls, v):
        if len(v) > MAX_FILTERS:
            raise ValueError(f"at most {MAX_FILTERS} filters")
        return v

    @model_validator(mode="after")
    def _check_allowlist(self):
        # late import: procedures type-imports Measure/QuerySpec from here
        from .procedures import get_procedure

        cat = CATALOGUE[self.dataset]
        dims = cat["dims"]
        internal_filters = cat.get("internal_filters", {})

        # measure: the registered procedure owns its admissibility check (O1);
        # an unregistered fn fails loudly here even if the Literal grows (R14)
        get_procedure(self.measure.fn).validate_measure(self.measure, cat, self.dataset)

        # group-by must be allowlisted dimensions
        for g in self.group_by:
            if g not in dims:
                raise ValueError(f"group-by {g!r} is not a permitted dimension")

        # filters: allowlisted dims, op valid for type, value type-checked
        for f in self.filters:
            filter_columns = dims | internal_filters
            if f.column not in filter_columns:
                raise ValueError(f"filter column {f.column!r} is not a permitted dimension")
            kind = filter_columns[f.column]
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
        if f.op == "in" and len(f.value) == 0:
            raise ValueError("`in` list cannot be empty")
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
        if self.measure.fn == "corr":
            x, y = sorted((self.measure.x or "", self.measure.y or ""))
            return f"{self.dataset}:corr:{x}:{y}"
        return f"{self.dataset}:{self.measure.fn}:{self.measure.column or '*'}"

    def normalized_filters(self) -> tuple:
        """Canonical, order-independent form of the filter set — the query's
        *cohort* identity for session lineage auditing.

        Filters are deduplicated and sorted; single-element `in` lists collapse
        to `==` so semantically identical cohorts compare equal.
        """
        norm = set()
        for f in self.filters:
            if f.op == "in":
                vals = tuple(sorted(set(f.value), key=repr))
                if len(vals) == 1:
                    norm.add((f.column, "==", vals[0]))
                else:
                    norm.add((f.column, "in", vals))
            else:
                norm.add((f.column, f.op, f.value))
        return tuple(sorted(norm, key=repr))
