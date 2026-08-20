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

from . import dataset as _dataset

# Fixed catalogue of pre-joined, read-only datasets, mirrored from the ACTIVE
# dataset definition (safetre/dataset.py — the facts are not literals here, so
# the gateway can serve any study an operator describes). dim type -> allowed
# ops.
# - dims: public dimensions; may be filtered, grouped, and returned as group keys
# - measures: public numeric measures; may be aggregated and used in corr
# - internal_filters: internal-only predicates; may filter but never group/output
# - internal_measures: internal-only numeric variables for fixed tools such as corr
CATALOGUE: dict[str, dict[str, Any]] = {}


def _apply(defn) -> None:
    CATALOGUE.clear()
    CATALOGUE.update(defn.catalogue())
    INTERNAL_RANGE_RULES.clear()
    INTERNAL_RANGE_RULES.update(defn.range_rules())


_dataset.register_sync(_apply)

CAT_OPS = {"==", "!=", "in"}
NUM_OPS = {"==", "!=", "<", "<=", ">", ">=", "in"}
MAX_GROUP_BY = 3
MAX_FILTERS = 5
MAX_IN_VALUES = 50      # cap `in` lists to bound query cost (DoS)

# --- internal high-granularity filters: band-aligned ranges only (#39) --------
# An internal filter variable is a differencing channel when it can cut finer
# than the public dimension it backs. A range sweep on exact age
# (age_years >= v for v = 13..69) reconstructs an age histogram the catalogue
# publishes only as bands; an exact-age equality pinpoints a sub-band cohort;
# and two such slices combined with two common narrowing dimensions recover a
# 1-3 donor cell from two large, individually safe releases. Range filters on
# an internal variable must therefore align to the declared band edges — every
# such predicate selects a union of whole bands, whose marginals are public —
# and equality/membership on the raw value is not offered at all. The edges
# mirror the declared public-band domain (tests/test_invariants.py keeps them
# in sync for the demo) and come from the active dataset definition's
# `internal_range_rules`.
INTERNAL_RANGE_RULES: dict[str, dict] = {}

_apply(_dataset.active())

GLM_FAMILIES = ("gaussian", "binomial", "poisson")
# terms bound == MAX_GROUP_BY so every design-cell query is a legal group-by
MAX_MODEL_TERMS = MAX_GROUP_BY


class Measure(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fn: Literal["count", "mean", "sum", "sum_sq", "sum_cube", "sum_quad", "corr"]
    column: str | None = None
    x: str | None = None
    y: str | None = None


class Filter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    column: str
    op: Literal["==", "!=", "<", "<=", ">", ">=", "in"]
    value: Any


def _check_filter_value(f: Filter, kind: str) -> None:
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


def check_filters(dataset: str, filters: list[Filter]) -> None:
    """Filters must name allowlisted (or internal-filter) columns, with an
    operator valid for the column type and type-checked values. Shared by
    QuerySpec and GLMSpec so both boundaries enforce identical rules."""
    cat = CATALOGUE[dataset]
    internal_filters = set(cat.get("internal_filters", {}))
    filter_columns = cat["dims"] | cat.get("internal_filters", {})
    for f in filters:
        if f.column not in filter_columns:
            raise ValueError(f"filter column {f.column!r} is not a permitted dimension")
        kind = filter_columns[f.column]
        allowed = CAT_OPS if kind in ("cat", "bool") else NUM_OPS
        if f.op not in allowed:
            raise ValueError(f"operator {f.op!r} not allowed on {f.column!r}")
        _check_filter_value(f, kind)
        rule = INTERNAL_RANGE_RULES.get(f.column)
        # #39 holds only because every expressible predicate on an internal
        # variable selects a union of whole public bands. A column declared as
        # an internal filter with no range rule would fall through to the
        # generic numeric branch, which permits `==`, `!=`, `in` and arbitrary
        # values -- the exact-age probe #39 closed. Declaring an internal
        # filter is therefore a commitment to declaring its band edges, and
        # the omission fails closed rather than silently reopening the sweep.
        if f.column in internal_filters and rule is None:
            raise ValueError(
                f"internal filter {f.column!r} declares no band-alignment rule; "
                f"internal variables may only be filtered by band-aligned "
                f"ranges (hardening #39)")
        if rule is not None:
            if f.op not in rule["ops"]:
                raise ValueError(
                    f"operator {f.op!r} is not allowed on internal filter "
                    f"{f.column!r}; use a band-aligned range "
                    f"({' or '.join(rule['ops'])})")
            edges = rule["edges"][f.op]
            if f.value not in edges:
                raise ValueError(
                    f"filter on internal variable {f.column!r} must align to "
                    f"the declared band edges ({', '.join(map(str, edges))} "
                    f"for {f.op!r}); the raw values are internal-only")


def check_model_allowlist(dataset: str, response: str, family: str,
                          terms: list[str], filters: list[Filter],
                          term_word: str = "model term") -> None:
    """The allowlist rules EVERY model tool shares (spec R15).

    GLMSpec and AnovaSpec ran five near-identical checks each, written out
    twice. Copy-paste is a poor place to keep a security boundary: the shared
    rules have to be compared line by line to confirm they still agree, and the
    two genuine differences — the family a tool permits, and GLM's reserved
    filter slot — were invisible among them. The differences now live in the
    callers, where they can be seen; the rules live here once.

    `family` is what the TOOL permits, not a free choice: GLM passes the
    analyst's requested family (which the response must declare), ANOVA passes
    `"gaussian"` unconditionally, because a one-way ANOVA is an
    interval-response procedure. `term_word` only names the concept in the
    error an analyst reads ("model term" / "factor").
    """
    cat = CATALOGUE[dataset]
    responses = cat.get("glm_responses", {})

    # the response must be a declared model response that permits this family
    if family not in responses.get(response, ()):
        allowed = sorted(c for c, fams in responses.items() if family in fams)
        raise ValueError(
            f"response {response!r} is not a permitted {family} model response "
            f"for dataset {dataset!r} (allowed: {allowed})")

    for t in terms:
        if t not in cat["dims"]:
            raise ValueError(f"{term_word} {t!r} is not a permitted dimension")

    # a response that is also a term, or filtered, is a model of itself: the
    # design cells would carry the outcome as a key or be cut on it
    if response in terms:
        raise ValueError(f"response cannot also be a {term_word}")
    check_filters(dataset, filters)
    if any(f.column == response for f in filters):
        raise ValueError("response cannot also be filtered in a model query")


def _normalized_filters(filters: list[Filter]) -> tuple:
    norm = set()
    for f in filters:
        if f.op == "in":
            vals = tuple(sorted(set(f.value), key=repr))
            if len(vals) == 1:
                norm.add((f.column, "==", vals[0]))
            else:
                norm.add((f.column, "in", vals))
        else:
            norm.add((f.column, f.op, f.value))
    return tuple(sorted(norm, key=repr))


def _known_dataset(v: str) -> str:
    """The dataset allowlist is the ACTIVE definition's, so it is a runtime
    membership check rather than a static `Literal`: the same code validates
    any study an operator describes."""
    if v not in CATALOGUE:
        raise ValueError(f"unknown dataset {v!r} (known: {sorted(CATALOGUE)})")
    return v


class QuerySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")   # reject unknown fields from the model
    dataset: str
    measure: Measure
    group_by: list[str] = []
    filters: list[Filter] = []

    @field_validator("dataset")
    @classmethod
    def _dataset_known(cls, v):
        return _known_dataset(v)

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

        # measure: the registered procedure owns its admissibility check (O1);
        # an unregistered fn fails loudly here even if the Literal grows (R14)
        get_procedure(self.measure.fn).validate_measure(self.measure, cat, self.dataset)

        # group-by must be allowlisted dimensions
        for g in self.group_by:
            if g not in dims:
                raise ValueError(f"group-by {g!r} is not a permitted dimension")

        # filters: allowlisted dims, op valid for type, value type-checked
        check_filters(self.dataset, self.filters)
        return self

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
        return _normalized_filters(self.filters)


class GLMSpec(BaseModel):
    """A generalized linear model request (spec R15) — the model analogue of
    QuerySpec, and like it a security boundary: typed, allowlisted, finite.

    Categorical terms only (L1). The model never touches rows: it compiles to
    ordinary design-cell QuerySpecs (`group_by = terms`) whose finalized,
    gateway-vetted outputs are the *only* input to the fitter (P21). One filter
    slot is reserved because the binomial successes query appends the
    `response == True` predicate to the analyst's filters.
    """

    model_config = ConfigDict(extra="forbid")
    tool: Literal["glm"] = "glm"
    dataset: str
    family: Literal["gaussian", "binomial", "poisson"]
    response: str
    terms: list[str]
    filters: list[Filter] = []

    @field_validator("dataset")
    @classmethod
    def _dataset_known(cls, v):
        return _known_dataset(v)

    @field_validator("terms")
    @classmethod
    def _limit_terms(cls, v):
        if not 1 <= len(v) <= MAX_MODEL_TERMS:
            raise ValueError(f"between 1 and {MAX_MODEL_TERMS} model terms")
        if len(v) != len(set(v)):
            raise ValueError("model terms must be unique")
        return v

    @field_validator("filters")
    @classmethod
    def _limit_filters(cls, v):
        if len(v) > MAX_FILTERS - 1:
            raise ValueError(
                f"at most {MAX_FILTERS - 1} filters on a model "
                f"(one slot is reserved for the response predicate)")
        return v

    @model_validator(mode="after")
    def _check_allowlist(self):
        # the analyst chooses the family; the response must declare it
        check_model_allowlist(self.dataset, self.response, self.family,
                              self.terms, self.filters, "model term")
        return self

    def model_key(self) -> str:
        return (f"{self.dataset}:glm:{self.family}:{self.response}"
                f"~{'+'.join(sorted(self.terms))}")

    def normalized_filters(self) -> tuple:
        return _normalized_filters(self.filters)


class SeriesSpec(BaseModel):
    """A time-series request (spec R15): a vetted per-window aggregate of one
    measure along a DECLARED time axis, with its trend, autocorrelation and
    periodogram computed from the released series alone.

    The window aggregate is an ordinary QuerySpec (`stat` of `response`
    grouped by `time`), so O2/O3/O4 are inherited; the series diagnostics are
    a pure function of the finalized windows (P21), and a suppressed window
    denies the whole series (P19). `terms` exposes the time axis so the
    generic model path drives this tool unchanged, as it does ANOVA.
    """

    model_config = ConfigDict(extra="forbid")
    tool: Literal["series"] = "series"
    dataset: str
    response: str
    time: str
    stat: Literal["mean", "sum"] = "mean"
    filters: list[Filter] = []

    @field_validator("dataset")
    @classmethod
    def _dataset_known(cls, v):
        return _known_dataset(v)

    @field_validator("filters")
    @classmethod
    def _limit_filters(cls, v):
        if len(v) > MAX_FILTERS:
            raise ValueError(f"at most {MAX_FILTERS} filters")
        return v

    @model_validator(mode="after")
    def _check_allowlist(self):
        cat = CATALOGUE[self.dataset]
        if self.response not in cat["measures"]:
            raise ValueError(
                f"response {self.response!r} is not a measure of dataset {self.dataset!r} "
                f"(measures: {sorted(cat['measures'])})")
        if self.time not in cat.get("time_dims", []):
            raise ValueError(
                f"time {self.time!r} is not a declared time axis of dataset "
                f"{self.dataset!r} (time axes: {sorted(cat.get('time_dims', []))})")
        # decidable from the PUBLIC domain, so refused at the request rather
        # than from data: an axis with fewer declared windows than a series
        # needs can never carry one, whatever the cohort
        from .schema import declared_domain
        domain = declared_domain(self.time)
        if domain is not None and len(domain) < 4:
            raise ValueError(
                f"time axis {self.time!r} declares only {len(domain)} windows; a "
                "series needs at least 4")
        check_filters(self.dataset, self.filters)
        if any(f.column == self.response for f in self.filters):
            raise ValueError("response cannot also be filtered in a series query")
        if any(f.column == self.time for f in self.filters):
            raise ValueError("the time axis cannot also be filtered in a series query")
        return self

    @property
    def terms(self) -> list[str]:
        """The time axis as a term list, for the generic model path."""
        return [self.time]

    def model_key(self) -> str:
        return f"{self.dataset}:series:{self.stat}:{self.response}~{self.time}"


class AnovaSpec(BaseModel):
    """A one-way ANOVA request (spec R15) — the simplest possible model tool,
    and a worked example of adding a statistical capability (docs/adding-a-
    statistical-tool.md).

    Deliberately narrower than GLMSpec: exactly ONE categorical factor and a
    gaussian (interval) response. The value of keeping it a separate tool rather
    than a GLM special case is pedagogical and contractual — it shows that a new
    procedure reuses the entire cells-first safety machinery (design-cell
    QuerySpecs, the gateway, P19–P22) and only adds its own *numerics* and
    *output contract*. `terms` is exposed as a one-element view of `factor` so
    the generic model path in `service._handle_model` (which speaks GLM's
    response/terms vocabulary) drives this tool unchanged.
    """

    model_config = ConfigDict(extra="forbid")
    tool: Literal["anova"] = "anova"
    dataset: str
    response: str
    factor: str
    filters: list[Filter] = []

    @field_validator("dataset")
    @classmethod
    def _dataset_known(cls, v):
        return _known_dataset(v)

    @field_validator("filters")
    @classmethod
    def _limit_filters(cls, v):
        if len(v) > MAX_FILTERS:
            raise ValueError(f"at most {MAX_FILTERS} filters")
        return v

    @model_validator(mode="after")
    def _check_allowlist(self):
        # the family is FIXED, not chosen: a one-way ANOVA is an
        # interval-response procedure, so gaussian regardless of what the
        # response otherwise permits
        check_model_allowlist(self.dataset, self.response, "gaussian",
                              self.terms, self.filters, "factor")
        return self

    @property
    def terms(self) -> list[str]:
        """The single factor as a term list — lets the generic model pipeline
        (coherence check, audit record) treat ANOVA like any other model."""
        return [self.factor]

    def model_key(self) -> str:
        return f"{self.dataset}:anova:{self.response}~{self.factor}"

    def normalized_filters(self) -> tuple:
        return _normalized_filters(self.filters)


class NormalitySpec(BaseModel):
    """A test of whether a gaussian response is normally distributed within each
    level of a factor (spec R15). Like ANOVA, it is a function of the per-group
    moments — but the first FOUR (n, mean, sum of squares, cubes, fourth
    powers), from which skewness, kurtosis and the Jarque-Bera statistic follow.
    Each moment is an ordinary vetted `QuerySpec`, so the disclosure claim is
    inherited; the third/fourth-moment cells carry their own (tighter, signed-
    aware) dominance witness. It exposes a one-element `terms` view like ANOVA,
    so `service._handle_model` drives it unchanged.
    """

    model_config = ConfigDict(extra="forbid")
    tool: Literal["normality"] = "normality"
    dataset: str
    response: str
    factor: str
    filters: list[Filter] = []

    @field_validator("dataset")
    @classmethod
    def _dataset_known(cls, v):
        return _known_dataset(v)

    @field_validator("filters")
    @classmethod
    def _limit_filters(cls, v):
        if len(v) > MAX_FILTERS:
            raise ValueError(f"at most {MAX_FILTERS} filters")
        return v

    @model_validator(mode="after")
    def _check_allowlist(self):
        check_model_allowlist(self.dataset, self.response, "gaussian",
                              self.terms, self.filters, "factor")
        return self

    @property
    def terms(self) -> list[str]:
        return [self.factor]

    def model_key(self) -> str:
        return f"{self.dataset}:normality:{self.response}~{self.factor}"

    def normalized_filters(self) -> tuple:
        return _normalized_filters(self.filters)
