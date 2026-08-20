"""Public analysis-tool manifest.

The outside planner needs to know what analyses it may request, but it must not
learn anything row-level or operationally sensitive. This module publishes a
small, deterministic capability contract: tool IDs, input shape, allowed
datasets/columns, and coarse constraints. The safepod still validates every
request independently against the real Pydantic models and disclosure policy.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .config import PolicyConfig, load_policy_config
from .procedures import REGISTRY
from .query import (
    CATALOGUE, GLM_FAMILIES, INTERNAL_RANGE_RULES, MAX_FILTERS, MAX_GROUP_BY,
    MAX_IN_VALUES, MAX_MODEL_TERMS,
)
from .schema import ROLE_LABELS, column_description, declared_domain, role_of

MANIFEST_VERSION = "2026-08-15.aggregate+glm+anova+series.v13"


def public_schema() -> dict[str, Any]:
    """A disclosure-safe data dictionary, safe to show outside the safepod.

    For each dataset it lists the dimensions and measures with their type,
    disclosure role (quasi-identifier / sensitive / reference / ...), a plain
    description, and — for categorical dimensions — the DECLARED value domain.
    Every field here is design-time metadata, independent of any participant, so
    none of it is row-level: it is the study codebook. It tells an analyst the
    vocabulary of legal filters and group-bys without guessing; the safepod still
    validates every request, and observed frequencies live behind /api/marginals
    (disclosure-checked), not here. Internal analysis variables (e.g. raw age)
    are deliberately absent — they can never be grouped or returned.
    """
    datasets: dict[str, Any] = {}
    for dataset, info in sorted(CATALOGUE.items()):
        dims = {}
        for name, dtype in sorted(info["dims"].items()):
            role = role_of(name)
            entry: dict[str, Any] = {
                "type": dtype,
                "role": role,
                "role_label": ROLE_LABELS.get(role, role),
                "description": column_description(name),
                "filterable": True,
                "groupable": True,
            }
            domain = declared_domain(name)
            if domain is not None:
                entry["domain"] = domain
            dims[name] = entry
        measures = {}
        for name in sorted(info["measures"]):
            role = role_of(name)
            measures[name] = {
                "type": "numeric",
                "role": role,
                "role_label": ROLE_LABELS.get(role, role),
                "description": column_description(name),
            }
        datasets[dataset] = {"dimensions": dims, "measures": measures}
    return {"schema_version": MANIFEST_VERSION, "datasets": datasets}


def _catalogue_for_manifest() -> dict[str, dict[str, Any]]:
    return {
        dataset: {
            "dimensions": dict(sorted(info["dims"].items())),
            "measures": sorted(info["measures"]),
        }
        for dataset, info in sorted(CATALOGUE.items())
    }


def _internal_filter_ops() -> dict[str, Any]:
    """The band-aligned range rules, read from the live rule table (#39).

    Written out as literals once, which meant a rule change shipped a manifest
    describing the previous one.
    """
    return {column: dict(rule["edges"])
            for column, rule in sorted(INTERNAL_RANGE_RULES.items())}


def _require_policy(policy: PolicyConfig | None) -> None:
    """The announced policy must be the ENFORCED one, so it has to be passed in.

    `load_policy_config()` re-reads config.yaml and the environment, so a
    defaulted argument would announce a SECOND resolution of the policy while
    the gateway keeps enforcing the one captured at startup. Editing
    config.yaml under a running server moved the announced numbers and left the
    enforced ones alone — #61 one layer up: the manifest said 10 while the
    gateway held 25, and that sha goes into the planner prompt, where a planner
    uses `minimum_cell_size` to decide what to ask for (round 11, #89).

    That rule used to live in a comment saying callers "MUST" pass the policy,
    which the signature did not enforce. It is now the signature's job: callers
    that legitimately want the current config ask for it by name, via
    `manifest_for_current_config()`.
    """
    if policy is None:
        raise TypeError(
            "manifest functions require the RESOLVED policy the gateway is "
            "enforcing; pass it explicitly, or call "
            "manifest_for_current_config() to re-read config.yaml on purpose "
            "(hardening #89)")


def public_manifest(policy: PolicyConfig) -> dict[str, Any]:
    """Return the public capability manifest safe to show outside the safepod.

    The disclosure numbers come from the RESOLVED policy, not from literals.
    They used to be hard-coded, so an operator who raised `min_cell_size` to 25
    shipped a manifest — served to outside planners and shown in the UI — still
    announcing 10. That is the #46 defect in a metadata surface: a control that
    reads as set and is not. A wrong number here is worse than a missing one,
    because a planner uses it to decide what to ask for (hardening #61).
    """
    _require_policy(policy)
    return {
        "manifest_version": MANIFEST_VERSION,
        "security_model": {
            "planner_trust": "untrusted",
            "execution": "safepod_validated_only",
            "raw_rows_available": False,
            "code_execution_available": False,
            "sql_available": False,
        },
        # The response-time boundary (R18, D5). Published because a caller
        # cannot use the deadline it is subject to without knowing it, and a
        # client that wants to show the analyst how long is left before the
        # ceiling refuses must calibrate to the real number rather than guess
        # (D11). Safe to publish: both are policy constants, identical for
        # every request, and the control R18 provides is that responses are
        # INDISTINGUISHABLE within a quantum — knowing the quantum does not
        # help tell two of them apart. `minimum_cell_size` sits a few lines
        # below and is a far more sensitive dial.
        "response_timing": {
            "quantum_ms": policy.response_quantum_ms,
            "ceiling_ms": policy.response_ceiling_ms,
            "streamed": False,
            "note": ("every response is buffered and released on a quantum "
                     "boundary; work exceeding the ceiling is refused at the "
                     "boundary rather than answered late"),
        },
        "datasets": _catalogue_for_manifest(),
        "tools": [
            {
                "id": "aggregate_query",
                "version": "4",
                "status": "available",
                "description": "Disclosure-checked count, mean, sum, sum of squares, or Pearson correlation over an allowlisted dataset.",
                "request_schema": "QuerySpec",
                "measures": {
                    "functions": sorted(REGISTRY),
                    "count_column": None,
                    "corr_columns": "x and y must be two distinct allowed measure columns from one dataset",
                },
                "constraints": {
                    "max_group_by": MAX_GROUP_BY,
                    "max_filters": MAX_FILTERS,
                    "max_in_values": MAX_IN_VALUES,
                    "identifiers_allowed": False,
                    "text_fields_allowed": False,
                    "raw_rows_allowed": False,
                    "internal_analysis_variables_returnable": False,
                    # hardening #39: internal range filters are band-aligned
                    "internal_filter_ops": _internal_filter_ops(),
                },
                "release": {
                    "minimum_cell_size": policy.min_cell_size,
                    "counts_rounded_to_nearest": policy.round_base,
                    "corr_outputs": ["value", "p_value", "n"],
                    "dominance_check": True,
                    "subject_to_session_audit": True,
                },
            },
            {
                "id": "glm",
                "version": "1",
                "status": "available",
                "description": (
                    "Generalized linear model over allowlisted categorical terms, "
                    "fitted exclusively from disclosure-checked design-cell "
                    "aggregates (never row-level data)."),
                "request_schema": "GLMSpec",
                "model": {
                    "families": list(GLM_FAMILIES),
                    "links": "canonical only (identity / logit / log)",
                    "responses": {
                        dataset: {col: sorted(fams) for col, fams
                                  in sorted(info.get("glm_responses", {}).items())}
                        for dataset, info in sorted(CATALOGUE.items())
                    },
                    "terms": "allowlisted categorical dimensions of the dataset",
                },
                "constraints": {
                    "max_terms": MAX_MODEL_TERMS,
                    "max_filters": MAX_FILTERS - 1,
                    "interactions_allowed": False,
                    "continuous_predictors_allowed": False,
                    "per_observation_outputs": False,
                },
                "release": {
                    "coefficient_outputs": ["term", "level", "estimate",
                                            "std_error", "statistic", "p_value"],
                    "model_outputs": ["family", "link", "response", "n", "n_cells",
                                      "params", "df_resid", "deviance", "r_squared"],
                    "cell_table_released": True,
                    "denied_if_any_design_cell_suppressed": True,
                    "fitted_from_finalized_aggregates_only": True,
                    "subject_to_session_audit": True,
                },
            },
            {
                "id": "anova",
                "version": "1",
                "status": "available",
                "description": (
                    "One-way ANOVA of a gaussian response across the levels of "
                    "one allowlisted categorical factor, computed exclusively "
                    "from disclosure-checked group-cell aggregates (never "
                    "row-level data)."),
                "request_schema": "AnovaSpec",
                "model": {
                    "response": (
                        "an allowlisted gaussian model response (interval scale)"),
                    "factor": "one allowlisted categorical dimension of the dataset",
                    "responses": {
                        dataset: sorted(col for col, fams
                                        in info.get("glm_responses", {}).items()
                                        if "gaussian" in fams)
                        for dataset, info in sorted(CATALOGUE.items())
                    },
                },
                "constraints": {
                    "factors": 1,
                    "max_filters": MAX_FILTERS,
                    "continuous_predictors_allowed": False,
                    "per_observation_outputs": False,
                },
                "release": {
                    "table_outputs": ["source", "df", "sum_sq", "mean_sq",
                                      "statistic", "p_value"],
                    "model_outputs": ["response", "factor", "n", "n_groups",
                                      "grand_mean", "eta_squared", "df_between",
                                      "df_within"],
                    "cell_table_released": True,
                    "denied_if_any_group_cell_suppressed": True,
                    "fitted_from_finalized_aggregates_only": True,
                    "subject_to_session_audit": True,
                },
            },
            {
                "id": "series",
                "version": "1",
                "status": "available",
                "description": (
                    "A time series of one measure — its mean or sum per window "
                    "along a declared time axis (month, wave) — released as the "
                    "disclosure-checked window table together with its trend, "
                    "autocorrelation and periodogram, all computed exclusively "
                    "from the released windows (never row-level data)."),
                "request_schema": "SeriesSpec",
                "model": {
                    "response": "an allowlisted measure of the dataset",
                    "time": "a declared time axis of the dataset (integer-kind, ordered)",
                    "stat": "mean | sum — the per-window aggregate",
                    "time_axes": {
                        dataset: sorted(info.get("time_dims", []))
                        for dataset, info in sorted(CATALOGUE.items())
                        if info.get("time_dims")
                    },
                },
                "constraints": {
                    "min_windows": 4,
                    "max_lags": 4,
                    "max_filters": MAX_FILTERS,
                    "per_observation_outputs": False,
                },
                "release": {
                    "table_outputs": ["quantity", "value"],
                    "quantities": ["n_windows", "mean", "sd", "trend_slope",
                                   "trend_intercept", "trend_r_squared",
                                   "acf_lag_k", "dominant_period",
                                   "dominant_period_share"],
                    "model_outputs": ["response", "time", "stat", "n_windows", "n",
                                      "first_window", "last_window"],
                    "cell_table_released": True,
                    "denied_if_any_window_suppressed": True,
                    "fitted_from_finalized_aggregates_only": True,
                    "subject_to_session_audit": True,
                },
            },
        ],
        "planned_tool_classes": [
            {
                "id": "regression",
                "status": "planned",
                "note": "Continuous-predictor regression (moment cells, L2); not executable until present in tools[].",
            },
        ],
    }


def manifest_json(policy: PolicyConfig) -> str:
    return json.dumps(public_manifest(policy), sort_keys=True,
                      separators=(",", ":"))


def manifest_sha256(policy: PolicyConfig) -> str:
    return hashlib.sha256(manifest_json(policy).encode()).hexdigest()


def manifest_for_current_config() -> dict[str, Any]:
    """The manifest for a FRESH read of config.yaml and the environment.

    For callers with no gateway to agree with — the CLI, docs generation, an
    eval harness. Named so that re-resolving the policy is something a caller
    asks for, never something it gets by omitting an argument (#89). Anything
    serving a request must pass the policy the gateway is enforcing instead.
    """
    return manifest_for_response(load_policy_config())


def manifest_for_response(policy: PolicyConfig) -> dict[str, Any]:
    """The manifest plus its own hash, both from ONE resolution of the policy.

    Computing the hash from a second `public_manifest()` call would reintroduce
    the split this signature exists to close (#89): under a concurrent config
    edit the body and the hash could come from different policies.
    """
    manifest = public_manifest(policy)
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return manifest
