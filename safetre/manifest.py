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

from .procedures import REGISTRY
from .query import (
    CATALOGUE, GLM_FAMILIES, MAX_FILTERS, MAX_GROUP_BY, MAX_IN_VALUES,
    MAX_MODEL_TERMS,
)
from .schema import ROLE_LABELS, column_description, declared_domain, role_of

MANIFEST_VERSION = "2026-07-07.aggregate+glm.v4"


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


def public_manifest() -> dict[str, Any]:
    """Return the public capability manifest safe to show outside the safepod."""
    return {
        "manifest_version": MANIFEST_VERSION,
        "security_model": {
            "planner_trust": "untrusted",
            "execution": "safepod_validated_only",
            "raw_rows_available": False,
            "code_execution_available": False,
            "sql_available": False,
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
                },
                "release": {
                    "minimum_cell_size": 10,
                    "counts_rounded_to_nearest": 5,
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
        ],
        "planned_tool_classes": [
            {
                "id": "anova",
                "status": "planned",
                "note": "Future fixed-function ANOVA/contrast tool; not executable until present in tools[].",
            },
            {
                "id": "regression",
                "status": "planned",
                "note": "Continuous-predictor regression (moment cells, L2); not executable until present in tools[].",
            },
        ],
    }


def manifest_json() -> str:
    return json.dumps(public_manifest(), sort_keys=True, separators=(",", ":"))


def manifest_sha256() -> str:
    return hashlib.sha256(manifest_json().encode()).hexdigest()


def manifest_for_response() -> dict[str, Any]:
    manifest = public_manifest()
    manifest["manifest_sha256"] = manifest_sha256()
    return manifest
