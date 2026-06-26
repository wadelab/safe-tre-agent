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

from .query import CATALOGUE, MAX_FILTERS, MAX_GROUP_BY, MAX_IN_VALUES

MANIFEST_VERSION = "2026-06-26.aggregate.v1"


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
                "version": "1",
                "status": "available",
                "description": "Disclosure-checked count, mean, or sum over an allowlisted dataset.",
                "request_schema": "QuerySpec",
                "measures": {
                    "functions": ["count", "mean", "sum"],
                    "count_column": None,
                },
                "constraints": {
                    "max_group_by": MAX_GROUP_BY,
                    "max_filters": MAX_FILTERS,
                    "max_in_values": MAX_IN_VALUES,
                    "identifiers_allowed": False,
                    "text_fields_allowed": False,
                    "raw_rows_allowed": False,
                },
                "release": {
                    "minimum_cell_size": 10,
                    "counts_rounded_to_nearest": 5,
                    "dominance_check": True,
                    "subject_to_session_audit": True,
                },
            },
        ],
        "planned_tool_classes": [
            {
                "id": "glm",
                "status": "planned",
                "note": "Future fixed-function GLM tool; not executable until present in tools[].",
            },
            {
                "id": "anova",
                "status": "planned",
                "note": "Future fixed-function ANOVA/contrast tool; not executable until present in tools[].",
            },
            {
                "id": "regression",
                "status": "planned",
                "note": "Future fixed-function regression family; not executable until present in tools[].",
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
