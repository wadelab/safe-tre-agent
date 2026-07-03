"""Tests for the public analysis-tool manifest."""

from safetre.manifest import manifest_for_response, manifest_sha256, public_manifest
from safetre.schema import identifier_columns


def _manifest_columns(manifest):
    cols = set()
    for info in manifest["datasets"].values():
        cols.update(info["dimensions"])
        cols.update(info["measures"])
    return cols


def test_public_manifest_has_stable_hash():
    manifest = manifest_for_response()
    assert manifest["manifest_sha256"] == manifest_sha256()
    assert len(manifest["manifest_sha256"]) == 64


def test_public_manifest_does_not_expose_forbidden_columns():
    cols = _manifest_columns(public_manifest())
    assert not (cols & identifier_columns())
    assert "free_text" not in cols
    assert "ts" not in cols
    assert "age_years" not in cols


def test_only_available_tools_are_executable():
    manifest = public_manifest()
    available = {tool["id"] for tool in manifest["tools"] if tool["status"] == "available"}
    planned = {tool["id"] for tool in manifest["planned_tool_classes"]}
    assert available == {"aggregate_query"}
    assert manifest["tools"][0]["measures"]["functions"] == ["count", "mean", "sum", "corr"]
    assert manifest["tools"][0]["release"]["corr_outputs"] == ["value", "p_value", "n"]
    assert not (available & planned)
    assert all(tool["status"] == "planned" for tool in manifest["planned_tool_classes"])


def test_manifest_says_planner_is_untrusted():
    security = public_manifest()["security_model"]
    assert security["planner_trust"] == "untrusted"
    assert security["raw_rows_available"] is False
    assert security["code_execution_available"] is False
    assert security["sql_available"] is False
