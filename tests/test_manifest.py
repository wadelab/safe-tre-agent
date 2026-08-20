"""Tests for the public analysis-tool manifest."""

from safetre.config import load_policy_config
from safetre.manifest import (
    manifest_for_current_config, manifest_for_response, manifest_sha256,
    public_manifest,
)
from safetre.schema import identifier_columns

# #89: the manifest announces the policy the gateway ENFORCES, so it must be
# passed in. Tests resolve it once here, as a request-path caller would.
POLICY = load_policy_config()


def _manifest_columns(manifest):
    cols = set()
    for info in manifest["datasets"].values():
        cols.update(info["dimensions"])
        cols.update(info["measures"])
    return cols


def test_public_manifest_has_stable_hash():
    manifest = manifest_for_response(POLICY)
    assert manifest["manifest_sha256"] == manifest_sha256(POLICY)
    assert len(manifest["manifest_sha256"]) == 64


def test_public_manifest_does_not_expose_forbidden_columns():
    manifest = public_manifest(POLICY)
    cols = _manifest_columns(manifest)
    assert "donor_spend" in manifest["datasets"]
    assert not (cols & identifier_columns())
    assert "free_text" not in cols
    assert "ts" not in cols
    assert "age_years" not in cols


def test_only_available_tools_are_executable():
    manifest = public_manifest(POLICY)
    available = {tool["id"] for tool in manifest["tools"] if tool["status"] == "available"}
    planned = {tool["id"] for tool in manifest["planned_tool_classes"]}
    assert available == {"aggregate_query", "glm", "anova", "series", "normality"}
    assert manifest["tools"][0]["version"] == "4"
    assert manifest["tools"][0]["measures"]["functions"] == [
        "corr", "count", "mean", "sum", "sum_cube", "sum_quad", "sum_sq"]
    assert manifest["tools"][0]["release"]["corr_outputs"] == ["value", "p_value", "n"]
    assert not (available & planned)
    assert all(tool["status"] == "planned" for tool in manifest["planned_tool_classes"])


def test_glm_tool_contract_is_published():
    glm = next(t for t in public_manifest(POLICY)["tools"] if t["id"] == "glm")
    assert glm["request_schema"] == "GLMSpec"
    assert glm["model"]["families"] == ["gaussian", "binomial", "poisson"]
    assert glm["constraints"]["max_terms"] == 3
    assert glm["constraints"]["per_observation_outputs"] is False
    assert glm["release"]["denied_if_any_design_cell_suppressed"] is True
    assert glm["release"]["fitted_from_finalized_aggregates_only"] is True
    assert glm["release"]["cell_table_released"] is True
    # responses published per dataset must mirror the catalogue allowlist
    assert glm["model"]["responses"]["donor_spend"]["purchase_events"] == ["poisson"]
    assert "glm" not in {t["id"] for t in public_manifest(POLICY)["planned_tool_classes"]}


def test_anova_tool_contract_is_published():
    anova = next(t for t in public_manifest(POLICY)["tools"] if t["id"] == "anova")
    assert anova["request_schema"] == "AnovaSpec"
    assert anova["constraints"]["factors"] == 1
    assert anova["constraints"]["per_observation_outputs"] is False
    assert anova["release"]["denied_if_any_group_cell_suppressed"] is True
    assert anova["release"]["fitted_from_finalized_aggregates_only"] is True
    assert anova["release"]["cell_table_released"] is True
    # only gaussian responses are offered for ANOVA
    assert "wemwbs_score" in anova["model"]["responses"]["wellbeing"]
    assert "contains_lootboxes" not in anova["model"]["responses"].get("spend", [])
    assert "anova" not in {t["id"] for t in public_manifest(POLICY)["planned_tool_classes"]}


def test_manifest_says_planner_is_untrusted():
    security = public_manifest(POLICY)["security_model"]
    assert security["planner_trust"] == "untrusted"
    assert security["raw_rows_available"] is False
    assert security["code_execution_available"] is False
    assert security["sql_available"] is False


def test_release_numbers_track_the_resolved_policy():
    """#61 (round-9 V12): the manifest is served to outside planners and shown
    in the UI, and it used to state `minimum_cell_size: 10` as a literal. An
    operator who raised the threshold shipped a manifest announcing a control
    the system was not running — the #46 defect in a metadata surface."""
    from safetre.config import PolicyConfig

    tight = PolicyConfig(min_cell_size=25, round_base=10)
    tool = next(t for t in public_manifest(tight)["tools"]
                if t["id"] == "aggregate_query")
    assert tool["release"]["minimum_cell_size"] == 25
    assert tool["release"]["counts_rounded_to_nearest"] == 10


def test_internal_filter_ops_track_the_live_rules():
    """#61: the band edges were literals too, so a rule change shipped a
    manifest describing the previous one."""
    from safetre.query import INTERNAL_RANGE_RULES

    tool = next(t for t in public_manifest(POLICY)["tools"]
                if t["id"] == "aggregate_query")
    published = tool["constraints"]["internal_filter_ops"]
    assert published == {c: dict(r["edges"])
                         for c, r in INTERNAL_RANGE_RULES.items()}
    assert published, "the demo dataset declares at least one range rule"


def test_manifest_refuses_to_resolve_the_policy_for_you():
    """#89, as a signature rather than a comment.

    The announced policy must be the enforced one. These functions used to
    default `policy=None` and fall back to `load_policy_config()`, so a
    request-path caller that omitted the argument announced a SECOND
    resolution of config.yaml -- the manifest saying 10 while the gateway
    held 25. Omission is now a TypeError, and a caller that genuinely wants
    a fresh read asks for it by name.
    """
    import pytest

    for fn in (public_manifest, manifest_sha256, manifest_for_response):
        with pytest.raises(TypeError):
            fn()                                    # no argument at all
        with pytest.raises(TypeError, match="RESOLVED policy"):
            fn(None)                                # explicitly nothing

    # the named re-resolution is what the CLI / evals / docs use
    fresh = manifest_for_current_config()
    assert fresh["manifest_sha256"] == manifest_sha256(POLICY)
