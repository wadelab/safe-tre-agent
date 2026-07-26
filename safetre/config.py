"""Disclosure-policy configuration loader.

The thresholds that decide what is released are *safety* parameters, so they must
come from one authoritative place and actually take effect. This module resolves
them with a clear precedence — built-in defaults, then `config.yaml`, then
environment overrides — and returns an immutable `PolicyConfig` that the web app
threads into the `DisclosurePolicy` and `SessionAuditor`.

Precedence (last wins): dataclass defaults < config.yaml < environment.

Historically `config.yaml` and `SAFETRE_MIN_CELL` were documented but never read,
so an operator tightening `min_cell_size` got no change in behaviour. This loader
closes that gap; `tests/test_hardening.py` asserts a changed threshold changes a
real suppression decision.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields

try:  # pyyaml is a normal dependency, but keep the import defensive
    import yaml
except Exception:  # pragma: no cover - yaml is pinned in uv.lock
    yaml = None


@dataclass(frozen=True)
class PolicyConfig:
    min_cell_size: int = 10
    max_output_rows: int = 100
    query_budget: int = 20
    differencing_delta: int = 10
    dom_threshold: float = 0.5
    influence_threshold: float = 0.5
    round_base: int = 5
    # which rules vet a cell: "standin" (the prototype's own) or
    # "standin+external" (those AND an external output checker, a cell
    # suppressed if either says so). An external checker is never the only
    # vetter: it has no egress rules and no complementary suppression.
    vetter: str = "standin"
    # the command that starts that checker, e.g.
    # "uv run --no-default-groups --group acro python redteam/acro_checker.py".
    # There is no default: a checker the operator did not choose is not one
    # they can vouch for, and vetting must never silently not happen.
    checker_cmd: str = ""


# env var -> (config field, caster). Env always wins so an operator can override
# a checked-in config.yaml without editing files.
_ENV_OVERRIDES: dict[str, tuple[str, type]] = {
    "SAFETRE_MIN_CELL": ("min_cell_size", int),
    "SAFETRE_MAX_OUTPUT_ROWS": ("max_output_rows", int),
    "SAFETRE_QUERY_BUDGET": ("query_budget", int),
    "SAFETRE_DIFFERENCING_DELTA": ("differencing_delta", int),
    "SAFETRE_DOM_THRESHOLD": ("dom_threshold", float),
    "SAFETRE_INFLUENCE_THRESHOLD": ("influence_threshold", float),
    "SAFETRE_ROUND_BASE": ("round_base", int),
    "SAFETRE_VETTER": ("vetter", str),
    "SAFETRE_CHECKER_CMD": ("checker_cmd", str),
}

VETTERS = ("standin", "standin+external")


def _yaml_values(path: str) -> dict:
    """Flatten the (nested) config.yaml into policy fields we understand."""
    if yaml is None or not path or not os.path.exists(path):
        return {}
    with open(path) as fh:
        doc = yaml.safe_load(fh) or {}
    disc = doc.get("disclosure", {}) or {}
    sess = doc.get("session", {}) or {}
    out: dict = {}
    if "min_cell_size" in disc:
        out["min_cell_size"] = int(disc["min_cell_size"])
    if "max_output_rows" in disc:
        out["max_output_rows"] = int(disc["max_output_rows"])
    if "dom_threshold" in disc:
        out["dom_threshold"] = float(disc["dom_threshold"])
    if "influence_threshold" in disc:
        out["influence_threshold"] = float(disc["influence_threshold"])
    if "round_base" in disc:
        out["round_base"] = int(disc["round_base"])
    if "query_budget" in sess:
        out["query_budget"] = int(sess["query_budget"])
    if "differencing_delta" in sess:
        out["differencing_delta"] = int(sess["differencing_delta"])
    return out


def load_policy_config(path: str | None = None) -> PolicyConfig:
    """Resolve the effective disclosure policy: defaults < config.yaml < env."""
    path = path if path is not None else os.environ.get("SAFETRE_CONFIG", "config.yaml")
    valid = {f.name for f in fields(PolicyConfig)}
    values = {k: v for k, v in _yaml_values(path).items() if k in valid}

    for env_name, (field_name, cast) in _ENV_OVERRIDES.items():
        raw = os.environ.get(env_name)
        if raw is not None and raw != "":
            try:
                values[field_name] = cast(raw)
            except ValueError as exc:
                raise ValueError(f"{env_name}={raw!r} is not a valid {cast.__name__}") from exc

    cfg = PolicyConfig(**values)
    _validate(cfg)
    return cfg


def _validate(cfg: PolicyConfig) -> None:
    if cfg.min_cell_size < 1:
        raise ValueError("min_cell_size must be >= 1")
    if cfg.query_budget < 1:
        raise ValueError("query_budget must be >= 1")
    if cfg.round_base < 1:
        raise ValueError("round_base must be >= 1")
    if not (0.0 < cfg.dom_threshold <= 1.0):
        raise ValueError("dom_threshold must be in (0, 1]")
    if cfg.influence_threshold <= 0.0:
        raise ValueError("influence_threshold must be > 0")
    if cfg.vetter not in VETTERS:
        raise ValueError(f"vetter must be one of {VETTERS}, not {cfg.vetter!r}")
    # asking for an external checker without saying how to start it must fail
    # at startup, not at the first query: a gateway that cannot reach the
    # checker it was told to use denies everything, which is safe but useless,
    # and the operator should learn about it before an analyst does
    if cfg.vetter.endswith("external") and not cfg.checker_cmd.strip():
        raise ValueError("vetter 'standin+external' needs checker_cmd")
