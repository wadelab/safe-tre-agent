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
from dataclasses import dataclass, field, fields

try:  # pyyaml is a normal dependency, but keep the import defensive
    import yaml
except Exception:  # pragma: no cover - yaml is pinned in uv.lock
    yaml = None


def _dial(default, *, controls: str, means: str, clause: str, yaml_key: str,
          pinned_by: str, evidence: str | None = None,
          unset_means: str | None = None):
    """A safety parameter, declared with what it means.

    Every field of `PolicyConfig` is one of these. The metadata is not a
    comment: `scripts/gen_policy_catalogue.py` renders it into the operator's
    parameter catalogue, and `tests/test_policy_catalogue.py` fails the build
    if a parameter is added without it, if the documented ways of setting it
    do not actually set it, or if the clause it cites does not exist. A dial
    nobody can explain is a dial nobody should be turning.

    controls     - what it changes, in one line
    means        - what the NUMBER means, in terms of donors and cells; the
                   thing an operator needs and a default cannot convey
    clause       - the specification clause that governs it
    yaml_key     - its key under `disclosure:`/`session:` in config.yaml
    pinned_by    - a test proving a change to it changes a real decision
    evidence     - a measurement of what it costs, where one exists
    unset_means  - for optional parameters, what leaving it unset does
    """
    return field(default=default, metadata={
        "controls": controls, "means": means, "clause": clause,
        "yaml_key": yaml_key, "pinned_by": pinned_by,
        "evidence": evidence, "unset_means": unset_means,
    })


@dataclass(frozen=True)
class PolicyConfig:
    min_cell_size: int = _dial(
        10,
        controls="the minimum number of distinct donors a released cell may "
                 "describe",
        means="a cell is suppressed unless at least this many DONORS (not "
              "rows) contribute to it. Ten is the SDC convention; raising it "
              "suppresses more small cells, which mostly costs fine-grained "
              "breakdowns.",
        clause="R5", yaml_key="disclosure.min_cell_size",
        pinned_by="tests/test_hardening.py")
    max_output_rows: int = _dial(
        100,
        controls="how many rows a result may have before it looks like a row "
                 "dump",
        means="an un-aggregated result longer than this is flagged for human "
              "review rather than released automatically. It bounds "
              "granularity, not cell size.",
        clause="R5", yaml_key="disclosure.max_output_rows",
        pinned_by="tests/test_disclosure.py")
    query_budget: int = _dial(
        20,
        controls="how many aggregates one session may release",
        means="each released aggregate is individually differencable, so the "
              "budget bounds how much an analyst can accumulate in one "
              "sitting — including one per design cell table of a model. It "
              "is a cost bound, not a privacy bound: it does not compose "
              "across sessions or users.",
        clause="R6", yaml_key="session.query_budget",
        pinned_by="tests/test_hardening.py")
    differencing_delta: int = _dial(
        10,
        controls="how similar two cohorts may be before the second is refused",
        means="if a new cohort differs from one already released by fewer "
              "than this many donors, the release is denied — the difference "
              "would isolate that few people. The bound is computed from "
              "PUBLISHED marginals, so the refusal itself leaks nothing.",
        clause="R6", yaml_key="session.differencing_delta",
        pinned_by="tests/test_hardening.py")
    dom_threshold: float = _dial(
        0.5,
        controls="how much of a cell one donor may account for",
        means="a sum or mean cell is suppressed when its largest contributor "
              "holds more than this share of the total — at 0.5, one donor "
              "may not be more than half the cell. ACRO's defaults express "
              "the same concern differently (p%- and NK-rules) and neither "
              "set subsumes the other, so a deployment running both keeps "
              "both.",
        clause="R5", yaml_key="disclosure.dom_threshold",
        pinned_by="tests/test_disclosure.py",
        evidence="docs/acro-comparison.md")
    influence_threshold: float = _dial(
        0.5,
        controls="how far one donor may move a released correlation",
        means="a correlation cell is suppressed when removing any single "
              "donor would shift r by more than this. It is the corr analogue "
              "of dominance, and its value is bespoke rather than derived "
              "from a standard — see best-practice review D6.",
        clause="R5", yaml_key="disclosure.influence_threshold",
        pinned_by="tests/test_disclosure.py",
        evidence="docs/best-practice-review.md")
    round_base: int = _dial(
        5,
        controls="the granularity released counts are rounded to",
        means="every released count is rounded to a multiple of this, so a "
              "count carries at most this much precision about how many "
              "people a cell describes. Everything else the release reveals "
              "must be a function of the ROUNDED value, which is what "
              "hardenings #26 to #28 were about.",
        clause="R5", yaml_key="disclosure.round_base",
        pinned_by="tests/test_disclosure.py",
        evidence="artifacts/rounding_distortion.json")
    moment2_dom_threshold: float | None = _dial(
        None,
        controls="dominance for SECOND-MOMENT cells (sums of squares), which "
                 "back a model's standard errors",
        means="squaring is not share-preserving, so the same number is a much "
              "tighter rule here: a donor holding a fraction p of a cell "
              "holds p²/(p² + (1-p)²/(k-1)) of its squared total, crossing "
              "one half at p = 1/(1+√(k-1)). A bound of 0.5 therefore allows "
              "about 0.19 of a twenty-donor cell and 0.13 of a fifty-donor "
              "one; a bound of 0.8 allows 0.31 and 0.22. Because a model dies "
              "if either moment table is suppressed, this dial governs how "
              "often models are available at all.",
        clause="R5", yaml_key="disclosure.moment2_dom_threshold",
        pinned_by="tests/test_second_moment.py",
        evidence="artifacts/dispersion_sensitivity.json",
        unset_means="second moments are checked at `dom_threshold`, the "
                    "stricter reading")
    vetter: str = _dial(
        "standin",
        controls="which rules decide whether a cell may be released",
        means="`standin` uses this prototype's own rules. "
              "`standin+external` ALSO asks an external output checker and "
              "suppresses a cell if either says so — a union, so adding the "
              "checker can only suppress more. An external checker is never "
              "the only vetter: it has no egress rules and no complementary "
              "suppression.",
        clause="R5", yaml_key="disclosure.vetter",
        pinned_by="tests/test_cell_vetter.py",
        evidence="docs/acro-integration.md")
    checker_cmd: str = _dial(
        "",
        controls="the command that starts that external checker",
        means="a command line, run per vetted table, speaking the JSON "
              "contract in `safetre/external_checker.py`. Every failure — "
              "exit code, timeout, bad protocol, incomplete answer — denies "
              "the release rather than falling back to the built-in rules.",
        clause="R5", yaml_key="disclosure.checker_cmd",
        pinned_by="tests/test_acro_boundary.py",
        unset_means="no external checker; required when `vetter` names one")


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
    "SAFETRE_MOMENT2_DOM_THRESHOLD": ("moment2_dom_threshold", float),
    "SAFETRE_VETTER": ("vetter", str),
    "SAFETRE_CHECKER_CMD": ("checker_cmd", str),
}

VETTERS = ("standin", "standin+external")


# field -> caster, taken from the env table so the two routes cannot disagree
_CASTERS = {name: cast for name, cast in _ENV_OVERRIDES.values()}


def _yaml_values(path: str) -> dict:
    """Read config.yaml through the parameters' own declared keys.

    Generic on purpose. This module used to name each key by hand, and a
    parameter documented but absent from that list was silently never read —
    an operator tightening a threshold got no change in behaviour. Now the
    declaration IS the reader: `yaml_key` in a parameter's metadata is where
    it is looked for, so documenting a key and honouring it are the same act.
    """
    if yaml is None or not path or not os.path.exists(path):
        return {}
    with open(path) as fh:
        doc = yaml.safe_load(fh) or {}
    out: dict = {}
    for f in fields(PolicyConfig):
        section, _, key = str(f.metadata["yaml_key"]).partition(".")
        block = doc.get(section, {}) or {}
        if key in block:
            out[f.name] = _CASTERS[f.name](block[key])
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
    if cfg.moment2_dom_threshold is not None and not (
            0.0 < cfg.moment2_dom_threshold <= 1.0):
        raise ValueError("moment2_dom_threshold must be in (0, 1]")
    if cfg.vetter not in VETTERS:
        raise ValueError(f"vetter must be one of {VETTERS}, not {cfg.vetter!r}")
    # asking for an external checker without saying how to start it must fail
    # at startup, not at the first query: a gateway that cannot reach the
    # checker it was told to use denies everything, which is safe but useless,
    # and the operator should learn about it before an analyst does
    if cfg.vetter.endswith("external") and not cfg.checker_cmd.strip():
        raise ValueError("vetter 'standin+external' needs checker_cmd")
