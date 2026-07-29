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

import logging
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
        controls="how many cells a released result may have before it goes to "
                 "a human output checker",
        means="a result finer than this is escalated rather than released "
              "automatically: the cells passed every rule individually, and it "
              "is their NUMBER that wants a second opinion. Counted on what is "
              "released, not on what was computed — a query whose cells were "
              "mostly suppressed has released a small table, not a fine one. "
              "This used to read 'rows with no aggregation at all', which on "
              "the QuerySpec path is unsatisfiable, because every compiled "
              "query appends a count: the dial described a control that could "
              "not fire (hardening #35, #56). Measured over the whole group-by "
              "skeleton: median 20 released cells, max 157, and 11 of 241 "
              "combinations escalate at this default — all of them "
              "three-dimension cross-tabs.",
        clause="R5", yaml_key="disclosure.max_output_rows",
        pinned_by="tests/test_hardening.py")
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
    session_window_hours: int = _dial(
        24,
        controls="how long a session's differencing lineage and query budget "
                 "survive",
        means="the controls that bound what one analyst can accumulate are "
              "rebuilt from the audit log on startup, over this many hours of "
              "history. It answers a question the code used to answer by "
              "accident: a session used to last exactly as long as the process, "
              "so a deploy or a crash handed every analyst a fresh budget and "
              "an empty lineage, and the two halves of a differencing pair "
              "could be split across a restart. Longer is stricter and costs "
              "startup time proportional to the history replayed; it is a "
              "window on ONE identity's own releases, not cross-user "
              "accounting, which needs the DP work.",
        clause="R6", yaml_key="session.window_hours",
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
    response_quantum_ms: int = _dial(
        50,
        controls="the interval every response is rounded up to at the "
                 "deployment boundary",
        means="a response is held until the next multiple of this many "
              "milliseconds, so requests doing similar work become "
              "indistinguishable by latency. It does not need to hide "
              "everything: cells at or above the frequency threshold have "
              "their counts published anyway, so the quantum only has to "
              "exceed the spread of work done on the SUB-threshold cohorts "
              "whose counts are withheld. Measured, those sit within a few "
              "milliseconds of each other, so 50 puts them all in one bucket. "
              "Set to 0 to disable, which reopens the channel.",
        clause="R18", yaml_key="disclosure.response_quantum_ms",
        pinned_by="tests/test_timing_channel.py",
        evidence="artifacts/timing_channel_standin.json")
    response_ceiling_ms: int = _dial(
        5000,
        controls="the longest a response may take before the request is "
                 "refused",
        means="work that would exceed this is refused and the refusal is "
              "still padded, because an overflow is itself a signal: without "
              "a ceiling the slowest queries advertise their size by running "
              "long. It is a compute cap in the same family as the row and "
              "memory limits, and like them it bounds cost as well as "
              "disclosure. Must be a multiple of the quantum to avoid a "
              "half-bucket at the top. "
              "Set it generously. Raising it costs nothing — padding goes to "
              "the next QUANTUM, not to the ceiling, so no query gets slower "
              "— and it does not weaken the hiding, because the work that "
              "must be indistinguishable is the sub-threshold work and that "
              "all lands in the first bucket whatever the ceiling is. The "
              "asymmetry runs the other way: too low refuses legitimate "
              "analysis, which is loud and damaging. The default is about "
              "170x the worst query measured on the demo data (28 ms "
              "steady-state); a deployment should measure its own worst case "
              "— a leave-one-out correlation over a large cohort is the shape "
              "to time — and leave an order of magnitude.",
        clause="R18", yaml_key="disclosure.response_ceiling_ms",
        pinned_by="tests/test_timing_channel.py")
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
        evidence="artifacts/composite_cost.json",
        unset_means="an external checker is used IF `checker_cmd` is "
                    "configured, and not otherwise — measured, composing "
                    "costs about 5% of gaussian model availability. Name a "
                    "vetter explicitly to require one")
    checker_cmd: str = _dial(
        "",
        controls="the command that starts that external checker",
        means="a command line, started ONCE and then fed one request per "
              "line, speaking the JSON contract in "
              "`safetre/external_checker.py`. Starting a process per vetted "
              "table cost a second or two of imports each; reusing one costs "
              "that once. Every failure — exit code, timeout, bad protocol, "
              "an answer to the wrong request, an incomplete answer — denies "
              "the release rather than falling back to the built-in rules, "
              "and discards the process rather than trusting it again.",
        clause="R5", yaml_key="disclosure.checker_cmd",
        pinned_by="tests/test_acro_boundary.py",
        unset_means="no external checker; required when `vetter` names one")

    def digest(self) -> str:
        """The effective policy, in one line, for the startup log.

        A released audit row records the request, the spec and the status, but
        nothing about the thresholds that allowed it: a clean release under
        `min_cell=1, dom=1.0, round=1` is schema-identical to one under the
        shipped policy, so the tamper-evident log cannot answer "which rules
        approved this?" — the question `CellVetter.describe` exists to answer.
        Stating the resolved policy at startup is the cheap half of closing
        that; binding it into the chain itself needs a schema change to
        `audit.records` and is tracked separately.
        """
        return " ".join(f"{f.name}={getattr(self, f.name)!r}"
                        for f in fields(self))


# env var -> (config field, caster). Env always wins so an operator can override
# a checked-in config.yaml without editing files.
_ENV_OVERRIDES: dict[str, tuple[str, type]] = {
    "SAFETRE_MIN_CELL": ("min_cell_size", int),
    "SAFETRE_MAX_OUTPUT_ROWS": ("max_output_rows", int),
    "SAFETRE_QUERY_BUDGET": ("query_budget", int),
    "SAFETRE_DIFFERENCING_DELTA": ("differencing_delta", int),
    "SAFETRE_SESSION_WINDOW_HOURS": ("session_window_hours", int),
    "SAFETRE_DOM_THRESHOLD": ("dom_threshold", float),
    "SAFETRE_INFLUENCE_THRESHOLD": ("influence_threshold", float),
    "SAFETRE_ROUND_BASE": ("round_base", int),
    "SAFETRE_MOMENT2_DOM_THRESHOLD": ("moment2_dom_threshold", float),
    "SAFETRE_RESPONSE_QUANTUM_MS": ("response_quantum_ms", int),
    "SAFETRE_RESPONSE_CEILING_MS": ("response_ceiling_ms", int),
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

    # The default is to USE an external checker when one is configured. The
    # package cannot require one — it is a library a TRE embeds, and ACRO
    # cannot even be imported into the service environment — so "on by
    # default" can only mean "on when available". That is not a silent
    # downgrade: every release records which vetter decided it
    # (`CellVetter.describe`), so an output never implies checks that did not
    # run. An operator who wants the checker GUARANTEED sets `vetter`
    # explicitly and gets a startup failure if it is missing.
    if "vetter" not in values and values.get("checker_cmd", "").strip():
        values["vetter"] = "standin+external"

    cfg = PolicyConfig(**values)
    _validate(cfg)
    return cfg


def _allow_unsafe_policy() -> bool:
    return os.environ.get("SAFETRE_ALLOW_UNSAFE_POLICY", "").strip().lower() in (
        "1", "true", "yes", "on")


# Floors on the RESOLVED policy, not on the dataclass defaults (hardening #46).
#
# `_validate` used to check only that each dial parsed: `min_cell_size=1`,
# `dom_threshold=1.0`, `round_base=1`, `response_quantum_ms=0` and
# `query_budget=10**9` all validated, and each silently disables a control.
# Measured before this existed: any ONE of those relaxed passed 737 of 737
# tests, and all of them together failed a single incidental web assertion —
# never `test_disclosure_thresholds_have_a_floor`, which reads the dataclass
# defaults and the module constants and so cannot see a config file at all.
#
# Each entry is (predicate, message). They express the SDC conventions the
# parameters' own documentation cites, so a deployment that means to depart
# from them is departing from the documented policy and should say so.
_FLOORS: tuple[tuple, ...] = (
    (lambda c: c.min_cell_size >= 5,
     "min_cell_size must be >= 5: below that a released cell describes too few "
     "people for the threshold rule to mean anything"),
    (lambda c: 0.0 < c.dom_threshold <= 0.5,
     "dom_threshold must be <= 0.5: above one half a single donor may be most "
     "of a cell and the p%-rule stops bounding anything"),
    (lambda c: 0.0 < c.influence_threshold <= 0.5,
     "influence_threshold must be <= 0.5: it is the correlation analogue of "
     "dominance and loosening it releases donor-driven correlations"),
    (lambda c: c.round_base >= 5,
     "round_base must be >= 5: finer rounding publishes counts at a precision "
     "hardenings #26 to #28 exist to blur"),
    (lambda c: 1 <= c.query_budget <= 1_000,
     "query_budget must be between 1 and 1000: an unbounded budget is not a "
     "budget, and every released aggregate is individually differencable. The "
     "upper bound is measured, not chosen (round-9 V14, hardening #69): the "
     "differencing lineage compares a new cohort against every cohort already "
     "released, at ~1.2 ms each on the demo data, and the number of recorded "
     "cohorts is bounded by the budget. At 10000 that is ~12 s of lineage "
     "checking per request against a 5 s response ceiling — the control could "
     "not finish inside the deadline, so the ceiling would refuse every query "
     "and effectively replace it. At 1000 it is ~1.2 s, which fits"),
    (lambda c: c.differencing_delta >= 5,
     "differencing_delta must be >= 5: it is the number of individuals two "
     "releases may differ over, and it should not sit below the cell floor"),
    (lambda c: 1 <= c.session_window_hours <= 24 * 90,
     "session_window_hours must be between 1 and 2160: zero would mean the "
     "differencing lineage does not survive a restart, which is the defect it "
     "exists to close"),
    (lambda c: 1 <= c.max_output_rows <= 10_000,
     "max_output_rows must be between 1 and 10000"),
    (lambda c: c.response_quantum_ms > 0,
     "response_quantum_ms must be > 0: zero reopens the timing channel that "
     "D5 measured putting sub-threshold cohorts in size order"),
)


def policy_floor_problems(cfg: PolicyConfig) -> list[str]:
    """Which resolved-policy floors this configuration fails."""
    return [message for ok, message in _FLOORS if not ok(cfg)]


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
    if cfg.response_quantum_ms < 0:
        raise ValueError("response_quantum_ms must be >= 0")
    if cfg.response_quantum_ms and cfg.response_ceiling_ms % cfg.response_quantum_ms:
        raise ValueError(
            "response_ceiling_ms must be a whole number of quanta, or the top "
            "bucket is a different size from the others and says so")
    if cfg.response_ceiling_ms <= 0:
        raise ValueError("response_ceiling_ms must be > 0")
    if cfg.vetter not in VETTERS:
        raise ValueError(f"vetter must be one of {VETTERS}, not {cfg.vetter!r}")
    # asking for an external checker without saying how to start it must fail
    # at startup, not at the first query: a gateway that cannot reach the
    # checker it was told to use denies everything, which is safe but useless,
    # and the operator should learn about it before an analyst does
    if cfg.vetter.endswith("external") and not cfg.checker_cmd.strip():
        raise ValueError("vetter 'standin+external' needs checker_cmd")

    # Semantic floors last, so a config that is merely malformed still fails
    # with the specific message. Research deployments that genuinely need a
    # weakened policy set SAFETRE_ALLOW_UNSAFE_POLICY=1 — which is deliberately
    # an environment variable and not a config key, so it cannot be smuggled in
    # by the same file whose values it waives, and it leaves a record in the
    # process environment rather than in a file that looks like policy.
    problems = policy_floor_problems(cfg)
    if problems and not _allow_unsafe_policy():
        raise ValueError(
            "resolved disclosure policy is below the safety floors: "
            + "; ".join(problems)
            + ". Set SAFETRE_ALLOW_UNSAFE_POLICY=1 to override deliberately.")
    if problems:
        logging.getLogger("safetre").warning(
            "SAFETRE_ALLOW_UNSAFE_POLICY is set; running below the safety "
            "floors: %s", "; ".join(problems))
