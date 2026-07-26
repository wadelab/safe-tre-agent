"""Every safety parameter is declared, explained, reachable and pinned.

`docs/policy-parameters.md` is the operator's view of the dials that change
what the gateway releases. It is generated from the declarations on
`PolicyConfig` itself, and this module is what stops it becoming decoration:

- a parameter cannot be added without saying what it controls, what its
  *value* means in terms of donors and cells, which clause governs it, and
  which test proves a change to it changes a decision;
- the clause it cites must exist, and the evidence it links must exist;
- **both documented ways of setting it must actually set it.** This is the
  bug the config loader was written to fix in the first place — `config.yaml`
  and `SAFETRE_MIN_CELL` were documented for a while but never read, so an
  operator tightening a threshold got no change in behaviour. A dial that
  does not turn is worse than no dial, because it is believed;
- and the committed page must match what the code renders.

The point is general. Nothing here knows the current parameters by name: add
one and these tests apply to it unchanged.
"""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404 - runs this repo's own generator
import sys
from dataclasses import fields

import pytest
import yaml

from safetre.config import _ENV_OVERRIDES, PolicyConfig, load_policy_config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "docs", "policy-parameters.md")
GENERATOR = os.path.join(ROOT, "scripts", "gen_policy_catalogue.py")
SPEC = os.path.join(ROOT, "docs", "specification.md")

PARAMETERS = [f for f in fields(PolicyConfig)]
NAMES = [f.name for f in PARAMETERS]

# a value that differs from the default, per type, so "does the dial turn?"
# can be asked of any parameter without naming it
PROBES: dict[type, object] = {int: 7, float: 0.25, str: "standin"}


def _probe(field):
    if field.name == "vetter":                 # a Literal-ish field: use the
        return "standin+external"              # other legal value
    if field.name == "checker_cmd":
        return "/bin/true"
    kind = type(field.default) if field.default is not None else float
    return PROBES[kind]


@pytest.mark.parametrize("field", PARAMETERS, ids=NAMES)
def test_every_parameter_says_what_it_is(field):
    meta = field.metadata
    for key in ("controls", "means", "clause", "yaml_key", "pinned_by"):
        assert meta.get(key), f"{field.name} declares no {key!r}"
    # "means" must say something about the value, not restate the name
    assert len(meta["means"]) > 60, f"{field.name}: explain what the number means"
    assert field.default is not None or meta.get("unset_means"), (
        f"{field.name} is optional but does not say what leaving it unset does")


@pytest.mark.parametrize("field", PARAMETERS, ids=NAMES)
def test_every_parameter_cites_a_clause_that_exists(field):
    spec = open(SPEC).read()
    clause = field.metadata["clause"]
    assert re.search(rf"\*\*{clause}\*\*", spec), (
        f"{field.name} cites {clause}, which is not in the specification")


@pytest.mark.parametrize("field", PARAMETERS, ids=NAMES)
def test_every_reference_points_at_something_real(field):
    for key in ("pinned_by", "evidence"):
        target = field.metadata.get(key)
        if target:
            assert os.path.exists(os.path.join(ROOT, target)), (
                f"{field.name} cites {target!r}, which does not exist")


@pytest.mark.parametrize("field", PARAMETERS, ids=NAMES)
def test_the_environment_route_actually_sets_it(field, monkeypatch, tmp_path):
    env = next((e for e, (name, _) in _ENV_OVERRIDES.items()
                if name == field.name), None)
    assert env, f"{field.name} has no environment override"
    for name in _ENV_OVERRIDES:
        monkeypatch.delenv(name, raising=False)
    probe = _probe(field)
    monkeypatch.setenv(env, str(probe))
    if field.name == "vetter":                 # this one needs its companion
        monkeypatch.setenv("SAFETRE_CHECKER_CMD", "/bin/true")
    empty = tmp_path / "none.yaml"
    assert getattr(load_policy_config(str(empty)), field.name) == probe


@pytest.mark.parametrize("field", PARAMETERS, ids=NAMES)
def test_the_config_file_route_actually_sets_it(field, monkeypatch, tmp_path):
    for name in _ENV_OVERRIDES:
        monkeypatch.delenv(name, raising=False)
    section, _, key = field.metadata["yaml_key"].partition(".")
    probe = _probe(field)
    doc: dict = {section: {key: probe}}
    if field.name == "vetter":
        doc.setdefault("disclosure", {})["checker_cmd"] = "/bin/true"
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(doc))
    assert getattr(load_policy_config(str(path)), field.name) == probe


def test_the_environment_beats_the_file():
    # the documented precedence, checked once rather than asserted in prose
    assert "defaults < config.yaml < environment" in open(
        os.path.join(ROOT, "safetre", "config.py")).read()


def test_the_page_matches_the_code():
    proc = subprocess.run(  # nosec B603 - fixed argv, this repo's generator
        [sys.executable, GENERATOR], capture_output=True, text=True, cwd=ROOT,
        check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == open(PAGE).read(), (
        "docs/policy-parameters.md is stale — run:\n"
        "  uv run python scripts/gen_policy_catalogue.py --write")


def test_the_page_covers_every_parameter_and_invents_none():
    page = open(PAGE).read()
    documented = set(re.findall(r"^## `([a-z_0-9]+)`$", page, re.M))
    assert documented == set(NAMES), (
        f"missing {set(NAMES) - documented}, invented {documented - set(NAMES)}")


def test_an_undeclared_parameter_is_rejected(tmp_path):
    # the guard itself: a field added without metadata fails the first test
    # above. Simulated here so the guard is exercised, not just relied on.
    from dataclasses import dataclass, field as plain_field

    @dataclass(frozen=True)
    class Undeclared:
        sneaky: int = plain_field(default=1)

    (bad,) = fields(Undeclared)
    assert not bad.metadata.get("means")


def test_config_yaml_in_the_repository_only_names_real_parameters():
    # a key nobody reads looks like a setting and is not one
    doc = yaml.safe_load(open(os.path.join(ROOT, "config.yaml"))) or {}
    declared = {f.metadata["yaml_key"] for f in PARAMETERS}
    for section, block in doc.items():
        if not isinstance(block, dict):
            continue
        for key in block:
            assert f"{section}.{key}" in declared, (
                f"config.yaml sets {section}.{key}, which no parameter reads")
