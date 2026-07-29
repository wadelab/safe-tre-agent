"""The shipped systemd unit must satisfy what the code calls production.

Two findings were the same shape: `deploy/safetre-web.service` did not set
something the running code treats as required. #45 set
`SAFETRE_REQUIRE_IDENTITY=1` with no proxy secret and no allowlist, so every
forged login was admitted; #65 set the audit database path and not the key, so
the log was signed by a key sitting beside it. Both were found by reading, a
round apart, and nothing in CI had ever looked at the file.

This is what F8 was withdrawn in favour of (`docs/security2.md`). A trust-zone
model would have restated `docs/security.md`'s zone table with nothing tying it
to the deployment, and passed forever regardless of what the unit said. The
artifact under test here IS the thing that ships.

**The requirement list is derived, not restated.** `_required_by_the_code`
reads the variable names out of `identity.configuration_problems()` — the
code's own account of what production needs — so adding a new production
requirement makes this test demand the unit satisfy it, rather than leaving the
unit behind until someone reads it again. Restating the list here would be a
second implementation of one rule, which is #58's lesson.
"""

from __future__ import annotations

import os
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
UNIT = ROOT / "deploy" / "safetre-web.service"

# Set to a literal value in the unit: these are settings, not secrets.
MUST_BE_SET = {
    "SAFETRE_REQUIRE_IDENTITY": "1",
    "SAFETRE_RESTRICTED_CHANNEL": "1",
}

# Provided, but NEVER as a literal in a world-readable unit file: these are
# secrets, and one pasted here would be a finding of its own.
MUST_COME_FROM_A_FILE = {"SAFETRE_PROXY_SHARED_SECRET", "SAFETRE_AUDIT_KEY"}

# Operator-specific and per-deployment: the unit must carry the instruction
# even where it cannot carry the value (the chain head is only knowable once
# the chain exists).
MUST_BE_DOCUMENTED = {"SAFETRE_AUDIT_HEAD_ANCHOR"}


@pytest.fixture(scope="module")
def unit() -> str:
    assert UNIT.exists(), f"the shipped unit is missing: {UNIT}"
    return UNIT.read_text()


def _environment_lines(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Environment=") and "=" in line[len("Environment="):]:
            name, _, value = line[len("Environment="):].partition("=")
            out[name.strip()] = value.strip()
    return out


def _environment_files(text: str) -> list[str]:
    return [line.split("=", 1)[1].strip() for line in text.splitlines()
            if line.strip().startswith("EnvironmentFile=")]


def _required_by_the_code() -> set[str]:
    """Every `SAFETRE_*` the code names when asked what production is missing.

    Read from the messages rather than from a list kept here, so the two cannot
    disagree — the failure mode this whole file exists to catch.
    """
    saved = {k: v for k, v in os.environ.items() if k.startswith("SAFETRE_")}
    try:
        for key in saved:
            del os.environ[key]
        os.environ["SAFETRE_REQUIRE_IDENTITY"] = "1"
        from safetre_web.identity import configuration_problems
        names: set[str] = set()
        for problem in configuration_problems():
            names |= set(re.findall(r"SAFETRE_[A-Z_]+", problem))
        return names - {"SAFETRE_REQUIRE_IDENTITY"}
    finally:
        for key in [k for k in os.environ if k.startswith("SAFETRE_")]:
            del os.environ[key]
        os.environ.update(saved)


def test_the_unit_sets_the_settings_production_needs(unit):
    """#45: `SAFETRE_REQUIRE_IDENTITY=1` on its own is a gate with nothing
    behind it."""
    env = _environment_lines(unit)
    for name, expected in MUST_BE_SET.items():
        assert env.get(name) == expected, (
            f"{name} should be {expected!r} in the shipped unit, got "
            f"{env.get(name)!r}")
    assert env.get("SAFETRE_AUDIT_DB"), "the audit log needs a durable path"
    assert env.get("SAFETRE_ALLOWLIST"), (
        "an empty allowlist admits nobody in production, so shipping without "
        "one ships a wall of 403s (#45)")


def test_secrets_come_from_a_file_and_never_from_the_unit(unit):
    """#65: the key must not be derivable from this host's repository, and a
    unit file is exactly that. A literal here would also put it in every
    backup and every `systemctl cat`."""
    env = _environment_lines(unit)
    for name in MUST_COME_FROM_A_FILE:
        assert name not in env, (
            f"{name} is a secret and must not be a literal in the unit")
    files = _environment_files(unit)
    assert files, "no EnvironmentFile= to carry the secrets"
    for name in MUST_COME_FROM_A_FILE:
        assert name in unit, (
            f"{name} is never mentioned, so an operator following this unit "
            f"would not know to provide it")


def test_every_production_requirement_the_code_names_is_in_the_unit(unit):
    """The drift guard, and the reason this test is worth having: the list
    comes from `configuration_problems()`, so a NEW production requirement in
    the code fails here until the unit answers it."""
    env = _environment_lines(unit)
    handled = set(env) | MUST_COME_FROM_A_FILE | MUST_BE_DOCUMENTED
    missing = {name for name in _required_by_the_code() if name not in handled}
    assert not missing, (
        f"the code calls these production requirements and the shipped unit "
        f"neither sets nor documents them: {sorted(missing)}")


def test_documented_requirements_are_actually_documented(unit):
    """A requirement the unit cannot set — the chain head is only knowable once
    the chain exists — still has to tell the operator it exists."""
    for name in MUST_BE_DOCUMENTED:
        assert name in unit, f"{name} is not mentioned in the unit at all"


def test_the_service_binds_loopback_only(unit):
    """`docs/security.md` puts the model runtime in the untrusted zone on this
    host, so the bind address is load-bearing: never 0.0.0.0."""
    exec_lines = [line for line in unit.splitlines()
                  if line.strip().startswith("ExecStart=")]
    assert exec_lines, "no ExecStart"
    assert any("--host 127.0.0.1" in line for line in exec_lines), exec_lines
    assert not any("0.0.0.0" in line for line in exec_lines), exec_lines


def test_the_sandboxing_directives_are_present(unit):
    """These are the process-level half of the boundary. Losing one to an edit
    is silent — `systemd-analyze security` is not run in CI."""
    for directive in ("NoNewPrivileges=yes", "ProtectSystem=strict",
                      "PrivateTmp=yes", "ProtectHome=yes",
                      "RestrictAddressFamilies=", "IPAddressDeny=any",
                      "CapabilityBoundingSet=", "MemoryDenyWriteExecute=yes"):
        assert directive in unit, f"the unit lost {directive}"


def test_the_unit_would_start_under_its_own_settings(monkeypatch):
    """The end-to-end reading of the same question: with the unit's literal
    settings applied and its EnvironmentFile secrets supplied, does the code
    still say anything is missing?

    `SAFETRE_AUDIT_HEAD_ANCHOR` is the one exception — the unit ships it
    commented out because a chain head cannot be known before the chain exists,
    so it is checked as documentation above rather than as a value here.
    """
    from safetre_web.identity import configuration_problems

    for key in [k for k in os.environ if k.startswith("SAFETRE_")]:
        monkeypatch.delenv(key, raising=False)
    for name, value in _environment_lines(UNIT.read_text()).items():
        monkeypatch.setenv(name, value)
    for name in MUST_COME_FROM_A_FILE:            # supplied by EnvironmentFile
        monkeypatch.setenv(name, "x" * 32)

    problems = [p for p in configuration_problems()
                if "SAFETRE_AUDIT_HEAD_ANCHOR" not in p]
    assert not problems, problems
