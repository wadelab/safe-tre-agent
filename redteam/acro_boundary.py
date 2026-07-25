"""The out-of-process boundary an external checker is called across (§4 of
`docs/acro-integration.md`).

ACRO 0.4.x pins `pandas < 3` and cannot be imported into the service
environment at all (C3), so the checker runs in its own environment and the
gateway talks to it over a versioned JSON contract. That is the design rather
than a workaround: a TRE can then pin or upgrade its output checker
independently of the agent, and the checker's version is a fact recorded per
release instead of a property of whatever happened to be installed.

The contract, one request and one response per cell table:

    -> {"protocol": 1, "keys": [...], "aggfunc": "sum"|null,
        "contributions": [{<key>: ..., "v": <float>, "donor_id": ...}, ...]}
    <- {"protocol": 1, "checker": "acro", "version": "0.4.12",
        "verdicts": [{"cell": ["Wales"], "rule": "nk-rule;"}, ...]}

**Everything that can go wrong denies.** A non-zero exit, a timeout, a
malformed response, a protocol mismatch or a verdict list that does not cover
the table all withhold the whole table. There is deliberately no path that
falls back to the stand-in's rules and releases anyway: applying rules other
than the ones a release claims were applied is precisely the failure this
project refuses elsewhere, and a checker that is down is not a checker that
approved.

What crosses the boundary is a donor-level contribution frame — data that has
not yet passed the gateway. The boundary is therefore *inside* the safepod and
crosses no trust boundary; it is a dependency-isolation boundary, not a
security one.
"""

from __future__ import annotations

import json
import os
# spawns a fixed local checker with a literal argv, never a shell
import subprocess  # nosec B404

import pandas as pd

from safetre.disclosure import CellVetter, Finding, Verdicts, VettingParameters

PROTOCOL = 1
CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "acro_checker.py")
DEFAULT_TIMEOUT = 120.0


def checker_command() -> list[str]:
    """The command that starts the checker in its own environment — the `acro`
    dependency group, resolved separately from the runtime's
    (`[tool.uv] conflicts` in `pyproject.toml`)."""
    return ["uv", "run", "--frozen", "--no-default-groups", "--group", "acro",
            "python", CHECKER]


def build_request(contributions: pd.DataFrame, keys: list[str],
                  aggfunc: str | None) -> dict:
    """The checker's input: the cells' donor-level contributions and how to
    aggregate them. Records rather than a frame, so the contract does not
    depend on a pandas version — which is the whole reason for the boundary."""
    return {
        "protocol": PROTOCOL,
        "keys": list(keys),
        "aggfunc": aggfunc,
        "contributions": json.loads(contributions.to_json(orient="records")),
    }


def parse_response(payload: str) -> tuple[dict[tuple, str], str]:
    """(verdicts by cell key, checker version). Raises ValueError on anything
    the caller must fail closed on."""
    try:
        response = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"checker response is not JSON: {exc}") from None
    if not isinstance(response, dict):
        raise ValueError("checker response is not an object")
    if response.get("error"):
        raise ValueError(f"checker reported: {response['error']}")
    if response.get("protocol") != PROTOCOL:
        raise ValueError(
            f"checker speaks protocol {response.get('protocol')!r}, "
            f"this gateway speaks {PROTOCOL}")
    version = str(response.get("version", "unknown"))
    verdicts: dict[tuple, str] = {}
    for entry in response.get("verdicts", []):
        try:
            verdicts[tuple(str(part) for part in entry["cell"])] = str(entry["rule"])
        except (KeyError, TypeError) as exc:
            raise ValueError(f"malformed verdict {entry!r}: {exc}") from None
    return verdicts, version


class ExternalAcroVetter(CellVetter):
    """Vets a cell table by asking a checker running in another process.

    Holds no ACRO code and imports nothing from it, so it is safe to construct
    in the service environment where ACRO cannot be installed. The `version`
    attribute carries what the checker reported for the most recent call — the
    value a release should record, so "which rules did this output pass?" has
    an answer a year later.
    """

    name = "acro-external"

    def __init__(self, contributions: pd.DataFrame, keys: list[str],
                 aggfunc: str | None, command: list[str] | None = None,
                 timeout: float = DEFAULT_TIMEOUT):
        self.contributions = contributions
        self.keys = list(keys)
        self.aggfunc = aggfunc
        self.command = list(command) if command else checker_command()
        self.timeout = timeout
        self.version: str | None = None

    def _ask(self) -> tuple[dict[tuple, str], str]:
        request = json.dumps(build_request(self.contributions, self.keys,
                                           self.aggfunc))
        try:
            # argv is built here, never from the request; no shell is involved
            done = subprocess.run(  # nosec B603
                self.command, input=request, capture_output=True, text=True,
                timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            raise ValueError(f"checker did not answer within {self.timeout}s") from None
        except OSError as exc:
            raise ValueError(f"checker could not be started: {exc}") from None
        if done.returncode != 0:
            detail = (done.stderr or "").strip().splitlines()
            raise ValueError(
                f"checker exited {done.returncode}"
                + (f": {detail[-1]}" if detail else ""))
        return parse_response(done.stdout)

    def vet(self, df: pd.DataFrame, params: VettingParameters) -> Verdicts:
        # late import: the in-process vetter is only needed to reuse the cell
        # key convention, and importing it must not drag ACRO in
        from acro_vetter import RELEASE, cell_key

        try:
            verdicts, version = self._ask()
        except ValueError as exc:
            # nothing checked this table, so nothing about it may be released
            return Verdicts(suppress=pd.Series(True, index=df.index, dtype=bool),
                            findings=[Finding("high", "checker_unavailable", str(exc))],
                            deny=True)
        self.version = version

        suppress, fired, unknown = [], {}, 0
        for _, row in df.iterrows():
            rule = verdicts.get(cell_key(row, self.keys))
            if rule is None:
                unknown += 1
                suppress.append(True)
                continue
            if rule == RELEASE:
                suppress.append(False)
                continue
            suppress.append(True)
            for name in (r.strip() for r in rule.split(";") if r.strip()):
                fired[name] = fired.get(name, 0) + 1

        findings = [Finding("high", f"acro_{name}",
                            f"{count} cell(s) failed ACRO's {name}")
                    for name, count in sorted(fired.items())]
        if unknown:
            # a table the checker only partly answered for is a table it did
            # not check: deny rather than release the part it happened to cover
            findings.append(Finding("high", "checker_incomplete",
                                    f"{unknown} cell(s) received no verdict"))
            return Verdicts(suppress=pd.Series(True, index=df.index, dtype=bool),
                            findings=findings, deny=True)
        return Verdicts(suppress=pd.Series(suppress, index=df.index, dtype=bool),
                        findings=findings, deny=False)
