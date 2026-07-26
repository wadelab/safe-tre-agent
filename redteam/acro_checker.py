"""The external output checker: ACRO's rules, behind the process boundary.

Runs in the `acro` dependency group — the only environment ACRO 0.4.x can be
installed in (C3) — reads one request on stdin and writes one response on
stdout, per the contract in `acro_boundary.py`. It is deliberately dumb: it
translates, calls ACRO's own check implementations, and reports. Every
decision about what a failure means belongs to the caller, which denies.

    uv run --no-default-groups --group acro python redteam/acro_checker.py

Nothing is printed to stdout except the response; diagnostics go to stderr, so
a stray print cannot corrupt the contract.
"""

from __future__ import annotations

import json
import os
import sys
from importlib.metadata import PackageNotFoundError, version

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safetre.external_checker import PROTOCOL   # noqa: E402
from acro_vetter import AcroVetter          # noqa: E402


def check(request: dict) -> dict:
    """Answer one request. Raises ValueError on anything malformed — the
    caller turns that into a denial."""
    if request.get("protocol") != PROTOCOL:
        raise ValueError(f"request speaks protocol {request.get('protocol')!r}, "
                         f"this checker speaks {PROTOCOL}")
    keys = list(request.get("keys", []))
    contributions = pd.DataFrame(request.get("contributions", []))
    for key in keys:
        if key not in contributions.columns:
            raise ValueError(f"contributions are missing the key column {key!r}")
    # the same rule implementation the in-process vetter uses, so the boundary
    # cannot drift from what the comparison measured
    verdicts = AcroVetter(contributions, keys, request.get("aggfunc")).decisions()
    try:
        acro_version = version("acro")
    except PackageNotFoundError:            # pragma: no cover - env assertion
        raise ValueError("acro is not installed in the checker environment") from None
    return {
        "protocol": PROTOCOL,
        "checker": "acro",
        "version": acro_version,
        "verdicts": [{"cell": list(cell), "rule": rule}
                     for cell, rule in sorted(verdicts.items())],
    }


def main() -> int:
    try:
        request = json.loads(sys.stdin.read())
        response = check(request)
    except Exception as exc:                # noqa: BLE001 - reported, not raised
        print(json.dumps({"protocol": PROTOCOL, "error": str(exc)}))
        print(f"checker failed: {exc!r}", file=sys.stderr)
        return 1
    print(json.dumps(response))
    return 0


if __name__ == "__main__":
    sys.exit(main())
