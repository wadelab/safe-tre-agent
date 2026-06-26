"""Enclave guards: static analysis of generated code + a restricted sandbox.

PROTOTYPE-GRADE. This is defence-in-depth illustration, not a secure sandbox.
In production the executor would run in a network-isolated container (e.g.
gVisor/Firecracker) with read-only data mounts; this layer is the *first* gate,
not the only one.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

# Patterns that must never appear in agent-generated analysis code.
FORBIDDEN = [
    "import ", "from ", "__", "open(", "exec(", "eval(", "compile(",
    "input(", "globals(", "locals(", "vars(", "getattr", "setattr",
    "subprocess", "socket", "requests", "urllib", "os.", "sys.",
    "to_csv", "to_pickle", "to_json", "read_csv", "read_", "np.save",
    "system(", "popen", "pickle", "marshal",
]

# Curated builtins available to sandboxed code. Note: pandas/numpy library
# internals use their own builtins, so restricting these only constrains the
# *agent-written* code, not the libraries it calls.
_ALLOWED_BUILTIN_NAMES = [
    "abs", "min", "max", "sum", "len", "range", "round", "sorted", "list",
    "dict", "set", "tuple", "float", "int", "str", "bool", "enumerate", "zip",
    "map", "filter", "any", "all", "print", "isinstance", "frozenset",
    "reversed", "divmod", "pow", "slice",
]
SAFE_BUILTINS = {n: getattr(builtins, n) for n in _ALLOWED_BUILTIN_NAMES}
SAFE_BUILTINS.update({"True": True, "False": False, "None": None})


@dataclass
class StaticResult:
    ok: bool
    reasons: list[str] = field(default_factory=list)


def static_check(code: str) -> StaticResult:
    """Reject code that imports, touches IO/network, or never assigns `result`."""
    reasons = []
    lowered = code.lower()
    for pat in FORBIDDEN:
        if pat in lowered:
            reasons.append(f"forbidden token: {pat!r}")
    if "result" not in code:
        reasons.append("code must assign an aggregate DataFrame named `result`")
    return StaticResult(ok=not reasons, reasons=reasons)


@dataclass
class SandboxResult:
    ok: bool
    result: pd.DataFrame | None = None
    error: str | None = None


def run_in_sandbox(code: str, tables: dict[str, pd.DataFrame]) -> SandboxResult:
    """Execute static-checked code against the data, returning `result`."""
    env = {"__builtins__": SAFE_BUILTINS, "pd": pd, "np": np}
    # expose copies so the agent cannot mutate the source tables
    env.update({name: df.copy() for name, df in tables.items()})
    try:
        exec(code, env)  # noqa: S102 - sandboxed namespace, static-checked
    except Exception as exc:  # noqa: BLE001
        return SandboxResult(ok=False, error=f"{type(exc).__name__}: {exc}")
    result = env.get("result")
    if not isinstance(result, pd.DataFrame):
        # allow Series/scalars by coercing to a frame
        if isinstance(result, (pd.Series,)):
            result = result.to_frame()
        else:
            return SandboxResult(ok=False, error="`result` is not a DataFrame/Series")
    return SandboxResult(ok=True, result=result)
