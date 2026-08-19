"""The verifiable-research-record layer is strictly additive to the release path.

The strongest way to turn a subsystem off is for nothing to be able to reach it,
and that is where the VRR starts: the dependency arrow points one way only — the
record modules import the gateway's types, and no module the gateway uses imports
a record module. Building a record changes no release behaviour because building
a record is not on the release path at all.

That is a property of today's imports, not a law, so this pins it. Without a
check, the first convenient `from .recorder import ...` inside `service.py` would
make the record layer load on every request, and the "off switch" would quietly
become "we do not call it much".

It matters for merging to main. A branch whose new subsystem cannot be reached
from the old one needs no feature flag to be off — but it does need something
that fails when that stops being true.

There is a second, independent gate. `internal_commitment_key()` has no default
and raises: a record cannot be built at all until an operator sets
`SAFETRE_VRR_COMMIT_KEY`, because the fallback would be an unkeyed hash of
low-entropy private values. So the layer is off unless it is both called AND
configured.
"""

from __future__ import annotations

import ast
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The record layer: additive, and reachable only by a caller that wants it.
VRR_MODULES = {
    "research_record", "recorder", "evidence", "provenance", "replay",
    "attestation", "vrr_bundle",
}

PACKAGES = ("safetre", "safetre_web")


def _modules() -> list[tuple[str, str]]:
    out = []
    for package in PACKAGES:
        directory = os.path.join(ROOT, package)
        for name in sorted(os.listdir(directory)):
            if name.endswith(".py"):
                out.append((f"{package}/{name}", os.path.join(directory, name)))
    return out


def _imported_names(path: str) -> set[str]:
    """Every module this file imports, by last component.

    AST rather than a grep, so a name inside a docstring or a comment — and this
    repository's modules are heavily commented, several of them ABOUT the record
    layer — cannot be mistaken for an import.
    """
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.rsplit(".", 1)[-1])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.rsplit(".", 1)[-1])
            for alias in node.names:
                names.add(alias.name)
    return names


CORE = [(rel, path) for rel, path in _modules()
        if os.path.basename(path)[:-3] not in VRR_MODULES]


@pytest.mark.parametrize("rel,path", CORE, ids=[rel for rel, _ in CORE])
def test_the_release_path_does_not_import_the_record_layer(rel, path):
    reached = _imported_names(path) & VRR_MODULES
    assert not reached, (
        f"{rel} imports {sorted(reached)}. The record layer must stay additive: "
        "a record is evidence about the release path, and a release path that "
        "loads the recorder is a different path from the one the evidence is "
        "about.")


def test_the_record_layer_is_a_real_layer_not_an_empty_set():
    """Guard against the check above passing because the names went stale."""
    present = {os.path.basename(p)[:-3] for _, p in _modules()}
    missing = VRR_MODULES - present
    assert not missing, f"VRR_MODULES names modules that no longer exist: {missing}"
    assert len(CORE) > 20, "the core module list looks wrong"


def test_a_record_cannot_be_built_without_an_explicit_commitment_key(monkeypatch):
    """The second gate: configured, not merely called."""
    from safetre.research_record import RecordError, internal_commitment_key

    monkeypatch.delenv("SAFETRE_VRR_COMMIT_KEY", raising=False)
    with pytest.raises(RecordError, match="no safe default"):
        internal_commitment_key()


def test_importing_the_gateway_does_not_import_the_record_layer():
    """The runtime form of the same property: a process that only serves queries
    never loads the record layer, so it cannot be slowed, broken or influenced
    by it."""
    import subprocess  # nosec B404
    import sys

    probe = (
        "import safetre.service, safetre.plan, safetre.disclosure, sys; "
        "loaded = [m for m in sys.modules "
        "if m.split('.')[-1] in "
        f"{sorted(VRR_MODULES)!r}]; "
        "print(loaded)"
    )
    out = subprocess.run(  # nosec B603
        [sys.executable, "-c", probe], cwd=ROOT, capture_output=True,
        text=True, timeout=120, check=False)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]", (
        f"importing the gateway pulled in the record layer: {out.stdout.strip()}")
