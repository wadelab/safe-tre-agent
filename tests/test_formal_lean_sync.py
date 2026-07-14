"""The committed Lean artifacts must match the live code (R16).

Same correspondence discipline as the Alloy hops, pure Python — no Lean
toolchain needed here. `scripts/gen_lean_catalogue.py` without --write exits 1
when formal/lean/SafeTre/Catalogue.lean (catalogue, disclosure-role labels,
live view columns) or Cases.lean (compiled-SQL pin pairs) is stale, so the
Lean proofs always speak about the catalogue and SQL the code actually
produces. The CI `formal` job then only has to replay the proofs.
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATOR = os.path.join(ROOT, "scripts", "gen_lean_catalogue.py")
LEAN_ROOT = os.path.join(ROOT, "formal", "lean")


def test_lean_artifacts_match_live_code():
    proc = subprocess.run([sys.executable, GENERATOR],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, (
        f"lean formal artifacts are stale:\n{proc.stdout}{proc.stderr}")


def test_lean_root_imports_every_module():
    # `lake build` builds the root module and its imports; a module missing
    # from SafeTre.lean (the proofs, say) would leave the build green while
    # silently checking nothing
    with open(os.path.join(LEAN_ROOT, "SafeTre.lean")) as fh:
        root = fh.read()
    modules = sorted(name[:-5]
                     for name in os.listdir(os.path.join(LEAN_ROOT, "SafeTre"))
                     if name.endswith(".lean"))
    missing = [m for m in modules if f"import SafeTre.{m}" not in root]
    assert not missing, f"SafeTre.lean does not import: {missing}"
