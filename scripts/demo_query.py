"""Drive the secure QuerySpec/GLMSpec pipeline from the repo checkout.

Thin wrapper: the implementation lives in `safetre.cli` so the installed
package exposes the same thing as the console script `safetre-demo`.
(The existing scripts/demo.py exercises the legacy code-writing path; this
drives QueryService — the boundary the security claim is about.)

Usage:
    uv run python scripts/demo_query.py "regress total spend on age band"
    uv run python scripts/demo_query.py --planner real "mean spend by region"
    uv run python scripts/demo_query.py            # a short scripted tour
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
