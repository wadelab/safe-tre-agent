"""Drive the secure QuerySpec/GLMSpec pipeline from the command line.

The existing scripts/demo.py exercises the legacy code-writing path; this one
drives QueryService — the boundary the security claim is about — and prints
everything a release carries: the output frame, and for models the summary
block and the vetted cell table the fit is reproducible from (R15).

Usage:
    uv run python scripts/demo_query.py "regress total spend on age band"
    uv run python scripts/demo_query.py --planner real "mean spend by region"
    uv run python scripts/demo_query.py            # a short scripted tour
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                              # noqa: E402
from safetre.disclosure import SessionAuditor          # noqa: E402
from safetre.planner import LLMPlanner, MockPlanner    # noqa: E402
from safetre.service import QueryService               # noqa: E402

TOUR = [
    "mean spend by age band",
    "regress total spend on age band",
    "logistic glm of lootbox availability by price tier",
    "regress total spend on age band and sex",          # denied: suppressed cell
    "poisson glm of purchase events on device os",      # denied: hostile value cell
]


def show(service: QueryService, planner, auditor: SessionAuditor, request: str) -> None:
    print("=" * 78)
    print(f"request: {request}")
    result = service.handle(request, planner, auditor=auditor)
    print(f"status:  {result.status}" + (f" — {result.message}" if result.message else ""))
    for step in result.trace:
        print(f"  trace: {step}")
    if result.output is not None:
        print(result.output.to_string(index=False))
    if result.artifacts:
        for name, frame in result.artifacts.items():
            print(f"--- {name} ---")
            print(frame.to_string(index=False))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("requests", nargs="*", help="natural-language requests")
    ap.add_argument("--planner", choices=["mock", "real"], default="mock")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    if args.planner == "mock":
        planner = MockPlanner()
    else:
        from safetre.llm import LLMClient
        planner = LLMPlanner(LLMClient())

    service = QueryService(synth.generate(seed=args.seed))
    auditor = SessionAuditor()
    for request in (args.requests or TOUR):
        show(service, planner, auditor, request)
    return 0


if __name__ == "__main__":
    sys.exit(main())
