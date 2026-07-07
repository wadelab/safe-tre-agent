"""`safetre-demo` — drive the secure QuerySpec/GLMSpec pipeline from a shell.

The pip-installable face of the gateway: generates the synthetic dataset,
stands up a QueryService, and prints everything a release carries — the output
frame, and for models the summary block and the vetted cell table the fit is
reproducible from (R15). Synthetic data only; the deterministic mock planner
by default, a real local model with --planner real (SAFETRE_LLM_* env).

Usage:
    safetre-demo "regress total spend on age band"
    safetre-demo --planner real "mean spend by region"
    safetre-demo                     # a short scripted tour
"""

from __future__ import annotations

import argparse

from . import synth
from .disclosure import SessionAuditor
from .planner import LLMPlanner, MockPlanner
from .service import QueryService

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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="safetre-demo", description=__doc__)
    ap.add_argument("requests", nargs="*", help="natural-language requests")
    ap.add_argument("--planner", choices=["mock", "real"], default="mock")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)

    if args.planner == "mock":
        planner = MockPlanner()
    else:
        from .llm import LLMClient
        planner = LLMPlanner(LLMClient())

    service = QueryService(synth.generate(seed=args.seed))
    auditor = SessionAuditor()
    for request in (args.requests or TOUR):
        show(service, planner, auditor, request)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
