"""Run a single natural-language request end-to-end through the guarded analyst.

Offline (MockLLM):   uv run python scripts/demo.py "mean spend by age band"
Real local model:    SAFETRE_LLM=real SAFETRE_LLM_BASE_URL=http://127.0.0.1:8000/v1 \
                     SAFETRE_LLM_MODEL=local-120b uv run python scripts/demo.py "..."
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre import synth                            # noqa: E402
from safetre.analyst import Analyst                  # noqa: E402
from safetre.llm import LLMClient, MockLLM, real_llm_enabled  # noqa: E402


def make_llm():
    # honours SAFETRE_LLM in {real, exampleprovider, ...}; anything else -> offline mock
    if real_llm_enabled():
        return LLMClient()
    return MockLLM()


def main():
    request = " ".join(sys.argv[1:]) or "mean spend by age band"
    tables = synth.load_csvs() if os.path.isdir("data") and os.listdir("data") else synth.generate()
    analyst = Analyst(make_llm(), tables)

    resp = analyst.run(request, guard=True)
    print(f"\nREQUEST: {request}")
    print(f"STATUS : {resp.status}")
    if resp.message:
        print(f"MESSAGE: {resp.message}")
    print("TRACE  :")
    for step in resp.trace:
        print(f"   - {step}")
    if resp.output is not None:
        print("\nOUTPUT:")
        print(resp.output.to_string(index=False))


if __name__ == "__main__":
    main()
