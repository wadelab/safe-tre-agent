"""Run a single natural-language request end-to-end through the guarded analyst.

Offline (MockLLM):   python scripts/demo.py "mean spend by age band"
Real model:          SAFETRE_LLM=real OPENAI_BASE_URL=... OPENAI_API_KEY=... \
                     SAFETRE_MODEL=provider-a/model-small python scripts/demo.py "..."
"""

import os
import sys

from safetre import synth
from safetre.analyst import Analyst
from safetre.llm import LLMClient, MockLLM


def make_llm():
    if os.environ.get("SAFETRE_LLM", "mock").lower() == "real":
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
