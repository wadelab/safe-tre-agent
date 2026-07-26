"""Render the disclosure policy's parameters into an operator's catalogue.

Every dial that changes what the gateway releases, on one page: what it
controls, what the *number* means in terms of donors and cells, how to set it,
which specification clause governs it, what evidence exists for the cost of
changing it, and which test proves a change to it changes a real decision.

The page is generated from the parameters themselves — the metadata declared
on each `PolicyConfig` field (`config._dial`) — not written alongside them. A
parameter cannot be added without documenting it, its documented settings are
checked to actually work, and drift between the code and the page fails the
build (`tests/test_policy_catalogue.py`), the same discipline the Lean and
Alloy catalogues use.

Usage:
    uv run python scripts/gen_policy_catalogue.py            # print
    uv run python scripts/gen_policy_catalogue.py --write    # update the page
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import fields

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safetre.config import _ENV_OVERRIDES, PolicyConfig   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "docs", "policy-parameters.md")

HEADER = """# Policy parameters

Every dial that changes what this gateway releases. Each is declared where it
lives — on the `PolicyConfig` field itself — and this page is generated from
those declarations, so a parameter cannot exist here without an explanation or
exist in the code without appearing here.

Three things are worth knowing before turning anything.

**The defaults are the strict reading.** Where a parameter is optional,
leaving it unset selects the more conservative behaviour. Nothing here has to
be set for the gateway to be safe; the dials exist so a TRE can be *stricter*,
or can accept a stated, measured relaxation deliberately rather than by
accident.

**A number is not a policy until you know what it means.** A dominance bound
of 0.5 sounds like one rule and is two, depending on whether the cell holds a
sum or a sum of squares. Each parameter below says what its value means in
terms of donors and cells, which is the form an output checker can actually
reason about.

**Where a cost has been measured, it is linked.** Tightening a dial suppresses
more; loosening it releases more. Some of those trades have been quantified
against this project's synthetic data, and the evidence column points at the
measurement rather than an assertion. Where there is no link, the cost has not
been measured, and that is itself worth knowing.

Set any of them by environment variable (which wins) or in `config.yaml`
(which beats the built-in default). Both routes are tested against every
parameter listed here.

"""

FOOTER = """
## Adding a parameter

Declare it on `PolicyConfig` with `_dial(...)`, giving what it controls, what
the number means, its governing clause, its `config.yaml` key, and a test that
proves changing it changes a decision. Add its environment variable to
`_ENV_OVERRIDES`, then regenerate this page:

```sh
uv run python scripts/gen_policy_catalogue.py --write
```

`tests/test_policy_catalogue.py` will otherwise fail the build — for a missing
declaration, a clause that does not exist, evidence that has gone missing, a
`config.yaml` key or environment variable that does not actually take effect,
or a page that no longer matches the code.
"""


def env_for(name: str) -> str | None:
    for env, (field_name, _) in _ENV_OVERRIDES.items():
        if field_name == name:
            return env
    return None


def render() -> str:
    out = [HEADER]
    for f in fields(PolicyConfig):
        meta = f.metadata
        default = "unset" if f.default is None else f"`{f.default!r}`"
        out.append(f"## `{f.name}`\n")
        out.append(f"{meta['controls'].capitalize()}.\n")
        out.append(f"**What the value means.** {meta['means']}\n")
        rows = [
            ("Default", default
             + (f" — {meta['unset_means']}" if meta.get("unset_means") else "")),
            ("Environment", f"`{env_for(f.name)}`"),
            ("`config.yaml`", f"`{meta['yaml_key']}`"),
            ("Clause", f"[{meta['clause']}](specification.md)"),
            ("Pinned by", f"`{meta['pinned_by']}`"),
        ]
        evidence = meta.get("evidence")
        rows.append(("Measured cost",
                     f"[{evidence}]({_link(evidence)})" if evidence
                     else "*not measured*"))
        out.append("| | |\n|---|---|")
        out.extend(f"| {label} | {value} |" for label, value in rows)
        out.append("")
    out.append(FOOTER)
    return "\n".join(out).rstrip() + "\n"


def _link(evidence: str) -> str:
    """Docs links are relative to this page; anything else is a repo path."""
    if evidence.startswith("docs/"):
        return evidence[len("docs/"):]
    return f"https://github.com/wadelab/safe-tre-agent/blob/main/{evidence}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true",
                    help="update docs/policy-parameters.md in place")
    args = ap.parse_args()
    page = render()
    if not args.write:
        sys.stdout.write(page)          # exactly the file, so a diff is a diff
        return 0
    with open(PAGE, "w") as fh:
        fh.write(page)
    print(f"wrote {os.path.relpath(PAGE, ROOT)} "
          f"({len(fields(PolicyConfig))} parameters)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
