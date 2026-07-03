"""Planner — the untrusted step. Turns a request into a *proposed* QuerySpec.

The LLM is treated as adversarial: its only power is to suggest a JSON QuerySpec,
which the validator then accepts or rejects. A prompt-injection or a hostile
model can at worst propose an off-allowlist spec, which is rejected with no
execution. A deterministic MockPlanner lets everything run offline.
"""

from __future__ import annotations

import json
import re

from .manifest import manifest_sha256, public_manifest


def _manifest_text() -> str:
    manifest = public_manifest()
    lines = []
    lines.append(f"manifest_sha256: {manifest_sha256()}")
    for tool in manifest["tools"]:
        lines.append(
            f"- tool '{tool['id']}' v{tool['version']} ({tool['status']}): "
            f"{tool['description']}"
        )
    for ds, info in manifest["datasets"].items():
        dims = ", ".join(info["dimensions"])
        meas = ", ".join(info["measures"])
        lines.append(f"- dataset '{ds}': dimensions [{dims}]; measures [{meas}]")
    return "\n".join(lines)


PLANNER_SYSTEM = (
    "You translate a researcher's request into a QuerySpec JSON for a Trusted "
    "Research Environment. You CANNOT write code or SQL and CANNOT access "
    "individuals. Output ONLY JSON of the form:\n"
    '{"dataset":"spend|wellbeing","measure":{"fn":"count|mean|sum|corr",'
    '"column":<measure column or null>,"x":<corr measure column or null>,'
    '"y":<corr measure column or null>},"group_by":[...],"filters":[{"column":...,'
    '"op":"==|!=|<|<=|>|>=|in","value":...}]}\n'
    "For correlation requests, use fn='corr' with x and y set to two allowed "
    "measure columns from the same dataset, and column null. "
    "Published tool manifest (anything else is rejected):\n" + _manifest_text() +
    "\nNever reference identifiers, names, timestamps or free text. JSON only."
)


def _extract_json(text: str) -> str:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return m.group(0) if m else text


class LLMPlanner:
    """Real planner over any OpenAI-compatible client (see safetre.llm)."""

    def __init__(self, client):
        self.client = client

    def plan(self, request: str) -> dict:
        raw = self.client.complete(PLANNER_SYSTEM, request)
        return json.loads(_extract_json(raw))


class MockPlanner:
    """Deterministic planner. Some cases deliberately propose *off-allowlist*
    specs (free_text / donor_id) to prove validation rejects them."""

    def plan(self, request: str) -> dict:
        u = request.lower()

        if "canton" in u and "device" in u:                 # over-granular -> small cells
            return {"dataset": "spend",
                    "measure": {"fn": "mean", "column": "amount_chf"},
                    "group_by": ["age_band", "canton", "device_os"],
                    "filters": [{"column": "event_type", "op": "in",
                                 "value": ["purchase", "lootbox_open"]}]}

        if "free-text" in u or "free text" in u:            # rejected by allowlist
            return {"dataset": "wellbeing", "measure": {"fn": "count"},
                    "group_by": ["free_text"]}

        if "per donor" in u or "per-donor" in u:            # rejected by allowlist
            return {"dataset": "wellbeing",
                    "measure": {"fn": "mean", "column": "wemwbs_score"},
                    "group_by": ["donor_id"]}

        if "correlat" in u or "relationship" in u or "association" in u:
            if "wellbeing" in u or "wemwbs" in u:
                return {"dataset": "wellbeing",
                        "measure": {"fn": "corr",
                                    "x": "monthly_spend_selfreport",
                                    "y": "wemwbs_score"}}
            if "pgsi" in u or "gambling" in u:
                return {"dataset": "wellbeing",
                        "measure": {"fn": "corr",
                                    "x": "monthly_spend_selfreport",
                                    "y": "pgsi_score"}}
            return {"dataset": "spend",
                    "measure": {"fn": "corr", "x": "amount_chf", "y": "ingame_currency"}}

        if "wellbeing" in u:
            return {"dataset": "wellbeing",
                    "measure": {"fn": "mean", "column": "wemwbs_score"},
                    "group_by": ["canton"]}

        return {"dataset": "spend",                          # benign default
                "measure": {"fn": "mean", "column": "amount_chf"},
                "group_by": ["age_band"],
                "filters": [{"column": "event_type", "op": "in",
                             "value": ["purchase", "lootbox_open"]}]}
