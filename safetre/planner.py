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
    '{"dataset":"spend|donor_spend|wellbeing","measure":{"fn":"count|mean|sum|corr",'
    '"column":<measure column or null>,"x":<corr measure column or null>,'
    '"y":<corr measure column or null>},"group_by":[...],"filters":[{"column":...,'
    '"op":"==|!=|<|<=|>|>=|in","value":...}]}\n'
    "For correlation requests, use fn='corr' with x and y set to two allowed "
    "measure columns from the same dataset, and column null. "
    "For age-versus-spend correlation, use dataset 'donor_spend', x='age_years', "
    "y='total_spend_gbp'. Raw age is an internal analysis variable only: never "
    "group by it or return it. Composite criteria such as sex==M and "
    "region==London must be emitted as separate filter objects. "
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

    @staticmethod
    def _filters_from_text(request: str) -> list[dict]:
        filters: list[dict] = []
        sex = re.search(r"\bsex\s*==\s*([A-Za-z])\b", request, re.I)
        if sex:
            filters.append({"column": "sex", "op": "==", "value": sex.group(1).upper()})

        region = re.search(r"\bregion\s*==\s*([A-Za-z]+)\b", request, re.I)
        if region:
            canonical = {
                "london": "London",
                "south east": "South East",
                "north west": "North West",
                "scotland": "Scotland",
                "wales": "Wales",
                "northern ireland": "Northern Ireland",
            }
            value = canonical.get(region.group(1).lower(), region.group(1))
            filters.append({"column": "region", "op": "==", "value": value})

        between = re.search(r"\bage\s+between\s+(\d+)\s+and\s+(\d+)\b", request, re.I)
        if between:
            lo, hi = int(between.group(1)), int(between.group(2))
            filters.extend([
                {"column": "age_years", "op": ">=", "value": lo},
                {"column": "age_years", "op": "<=", "value": hi},
            ])
        else:
            for op, value in re.findall(r"\bage\s*(==|!=|<=|>=|<|>)\s*(\d+)\b", request, re.I):
                filters.append({"column": "age_years", "op": op, "value": int(value)})
        return filters

    def plan(self, request: str) -> dict:
        u = request.lower()

        if "region" in u and "device" in u:                 # over-granular -> small cells
            return {"dataset": "spend",
                    "measure": {"fn": "mean", "column": "amount_gbp"},
                    "group_by": ["age_band", "region", "device_os"],
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
            if "age" in u and "spend" in u:
                return {"dataset": "donor_spend",
                        "measure": {"fn": "corr", "x": "age_years", "y": "total_spend_gbp"},
                        "filters": self._filters_from_text(request)}
            if "wellbeing" in u or "wemwbs" in u:
                return {"dataset": "wellbeing",
                        "measure": {"fn": "corr",
                                    "x": "monthly_spend_selfreport",
                                    "y": "wemwbs_score"},
                        "filters": self._filters_from_text(request)}
            if "pgsi" in u or "gambling" in u:
                return {"dataset": "wellbeing",
                        "measure": {"fn": "corr",
                                    "x": "monthly_spend_selfreport",
                                    "y": "pgsi_score"},
                        "filters": self._filters_from_text(request)}
            return {"dataset": "spend",
                    "measure": {"fn": "corr", "x": "amount_gbp", "y": "ingame_currency"},
                    "filters": self._filters_from_text(request)}

        if "wellbeing" in u:
            return {"dataset": "wellbeing",
                    "measure": {"fn": "mean", "column": "wemwbs_score"},
                    "group_by": ["region"]}

        return {"dataset": "spend",                          # benign default
                "measure": {"fn": "mean", "column": "amount_gbp"},
                "group_by": ["age_band"],
                "filters": [{"column": "event_type", "op": "in",
                             "value": ["purchase", "lootbox_open"]}]}
