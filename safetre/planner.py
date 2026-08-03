"""Planner — the untrusted step. Turns a request into a *proposed* QuerySpec.

The LLM is treated as adversarial: its only power is to suggest a JSON QuerySpec,
which the validator then accepts or rejects. A prompt-injection or a hostile
model can at worst propose an off-allowlist spec, which is rejected with no
execution. A deterministic MockPlanner lets everything run offline.
"""

from __future__ import annotations

import json
import re

from . import dataset as _dataset
from .config import load_policy_config
from .manifest import manifest_sha256, public_manifest
from .query import CATALOGUE, INTERNAL_RANGE_RULES


def _manifest_text(policy) -> str:
    manifest = public_manifest(policy)
    lines = []
    lines.append(f"manifest_sha256: {manifest_sha256(policy)}")
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


def planner_system(policy=None) -> str:
    """The planner system prompt, generated from the ACTIVE dataset definition.

    `policy` is the RESOLVED policy the gateway is enforcing. Omitting it
    re-reads config.yaml and the environment HERE, at one named place, so the
    prompt can announce a `minimum_cell_size` the gateway is not running — and
    a planner uses that number to decide what to ask for (round 11, #89). Any
    caller serving a request must pass the gateway's policy; the fallback is
    for callers that have no gateway to agree with (the CLI, evals, docs).

    The fixed parts state the security contract (JSON only, the three spec
    shapes, what a model may release); every dataset-specific fact — the
    dataset names, the internal-filter band edges, the model responses and
    families, the few-shot examples and any operator hints — comes from the
    active definition, so the same text generator serves any study.
    """
    policy = policy if policy is not None else load_policy_config()
    defn = _dataset.active()
    parts = [
        "You translate a researcher's request into a QuerySpec JSON for a Trusted "
        "Research Environment. You CANNOT write code or SQL and CANNOT access "
        "individuals. Output ONLY JSON of the form:\n"
        f'{{"dataset":"{"|".join(CATALOGUE)}","measure":{{"fn":"count|mean|sum|sum_sq|corr",'
        '"column":<measure column or null>,"x":<corr measure column or null>,'
        '"y":<corr measure column or null>},"group_by":[...],"filters":[{"column":...,'
        '"op":"==|!=|<|<=|>|>=|in","value":...}]}\n'
        "For correlation requests, use fn='corr' with x and y set to two allowed "
        "measure columns from the same dataset, and column null. "
        + (" ".join(defn.planner_hints) + " " if defn.planner_hints else "")
        + "Composite criteria must be emitted as separate filter objects, one "
        "criterion per object.\n"
        "For a regression / GLM request ('regress Y on A and B', 'does A predict "
        "Y', 'model Y as a function of A adjusting for B'), output instead a "
        "GLMSpec JSON of the form:\n"
        '{"tool":"glm","dataset":...,"family":"gaussian|binomial|poisson",'
        '"response":<allowed model response column>,"terms":[<up to 3 allowlisted '
        'dimensions>],"filters":[...]}\n'
        "Choose the family permitted for the response. Permitted model responses "
        f"and families: {defn.glm_responses_text()}. Terms must be dimensions "
        "the request actually names; never invent or drop one. Models release only "
        "coefficients, a summary block, and the vetted cell table — never "
        "residuals, fitted values, or per-individual predictions.\n",
    ]
    for col, rule in INTERNAL_RANGE_RULES.items():
        edges = " and ".join(f"{op} one of {', '.join(map(str, rule['edges'][op]))}"
                             for op in rule["ops"])
        parts.append(
            f"Filters on {col} must align to the declared band edges: {edges}. "
            f"Equality or membership filters on {col} are rejected.\n")
    if defn.planner_examples:
        lines = ["Examples:"]
        for ex in defn.planner_examples:
            lines.append(f"  '{ex.request}' -> "
                         f"{json.dumps(ex.spec, separators=(',', ':'))}")
        parts.append("\n".join(lines) + "\n")
    parts.append(
        "For a one-way ANOVA request ('one-way ANOVA of Y by A', 'does mean Y "
        "differ across A', 'analysis of variance of Y between A groups'), output an "
        "AnovaSpec JSON of the form:\n"
        '{"tool":"anova","dataset":...,"response":<allowed gaussian response>,'
        '"factor":<one allowlisted dimension>,"filters":[...]}\n'
        "ANOVA takes exactly one categorical factor and a gaussian (interval-scale) "
        "response. If the request names more than one factor, use the glm tool "
        "instead.\n"
        "Published tool manifest (anything else is rejected):\n"
        + _manifest_text(policy) +
        "\nNever reference identifiers, names, timestamps or free text. JSON only."
    )
    return "".join(parts)


def _extract_json(text: str) -> str:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return m.group(0) if m else text


class LLMPlanner:
    """Real planner over any OpenAI-compatible client (see safetre.llm).

    `policy` is the resolved policy the gateway enforces; the app passes the
    one it captured at startup so the prompt cannot announce a threshold the
    gateway is not running (#89).
    """

    def __init__(self, client, policy=None):
        self.client = client
        self.policy = policy

    def plan(self, request: str) -> dict:
        raw = self.client.complete(planner_system(self.policy), request)
        return json.loads(_extract_json(raw))


def _band_edges(column: str) -> tuple[tuple, tuple]:
    """(lower edges, upper edges) of an internal filter's range rule, or
    empty tuples when the active definition declares no rule for it."""
    rule = INTERNAL_RANGE_RULES.get(column)
    if rule is None:
        return (), ()
    return rule["edges"].get(">=", ()), rule["edges"].get("<=", ())


def _age_window_filters(lo: int, hi: int) -> list[dict]:
    """The tightest whole-band age filter set covering [lo, hi].

    Validation accepts only band-aligned range filters on `age_years`
    (hardening #39), so the mock snaps: the lower edge is the smallest band
    start >= lo, the upper edge the largest band end <= hi. The result never
    includes an age outside the asked window.
    """
    lo_edges, hi_edges = _band_edges("age_years")
    out: list[dict] = []
    los = [b for b in lo_edges if b >= lo]
    his = [b for b in hi_edges if b <= hi]
    if los and lo_edges and los[0] > lo_edges[0]:
        out.append({"column": "age_years", "op": ">=", "value": los[0]})
    if his and hi_edges and his[-1] < hi_edges[-1]:
        out.append({"column": "age_years", "op": "<=", "value": his[-1]})
    return out


def _containing_band_filters(v: int) -> list[dict]:
    """Exact-age equality is not filterable (#39); answer with the band that
    contains v, which is what the request almost always means."""
    lo_edges, hi_edges = _band_edges("age_years")
    out: list[dict] = []
    lo_edge = max((b for b in lo_edges if b <= v), default=None)
    hi_edge = min((b for b in hi_edges if b >= v), default=None)
    if lo_edge is not None and lo_edges and lo_edge > lo_edges[0]:
        out.append({"column": "age_years", "op": ">=", "value": lo_edge})
    if hi_edge is not None and hi_edges and hi_edge < hi_edges[-1]:
        out.append({"column": "age_years", "op": "<=", "value": hi_edge})
    return out


class MockPlanner:
    """Deterministic offline planner double for tests/CI, keyed to the
    packaged DEMO dataset's vocabulary. Some cases deliberately propose
    *off-allowlist* specs (free_text / donor_id) to prove validation rejects
    them. It is not a per-dataset component: with any other active definition
    its proposals mostly fail validation (the safe direction); production
    deployments plan with a real model (LLMPlanner), whose prompt IS generated
    from the active definition."""

    @staticmethod
    def _filters_from_text(request: str) -> list[dict]:
        filters: list[dict] = []
        sex = re.search(r"\bsex\s*==\s*([A-Za-z])\b", request, re.I)
        if sex:
            filters.append({"column": "sex", "op": "==", "value": sex.group(1).upper()})

        region = re.search(r"\bregion\s*==\s*([A-Za-z]+)\b", request, re.I)
        if region:
            # single-word aliases (the regex captures one word); multi-word
            # regions can be spelled exactly in quotes-free text and pass through
            canonical = {
                "london": "London",
                "scotland": "Scotland",
                "wales": "Wales",
                "yorkshire": "Yorkshire and The Humber",
                "ireland": "Northern Ireland",
            }
            value = canonical.get(region.group(1).lower(), region.group(1))
            filters.append({"column": "region", "op": "==", "value": value})

        between = re.search(r"\bage\s+between\s+(\d+)\s+and\s+(\d+)\b", request, re.I)
        if between:
            filters.extend(_age_window_filters(int(between.group(1)),
                                               int(between.group(2))))
        else:
            for op, value in re.findall(r"\bage\s*(==|!=|<=|>=|<|>)\s*(\d+)\b", request, re.I):
                v = int(value)
                # snap to whole bands (hardening #39); an exact-age exclusion
                # is not expressible at all and is dropped
                if op == "==":
                    filters.extend(_containing_band_filters(v))
                elif op == "!=":
                    continue
                elif op == ">=":
                    filters.extend(_age_window_filters(v, 10**9))
                elif op == ">":
                    filters.extend(_age_window_filters(v + 1, 10**9))
                elif op == "<=":
                    filters.extend(_age_window_filters(-10**9, v))
                elif op == "<":
                    filters.extend(_age_window_filters(-10**9, v - 1))
        return filters

    @staticmethod
    def _terms_from_text(u: str, candidates: tuple[tuple[str, str], ...]) -> list[str]:
        return [dim for dim, cue in candidates if cue in u]

    def _plan_model(self, request: str, u: str) -> dict:
        """Deterministic GLMSpec proposals for model-shaped requests."""
        filters = self._filters_from_text(request)
        if "lootbox" in u or "logistic" in u:
            terms = self._terms_from_text(u, (("genre", "genre"),
                                              ("price_tier", "price"),
                                              ("age_rating", "rating")))
            return {"tool": "glm", "dataset": "spend", "family": "binomial",
                    "response": "contains_lootboxes",
                    "terms": terms or ["genre"], "filters": filters}
        if "purchase" in u or "poisson" in u:
            terms = self._terms_from_text(u, (("income_band", "income"),
                                              ("age_band", "age"),
                                              ("sex", "sex"),
                                              ("region", "region"),
                                              ("device_os", "device")))
            return {"tool": "glm", "dataset": "donor_spend", "family": "poisson",
                    "response": "purchase_events",
                    "terms": terms or ["income_band"], "filters": filters}
        if any(kw in u for kw in ("wellbeing", "wemwbs", "pgsi", "gambling", "igds")):
            if "pgsi" in u or "gambling" in u:
                response = "pgsi_score"
            elif "igds" in u:
                response = "igds_score"
            else:
                response = "wemwbs_score"
            terms = self._terms_from_text(u, (("region", "region"),
                                              ("sex", "sex"),
                                              ("age_band", "age"),
                                              ("income_band", "income"),
                                              ("device_os", "device")))
            return {"tool": "glm", "dataset": "wellbeing", "family": "gaussian",
                    "response": response, "terms": terms or ["region"],
                    "filters": filters}
        terms = self._terms_from_text(u, (("age_band", "age"),
                                          ("sex", "sex"),
                                          ("region", "region"),
                                          ("income_band", "income"),
                                          ("device_os", "device")))
        return {"tool": "glm", "dataset": "donor_spend", "family": "gaussian",
                "response": "total_spend_gbp",
                "terms": terms or ["age_band"], "filters": filters}

    def _plan_anova(self, request: str, u: str) -> dict:
        """Deterministic AnovaSpec for one-way ANOVA requests. Response and
        dataset are inferred from domain cues; the factor is the first
        recognised dimension (defaulting to region, a dimension of every
        dataset). A single factor only — multi-factor requests belong to glm."""
        filters = self._filters_from_text(request)
        if any(kw in u for kw in ("wellbeing", "wemwbs", "pgsi", "gambling",
                                  "igds", "mental")):
            dataset = "wellbeing"
            if "pgsi" in u or "gambling" in u:
                response = "pgsi_score"
            elif "igds" in u:
                response = "igds_score"
            else:
                response = "wemwbs_score"
        elif "in-game" in u or "currency" in u:
            dataset, response = "spend", "ingame_currency"
        else:
            dataset, response = "donor_spend", "total_spend_gbp"
        factors = self._terms_from_text(u, (("region", "region"), ("sex", "sex"),
                                            ("age_band", "age"),
                                            ("income_band", "income"),
                                            ("device_os", "device")))
        factor = factors[0] if factors else "region"
        return {"tool": "anova", "dataset": dataset, "response": response,
                "factor": factor, "filters": filters}

    def plan(self, request: str) -> dict:
        u = request.lower()

        if "anova" in u or "analysis of variance" in u:
            return self._plan_anova(request, u)

        if any(kw in u for kw in ("regress", "as a function of", "logistic",
                                  "poisson", "controlling for", "glm")):
            return self._plan_model(request, u)

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

        if "region" in u:                                    # mean spend by UK region
            return {"dataset": "spend",
                    "measure": {"fn": "mean", "column": "amount_gbp"},
                    "group_by": ["region"],
                    "filters": [{"column": "event_type", "op": "in",
                                 "value": ["purchase", "lootbox_open"]}]}

        return {"dataset": "spend",                          # benign default
                "measure": {"fn": "mean", "column": "amount_gbp"},
                "group_by": ["age_band"],
                "filters": [{"column": "event_type", "op": "in",
                             "value": ["purchase", "lootbox_open"]}]}
