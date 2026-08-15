"""Request vetting and fidelity checks for the secure path.

Three gates the QuerySpec pipeline runs before and after the planner:

- `vet_request` — refuse a request whose *intent* is row-level or
  re-identifying, before any planning happens. Defence in depth only; the
  allowlist is the real boundary.
- `check_grouping_coherence` / `check_term_coherence` — refuse a spec that
  validated but answers a different question from the one asked, rather than
  silently returning an answer to a substituted question.

The "LLM writes pandas" analyst loop that used to live here has moved to
`redteam/legacy/sandbox.py` (hardening #52). It was never reachable from the
web app or the CLI, but it shipped inside the package and its denylist guard
was reported by the red-team suite as though it were a control. It is a
counter-example, so it now lives with the red-team code that uses it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import pandas as pd

from . import dataset as _dataset
from . import disclosure as D
from .query import CATALOGUE

# Requests we will not even send to the model. This is a cheap defence-in-depth
# pre-filter, NOT the security boundary — the QuerySpec allowlist is. Cues are
# broad paraphrases of "give me the microdata"; the real guarantee is that
# identifiers/free-text/raw-age are not expressible in a QuerySpec at all.
BLOCKED_INTENT = [
    # microdata / re-identification paraphrases
    "row-level", "row level", "line level", "line-level",
    "individual record", "individual-level", "unit record",
    "microdata", "micro-data", "raw row", "raw record",
    "raw event", "raw data row", "record-level", "record level",
    "deanonymise", "deanonymize", "re-identify", "reidentify",
    # per-individual / one-row-per-subject enumeration. The safe interface only
    # exposes per-donor results as AGGREGATES over grouped dimensions, never a
    # row per subject. This is caught deterministically here, BEFORE the planner,
    # so a capable model cannot quietly "repair" a disclosive request into a
    # permitted overall aggregate and release that instead — a silent downgrade
    # in which the user asked for row-level data and got a single number with no
    # signal their request was refused. Fail loudly instead.
    "per donor", "per-donor", "per participant", "per-participant",
    "per respondent", "per-respondent", "per individual", "per-individual",
    "each donor", "each participant", "each respondent", "each individual",
    "by row", "one row per", "row per donor", "row per participant",
    "row per respondent",
    # per-observation model outputs (P20). Not expressible in a GLMSpec —
    # models release only the fixed coefficient/summary/cell-table frames —
    # but refuse the *request* loudly rather than answer a different question.
    "residual", "residuals", "fitted value", "fitted values", "leverage",
    "cook's distance", "cooks distance", "dfbeta", "influence score",
    "per-donor prediction", "per donor prediction", "predicted value for each",
    "prediction for each",
]
BLOCKED_TEXT_INTENT = [
    "free-text", "free text", "raw text", "verbatim",
    "open-ended", "open ended", "qualitative response",
    "qualitative responses", "comments", "comment field",
]
ANALYSIS_CUES = [
    "aggregate", "summary", "summarise", "summarize", "report", "mean",
    "average", "sum", "sums", "total", "count", "counts", "number",
    "how many", "population", "distribution", "rate", "percent", "percentage",
    "group", "grouped", " by ", " per ", "per-", "excluding", "exclude",
    "filter", "where", "compare", "comparison", "breakdown", "outlier", "top",
    "correlat", "relationship", "association",
    # model requests (R15)
    "regress", "regression", "model", "predict", "glm", "logistic", "poisson",
    "as a function of", "controlling for", "adjusted for", "adjusting for",
    "effect of", "odds", "anova", "analysis of variance", "differ across",
    "differ between",
    # time-series requests (R15, the `series` tool)
    "time series", "time-series", "series of", "over time", "trend",
    "seasonal", "seasonality", "autocorrelation", "periodogram", "by month",
    "monthly", "by wave", "across waves",
]
# The dataset-specific vocabulary the intent filter accepts as on-topic, and
# the synonym maps the fidelity checks resolve requests against. Mirrored from
# the active dataset definition's `lexicon` (safetre/dataset.py).
DOMAIN_CUES: list[str] = []
DIMENSION_SYNONYMS: dict[str, str] = {}
RESPONSE_SYNONYMS: dict[str, dict[str, str]] = {}


def _apply(defn) -> None:
    DOMAIN_CUES[:] = list(defn.lexicon.domain_cues)
    DIMENSION_SYNONYMS.clear()
    DIMENSION_SYNONYMS.update(defn.lexicon.dimension_synonyms)
    RESPONSE_SYNONYMS.clear()
    RESPONSE_SYNONYMS.update({k: dict(v) for k, v in defn.lexicon.response_synonyms.items()})


_dataset.register_sync(_apply)
_apply(_dataset.active())


@dataclass
class Response:
    status: str                      # released | redacted | denied | error
    output: pd.DataFrame | None = None
    message: str = ""
    findings: list[D.Finding] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)


def vet_request(request: str) -> tuple[bool, str]:
    low = f" {request.lower()} "
    for bad in BLOCKED_INTENT:
        if bad in low:
            return False, f"request intent blocked ({bad!r})"
    for bad in BLOCKED_TEXT_INTENT:
        if bad in low:
            return False, f"free-text request blocked ({bad!r})"
    has_analysis_cue = any(cue in low for cue in ANALYSIS_CUES)
    has_domain_cue = any(cue in low for cue in DOMAIN_CUES)
    if not (has_analysis_cue and has_domain_cue):
        return False, "request is outside the supported aggregate-analysis scope"
    return True, "ok"


# Phrases that introduce a grouping/breakdown in a request.
GROUPING_KEYWORDS = [
    "broken down by", "break down by", "grouped by", "group by", "split by",
    "breakdown by", "breakdown of", "for each ", " per ", " by ", " across ",
]

# Natural-language term -> the catalogue dimension it names (from the active
# dataset definition). Longer, more specific phrases are matched first so
# "age band" wins over "age", etc.


# Words that end a grouping clause and begin a filter/condition, so a breakdown
# ("by region for age > 40") is not mistaken for a request to group by the
# filtered column.
FILTER_TERMINATORS = [
    " for ", " where ", " excluding ", " exclude ", " with ", " in ",
    " between ", " over ", " under ", " above ", " below ", " during ",
    " among ", " if ", " that ", " who ", " having ", " restricted to ",
]


def _dims_mentioned(text: str) -> set[str]:
    """Catalogue dimensions named (by synonym) in `text`.

    Longest synonyms match first and consume their span, so "age rating" names
    age_rating only — not also age_band via the "age" inside it.
    """
    low = text.lower()
    consumed = [False] * len(low)
    found = set()
    for term in sorted(DIMENSION_SYNONYMS, key=len, reverse=True):
        dim = DIMENSION_SYNONYMS[term]
        for m in re.finditer(rf"(?<!\w){re.escape(term)}(?:s|es)?(?!\w)", low):
            if not any(consumed[m.start():m.end()]):
                found.add(dim)
                for i in range(m.start(), m.end()):
                    consumed[i] = True
    return found


def _grouping_clause(request: str) -> str | None:
    """The breakdown clause: text from the first grouping keyword up to the next
    filter keyword (or end). None if the request asks for no explicit breakdown."""
    low = f" {request.lower()} "
    start = None
    for kw in GROUPING_KEYWORDS:
        idx = low.find(kw)
        if idx != -1 and (start is None or idx < start[0]):
            start = (idx, idx + len(kw))
    if start is None:
        return None
    clause = low[start[1]:]
    cut = len(clause)
    for term in FILTER_TERMINATORS:
        t = clause.find(term)
        if t != -1:
            cut = min(cut, t)
    return clause[:cut]


def check_grouping_coherence(request: str, dataset: str,
                             group_by: list[str]) -> tuple[bool, str]:
    """Deterministic request<->spec fidelity check for grouping.

    The untrusted planner can emit a spec that VALIDATES (every group_by dim is
    on the dataset's allowlist) yet answers a *different* question than the one
    asked. Rather than release an answer to a substituted question, refuse.
    Three ways the spec can be unfaithful to an explicit breakdown request:
      A. a breakdown this dataset cannot provide ("wellbeing per lootbox");
      B. a group_by dimension the request never named (hallucination);
      C. a requested, valid breakdown the planner silently dropped (omission).
    Runs after validation, before the engine, independent of the planner.

    Lenient by design: it only fires when the request names a groupable concept,
    so it does not flag differencing follow-ups ("same, excluding ...") or
    requests with no explicit breakdown.
    """
    dims = CATALOGUE[dataset]["dims"]
    clause = _grouping_clause(request)
    if clause is None:
        return True, "no explicit grouping requested"
    clause_dims = _dims_mentioned(clause)
    if not clause_dims:
        return True, "no recognised grouping dimension in request"
    grouped = set(group_by)

    # Rule A: a requested breakdown this dataset cannot provide.
    unsupported = sorted(d for d in clause_dims if d not in dims)
    if unsupported:
        where = "; ".join(
            f"{d!r} is available on "
            f"{', '.join(sorted(ds for ds, i in CATALOGUE.items() if d in i['dims'])) or 'no dataset'}"
            for d in unsupported)
        return False, (
            f"cannot break {dataset!r} down by {', '.join(unsupported)}: {where}. "
            f"valid breakdowns for {dataset!r}: {', '.join(sorted(dims))}")

    # Rule C: a requested, valid breakdown the planner silently dropped.
    missing = sorted(d for d in clause_dims if d in dims and d not in grouped)
    if missing:
        return False, (
            f"request asks to break {dataset!r} down by {', '.join(missing)}, but the "
            f"query {'omits it' if len(missing) == 1 else 'omits them'} "
            f"(group_by={sorted(grouped)})")

    # Rule B: the planner grouped by a dimension the request never mentioned.
    referenced = _dims_mentioned(request)
    hallucinated = sorted(g for g in grouped if g not in referenced)
    if hallucinated:
        return False, (
            f"query groups by {', '.join(hallucinated)}, which was not part of the "
            f"request; valid breakdowns for {dataset!r}: {', '.join(sorted(dims))}")
    return True, "grouping matches request"


# Phrases that introduce a model's predictor list in a request.
MODEL_TERM_KEYWORDS = [
    " as a function of ", " controlling for ", " adjusted for ",
    " adjusting for ", " regressed on ", " on ", " against ", " by ",
]

# Natural-language response name -> the model response column it names, per
# dataset (from the active dataset definition). Deliberately minimal and
# unambiguous: the check is lenient and only fires when the request names a
# response we can recognise.


def _term_clause(request: str) -> str | None:
    """The predictor clause of a model request: text from the first term
    keyword up to the next filter keyword (or end)."""
    low = f" {request.lower()} "
    start = None
    for kw in MODEL_TERM_KEYWORDS:
        idx = low.find(kw)
        if idx != -1 and (start is None or idx < start[0]):
            start = (idx, idx + len(kw))
    if start is None:
        return None
    clause = low[start[1]:]
    cut = len(clause)
    for term in FILTER_TERMINATORS:
        t = clause.find(term)
        if t != -1:
            cut = min(cut, t)
    return clause[:cut]


def check_term_coherence(request: str, dataset: str, response: str,
                         terms: list[str]) -> tuple[bool, str]:
    """Deterministic request<->spec fidelity check for model terms — the model
    analogue of `check_grouping_coherence`, applying the same three rules to
    the predictor list (A: unsupported, B: hallucinated, C: dropped), plus a
    response check against a minimal synonym map. Lenient by design: rules
    only fire on concepts the request recognisably names.
    """
    dims = CATALOGUE[dataset]["dims"]
    low = f" {request.lower()} "

    # Response: if the request names a response we recognise for this dataset
    # and the spec models a different one, that answers a substituted question.
    named = [col for phrase, col in
             sorted(RESPONSE_SYNONYMS.get(dataset, {}).items(),
                    key=lambda kv: len(kv[0]), reverse=True)
             if f" {phrase} " in low or f" {phrase}," in low]
    if named and response not in named:
        return False, (
            f"request asks to model {named[0]!r} but the query models "
            f"{response!r} instead")

    clause = _term_clause(request)
    clause_dims = _dims_mentioned(clause) if clause is not None else set()
    referenced = _dims_mentioned(request)
    modelled = set(terms)

    # Rule A: a predictor this dataset cannot provide.
    unsupported = sorted(d for d in clause_dims if d not in dims)
    if unsupported:
        return False, (
            f"cannot model {dataset!r} with predictor(s) {', '.join(unsupported)}; "
            f"valid predictors: {', '.join(sorted(dims))}")

    # Rule C: a requested, valid predictor the planner silently dropped.
    missing = sorted(d for d in clause_dims if d in dims and d not in modelled
                     and d != response)
    if missing:
        return False, (
            f"request asks to model with {', '.join(missing)}, but the query "
            f"{'omits it' if len(missing) == 1 else 'omits them'} "
            f"(terms={sorted(modelled)})")

    # Rule B: a predictor the request never mentioned. A declared TIME AXIS
    # is exempt: it is the natural axis of any series / trend / "over time"
    # request whether or not the request names it ("monthly", "over the
    # year"), and there is at most one per view, so modelling it substitutes
    # no question. A dropped time axis is still caught by rule C above.
    time_axes = set(CATALOGUE[dataset].get("time_dims", ()))
    hallucinated = sorted(t for t in modelled if t not in referenced and t not in time_axes)
    if hallucinated:
        return False, (
            f"query models with {', '.join(hallucinated)}, which was not part "
            f"of the request; valid predictors for {dataset!r}: "
            f"{', '.join(sorted(dims))}")
    return True, "model terms match request"


def _measure_and_total(df: pd.DataFrame) -> tuple[str, float]:
    count_cols = [c for c in df.columns if str(c).lower() in D.COUNT_COLUMNS]
    total = float(df[count_cols].to_numpy().sum()) if count_cols else float(len(df))
    if "measure" in df.columns:
        label = str(df["measure"].iloc[0])
    else:
        label = "|".join(sorted(c for c in df.columns if c not in count_cols and c != "measure"))
    return label, total
