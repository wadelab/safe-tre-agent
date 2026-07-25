"""Safe-outputs gateway: disclosure control + session-level auditing + HITL.

Lightweight, ACRO-inspired statistical disclosure control. In production this
would wrap the ACRO package (github AI-SDC) rather than reimplement it; the
rules here mirror its core checks (threshold, dominance, and — for correlation —
single-donor influence) so the demo runs with no extra dependency.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import ClassVar

import pandas as pd

from .schema import identifier_columns, sensitive_columns

COUNT_COLUMNS = {"n", "count", "size", "freq", "n_donors"}
DOM_THRESHOLD = 0.5      # suppress a cell if one contributor exceeds this share
INFLUENCE_THRESHOLD = 0.5  # suppress a corr cell if removing one donor moves r by more than this
ROUND_BASE = 5           # released counts are rounded to this base
# cap the per-session history scanned by `observe`; the query budget short-circuit
# keeps this well under the cap in normal use, but bound it so a flood cannot grow
# it without limit (memory + O(n) scan per call).
MAX_HISTORY = 1000


@dataclass
class Finding:
    severity: str   # "high" | "medium" | "low"
    rule: str
    detail: str


def _count_cols(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if str(c).lower() in COUNT_COLUMNS]


# payload and internal-helper columns: everything else in an aggregate frame is
# a cell key. Group keys are categorical/int; float columns are measures.
_NON_KEY_COLUMNS = COUNT_COLUMNS | {"value", "p_value", "dominance", "influence"}


def _group_columns(df: pd.DataFrame) -> list[str]:
    """The cell-key columns of an aggregate frame, in frame order."""
    return [c for c in df.columns
            if str(c).lower() not in _NON_KEY_COLUMNS
            and not pd.api.types.is_float_dtype(df[c])]


def leak_detector(df: pd.DataFrame | None, threshold: int | None = None,
                  max_rows: int | None = None, dom_threshold: float | None = None,
                  influence_threshold: float | None = None) -> list[Finding]:
    """Inspect a released output for residual disclosure risk.

    Used both as the gateway's check and as the red-team's ground-truth oracle.
    Thresholds default to the policy defaults so the oracle keeps a fixed meaning;
    the gateway passes its *configured* thresholds so `config.yaml` actually bites.

    Fails **closed**: a safety column that is NULL/NaN/±inf (i.e. the engine could
    not establish the cell is safe) is treated as a violation, not as safe. A
    fail-open default here would release a cell whose dominance/influence check
    silently produced no value.
    """
    if df is None or len(df) == 0:
        return []
    threshold = DisclosurePolicy.DEFAULT_THRESHOLD if threshold is None else threshold
    max_rows = DisclosurePolicy.DEFAULT_MAX_ROWS if max_rows is None else max_rows
    dom_threshold = DOM_THRESHOLD if dom_threshold is None else dom_threshold
    influence_threshold = INFLUENCE_THRESHOLD if influence_threshold is None else influence_threshold
    findings: list[Finding] = []
    cols = {str(c) for c in df.columns}

    leaked_ids = cols & identifier_columns()
    if leaked_ids:
        findings.append(Finding("high", "identifier_egress",
                                f"row-level identifier column(s): {sorted(leaked_ids)}"))

    leaked_sensitive = cols & (sensitive_columns() - identifier_columns())
    # sensitive columns are only safe when aggregated; presence of a per-row
    # sensitive column with no count column implies raw rows
    if leaked_sensitive and not _count_cols(df):
        findings.append(Finding("high", "raw_sensitive",
                                f"un-aggregated sensitive column(s): {sorted(leaked_sensitive)}"))

    # free-text is never releasable
    if "free_text" in cols:
        findings.append(Finding("high", "free_text_egress", "free-text column present"))

    # small cells (a NaN count means "unknown size" -> unsafe)
    for c in _count_cols(df):
        small = df[df[c].isna() | (df[c] < threshold)]
        if len(small) > 0:
            findings.append(Finding("high", "small_cell",
                                    f"{len(small)} cell(s) in '{c}' below threshold "
                                    f"{threshold}"))

    # dominance (p%-rule): one contributor dominates a cell's sum/mean.
    # Missing/NaN dominance is fail-closed (the engine fills unresolved cells with
    # +inf, which trips this rule) so an uncomputed check cannot pass.
    if "dominance" in cols:
        dom = pd.to_numeric(df["dominance"], errors="coerce")
        dominated = df[dom.isna() | (dom > dom_threshold)]
        if len(dominated) > 0:
            findings.append(Finding("high", "dominance",
                                    f"{len(dominated)} cell(s) where one contributor "
                                    f"exceeds {dom_threshold:.0%} of the total (or was unresolved)"))

    # influence (corr analogue of the p%-rule): one donor drives a correlation.
    # Same fail-closed treatment: an unresolved influence (NaN/inf) is a violation.
    if "influence" in cols:
        inf = pd.to_numeric(df["influence"], errors="coerce")
        influential = df[inf.isna() | (inf > influence_threshold)]
        if len(influential) > 0:
            findings.append(Finding("high", "influence",
                                    f"{len(influential)} correlation cell(s) where removing "
                                    f"one donor shifts r by more than {influence_threshold} "
                                    "(or was unresolved)"))

    # excessive granularity (looks like a row dump)
    if len(df) > max_rows and not _count_cols(df):
        findings.append(Finding("medium", "too_granular",
                                f"{len(df)} rows with no aggregation"))
    return findings


# findings that are resolved by suppressing the offending rows rather than denying
SUPPRESSABLE = {"small_cell", "dominance", "influence"}


@dataclass
class DisclosurePolicy:
    # Class constants: the oracle/default meaning of the thresholds (not fields).
    DEFAULT_THRESHOLD: ClassVar[int] = 10
    DEFAULT_MAX_ROWS: ClassVar[int] = 100
    threshold: int = 10
    max_rows: int = 100
    dom_threshold: float = DOM_THRESHOLD
    influence_threshold: float = INFLUENCE_THRESHOLD
    round_base: int = ROUND_BASE

    def _finalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Drop internal helper columns, round released counts, and order the
        rows by released quantities alone.

        `n_donors` is an internal distinct-donor count used to enforce the
        frequency threshold on individuals; it is dropped here (before the count
        columns are rounded) so it is never released.

        The engine returns cells in `ORDER BY n DESC` — the *exact* count — so
        the row order of a released table used to rank cells more finely than
        the released counts do: of two cells both released as `n = 10`, the
        order said which had more rows (hardening #28). Re-sorting on the
        rounded count, tie-broken on the public cell key, makes the order a
        function of what is already released — and makes a release
        reproducible run to run, which `ORDER BY` over tied counts is not.
        """
        out = df.drop(columns=["dominance", "influence", "n_donors"], errors="ignore").copy()
        counts = _count_cols(out)
        for c in counts:
            out[c] = (out[c] / self.round_base).round().astype(int) * self.round_base
        ordering = pd.DataFrame(index=out.index)
        if counts:
            ordering["_count"] = -out[counts[0]]           # released count, descending
        for key in _group_columns(out):
            ordering[f"_key_{key}"] = out[key].astype(str)
        if len(ordering.columns):
            out = out.loc[ordering.sort_values(list(ordering.columns),
                                               kind="stable").index]
        return out.reset_index(drop=True)

    def _secondary_suppress(self, original: pd.DataFrame,
                            released: pd.DataFrame) -> tuple[pd.DataFrame, int]:
        """Complementary suppression: a margin with exactly one suppressed cell
        leaks it (margin total minus the released cells recovers the value), so
        also suppress the smallest remaining cell in that margin.

        Exact for one group-by dimension (margin = the grand total, obtainable
        as a coarser query). For >=2 dimensions it conservatively applies the
        same rule per dimension level; complete multi-dimensional suppression
        is an LP problem whose proper home is tau-Argus-class tooling — ACRO
        masks failing cells only, so this rule stays in force on top of it
        (roadmap item 1). Cross-query margin attacks are the lineage
        auditor's job, not this one's.
        """
        count_cols = _count_cols(original)
        group_cols = _group_columns(original)
        if not count_cols or not group_cols or len(released) == len(original):
            return released, 0
        size = count_cols[0]

        # each margin = a slice that has its own recoverable total
        if len(group_cols) == 1:
            margins = [[]]                              # the grand total
        else:
            margins = [[(dim, lvl)] for dim in group_cols
                       for lvl in original[dim].unique()]

        extra = 0
        changed = True
        while changed and len(released):                # each pass drops >=1 row
            changed = False
            for margin in margins:
                orig_slice, rel_slice = original, released
                for dim, lvl in margin:
                    orig_slice = orig_slice[orig_slice[dim] == lvl]
                    rel_slice = rel_slice[rel_slice[dim] == lvl]
                if len(orig_slice) - len(rel_slice) == 1 and len(rel_slice) > 0:
                    released = released.drop(index=self._sacrifice(rel_slice, size))
                    extra += 1
                    changed = True
        return released, extra

    def _sacrifice(self, candidates: pd.DataFrame, size: str):
        """Which cell complementary suppression gives up.

        Still the smallest cell — but ranked on the count as it will be
        *released* (base-5 rounded) and tie-broken on the public cell key,
        never on the exact count. Ranking on the exact count made the identity
        of the sacrificed cell a function of pre-rounding counts: of two cells
        that both release as `n = 10`, an analyst learned which one was
        smaller, which is the information rounding exists to blur (hardening
        #27, the same class as #26).
        """
        rounded = (candidates[size] / self.round_base).round().astype(int)
        keys = candidates[_group_columns(candidates)].astype(str).apply(
            lambda row: "|".join(row), axis=1)
        return pd.DataFrame({"count": rounded, "key": keys}).sort_values(
            ["count", "key"], kind="stable").index[0]

    def apply(self, df: pd.DataFrame | None):
        """Return (released_df_or_None, action, findings).

        action in {"release", "redacted", "deny"}.
        """
        findings = leak_detector(df, self.threshold, self.max_rows,
                                 self.dom_threshold, self.influence_threshold)
        if df is None:
            return None, "deny", findings

        high = [f for f in findings if f.severity == "high"]
        # non-suppressable high findings (identifier/free-text/raw) -> deny outright
        if any(f.rule not in SUPPRESSABLE for f in high):
            return None, "deny", findings

        if any(f.rule in SUPPRESSABLE for f in high):
            redacted = df.copy()
            for c in _count_cols(redacted):
                redacted = redacted[redacted[c] >= self.threshold]
            if "dominance" in redacted.columns:
                redacted = redacted[redacted["dominance"] <= self.dom_threshold]
            if "influence" in redacted.columns:
                redacted = redacted[redacted["influence"] <= self.influence_threshold]
            redacted, extra = self._secondary_suppress(df, redacted)
            if extra:
                findings.append(Finding(
                    "low", "secondary_suppression",
                    f"{extra} complementary cell(s) suppressed to protect margins"))
            return self._finalize(redacted), "redacted", findings

        return self._finalize(df), "release", findings


def _dim_value_set(universe: set, predicates: list) -> set:
    """The set of a dimension's values selected by a list of (op, value) predicates."""
    s = set(universe)
    for op, value in predicates:
        if op == "==":
            s &= {value}
        elif op == "!=":
            s -= {value}
        elif op == "in":
            s &= set(value)
        elif op == "<":
            s = {u for u in s if u < value}
        elif op == "<=":
            s = {u for u in s if u <= value}
        elif op == ">":
            s = {u for u in s if u > value}
        elif op == ">=":
            s = {u for u in s if u >= value}
    return s


ALLOW_SENTINEL = 10 ** 9


def simulatable_cohort_bound(marginals: dict, dataset: str,
                             filters_a: tuple, filters_b: tuple) -> int:
    """A simulatable upper bound on |A △ B|, from published donor marginals only.

    The session auditor must not decide releases from the live donor sets, or the
    refusal itself leaks (Kenthapadi–Mishra–Nissim, *simulatable auditing*, 2005).
    This decides from `marginals` — a donor-frequency table per (dataset, dim,
    value) that is itself disclosure-safe metadata (see
    `engine.QueryEngine.marginal_donor_counts`) — so an analyst holding the
    same public marginals could reproduce every decision, and a refusal reveals
    nothing new.

    For two cohorts that differ on exactly one dimension, the whole-population
    donor marginal of the differing values is an *upper* bound on the symmetric
    difference. So a denial (bound < threshold) is always sound, and this catches
    the canonical attack: isolating a globally-rare category by adding or
    removing one predicate ("exclude age 69", "exclude sex X").

    Being an upper bound, it does NOT catch differencing that isolates a small
    group through the *interaction* of a common category with an otherwise-narrow
    cohort (e.g. the over-50s within one small region): the marginal is then
    large even though the real symmetric difference is small. That residual is
    the price of simulatability; it is largely covered by the per-cell donor
    threshold (a narrow cohort's cells are suppressed anyway) and fully by a DP
    accountant. Cohorts differing on more than one dimension return a sentinel
    that never denies and rely on the query-budget and total-delta checks.
    """
    dmap = marginals.get(dataset, {})

    def by_dim(filters: tuple) -> dict:
        grouped: dict = {}
        for column, op, value in filters:
            grouped.setdefault(column, []).append((op, value))
        return grouped

    a, b = by_dim(filters_a), by_dim(filters_b)
    differing = []
    for dim in set(a) | set(b):
        universe = set(dmap.get(dim, {}))
        sa = _dim_value_set(universe, a.get(dim, []))
        sb = _dim_value_set(universe, b.get(dim, []))
        if sa != sb:
            differing.append((dim, sa ^ sb))
    if len(differing) != 1:
        return ALLOW_SENTINEL
    dim, symdiff_values = differing[0]
    return sum(dmap[dim].get(v, 0) for v in symdiff_values)


@dataclass
class SessionAuditor:
    """Tracks released aggregates to catch differencing/triangulation.

    Two layers:
    - `observe` — cheap first pass comparing released totals per measure.
    - `observe_cohort` / `record_cohort` — query lineage: each released
      query's cohort (its normalized filter predicate) is remembered, and a new
      cohort whose symmetric difference with a prior one is a small set of
      individuals is flagged, whatever the totals look like. This catches
      sum/mean differencing across overlapping cohorts that the total-delta
      check cannot see.

    Deterministic and explainable by design; does not defend across sessions or
    colluding users (that needs global accounting — DP, round 3).

    Refusal messages are deliberately non-numeric. The deny/allow decision is a
    thin signal an interactive SDC control must expose to function, but the exact
    total delta or symmetric-difference size is itself the quantity a differencing
    attack is trying to recover, so it is never put in a finding shown to the
    caller (or written to the audit trail).
    """
    threshold: int = 10
    budget: int = 20
    _history: deque = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    _cohorts: list[tuple[str, tuple]] = field(default_factory=list)
    _spent: int = 0

    @property
    def spent(self) -> int:
        return self._spent

    def over_budget(self) -> bool:
        """True once the session has already spent its query budget.

        Lets the caller short-circuit further work (engine + planner) instead of
        computing an aggregate only to deny it — bounds both cost and the
        per-session state a flood can accumulate.
        """
        return self._spent >= self.budget

    def observe(self, measure: str, total_n: float) -> list[Finding]:
        findings: list[Finding] = []
        self._spent += 1
        if self._spent > self.budget:
            findings.append(Finding("high", "query_budget",
                                    f"session query budget {self.budget} exceeded"))
        for prev_measure, prev_n in self._history:
            if prev_measure == measure and 0 < abs(prev_n - total_n) < self.threshold:
                findings.append(Finding("high", "differencing",
                                        f"'{measure}' totals are within {self.threshold} of a "
                                        "prior release: possible differencing attack"))
                break
        self._history.append((measure, total_n))
        return findings

    def observe_cohort(self, dataset: str, filters: tuple, bound) -> list[Finding]:
        """Flag a cohort nearly identical to one already released this session.

        `filters` is QuerySpec.normalized_filters(); `bound(a, b) -> int` returns
        an upper bound on the number of individuals in exactly one of the two
        cohorts. The caller injects a *simulatable* bound computed from published
        donor marginals, not the live donor sets. The refusal reveals only the one
        bit "too similar to a prior release", not the numeric bound (see
        `simulatable_cohort_bound` above and docs/security.md on simulatability).
        Cost is bounded by the session budget: at most `budget` prior cohorts.
        """
        for prev_dataset, prev_filters in self._cohorts:
            if prev_dataset != dataset or prev_filters == filters:
                continue
            d = bound(prev_filters, filters)
            if 0 < d < self.threshold:
                return [Finding(
                    "high", "differencing",
                    "cohort is within the differencing threshold of a previously "
                    "released cohort: possible differencing attack")]
        return []

    def record_cohort(self, dataset: str, filters: tuple) -> None:
        """Remember a cohort once its result has actually been released."""
        if (dataset, filters) not in self._cohorts:
            self._cohorts.append((dataset, filters))


def hitl_decision(findings: list[Finding]) -> str:
    """Human-in-the-loop policy. Returns 'auto' | 'human' | 'deny'."""
    if any(f.severity == "high" for f in findings):
        return "deny"
    if any(f.severity == "medium" for f in findings):
        return "human"
    return "auto"
