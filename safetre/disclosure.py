"""Safe-outputs gateway: disclosure control + session-level auditing + HITL.

Lightweight, ACRO-inspired statistical disclosure control. In production this
would wrap the ACRO package (github AI-SDC) rather than reimplement it; the
rules here mirror its core checks (threshold, dominance, and — for correlation —
single-donor influence) so the demo runs with no extra dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .schema import identifier_columns, sensitive_columns

COUNT_COLUMNS = {"n", "count", "size", "freq", "n_donors"}
DOM_THRESHOLD = 0.5      # suppress a cell if one contributor exceeds this share
INFLUENCE_THRESHOLD = 0.5  # suppress a corr cell if removing one donor moves r by more than this
ROUND_BASE = 5           # released counts are rounded to this base


@dataclass
class Finding:
    severity: str   # "high" | "medium" | "low"
    rule: str
    detail: str


def _count_cols(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if str(c).lower() in COUNT_COLUMNS]


def leak_detector(df: pd.DataFrame | None) -> list[Finding]:
    """Inspect a released output for residual disclosure risk.

    Used both as the gateway's check and as the red-team's ground-truth oracle.
    """
    if df is None or len(df) == 0:
        return []
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

    # small cells
    for c in _count_cols(df):
        small = df[df[c] < DisclosurePolicy.DEFAULT_THRESHOLD]
        if len(small) > 0:
            findings.append(Finding("high", "small_cell",
                                    f"{len(small)} cell(s) in '{c}' below threshold "
                                    f"{DisclosurePolicy.DEFAULT_THRESHOLD}"))

    # dominance (p%-rule): one contributor dominates a cell's sum/mean
    if "dominance" in cols:
        dominated = df[df["dominance"] > DOM_THRESHOLD]
        if len(dominated) > 0:
            findings.append(Finding("high", "dominance",
                                    f"{len(dominated)} cell(s) where one contributor "
                                    f"exceeds {DOM_THRESHOLD:.0%} of the total"))

    # influence (corr analogue of the p%-rule): one donor drives a correlation
    if "influence" in cols:
        influential = df[df["influence"] > INFLUENCE_THRESHOLD]
        if len(influential) > 0:
            findings.append(Finding("high", "influence",
                                    f"{len(influential)} correlation cell(s) where removing "
                                    f"one donor shifts r by more than {INFLUENCE_THRESHOLD}"))

    # excessive granularity (looks like a row dump)
    if len(df) > DisclosurePolicy.DEFAULT_MAX_ROWS and not _count_cols(df):
        findings.append(Finding("medium", "too_granular",
                                f"{len(df)} rows with no aggregation"))
    return findings


# findings that are resolved by suppressing the offending rows rather than denying
SUPPRESSABLE = {"small_cell", "dominance", "influence"}


@dataclass
class DisclosurePolicy:
    DEFAULT_THRESHOLD: int = 10
    DEFAULT_MAX_ROWS: int = 100
    threshold: int = 10
    max_rows: int = 100
    dom_threshold: float = DOM_THRESHOLD
    influence_threshold: float = INFLUENCE_THRESHOLD
    round_base: int = ROUND_BASE

    def _finalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Drop internal helper columns and round released counts.

        `n_donors` is an internal distinct-donor count used to enforce the
        frequency threshold on individuals; it is dropped here (before the count
        columns are rounded) so it is never released.
        """
        out = df.drop(columns=["dominance", "influence", "n_donors"], errors="ignore").copy()
        for c in _count_cols(out):
            out[c] = (out[c] / self.round_base).round().astype(int) * self.round_base
        return out

    def _secondary_suppress(self, original: pd.DataFrame,
                            released: pd.DataFrame) -> tuple[pd.DataFrame, int]:
        """Complementary suppression: a margin with exactly one suppressed cell
        leaks it (margin total minus the released cells recovers the value), so
        also suppress the smallest remaining cell in that margin.

        Exact for one group-by dimension (margin = the grand total, obtainable
        as a coarser query). For >=2 dimensions it conservatively applies the
        same rule per dimension level; complete multi-dimensional suppression
        is an LP problem whose proper home is ACRO (round 3). Cross-query
        margin attacks are the lineage auditor's job, not this one's.
        """
        count_cols = _count_cols(original)
        # group dims are categorical/int; float columns are measures, not margins
        group_cols = [c for c in original.columns
                      if str(c).lower() not in COUNT_COLUMNS | {"value", "p_value",
                                                                "dominance", "influence"}
                      and not pd.api.types.is_float_dtype(original[c])]
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
                    released = released.drop(index=rel_slice[size].idxmin())
                    extra += 1
                    changed = True
        return released, extra

    def apply(self, df: pd.DataFrame | None):
        """Return (released_df_or_None, action, findings).

        action in {"release", "redacted", "deny"}.
        """
        findings = leak_detector(df)
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
    """
    threshold: int = 10
    budget: int = 20
    _history: list[tuple[str, float]] = field(default_factory=list)
    _cohorts: list[tuple[str, tuple]] = field(default_factory=list)
    _spent: int = 0

    def observe(self, measure: str, total_n: float) -> list[Finding]:
        findings: list[Finding] = []
        self._spent += 1
        if self._spent > self.budget:
            findings.append(Finding("high", "query_budget",
                                    f"session query budget {self.budget} exceeded"))
        for prev_measure, prev_n in self._history:
            if prev_measure == measure and 0 < abs(prev_n - total_n) < self.threshold:
                findings.append(Finding("high", "differencing",
                                        f"'{measure}' totals differ by "
                                        f"{abs(prev_n - total_n):g} (<{self.threshold}): "
                                        "possible differencing attack"))
        self._history.append((measure, total_n))
        return findings

    def observe_cohort(self, dataset: str, filters: tuple, bound) -> list[Finding]:
        """Flag a cohort nearly identical to one already released this session.

        `filters` is QuerySpec.normalized_filters(); `bound(a, b) -> int` returns
        an upper bound on the number of individuals in exactly one of the two
        cohorts. The caller injects a *simulatable* bound computed from published
        donor marginals, not the live donor sets, so a refusal leaks nothing an
        analyst could not already compute (see engine.simulatable_cohort_bound).
        Cost is bounded by the session budget: at most `budget` prior cohorts.
        """
        for prev_dataset, prev_filters in self._cohorts:
            if prev_dataset != dataset or prev_filters == filters:
                continue
            d = bound(prev_filters, filters)
            if 0 < d < self.threshold:
                return [Finding(
                    "high", "differencing",
                    f"cohort differs from a previously released cohort by at most "
                    f"{d} individual(s) (<{self.threshold}): "
                    "possible differencing attack")]
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
