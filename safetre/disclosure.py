"""Safe-outputs gateway: disclosure control + session-level auditing + HITL.

Lightweight, ACRO-inspired statistical disclosure control. In production this
would wrap the ACRO package (github AI-SDC) rather than reimplement it; the
rules here mirror its core checks (threshold, dominance) so the demo runs with
no extra dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .schema import identifier_columns, sensitive_columns

COUNT_COLUMNS = {"n", "count", "size", "freq", "n_donors"}
DOM_THRESHOLD = 0.5      # suppress a cell if one contributor exceeds this share
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

    # excessive granularity (looks like a row dump)
    if len(df) > DisclosurePolicy.DEFAULT_MAX_ROWS and not _count_cols(df):
        findings.append(Finding("medium", "too_granular",
                                f"{len(df)} rows with no aggregation"))
    return findings


# findings that are resolved by suppressing the offending rows rather than denying
SUPPRESSABLE = {"small_cell", "dominance"}


@dataclass
class DisclosurePolicy:
    DEFAULT_THRESHOLD: int = 10
    DEFAULT_MAX_ROWS: int = 100
    threshold: int = 10
    max_rows: int = 100
    dom_threshold: float = DOM_THRESHOLD
    round_base: int = ROUND_BASE

    def _finalize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Drop the internal dominance helper and round released counts."""
        out = df.drop(columns=["dominance"], errors="ignore").copy()
        for c in _count_cols(out):
            out[c] = (out[c] / self.round_base).round().astype(int) * self.round_base
        return out

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
            return self._finalize(redacted), "redacted", findings

        return self._finalize(df), "release", findings


@dataclass
class SessionAuditor:
    """Tracks released aggregates to catch differencing/triangulation."""
    threshold: int = 10
    budget: int = 20
    _history: list[tuple[str, float]] = field(default_factory=list)
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


def hitl_decision(findings: list[Finding]) -> str:
    """Human-in-the-loop policy. Returns 'auto' | 'human' | 'deny'."""
    if any(f.severity == "high" for f in findings):
        return "deny"
    if any(f.severity == "medium" for f in findings):
        return "human"
    return "auto"
