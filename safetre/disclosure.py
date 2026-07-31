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

from .schema import declared_domain, identifier_columns, sensitive_columns

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
    # What the ANALYST is told. It must not carry a count, a size or any other
    # quantity read off the data: a refusal is shown for queries whose output
    # was withheld, so a number in it is a released number that skipped the
    # gateway. The auditor's findings were written this way from the start —
    # "the exact total delta is itself the quantity a differencing attack is
    # trying to recover" — and the gateway's were not. Red-teamed 2026-07-26:
    # a denied cross-tab reported how many cells existed, how many fell below
    # the threshold and how many were dominated, which is a numeric profile of
    # exactly the cells suppression had just withheld.
    detail: str
    # True when suppressing the offending cells resolves this finding. The
    # human-in-the-loop step escalates on what is left, so a vetter whose
    # findings do not say so has every query it touches denied — which is what
    # happened the first time an external checker ran end to end, because
    # suppressability was a fixed list of the stand-in's own rule names.
    suppressable: bool = False
    # The same finding with its numbers, for the audit log and nowhere else.
    # `service.record` serialises the whole finding, so this reaches the log by
    # construction; an output checker reviewing a session sees the quantities,
    # an analyst holding the refusal does not.
    audit_detail: str = ""


def _count_cols(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if str(c).lower() in COUNT_COLUMNS]


# payload and internal-helper columns: everything else in an aggregate frame is
# a cell key.
_NON_KEY_COLUMNS = COUNT_COLUMNS | {"value", "p_value", "dominance", "influence"}

# The released numbers themselves — what an analyst reads off the table, as
# opposed to the counts (rounded) and the safety witnesses (dropped).
PAYLOAD_COLUMNS = {"value", "p_value"}


def _payload_cols(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if str(c).lower() in PAYLOAD_COLUMNS]


def _nonfinite(series: pd.Series) -> pd.Series:
    """Rows whose payload is not a finite number.

    Missing counts as non-finite: an aggregate that could not be computed is
    not a statistic, and releasing it says something about the records behind
    it that the gateway never checked.
    """
    values = pd.to_numeric(series, errors="coerce")
    return values.isna() | values.abs().eq(float("inf"))


def _looks_like_a_measure(series: pd.Series) -> bool:
    """A float column carrying genuinely fractional values is a measure.

    The fallback for callers with no query context. It used to be "float dtype
    means measure", which is wrong for a reason ordinary data supply every day:
    an integer group key with a single missing value comes back from the engine
    as float64. `age_rating` and `wave` are both int dimensions, and one unrated
    app was enough to make the key stop being recognised as a key — silently
    disabling complementary suppression and removing the tie-break that keeps a
    released row order from ranking cells more finely than the released counts
    do (hardening #28). Integral-valued floats are therefore still keys.
    """
    if not pd.api.types.is_float_dtype(series):
        return False
    values = series.dropna()
    return not bool(len(values)) or not bool((values == values.round()).all())


def _key_text(series: pd.Series) -> pd.Series:
    """A cell key as text, for ordering and tie-breaking.

    Element-wise rather than `astype(str)`: a missing value in a key column
    survives `astype` as a float NaN under the newer string dtypes, which then
    fails to join. A cell whose key is missing still has to sort somewhere
    deterministic, so it renders like any other value.
    """
    return series.map(lambda v: "" if v is None or v != v else str(v))


def _group_columns(df: pd.DataFrame, keys: tuple[str, ...] | None = None) -> list[str]:
    """The cell-key columns of an aggregate frame, in frame order.

    `keys` is authoritative when the caller knows them — the query's group-by,
    carried on `CellContext` — and everything on the service path does. The
    heuristic below is for callers that do not (the CLI, the red-team oracle,
    a frame handed straight to a policy), and it is deliberately conservative:
    treating a key as a payload column loses protection, whereas the reverse
    only sorts on one more column.
    """
    if keys is not None:
        present = [c for c in df.columns if c in set(keys)]
        return present
    return [c for c in df.columns
            if str(c).lower() not in _NON_KEY_COLUMNS
            and not _looks_like_a_measure(df[c])]


def leak_detector(df: pd.DataFrame | None, threshold: int | None = None,
                  max_rows: int | None = None, dom_threshold: float | None = None,
                  influence_threshold: float | None = None,
                  keys: tuple[str, ...] | None = None) -> list[Finding]:
    """Inspect a released output for residual disclosure risk.

    Used both as the gateway's check and as the red-team's ground-truth oracle.
    Thresholds default to the policy defaults so the oracle keeps a fixed meaning;
    the gateway passes its *configured* thresholds so `config.yaml` actually bites.
    `keys` names the cell-key columns when the caller knows them (the query's own
    group-by); without it the same conservative heuristic as `_group_columns`.

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
            findings.append(Finding(
                "high", "small_cell", suppressable=True,
                detail=f"cells with fewer than {threshold} underlying individuals "
                       f"were suppressed",
                audit_detail=f"{len(small)} cell(s) in '{c}' below threshold "
                             f"{threshold}"))

    # dominance (p%-rule): one contributor dominates a cell's sum/mean.
    # Missing/NaN dominance is fail-closed (the engine fills unresolved cells with
    # +inf, which trips this rule) so an uncomputed check cannot pass.
    if "dominance" in cols:
        dom = pd.to_numeric(df["dominance"], errors="coerce")
        dominated = df[dom.isna() | (dom > dom_threshold)]
        if len(dominated) > 0:
            findings.append(Finding(
                "high", "dominance", suppressable=True,
                detail=f"cells where one contributor exceeds {dom_threshold:.0%} of "
                       f"the total (or the check was unresolved) were suppressed",
                audit_detail=f"{len(dominated)} cell(s) where one contributor "
                             f"exceeds {dom_threshold:.0%} of the total (or was "
                             f"unresolved)"))

    # influence (corr analogue of the p%-rule): one donor drives a correlation.
    # Same fail-closed treatment: an unresolved influence (NaN/inf) is a violation.
    if "influence" in cols:
        inf = pd.to_numeric(df["influence"], errors="coerce")
        influential = df[inf.isna() | (inf > influence_threshold)]
        if len(influential) > 0:
            findings.append(Finding(
                "high", "influence", suppressable=True,
                detail=f"correlation cells where removing one donor shifts r by more "
                       f"than {influence_threshold} (or the check was unresolved) "
                       f"were suppressed",
                audit_detail=f"{len(influential)} correlation cell(s) where removing "
                             f"one donor shifts r by more than {influence_threshold} "
                             f"(or was unresolved)"))

    # A released AGGREGATE payload must be a finite number (hardening #42).
    # Every other rule here fails closed on an unresolved witness; the payload
    # itself was never checked at all, and `value` appeared in this module only
    # to be classified as not-a-cell-key. An infinite total is not an
    # aggregate, it is the statement "an extreme or invalid record is in this
    # cell" — and it arrives without exotic data: a single -inf, or finite
    # magnitudes whose sum overflows, both released with a dominance witness
    # of ~0.
    #
    # Scoped to frames carrying a count column, i.e. engine cell tables, which
    # is where a payload is an aggregate over records. A fitted model's output
    # is a different shape with legitimate structural gaps — an ANOVA table's
    # `Residual` row has no F and no p by definition — and its numbers are a
    # deterministic function of already-vetted cells (P21) checked against a
    # declared output contract (R14). Treating those NaNs as disclosure risk
    # suppressed a benign model, which is a control firing on the arithmetic
    # rather than on the data.
    for c in (_payload_cols(df) if _count_cols(df) else []):
        bad = df[_nonfinite(df[c])]
        if len(bad) > 0:
            findings.append(Finding(
                "high", "nonfinite_value", suppressable=True,
                detail="cells whose released value is not a finite number were "
                       "suppressed",
                audit_detail=f"{len(bad)} cell(s) with a non-finite '{c}'"))

    # A released cell key must be a declared category (hardening #43).
    # Hardening #29 established that a value outside its column's declared
    # domain is disclosive by its NAME — a hostile string smuggled into a
    # field, a data-entry typo — and dropped such values from the published
    # marginals. The release path never got the same treatment, so a typo'd
    # category carried by enough donors to clear the threshold printed the
    # string anyway. Only the codebook vocabulary may appear as a key; a
    # missing key is left alone, because "unknown" is not a name that leaks.
    #
    # This runs on the query's DECLARED group-by keys and never on the dtype
    # heuristic. Only the query knows which frame column is which catalogue
    # dimension: a hand-built frame whose column happens to be called `region`
    # is not necessarily the catalogue's `region`, and projecting it onto that
    # domain would suppress cells for a name collision. Every service-path
    # release carries its keys (`CellContext`), so the production path is fully
    # covered; a caller with no query context gets the rest of the rules.
    for c in keys or ():
        if c not in df.columns:
            continue
        domain = declared_domain(str(c))
        if domain is None:
            continue
        column = df[c]
        undeclared = df[~(column.isin(domain) | column.isna())]
        if len(undeclared) > 0:
            findings.append(Finding(
                "high", "undeclared_cell_key", suppressable=True,
                detail="cells whose key is not a declared category were "
                       "suppressed",
                audit_detail=f"{len(undeclared)} cell(s) with an undeclared "
                             f"'{c}' key"))

    # Excessive granularity: too many cells to be a summary (hardening #56).
    #
    # This used to require `not _count_cols(df)` — "more than N rows and no
    # aggregation at all" — which on the QuerySpec path is unsatisfiable, because
    # `compile_query` appends `COUNT(*) AS n` unconditionally. So `max_output_rows`
    # was a live dial in `config.yaml` describing a control that could never fire:
    # exactly the defect the config loader was rewritten to prevent.
    #
    # The row-dump reading belongs to the legacy code-writing path, which is now
    # a counter-example rather than a shipped component (#52). What survives on
    # the secure path is the concern the parameter actually documents — an output
    # so finely cut that it stops being a summary — and cell count is how that is
    # measured here. Medium, so it escalates to a human output checker rather
    # than denying: the cells individually passed every rule, and it is their
    # number that wants a second opinion.
    #
    # Measured over the whole group-by skeleton: median 20 released cells, max
    # 157, and 11 of 241 combinations (5%) exceed the default of 100 — all of
    # them three-dimension cross-tabs, which is the granularity the bound is for.
    if len(df) > max_rows:
        findings.append(Finding(
            "medium", "too_granular",
            f"the result has more than {max_rows} cells, which is finer than "
            f"this dataset releases without review",
            audit_detail=f"{len(df)} cells against a bound of {max_rows}"))
    return findings


# the stand-in's own suppression-resolved rules, kept as a name set because the
# red-team corpus and the Alloy models refer to them by name
SUPPRESSABLE = {"small_cell", "dominance", "influence", "nonfinite_value",
                "undeclared_cell_key"}


def is_suppressable(finding: Finding) -> bool:
    """Whether suppressing cells resolves this finding, so it need not
    escalate. A vetter says so on the finding; the stand-in's own rules are
    also recognised by name."""
    return finding.suppressable or finding.rule in SUPPRESSABLE


@dataclass(frozen=True)
class VettingParameters:
    """The safety parameters a vetter decides with.

    Passed at call time rather than captured at construction, so a policy
    built from `config.yaml` cannot end up with a vetter deciding on stale
    thresholds — the configured value is the one that bites (spec R10).
    """

    threshold: int
    max_rows: int
    dom_threshold: float
    influence_threshold: float
    # Dominance for second-moment cells. The same nominal bound is a far
    # tighter rule on a sum of squares than on a sum — squaring is not
    # share-preserving, so a donor holding p of a cell holds
    # p^2/(p^2+(1-p)^2/(k-1)) of its squared total, which crosses one half at
    # p = 1/(1+sqrt(k-1)): 0.19 in a twenty-donor cell, 0.09 in a hundred.
    # Since a model dies if either moment cell is suppressed, that tighter
    # rule is what governs model availability. None means "same as
    # dom_threshold", which is the default and changes nothing.
    moment2_dom_threshold: float | None = None

    def dominance_for(self, value_class: str | None) -> float:
        """The dominance bound for a cell whose released value has this
        disclosure class (spec R14)."""
        if value_class == "moment2" and self.moment2_dom_threshold is not None:
            return self.moment2_dom_threshold
        return self.dom_threshold


@dataclass(frozen=True)
class CellContext:
    """What a vetter needs about the query behind a cell table.

    A cell table alone is not enough for an external checker. Its threshold
    counts donors and its dominance rules need each donor's share, neither of
    which survives aggregation; and it must know which columns are the cell
    keys and how the contributions aggregate, because a `mean` cell and a
    `sum` cell over the same contributions are different tables. Discovered
    the hard way: a vetter built from configuration has no query in it, so a
    long-lived vetter given only the frame silently vetted every table as a
    single total cell and released everything.
    """

    contributions: pd.DataFrame | None = None
    keys: tuple[str, ...] = ()
    aggfunc: str | None = None
    # the disclosure class of the cell's released value (spec R14), which
    # selects the dominance bound: a sum of squares is not a sum
    value_class: str | None = None


@dataclass(frozen=True)
class Verdicts:
    """One vetter's decisions about one cell table.

    `suppress` is a boolean Series indexed like the frame: True means the cell
    must not be released. `deny` marks a finding no suppression can fix — an
    identifier in the output, free text, un-aggregated sensitive columns —
    where the whole table is withheld rather than trimmed. `findings` explain
    both, and are what the caller shows and audits.
    """

    suppress: pd.Series
    findings: list[Finding]
    deny: bool


class CellVetter:
    """Decides, cell by cell, what a table may release.

    The seam ACRO enters through (roadmap item 1, `docs/acro-integration.md`).
    A vetter only ever *decides*: it never computes a released value, never
    rounds and never reorders. Everything downstream — complementary
    suppression, finalization, released-value shaping — is therefore
    unaffected by which vetter runs, which is what keeps hardening #27 and #28
    and the release-equality property (`tests/test_release_equality.py`) true
    however the decision is made.
    """

    name: str
    # whether this vetter decides on donor-level contributions as well as on
    # the cell table. The caller only pays for the extra engine query when
    # something actually reads it.
    needs_contributions: bool = False

    def describe(self) -> str:
        """What ran, for the trace and the audit trail.

        A release must never imply checks that did not happen. When an
        external checker is used the description carries its version, because
        "which rules approved this output?" is a question asked long after
        the session, and the answer cannot be reconstructed from the result.
        """
        return self.name

    def vet(self, df: pd.DataFrame, params: VettingParameters,
            context: CellContext | None = None) -> Verdicts:
        raise NotImplementedError


class StandinVetter(CellVetter):
    """The prototype's own rules: distinct-donor threshold, single-contributor
    dominance, leave-one-donor-out influence, and the egress checks that deny
    outright. `leak_detector` states them once, for both the findings it
    returns and the red-team's ground-truth oracle; the masks here select the
    same cells it complains about.
    """

    name = "standin"

    def vet(self, df: pd.DataFrame, params: VettingParameters,
            context: CellContext | None = None) -> Verdicts:
        dominance = params.dominance_for(context.value_class if context else None)
        # The query's own group-by, when it has one. `()` (an ungrouped query)
        # and `None` (a caller with no query at all) are different answers:
        # the first says "there are no cell keys", the second "I cannot say",
        # and only the first licenses projecting keys onto declared domains.
        keys = context.keys if context is not None else None
        findings = leak_detector(df, params.threshold, params.max_rows,
                                 dominance, params.influence_threshold, keys)
        deny = any(f.severity == "high" and f.rule not in SUPPRESSABLE
                   for f in findings)
        # a cell survives only if it passes every applicable rule, so the
        # suppression mask is the complement — and an unresolved witness
        # (NaN/inf) fails every comparison, which is the fail-closed default
        suppress = pd.Series(False, index=df.index)
        for column in _count_cols(df):
            suppress |= ~(df[column] >= params.threshold)
        if "dominance" in df.columns:
            suppress |= ~(df["dominance"] <= dominance)
        if "influence" in df.columns:
            suppress |= ~(df["influence"] <= params.influence_threshold)
        for column in (_payload_cols(df) if _count_cols(df) else []):
            suppress |= _nonfinite(df[column])
        for column in keys or ():
            domain = declared_domain(str(column))
            if column in df.columns and domain is not None:
                suppress |= ~(df[column].isin(domain) | df[column].isna())
        return Verdicts(suppress=suppress, findings=findings, deny=deny)


class CompositeVetter(CellVetter):
    """Runs several vetters and suppresses a cell if **any** of them does.

    The union is the only composition the ACRO comparison supports: neither
    rule set subsumes the other (`docs/acro-comparison.md`), so dropping
    either loses protection that was measured, not hypothesised. It is also
    monotone — adding a vetter can never release a cell that was suppressed
    without it — so composing cannot regress protection by construction.
    """

    def __init__(self, *vetters: CellVetter, name: str | None = None):
        if not vetters:
            raise ValueError("a composite vetter needs at least one vetter")
        self.vetters = tuple(vetters)
        self.name = name or "+".join(v.name for v in self.vetters)

    @property
    def needs_contributions(self) -> bool:
        return any(v.needs_contributions for v in self.vetters)

    def describe(self) -> str:
        return "+".join(v.describe() for v in self.vetters)

    def vet(self, df: pd.DataFrame, params: VettingParameters,
            context: CellContext | None = None) -> Verdicts:
        suppress = pd.Series(False, index=df.index)
        findings: list[Finding] = []
        deny = False
        for vetter in self.vetters:
            verdicts = vetter.vet(df, params, context)
            suppress |= verdicts.suppress
            findings.extend(verdicts.findings)
            deny = deny or verdicts.deny
        return Verdicts(suppress=suppress, findings=findings, deny=deny)


def build_vetter(name: str, checker_cmd: str = "") -> CellVetter:
    """The vetter a configuration asks for (`config.PolicyConfig.vetter`).

    An external checker is never the only vetter: it carries no egress rules
    and no complementary suppression, so it is always composed WITH the
    stand-in, and the composite suppresses a cell if either does.
    """
    if name == "standin":
        return StandinVetter()
    if name == "standin+external":
        from .external_checker import ExternalCheckerVetter

        return CompositeVetter(StandinVetter(),
                               ExternalCheckerVetter(command=checker_cmd.split()))
    raise ValueError(f"no vetter named {name!r}")


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
    # dominance for second-moment cells; None means "the same bound as any
    # other magnitude", which is the default and changes nothing
    moment2_dom_threshold: float | None = None
    # which rules decide a cell. Swapping this swaps the *decision* only:
    # suppression, finalization and shaping below are the policy's own
    # (docs/acro-integration.md).
    vetter: CellVetter = field(default_factory=StandinVetter)

    def parameters(self) -> VettingParameters:
        return VettingParameters(threshold=self.threshold, max_rows=self.max_rows,
                                 dom_threshold=self.dom_threshold,
                                 influence_threshold=self.influence_threshold,
                                 moment2_dom_threshold=self.moment2_dom_threshold)

    def _finalize(self, df: pd.DataFrame,
                  keys: tuple[str, ...] | None = None) -> pd.DataFrame:
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
        for key in _group_columns(out, keys):
            ordering[f"_key_{key}"] = _key_text(out[key])
        if len(ordering.columns):
            out = out.loc[ordering.sort_values(list(ordering.columns),
                                               kind="stable").index]
        return out.reset_index(drop=True)

    def _secondary_suppress(self, original: pd.DataFrame, released: pd.DataFrame,
                            keys: tuple[str, ...] | None = None
                            ) -> tuple[pd.DataFrame, int]:
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
        group_cols = _group_columns(original, keys)
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
                    released = released.drop(
                        index=self._sacrifice(rel_slice, size, keys))
                    extra += 1
                    changed = True
        return released, extra

    def _sacrifice(self, candidates: pd.DataFrame, size: str,
                   keys: tuple[str, ...] | None = None):
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
        columns = _group_columns(candidates, keys)
        cell_keys = pd.Series(
            ["|".join(parts) for parts in zip(
                *(_key_text(candidates[c]) for c in columns), strict=True)]
            if columns else [""] * len(candidates),
            index=candidates.index)
        return pd.DataFrame({"count": rounded, "key": cell_keys}).sort_values(
            ["count", "key"], kind="stable").index[0]

    def needs_contributions(self) -> bool:
        """Whether `apply` should be handed the donor-level contributions."""
        return bool(self.vetter.needs_contributions)

    def apply(self, df: pd.DataFrame | None, context: CellContext | None = None):
        """Return (released_df_or_None, action, findings).

        action in {"release", "redacted", "deny"}. `contributions` is the
        donor-level frame an external checker decides on (see
        `QueryEngine.contributions`); vetters that do not need it ignore it,
        and the caller need not compute it for them.
        """
        if df is None:
            return None, "deny", leak_detector(None)

        # the query's own group-by, when the caller knows it: a cell key must
        # not be identified by guessing at dtypes when the spec says what it is
        keys = context.keys if context is not None and context.keys else None
        verdicts = self.vetter.vet(df, self.parameters(), context)
        findings = list(verdicts.findings)
        # findings no suppression can fix (identifier/free-text/raw) -> deny outright
        if verdicts.deny:
            return None, "deny", findings

        if bool(verdicts.suppress.any()):
            redacted = df[~verdicts.suppress].copy()
            redacted, extra = self._secondary_suppress(df, redacted, keys)
            if extra:
                findings.append(Finding(
                    "low", "secondary_suppression",
                    "complementary cells were suppressed to protect margins",
                    audit_detail=f"{extra} complementary cell(s) suppressed to "
                                 f"protect margins"))
            return self._finalize(redacted, keys), "redacted", \
                self._granularity(redacted, findings)

        return self._finalize(df, keys), "release", self._granularity(df, findings)

    def _granularity(self, released: pd.DataFrame, findings: list) -> list:
        """Re-decide the granularity bound on what actually leaves.

        A vetter sees the CANDIDATE cells and cannot know how many survive
        suppression, so its `too_granular` verdict is about the wrong frame:
        counted there, 46 of 241 group-by combinations escalate; counted on the
        released frame, 11 do. The parameter bounds the granularity of the
        output, so the released frame is the one to measure — a query whose
        cells were mostly suppressed has not released a fine-grained table, it
        has released a small one.
        """
        out = [f for f in findings if f.rule != "too_granular"]
        if len(released) > self.max_rows:
            out.append(Finding(
                "medium", "too_granular",
                f"the result has more than {self.max_rows} cells, which is "
                f"finer than this dataset releases without review",
                audit_detail=f"{len(released)} released cells against a bound "
                             f"of {self.max_rows}"))
        return out


def _dim_value_set(universe: set, predicates: list) -> set:
    """The set of a dimension's values selected by a list of (op, value) predicates.

    Three-valued logic, as SQL has it. A comparison against NULL is NULL rather
    than true, so a row whose value is missing satisfies **no** predicate — not
    even `!=`. The model here used to keep the NULL sentinel through `!=`, and
    two things followed. `simulatable_cohort_bound` understated the true
    symmetric difference by exactly the donors carrying a NULL, so it stopped
    being the upper bound its docstring proves it to be — in the permissive
    direction, and a filter naming a value no record held recovered one donor's
    exact spend in two queries with no finding raised. And a range predicate
    raised outright, because `None < 5` is a TypeError in Python where it is
    merely NULL in SQL, turning a decision into a crash.

    Since hardening #40 the exact row-level difference is what actually decides
    a denial, so this is no longer load-bearing for safety. It is still the
    cheap first pass, and a bound that is wrong in the permissive direction is
    worth nothing as an early-out.
    """
    s = set(universe)
    if predicates:
        s.discard(None)             # any predicate at all excludes the NULL rows
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

    The bound is the sum, over every dimension the two cohorts select
    differently, of the whole-population donor marginals of the values selected
    by exactly one of them. That really is an upper bound on |A △ B|: a donor
    in A but not B satisfies all of A's predicates and violates one of B's, so
    on that dimension their value lies in A's selection and not in B's, and the
    marginal of that value counts them. (Donors failing on several dimensions
    are counted several times, which only makes the bound larger.) So a denial
    — bound below the threshold — is always sound, and it catches the canonical
    attack: isolating a globally-rare category by adding or removing one
    predicate ("exclude age 69", "exclude sex X").

    **Summing rather than giving up on multiple dimensions is load-bearing.**
    This used to return a never-denying sentinel as soon as more than one
    dimension differed, which meant an attacker refused a single rare exclusion
    could simply make two of them: excluding sex 'Other' (3 donors) was denied,
    excluding age 50 (1 donor) was denied, and excluding both — a true
    symmetric difference of 4 — was allowed. Summing costs nothing, because the
    sum is still a sound upper bound, and it removes a bypass that took two
    queries.

    Being an upper bound, it does NOT catch differencing that isolates a small
    group through the *interaction* of a common category with an otherwise-narrow
    cohort (e.g. the over-50s within one small region): the marginal is then
    large even though the real symmetric difference is small. That residual is
    the price of simulatability.

    It used to say the residual was "largely covered by the per-cell donor
    threshold (a narrow cohort's cells are suppressed anyway)", and that was
    wrong on the branch it mattered (hardening #72). The threshold suppresses
    small CELLS, and this attack never asks for one: it differences two
    releases that are each legitimately large, which is the whole shape of #39
    and #40. Assuming the analyst takes the path where a control fires, when
    the attack is defined by taking the path where it does not, is the same
    error as D7's "the bit a direct query already returns" (#62) and P22's
    "computable from the released cell table" (#66).

    What actually closes it is the EXACT row-level leg added by #40
    (`engine.row_symdiff_donors`, taken as the smaller bound in
    `service._difference_bound`): it counts the donors behind the differing
    rows rather than bounding them from published marginals, so the small true
    difference is seen whatever the marginals look like. The price of that is
    a denial the marginals cannot reproduce, measured and accepted as #62. A DP
    accountant would close the class rather than this instance.
    """
    dmap = marginals.get(dataset, {})

    def by_dim(filters: tuple) -> dict:
        grouped: dict = {}
        for column, op, value in filters:
            grouped.setdefault(column, []).append((op, value))
        return grouped

    a, b = by_dim(filters_a), by_dim(filters_b)
    bound = 0
    for dim in set(a) | set(b):
        universe = set(dmap.get(dim, {}))
        sa = _dim_value_set(universe, a.get(dim, []))
        sb = _dim_value_set(universe, b.get(dim, []))
        bound += sum(dmap.get(dim, {}).get(v, 0) for v in sa ^ sb)
    return bound


@dataclass
class SessionAuditor:
    """Tracks released aggregates to catch differencing/triangulation.

    Two layers:
    - `observe` — cheap first pass comparing released DISTINCT-DONOR totals
      per measure (rows would let a hyperactive donor's events mask a
      two-cohort pair that differs by only a few people — hardening #38).
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
    # Bounded by the BUDGET, not capped separately, and the difference matters
    # (round-9 V14, hardening #69). A cohort is recorded only when something is
    # released, and every release spends at least one budget unit, so
    # `len(_cohorts) <= _spent <= budget` — the list is not unbounded, which is
    # what the finding supposed. It must NOT be capped like `_history` either:
    # `_history` is the cheap total-delta layer and forgetting an entry costs
    # little, whereas forgetting a COHORT is precisely the unsafe direction #59
    # is about — it is how a differencing pair gets released. What the budget
    # bound leaves is a cost question, and that is answered where the budget's
    # own ceiling is set (`config.py::_FLOORS`).
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

    def restore_observation(self, measure: str, total_n: float) -> None:
        """Put a prior release's donor total back into the history on replay.

        Deliberately NOT `observe`: that charges budget and evaluates the
        differencing rule, both of which already happened when the release was
        live. This only restores the memory, which is what a restart lost
        (hardening #74, closing the residual #49 documented and #58 left).
        """
        self._history.append((measure, total_n))

    def charge(self, units: int = 1) -> None:
        """Spend budget for work that never reached `observe`.

        The budget's stated job is to bound cost as well as accumulation, but
        `_spent` only moved inside `observe`, which runs *after* a successful
        engine call. So a request that raised earlier — a planner failure, an
        engine error, a fit that raises — was caught by the audited boundary
        and answered as a denial for free, and round 9 measured five failing
        queries leaving the session at `_spent=0`. Under a real planner the
        failing call is itself the expensive one, so that was the cheapest way
        to use the system (hardening #60).
        """
        self._spent += units

    def observe(self, measure: str, total_n: float) -> list[Finding]:
        """`total_n` is the DISTINCT-DONOR total of the release, not a row
        count: the differencing threshold protects individuals (hardening
        #38). The service computes it from the engine's internal `n_donors`
        helper; callers with hand-built frames must do the same."""
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
        """Flag a release whose difference from an earlier one is too few people.

        `filters` is QuerySpec.normalized_filters();
        `bound(prev_dataset, a, dataset, b) -> int` returns an upper bound on
        the number of individuals the two releases differ over.
        The caller injects `service._difference_bound`, which takes the smaller of
        the simulatable marginal bound and the exact count of donors behind the
        rows exactly one of the two queries aggregated (hardening #40).

        The refusal reveals only the one bit "too similar to a prior release",
        never the numeric bound (see docs/security.md on simulatability).
        Cost is bounded by the session budget: at most `budget` prior cohorts.

        A difference of **zero** denies too. It used to pass, on the reading that
        identical cohorts are not a differencing attack — but genuinely identical
        cohorts are already skipped on the line above, so the only pairs reaching
        a zero here are ones whose predicates *differ* while selecting the same
        rows. That is a sub-threshold existence fact of its own: releasing both
        halves of `age >= 58` / `age >= 59` proves nobody in the study is 58, and
        a filter naming a value no record holds drops exactly the donors who
        carry a NULL. Both were live before this changed.
        """
        # Compared ACROSS views, not only within one (round 11, #95). The
        # skip used to be `prev_dataset != dataset`, and the spec's own
        # definition of a cohort is "the set of individuals a query's filters
        # select, identified by its normalized filter predicate" — the dataset
        # is not part of it. A catalogue publishes several views of the SAME
        # people (here `spend` and `donor_spend`, one a per-event sum and the
        # other its per-donor total), so a differencing pair with one leg in
        # each was never compared by either layer. Measured: two individually
        # safe releases 2065.77 and 1944.84, differing by one person, recovered
        # that individual's exact annual spend of GBP 120.93 with zero error.
        # The identical pair inside one view is denied.
        #
        # `same_population` is conservative on purpose: every dataset in a
        # definition shares one `person_key`, so they are treated as one
        # population unless a definition ever declares otherwise. Comparing too
        # much costs availability; comparing too little is this finding.
        for prev_dataset, prev_filters in self._cohorts:
            if prev_dataset == dataset and prev_filters == filters:
                continue
            if bound(prev_dataset, prev_filters, dataset, filters) < self.threshold:
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
