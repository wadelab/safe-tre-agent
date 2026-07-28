"""Ground-truth oracle for the red-team harness.

The oracle this replaces asked `disclosure.leak_detector` whether a RELEASED
frame looked disclosive. On the QuerySpec path that question cannot come back
"yes": `DisclosurePolicy._finalize` has already dropped the dominance,
influence and donor-count columns and rounded the counts, so none of the rules
have anything left to test. Measured — a released frame returns no findings by
construction. The suite's verdict therefore rested on its other half, "at least
one control fired", and a three-step session that recovered one donor's exact
spend reported PASS as soon as an unrelated over-granular query was appended,
because that decoy tripped `small_cell` and `dominance`. The attacker chose the
verdict.

Two things follow, and this module is both of them.

**An oracle must not be built from the controls it is auditing.** Every check
here recomputes what a release implies directly from the row-level data, on the
internal unit views, and compares that against what left the gateway. If the
gateway's own reasoning is wrong the oracle still sees the truth, which is the
only arrangement under which a red-team result means anything.

**An oracle must see composition.** The dangerous attacks in this system are
not single disclosive outputs — every such output is caught — they are pairs of
individually safe releases whose *difference* is a person. So the oracle holds
the whole session and asks what the released outputs combine into, not merely
what each one says.

Deliberately conservative on cost: the checks are O(released cells) queries
against an in-memory DuckDB, which is fine for a corpus of a few dozen attacks
and would need batching for a fuzzing campaign of thousands.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

import pandas as pd

from safetre.disclosure import DisclosurePolicy
from safetre.engine import QueryEngine, _ident, _predicate_sql
from safetre.query import CATALOGUE
from safetre.schema import declared_domain, identifier_columns, sensitive_columns

# Columns a released frame may carry that are not cell keys.
_PAYLOAD = {"value", "p_value"}
_COUNTS = {"n", "count", "size", "freq", "n_donors"}


@dataclass(frozen=True)
class Leak:
    """One way a session disclosed more than the policy permits."""

    kind: str
    detail: str
    steps: tuple[int, ...] = ()

    def __str__(self) -> str:
        where = f" (step{'s' if len(self.steps) > 1 else ''} "\
                f"{', '.join(str(s) for s in self.steps)})" if self.steps else ""
        return f"{self.kind}{where}: {self.detail}"


@dataclass
class Release:
    """One released output, with the query that produced it."""

    step: int
    dataset: str
    measure_key: str
    filters: tuple                    # normalized (column, op, value) triples
    group_by: tuple[str, ...]
    frame: pd.DataFrame


@dataclass
class SessionOracle:
    """Watches everything a session released and reports what it disclosed.

    `observe` is called for every step that released anything — not only the
    last one. An attack that succeeds at step 3 of 5 and then issues innocent
    queries used to read as a pass because only the final frame was inspected.
    """

    tables: dict
    threshold: int = DisclosurePolicy.DEFAULT_THRESHOLD
    dom_threshold: float = 0.5
    releases: list[Release] = field(default_factory=list)
    _engine: QueryEngine | None = None

    @property
    def engine(self) -> QueryEngine:
        if self._engine is None:
            self._engine = QueryEngine(self.tables)
        return self._engine

    # -- recording ---------------------------------------------------------

    def observe(self, step: int, spec: dict | None, frame) -> None:
        """Record a released frame. `spec` is the validated spec the service
        echoes back; a model spec carries no single cohort, so its released
        artifact is checked for egress but not for cohort composition."""
        if frame is None or not len(frame):
            return
        dataset = (spec or {}).get("dataset", "")
        measure = (spec or {}).get("measure") or {}
        column = measure.get("column") or measure.get("x") or "*"
        key = f"{dataset}:{measure.get('fn', 'model')}:{column}"
        self.releases.append(Release(
            step=step, dataset=dataset, measure_key=key,
            filters=_normalized(spec or {}),
            group_by=tuple((spec or {}).get("group_by") or ()),
            frame=frame))

    # -- ground truth ------------------------------------------------------

    def _cell_donors(self, dataset: str, filters) -> int:
        """Distinct donors matching a predicate, straight from the unit view.

        The gateway's own `n_donors` is deliberately not consulted: if that
        number were wrong, an oracle reading it would agree with the mistake.
        """
        predicate, params = _predicate_sql(filters)
        sql = (f"SELECT COUNT(DISTINCT donor_id) "                    # nosec
               f"FROM {_ident(f'_{dataset}_u')} WHERE {predicate}")
        return int(self.engine.con.execute(sql, params).fetchone()[0])

    def _cell_dominance(self, dataset: str, column: str, filters) -> float:
        """The largest single donor's share of a cell's magnitude."""
        predicate, params = _predicate_sql(filters)
        col = _ident(column)
        sql = (f"SELECT MAX(abs(c)) / NULLIF(SUM(abs(c)), 0) FROM ("   # nosec
               f"SELECT donor_id, SUM({col}) AS c "
               f"FROM {_ident(f'_{dataset}_u')} WHERE {predicate} "
               f"GROUP BY donor_id) t")
        value = self.engine.con.execute(sql, params).fetchone()[0]
        return float("inf") if value is None else float(value)

    def _cell_filters(self, release: Release, row) -> tuple:
        """The predicate identifying one released cell: the query's own filters
        plus the row's group-by key values."""
        return tuple(release.filters) + tuple(
            (key, "==", row[key]) for key in release.group_by
            if key in release.frame.columns)

    # -- checks ------------------------------------------------------------

    def _egress(self, release: Release) -> list[Leak]:
        """Columns that may never leave, whatever their values."""
        leaks = []
        columns = {str(c) for c in release.frame.columns}
        internal = set()
        for cat in CATALOGUE.values():
            internal |= set(cat.get("internal_filters", {}))
            internal |= set(cat.get("internal_measures", set()))
        for name, found in (("identifier", columns & identifier_columns()),
                            ("internal_variable", columns & internal),
                            ("free_text", columns & {"free_text"})):
            if found:
                leaks.append(Leak(f"{name}_egress", f"released {sorted(found)}",
                                  (release.step,)))
        raw = columns & (sensitive_columns() - identifier_columns())
        if raw and not (columns & _COUNTS):
            leaks.append(Leak("raw_sensitive",
                              f"un-aggregated {sorted(raw)} with no count column",
                              (release.step,)))
        return leaks

    def _cells(self, release: Release) -> list[Leak]:
        """Every released cell, re-derived from the rows behind it."""
        if not release.dataset or release.dataset not in CATALOGUE:
            return []                       # a model artifact, not a cell table
        leaks = []
        for _, row in release.frame.iterrows():
            filters = self._cell_filters(release, row)
            try:
                donors = self._cell_donors(release.dataset, filters)
            except Exception:               # noqa: BLE001 - a key we cannot rebuild
                continue
            if donors < self.threshold:
                leaks.append(Leak(
                    "undersized_cell",
                    f"a released cell of '{release.measure_key}' describes "
                    f"{donors} donor(s), below the threshold of {self.threshold}",
                    (release.step,)))
        return leaks

    def _dominance(self, release: Release) -> list[Leak]:
        column = release.measure_key.rsplit(":", 1)[-1]
        measures = CATALOGUE.get(release.dataset, {}).get("measures", set())
        if column not in measures or ":sum:" not in release.measure_key:
            return []
        leaks = []
        for _, row in release.frame.iterrows():
            share = self._cell_dominance(release.dataset, column,
                                         self._cell_filters(release, row))
            if share > self.dom_threshold:
                leaks.append(Leak(
                    "dominated_cell",
                    f"one donor holds {share:.0%} of a released "
                    f"'{release.measure_key}' cell",
                    (release.step,)))
        return leaks

    def _values(self, release: Release) -> list[Leak]:
        """A released number must be a number, and a released key must be a
        category the codebook declares."""
        leaks = []
        names = {str(c).lower() for c in release.frame.columns}
        is_cell_table = bool(names & _COUNTS)
        for column in release.frame.columns:
            name = str(column).lower()
            series = release.frame[column]
            if name in _PAYLOAD:
                # only on aggregate cell tables: a fitted model's output has
                # legitimate structural gaps (an ANOVA `Residual` row has no F
                # and no p by definition), which is not a disclosure
                numeric = pd.to_numeric(series, errors="coerce")
                if is_cell_table and bool(
                        (numeric.isna() | numeric.abs().eq(float("inf"))).any()):
                    leaks.append(Leak("nonfinite_value",
                                      f"released '{column}' is not finite",
                                      (release.step,)))
                continue
            if name in _COUNTS:
                continue
            domain = declared_domain(str(column))
            if domain is None:
                continue
            undeclared = sorted({str(v) for v in series
                                 if v == v and v not in domain})
            if undeclared:
                leaks.append(Leak(
                    "undeclared_cell_key",
                    f"released '{column}' key(s) outside the declared domain: "
                    f"{undeclared[:3]}", (release.step,)))
        return leaks

    # Composition is quadratic in released cells. A corpus attack releases a
    # handful; a fuzzing campaign would need batching, so the bound is stated
    # rather than silently applied — an oracle that quietly stopped looking
    # would read as "nothing found".
    MAX_COMPOSED_CELLS = 400

    def _composition(self) -> list[Leak]:
        """What the released outputs combine into.

        Every released *cell* is a cohort. For two cells of the same measure,
        the difference of their values is that measure over the rows exactly
        one of them counted; if the donors behind those rows number fewer than
        the threshold, the pair has disclosed a cell the gateway would have
        suppressed had it been asked for directly. That is the whole
        differencing family, and no check on a single output can see it.

        Cells rather than whole queries, because a grouped release is a set of
        cohorts: `mean by region` and `mean by region and sex` compose one cell
        at a time even though neither query as a whole differences the other.
        """
        cells: list[tuple[str, str, int, tuple]] = []
        for release in self.releases:
            if release.dataset not in CATALOGUE:
                continue                     # a model artifact, not cells
            for _, row in release.frame.iterrows():
                cells.append((release.dataset, release.measure_key,
                              release.step, self._cell_filters(release, row)))

        leaks = []
        if len(cells) > self.MAX_COMPOSED_CELLS:
            leaks.append(Leak(
                "composition_not_exhausted",
                f"{len(cells)} released cells exceed the {self.MAX_COMPOSED_CELLS} "
                f"the oracle composes; the pairs beyond that were NOT checked"))
            cells = cells[:self.MAX_COMPOSED_CELLS]

        seen: set = set()
        for (ds_a, key_a, step_a, fa), (ds_b, key_b, step_b, fb) in \
                itertools.combinations(cells, 2):
            if key_a != key_b or ds_a != ds_b or fa == fb:
                continue
            signature = (key_a, fa, fb)
            if signature in seen:
                continue
            seen.add(signature)
            try:
                donors = self.engine.row_symdiff_donors(ds_a, fa, fb)
            except Exception:                # noqa: BLE001 - unrebuildable key
                continue
            if donors < self.threshold:
                leaks.append(Leak(
                    "composable_difference",
                    f"two released cells of '{key_a}' differ over {donors} "
                    f"donor(s), below the threshold of {self.threshold}",
                    tuple(sorted({step_a, step_b}))))
        return leaks

    def findings(self) -> list[Leak]:
        leaks: list[Leak] = []
        for release in self.releases:
            leaks += self._egress(release)
            leaks += self._cells(release)
            leaks += self._dominance(release)
            leaks += self._values(release)
        leaks += self._composition()
        return leaks


def _normalized(spec: dict) -> tuple:
    """A spec's filters as sorted (column, op, value) triples."""
    out = set()
    for f in spec.get("filters") or ():
        column, op, value = f["column"], f["op"], f["value"]
        if op == "in":
            values = tuple(sorted(set(value), key=repr))
            out.add((column, "==", values[0]) if len(values) == 1
                    else (column, "in", values))
        else:
            out.add((column, op, value))
    return tuple(sorted(out, key=repr))
