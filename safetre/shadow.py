"""Shadow data: a fake study with the real study's *shape* and none of its content.

`synth.py` invents one particular fictional study, hard-coded, complete with
planted disclosure hazards — it is the fixture the gateway is tested against.
This module does something different and much duller on purpose: given a
`DatasetDefinition`, it emits tables carrying the same column names, types and
declared value domains as the real study, so that a researcher can open them in
a familiar tool (JASP, SPSS, R, a spreadsheet), design an analysis against
something that behaves like the real thing, and submit only the finished spec
to the gateway. The expensive, budget-consuming, disclosure-checked run happens
once, deliberately, against data the analyst never sees.

## Why this is safe, stated precisely

The function takes a `DatasetDefinition` and nothing else. It never opens the
real tables, never connects to the operator's database, and has no code path
that could: there is no parameter through which real rows could be passed.
Everything it emits comes from one of three places —

1. **Declared domains** (`columns.<name>.domain` in the definition). These are
   design-time knowledge — the value set a variable is *defined* to take, like
   the twelve UK ITL1 regions — authored and reviewed by the operator as part of
   configuration. Publishing them is a decision already made and already public
   in the catalogue the planner is given; it is not a new release.
2. **Declared kinds** (`cat` / `int` / `bool` from a dataset's `dims` and
   `internal_filters`, plus `measures` as numeric), and declared band edges from
   `internal_range_rules`.
3. **A fixed, uninformative fallback** for numeric columns the definition does
   not bound. Every column that falls back is listed in the manifest and in the
   generated README, because a silently invented range is exactly the kind of
   number somebody would later mistake for a measured one.

Nothing is *fitted*. That is the whole design. A synthesiser that learns
marginals, correlations or a joint model from real records makes the synthetic
dataset itself a release — one your gateway is not built to check, because it
checks frames of aggregates and a synthesised table is thousands of correlated
statistics with no budget entry. Measured value sets are worse still: the
*existence* of a rare category is disclosive, which is precisely what the demo
fixture's eight Northern Ireland donors exist to demonstrate. And the
literature does not let you assume otherwise — sequential-tree synthesisers can
reproduce outlying records near-verbatim, and membership inference against
synthetic data is an active attack area. "Synthetic" is a privacy property only
when the fitting step is itself private. Here there is no fitting step.

## What it is therefore useless for

Every column is drawn independently. There are no correlations, no realistic
marginals, no heavy tails, no small cells, no dominance. So:

- **Do not** use shadow data to test the disclosure gateway. It has no hazards
  to find, and a red-team run against it would pass while proving nothing.
  `synth.py` is the fixture for that, and it plants its hazards deliberately.
- **Do not** read effect sizes, power or model fit off a shadow run. An
  analysis that looks fine here can be badly specified for the real data.
- **Do** use it to check that a model *runs*: that the factors have the levels
  you expected, that a contrast is estimable, that a GLM family suits the
  response, that your syntax is right.

The honest middle ground, if this proves too thin in practice, is for the
operator to *declare* approximate marginals in the definition file alongside the
domains — reviewed configuration, same trust status as the domains themselves —
rather than for anything here to measure them. That keeps the boundary intact:
the generator's inputs stay operator-authored and analyst-independent.

## Output

`write_shadow()` writes, for each public dataset the definition serves, a CSV
of exactly the columns an analyst sees — built by running the definition's own
`public_view_sql()` over the generated base tables, so the shadow's columns
cannot drift from the real view's. The base tables go in `base/` for anyone who
wants them; note that they carry the person key, which no public view does.

A README and a MANIFEST.json go alongside, saying what the files are, which
seed produced them, and which columns used the fallback range.
"""

from __future__ import annotations

import json
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any

import duckdb
import numpy as np
import pandas as pd

from . import dataset as _dataset
from .dataset import BASE_SCHEMA, DatasetDefinition

# Numeric columns the definition does not bound get this range. Deliberately
# round, deliberately not on any real scale, and always reported: a shadow
# WEMWBS score of 41.7 must not be mistakable for one on the true 14-70 scale.
FALLBACK_RANGE = (0.0, 100.0)

# Non-person tables (a lookup of apps, sites, clinics) get this many rows by
# default, scaled off the person count but never silly-small.
_ENTITY_ROWS_PER_PERSON = 50
_MIN_ENTITY_ROWS = 8

# Person and foreign-key values are stamped so that a shadow extract found on
# a disk somewhere cannot be mistaken for a real one at a glance.
_PERSON_PREFIX = "SHADOW-P"
_KEY_PREFIX = "SHADOW-K"


class ShadowError(RuntimeError):
    """The definition does not declare enough to build a shadow of it.

    Raised rather than guessed: a column the gateway will let an analyst group
    by, but whose value set nobody wrote down, is a gap in the definition. The
    message names the column and what to add.
    """


@dataclass
class Shadow:
    """The generated tables plus the provenance of every column."""

    definition: str
    seed: int
    base: dict[str, pd.DataFrame]
    datasets: dict[str, pd.DataFrame]
    provenance: dict[str, str] = field(default_factory=dict)
    fallbacks: list[str] = field(default_factory=list)

    def manifest(self) -> dict[str, Any]:
        return {
            "definition": self.definition,
            "seed": self.seed,
            "generator": "safetre.shadow",
            "fitted_to_real_data": False,
            "base_tables": {t: len(df) for t, df in self.base.items()},
            "datasets": {d: len(df) for d, df in self.datasets.items()},
            "column_provenance": dict(sorted(self.provenance.items())),
            "fallback_range_columns": sorted(self.fallbacks),
            "fallback_range": list(FALLBACK_RANGE),
        }


# --------------------------------------------------------------------- #
# working out what each column is, from declarations only                 #
# --------------------------------------------------------------------- #
def _base_columns(defn: DatasetDefinition) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for table, cols in defn.tables.items():
        for col in cols:
            out.setdefault(col, set()).add(table)
    return out


def _declared_kinds(defn: DatasetDefinition,
                    base_columns: dict[str, set[str]]) -> dict[str, str]:
    """Base column -> declared kind (`cat` / `int` / `bool` / `num`).

    Read from every view's allowlists. A view's dims and measures name *output*
    columns; for a non-derived column that name is the base column's, and
    derived rollups are computed by the view rather than generated here, so
    anything not in a base table is skipped.

    A column may hold both roles at once, and in the demo study one does:
    `age_years` is an `int` internal filter *and* an internal measure, because
    an analyst may band on it and correlate against it. So an explicit kind
    (from `dims` / `internal_filters`) outranks the numeric role implied by
    being a measure; only two explicit kinds disagreeing is a definition bug,
    since the same base column cannot be `cat` in one dataset and `int` in
    another when both project it from the same table.
    """
    explicit: dict[str, str] = {}
    origin: dict[str, str] = {}
    numeric: set[str] = set()

    for name, view in defn.datasets.items():
        for kind_source, mapping in (("dims", view.dims),
                                     ("internal_filters", view.internal_filters)):
            for col, kind in mapping.items():
                if col not in base_columns:
                    continue
                where = f"dataset {name!r} {kind_source}"
                if col in explicit and explicit[col] != kind:
                    raise ShadowError(
                        f"column {col!r} is declared {explicit[col]!r} in "
                        f"{origin[col]} and {kind!r} in {where}; a base column "
                        f"has one kind")
                explicit[col] = kind
                origin[col] = where
        for col in (*view.measures, *view.internal_measures):
            if col in base_columns:
                numeric.add(col)

    kinds = dict(explicit)
    for col in numeric:
        kinds.setdefault(col, "num")
    return kinds


def _numeric_bounds(defn: DatasetDefinition, col: str,
                    ranges: dict[str, tuple[float, float]]) -> tuple[tuple[float, float], bool]:
    """(lo, hi) for a numeric column, and whether the fallback was used.

    Caller-supplied ranges win; then the declared band edges of an internal
    range rule, whose lowest and highest edges are by construction the extremes
    of the column's public banding; then the fallback.
    """
    if col in ranges:
        lo, hi = ranges[col]
        return (float(lo), float(hi)), False
    rule = defn.internal_range_rules.get(col)
    if rule is not None:
        edges = [float(v) for values in rule.edges.values() for v in values]
        if edges:
            return (min(edges), max(edges)), False
    return FALLBACK_RANGE, True


# --------------------------------------------------------------------- #
# generation                                                             #
# --------------------------------------------------------------------- #
def shadow_from_definition(
    defn: DatasetDefinition,
    n_persons: int = 500,
    seed: int = 0,
    rows: dict[str, int] | None = None,
    ranges: dict[str, tuple[float, float]] | None = None,
    derive: dict[str, str] | None = None,
) -> Shadow:
    """Build shadow tables for `defn`. Reads no data of any kind.

    `rows` overrides the row count per base table (events tables in particular
    want far more than one row per person). `ranges` bounds numeric columns the
    definition does not bound, so the fallback need not be accepted.

    `derive` maps a banded column to the numeric column it bands, e.g.
    `{"age_band": "age_years"}`. Without it every column is drawn
    independently, so a shadow row can carry age 51 in band 18-24 — harmless
    for checking that a query runs, confusing to look at. With it, the band is
    computed from the value using the source column's declared range-rule edges
    and the banded column's declared domain.

    The coupling is never inferred. Two declarations that happen to be the same
    length are not evidence that they describe the same banding, and quietly
    pairing them would be a guess dressed as configuration. It is stated by the
    operator, checked against both declarations, and refused if they disagree.
    """
    if n_persons < 1:
        raise ShadowError("n_persons must be at least 1")
    rows = dict(rows or {})
    ranges = dict(ranges or {})
    derive = dict(derive or {})
    unknown = set(rows) - set(defn.tables)
    if unknown:
        raise ShadowError(f"row counts given for unknown tables {sorted(unknown)}")

    rng = np.random.default_rng(seed)
    base_columns = _base_columns(defn)
    kinds = _declared_kinds(defn, base_columns)
    domains = {c: list(meta["domain"]) for c, meta in defn.columns.items()
               if (meta or {}).get("domain") is not None}

    # Join keys other than the person key: the join *target* owns the value
    # pool, and every other table carrying that column draws from it, so the
    # generated joins actually match.
    owners: dict[str, str] = {}
    for name, view in defn.datasets.items():
        for join in view.joins:
            if join.key == defn.person_key:
                continue
            previous = owners.setdefault(join.key, join.table)
            if previous != join.table:
                raise ShadowError(
                    f"join key {join.key!r} points at {previous!r} in one dataset "
                    f"and {join.table!r} in another; a key has one owning table")

    persons = [f"{_PERSON_PREFIX}{i:06d}" for i in range(n_persons)]
    key_pools: dict[str, list[str]] = {defn.person_key: persons}

    def row_count(table: str) -> int:
        # A table needs at least as many rows as its widest declared domain,
        # or that domain's levels cannot all appear and a factor arrives at the
        # analyst short of a level. Applied to an explicit `rows` too: an
        # operator asking for 3 rows of a table with a 7-level factor has asked
        # for something that cannot be a faithful shadow.
        widest = max((len(domains[c]) for c in defn.tables[table] if c in domains),
                     default=0)
        if table in rows:
            return max(rows[table], widest)
        if defn.person_key in defn.tables[table]:
            return max(n_persons, widest)
        return max(_MIN_ENTITY_ROWS, n_persons // _ENTITY_ROWS_PER_PERSON, widest)

    # Owning tables first, so a foreign key always has a pool to draw from.
    order = sorted(defn.tables, key=lambda t: (t not in owners.values(), t))

    provenance: dict[str, str] = {}
    fallbacks: list[str] = []
    base: dict[str, pd.DataFrame] = {}

    for table in order:
        n = row_count(table)
        if n < 0:
            raise ShadowError(f"row count for table {table!r} cannot be negative")
        frame: dict[str, Any] = {}
        for col in defn.tables[table]:
            values, how, fell_back = _column_values(
                defn, table, col, n, rng, kinds, domains, owners, key_pools, ranges)
            frame[col] = values
            provenance.setdefault(f"{table}.{col}", how)
            if fell_back and col not in fallbacks:
                fallbacks.append(col)
        for banded, source in derive.items():
            if banded not in frame:
                continue
            frame[banded] = _band(defn, table, banded, source, frame)
            provenance[f"{table}.{banded}"] = f"banded from {source!r}"
        base[table] = pd.DataFrame(frame)

    missing = {b for b in derive if not any(b in cols for cols in defn.tables.values())}
    if missing:
        raise ShadowError(f"derive names unknown columns {sorted(missing)}")

    datasets = _materialise_views(defn, base)
    shadow = Shadow(definition=defn.name, seed=seed, base=base, datasets=datasets,
                    provenance=provenance, fallbacks=fallbacks)
    # Enforced, not promised: refuse to hand back a frame carrying a value the
    # definition does not account for. See `verify_shadow`.
    verify_shadow(defn, shadow, ranges=ranges)
    return shadow


# --------------------------------------------------------------------- #
# the safety property, checked on every build                            #
# --------------------------------------------------------------------- #
def verify_shadow(defn: DatasetDefinition, shadow: Shadow,
                  ranges: dict[str, tuple[float, float]] | None = None) -> None:
    """Refuse to release a shadow that contains anything the definition does not
    declare.

    The safety argument for this module is "every emitted value traces to the
    definition file". That is the kind of claim that is true when written and
    quietly false three refactors later, so it is checked here on every build
    rather than asserted in a docstring: each column's values must lie in the
    set its declaration permits — a declared domain, `{{True, False}}`, a
    bounded numeric interval, a generated key pool, or the placeholder pattern.

    A failure means a code path invented a value from somewhere other than the
    definition, which is exactly the situation where "synthetic" would stop
    being a safety property. It raises rather than warns: a shadow that cannot
    be shown safe is not written.
    """
    ranges = dict(ranges or {})
    kinds = _declared_kinds(defn, _base_columns(defn))
    domains = {c: set(meta["domain"]) for c, meta in defn.columns.items()
               if (meta or {}).get("domain") is not None}
    person_values: set[Any] = set()
    for table, cols in defn.tables.items():
        if defn.person_key in cols:
            person_values |= set(shadow.base[table][defn.person_key])

    def fail(where: str, detail: str) -> None:
        raise ShadowError(
            f"shadow verification failed for {where}: {detail}. Every value a "
            f"shadow emits must come from the dataset definition; this one did "
            f"not, so the shadow was not written.")

    for table, cols in defn.tables.items():
        frame = shadow.base[table]
        if list(frame.columns) != list(cols):
            fail(f"table {table!r}",
                 f"columns {list(frame.columns)} do not match the declared "
                 f"{list(cols)}")
        for col in cols:
            series = frame[col]
            if series.isna().any():
                fail(f"{table}.{col}", "contains nulls, which are never generated")
            if col in domains:
                extra = set(series.unique()) - domains[col]
                if extra:
                    fail(f"{table}.{col}",
                         f"values {sorted(map(str, extra))[:5]} are outside the "
                         f"declared domain")
                continue
            if col == defn.person_key:
                if not set(series.unique()) <= person_values:
                    fail(f"{table}.{col}", "person ids outside the generated pool")
                if not all(str(v).startswith(_PERSON_PREFIX) for v in series.unique()):
                    fail(f"{table}.{col}",
                         f"person ids are not stamped {_PERSON_PREFIX!r}")
                continue
            kind = kinds.get(col)
            if kind == "bool":
                if not set(series.unique()) <= {True, False}:
                    fail(f"{table}.{col}", "non-boolean values in a declared bool")
                continue
            if kind in ("int", "num"):
                (lo, hi), _ = _numeric_bounds(defn, col, ranges)
                if len(series) and (series.min() < lo or series.max() > hi):
                    fail(f"{table}.{col}",
                         f"values outside the declared bounds [{lo:g}, {hi:g}]")
                continue
            # keys and placeholders are both stamped strings; anything else
            # would mean a branch invented free-form content.
            bad = [v for v in series.unique()
                   if not (str(v).startswith(_KEY_PREFIX) or str(v).startswith(f"{col}-"))]
            if bad:
                fail(f"{table}.{col}",
                     f"unstamped free-form values {sorted(map(str, bad))[:5]}")

    # The public frames must not carry a direct identifier. The definition
    # validator already forbids it in the view DDL; re-checked on the actual
    # output because this is the frame a researcher takes away.
    identifiers = {c for cols in defn.tables.values()
                   for c, role in cols.items() if role == "DI"}
    for name, frame in shadow.datasets.items():
        leaked = identifiers & set(frame.columns)
        if leaked:
            fail(f"dataset {name!r}",
                 f"public shadow frame exposes direct identifier(s) {sorted(leaked)}")
        for col in frame.columns:
            if frame[col].dtype == object and set(frame[col].dropna()) & person_values:
                fail(f"dataset {name!r}.{col}", "public shadow frame carries person ids")


def _column_values(defn, table, col, n, rng, kinds, domains, owners, key_pools, ranges):
    """One column's values, plus a human-readable provenance and whether the
    numeric fallback was used. Resolution order is declaration-first; the last
    branch is reached only by columns no dataset exposes."""
    # 1. the person key, and any table carrying it: drawn from the one pool, and
    #    covering every person before repeating, so a person table with one row
    #    per person really has one row per person.
    if col == defn.person_key:
        return _cover_draw(key_pools[col], n, rng), "person key", False

    # 2. another join key. The owning table gets a fresh unique pool; every
    #    other table draws from it, which is what makes the joins non-empty.
    if col in owners:
        if owners[col] == table:
            pool = [f"{_KEY_PREFIX}{col}-{i:06d}" for i in range(n)]
            key_pools[col] = pool
            return list(pool), f"key owned by {table!r}", False
        pool = key_pools.get(col)
        if pool is None:
            raise ShadowError(
                f"{table}.{col} references key pool {col!r} before its owning "
                f"table {owners[col]!r} was generated")
        return _cover_draw(pool, n, rng), f"foreign key -> {owners[col]!r}", False

    # 3. a declared domain: the operator wrote the value set down. Drawn with
    #    coverage — see `_cover_draw` — so every declared level is present.
    if col in domains:
        values = list(domains[col])
        return (_cover_draw(values, n, rng),
                f"declared domain ({len(values)} values)", False)

    kind = kinds.get(col)

    # 4. declared kind without a domain.
    if kind == "bool":
        return pd.Series(rng.integers(0, 2, size=n).astype(bool)), "declared bool", False
    if kind in ("int", "num"):
        (lo, hi), fell_back = _numeric_bounds(defn, col, ranges)
        if kind == "int":
            values = pd.Series(rng.integers(int(lo), int(hi) + 1, size=n))
        else:
            values = pd.Series(np.round(rng.uniform(lo, hi, size=n), 2))
        source = ("fallback range" if fell_back else
                  "caller range" if col in ranges else "declared band edges")
        return values, f"declared {kind}, {source} [{lo:g}, {hi:g}]", fell_back
    if kind == "cat":
        raise ShadowError(
            f"{table}.{col} is an analysable categorical ({kind!r}) but the "
            f"definition declares no `domain` for it, so there is no value set "
            f"to draw from. Add one under `columns.{col}.domain`. It is not "
            f"guessed here: the levels an analyst sees must be the levels the "
            f"operator published, not ones this generator invented.")

    # 5. not exposed by any dataset — free text, timestamps, row ids. No analyst
    #    can group by it or aggregate it, so an obvious placeholder is more
    #    honest than a plausible fake.
    return (pd.Series([f"{col}-{i:06d}" for i in range(n)]),
            "placeholder (not exposed by any dataset)", False)


def _band(defn: DatasetDefinition, table: str, banded: str, source: str,
          frame: dict[str, Any]) -> pd.Series:
    """Replace a banded column's independent draw with the band its source
    column's value actually falls in.

    Both halves must already be declared: the banded column needs a `domain`,
    the source needs an `internal_range_rules` entry giving `>=` lower edges and
    `<=` upper edges. The i-th band is the i-th edge pair, which is only
    meaningful if the two lists have the same length as the domain — checked
    here, because a silent mismatch would relabel every band.
    """
    if source not in frame:
        raise ShadowError(
            f"derive {banded}={source}: {source!r} is not a column of table "
            f"{table!r}, and a band can only be computed from a column beside it")
    domain = (defn.columns.get(banded) or {}).get("domain")
    if not domain:
        raise ShadowError(
            f"derive {banded}={source}: {banded!r} has no declared `domain`, so "
            f"there are no band labels to assign")
    rule = defn.internal_range_rules.get(source)
    if rule is None or ">=" not in rule.edges or "<=" not in rule.edges:
        raise ShadowError(
            f"derive {banded}={source}: {source!r} has no internal range rule "
            f"with both '>=' and '<=' edges, so its band boundaries are not "
            f"declared anywhere")
    lows = [float(v) for v in rule.edges[">="]]
    highs = [float(v) for v in rule.edges["<="]]
    if not (len(lows) == len(highs) == len(domain)):
        raise ShadowError(
            f"derive {banded}={source}: {len(domain)} band labels but "
            f"{len(lows)} lower and {len(highs)} upper edges. These must "
            f"describe the same bands; they are not paired up by position "
            f"unless the counts agree")

    def label(value):
        for lo, hi, name in zip(lows, highs, domain):
            if lo <= float(value) <= hi:
                return name
        raise ShadowError(
            f"derive {banded}={source}: value {value!r} falls outside every "
            f"declared band of {source!r}")

    return pd.Series([label(v) for v in frame[source]])


def _cover_draw(pool: list, n: int, rng) -> pd.Series:
    """`n` values from `pool`, every pool value appearing at least once when
    there is room, then shuffled.

    Coverage rather than a plain uniform draw, for one reason that matters: a
    factor level missing from the shadow makes a contrast estimable here and
    not in the real run — or the reverse — which is exactly the surprise this
    whole exercise exists to prevent. The same applies to keys: a person or an
    app that appears in no row of a fact table silently shrinks the joins.

    It costs nothing in safety. The pool is the declared domain or a generated
    key pool either way; only the multiplicities change, and shadow
    multiplicities carry no information about the real study.
    """
    if n <= 0:
        return pd.Series([], dtype=object)
    if n < len(pool):
        return pd.Series([pool[i] for i in rng.integers(0, len(pool), size=n)])
    extra = [pool[i] for i in rng.integers(0, len(pool), size=n - len(pool))]
    values = list(pool) + extra
    rng.shuffle(values)
    return pd.Series(values)


def _materialise_views(defn: DatasetDefinition,
                       base: dict[str, pd.DataFrame]) -> dict[str, pd.DataFrame]:
    """Run the definition's own public-view DDL over the shadow base tables.

    Reusing `public_view_sql()` rather than reimplementing the projection is
    the point: the shadow's columns are then the real view's columns by
    construction, including derived rollups, and a change to a view definition
    shows up in the shadow on the next run with nothing to keep in sync.

    Only the public views are built. The unit views — the internal ones
    carrying the person key — are never created here, so this function has no
    way to emit a person-level frame even by mistake.
    """
    con = duckdb.connect(database=":memory:")
    try:
        con.execute(f'CREATE SCHEMA IF NOT EXISTS "{BASE_SCHEMA}"')
        for name, frame in base.items():
            source = f"_shadow_{name}"
            con.register(source, frame)
            # every identifier here is a validated definition identifier
            con.execute(f'CREATE TABLE "{BASE_SCHEMA}"."{name}" '  # nosec
                        f'AS SELECT * FROM "{source}"')
            con.unregister(source)
        out: dict[str, pd.DataFrame] = {}
        for name, ddl in defn.public_view_sql().items():
            con.execute(ddl)
            out[name] = con.execute(f'SELECT * FROM "{name}"').df()  # nosec
        return out
    finally:
        con.close()


# --------------------------------------------------------------------- #
# writing it out                                                         #
# --------------------------------------------------------------------- #
_README = """\
# Shadow data for `{name}`

**These are not real data, and they are not a statistical stand-in for real
data.** They were generated by `safetre.shadow` from the study's *definition
file* alone — column names, declared value domains, declared types. Nothing
here was fitted to, measured from, or derived from any participant record. The
generator has no access to real data and no parameter through which real data
could be passed.

Generated with seed {seed}.

## What they are for

Designing an analysis in a familiar tool before submitting it to the gateway.
The columns, types and factor levels match the real datasets, so a model that
runs here will run there.

## What they are NOT for

Every column was drawn **independently**. There are no correlations, no
realistic distributions, no small cells and no disclosure structure of any
kind. Do not read effect sizes, power, model fit or data-quality conclusions
off these files, and do not use them to test disclosure control — there is
nothing here to find.

{fallback_note}## Files

Public datasets — the columns an analyst actually sees, produced by running the
study's own view definitions over the tables below:

{dataset_lines}

Base tables, in `base/`. These carry the person key, which no public dataset
does; they are here for tooling that wants the underlying shape.

{base_lines}
`MANIFEST.json` records the seed, the row counts and the provenance of every
generated column.
"""

_FALLBACK_NOTE = """\
## Numbers with no declared scale

The definition does not bound these columns, so their values are uniform on
{lo:g}-{hi:g} and are **not on the real scale**:

{columns}
Give them real bounds with `ranges=` (or `--range col=lo:hi`) if the wrong
magnitude gets in the way.

"""


def write_shadow(shadow: Shadow, out_dir: str | os.PathLike) -> list[pathlib.Path]:
    """Write the CSVs, README and manifest. Returns the paths written."""
    out = pathlib.Path(out_dir)
    (out / "base").mkdir(parents=True, exist_ok=True)
    written: list[pathlib.Path] = []

    for name, frame in sorted(shadow.datasets.items()):
        path = out / f"{name}.csv"
        frame.to_csv(path, index=False)
        written.append(path)
    for name, frame in sorted(shadow.base.items()):
        path = out / "base" / f"{name}.csv"
        frame.to_csv(path, index=False)
        written.append(path)

    note = ""
    if shadow.fallbacks:
        note = _FALLBACK_NOTE.format(
            lo=FALLBACK_RANGE[0], hi=FALLBACK_RANGE[1],
            columns="".join(f"- `{c}`\n" for c in sorted(shadow.fallbacks)))
    readme = out / "README.md"
    readme.write_text(_README.format(
        name=shadow.definition,
        seed=shadow.seed,
        fallback_note=note,
        dataset_lines="".join(
            f"- `{n}.csv` — {len(f)} rows, {len(f.columns)} columns\n"
            for n, f in sorted(shadow.datasets.items())),
        base_lines="".join(
            f"- `base/{n}.csv` — {len(f)} rows\n"
            for n, f in sorted(shadow.base.items())),
    ))
    written.append(readme)

    manifest = out / "MANIFEST.json"
    manifest.write_text(json.dumps(shadow.manifest(), indent=2) + "\n")
    written.append(manifest)
    return written


def shadow_for_active(n_persons: int = 500, seed: int = 0, **kwargs) -> Shadow:
    """Shadow of the process's active dataset definition."""
    return shadow_from_definition(_dataset.active(), n_persons=n_persons,
                                  seed=seed, **kwargs)
