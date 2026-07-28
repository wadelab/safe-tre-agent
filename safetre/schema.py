"""Schema roles and public column metadata for the ACTIVE dataset definition.

Roles drive the disclosure-control rules:
  DI = direct identifier      (pseudonymous; never released)
  QI = quasi-identifier       (can re-identify in combination)
  S  = sensitive attribute    (what min-cell-size / suppression protects)
  R  = reference / non-disclosive

The facts themselves (tables, columns, declared domains) used to be literals
in this module, binding the gateway to one study. They now live in the active
dataset definition (safetre/dataset.py; packaged demo: demo_dataset.yaml,
overridable via SAFETRE_DATASET) and are mirrored into the module-level
`TABLES` / `COLUMN_META` / `_DERIVED_ROLES` here at import and on every
`dataset.activate`, so the long-standing helper API below is unchanged. The
mirrors are mutated IN PLACE: modules that did `from .schema import TABLES`
before an activation keep the same objects and see the new contents.
"""

from __future__ import annotations

from . import dataset as _dataset

# table -> {column: role} (mirrored from the active definition)
TABLES: dict[str, dict[str, str]] = {}

# Public column metadata for the data dictionary (safe to disclose): a plain
# description and, for categorical columns, the DECLARED value domain — the set
# of categories the study design permits (like a form's dropdown options).
# Declared domains are design-time knowledge, independent of any participant, so
# publishing them in full discloses nothing row-level; a rare category being a
# *valid option* is not the same as anyone having selected it. They also define
# the disclosure-safe projection of the observed marginals: a value outside its
# declared domain — e.g. a hostile string smuggled into a field — was never a
# real category and is dropped from any published table, not merely count-nulled.
COLUMN_META: dict[str, dict] = {}

# Catalogue columns DERIVED per-person rollups in the engine views are not in
# any base table; they take an explicit disclosure role here.
_DERIVED_ROLES: dict[str, str] = {}


def _apply(defn) -> None:
    TABLES.clear()
    TABLES.update(defn.tables_as_dict())
    COLUMN_META.clear()
    COLUMN_META.update(defn.column_meta_as_dict())
    _DERIVED_ROLES.clear()
    _DERIVED_ROLES.update(dict(defn.derived_roles))


_dataset.register_sync(_apply)
_apply(_dataset.active())


# Human-readable role labels for the public data dictionary.
ROLE_LABELS = {
    "DI": "direct identifier",
    "QI": "quasi-identifier",
    "S": "sensitive",
    "R": "reference",
    "meta": "structural",
}


def role_of(column: str) -> str:
    """Disclosure role of a catalogue column, from the base-table schema."""
    for cols in TABLES.values():
        if column in cols:
            return cols[column]
    return _DERIVED_ROLES.get(column, "R")


def column_description(column: str) -> str:
    return COLUMN_META.get(column, {}).get("desc", "")


def declared_domain(column: str) -> list | None:
    """The declared categorical value domain for a column, or None when the
    column is numeric/continuous and has no enumerable domain."""
    domain = COLUMN_META.get(column, {}).get("domain")
    return list(domain) if domain is not None else None


def columns_with_role(role):
    """Return {table: [cols]} for every column with the given role."""
    return {t: [c for c, r in cols.items() if r == role] for t, cols in TABLES.items()}


def identifier_columns():
    return {c for cols in TABLES.values() for c, r in cols.items() if r == "DI"}


def sensitive_columns():
    return {c for cols in TABLES.values() for c, r in cols.items() if r in ("S", "DI")}


def schema_for_prompt():
    """Compact human-readable schema for the analyst system prompt."""
    lines = []
    for t, cols in TABLES.items():
        rendered = ", ".join(f"{c} [{r}]" for c, r in cols.items())
        lines.append(f"- {t}: {rendered}")
    return "\n".join(lines)
