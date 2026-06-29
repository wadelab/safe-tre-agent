"""Schema for the synthetic behavioural dataset.

Roles drive the disclosure-control rules:
  DI = direct identifier      (pseudonymous; never released)
  QI = quasi-identifier       (can re-identify in combination)
  S  = sensitive attribute    (what min-cell-size / suppression protects)
  R  = reference / non-disclosive

Modelled as a loot-box / in-app-spend + psychometrics study. All generated rows
are synthetic and carry no real participant data.
"""

# table -> {column: role}
TABLES = {
    "donors": {
        "donor_id": "DI",
        "enrolment_date": "meta",
        "age_years": "QI",
        "age_band": "QI",
        "sex": "QI",
        "canton": "QI",
        "income_band": "QI",
        "device_os": "QI",
    },
    "apps": {
        "app_id": "R",
        "app_name": "R",
        "developer": "R",
        "genre": "R",
        "contains_lootboxes": "R",
        "age_rating": "R",
        "price_tier": "R",
    },
    "events": {
        "event_id": "meta",
        "donor_id": "DI",          # foreign key -> a person
        "app_id": "R",
        "ts": "QI",                # precise timing can re-identify
        "event_type": "R",
        "item_name": "R",
        "amount_chf": "S",
        "ingame_currency": "S",
    },
    "survey": {
        "donor_id": "DI",
        "wave": "meta",
        "pgsi_score": "S",         # problem-gambling severity index
        "igds_score": "S",         # internet gaming disorder scale
        "wemwbs_score": "S",       # mental wellbeing
        "monthly_spend_selfreport": "S",
        "free_text": "S",          # unstructured + prompt-injection vector
    },
}


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
