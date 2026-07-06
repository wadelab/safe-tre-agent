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
        "region": "QI",
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
        "amount_gbp": "S",
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


# Human-readable role labels for the public data dictionary.
ROLE_LABELS = {
    "DI": "direct identifier",
    "QI": "quasi-identifier",
    "S": "sensitive",
    "R": "reference",
    "meta": "structural",
}

# Some catalogue columns are DERIVED per-donor rollups in the engine views, so
# they are not in any base table; give them an explicit disclosure role here.
_DERIVED_ROLES = {
    "total_spend_gbp": "S",
    "purchase_events": "S",
    "lootbox_events": "S",
}

# Public column metadata for the data dictionary (safe to disclose): a plain
# description and, for categorical columns, the DECLARED value domain — the set
# of categories the study design permits (like a form's dropdown options).
# Declared domains are design-time knowledge, independent of any participant, so
# publishing them in full discloses nothing row-level; a rare category being a
# *valid option* is not the same as anyone having selected it. They also define
# the disclosure-safe projection of the observed marginals: a value outside its
# declared domain — e.g. a hostile string smuggled into a field — was never a
# real category and is dropped from any published table, not merely count-nulled.
COLUMN_META: dict[str, dict] = {
    # donor quasi-identifiers
    "age_band": {"desc": "Age band at enrolment.",
                 "domain": ["13-15", "16-17", "18-24", "25-34", "35-49", "50+"]},
    "sex": {"desc": "Self-reported sex / gender.",
            "domain": ["F", "M", "X", "NS", "Other"]},
    "region": {"desc": "UK ITL1 region or nation of residence.",
               "domain": ["North East", "North West", "Yorkshire and The Humber",
                          "East Midlands", "West Midlands", "East of England",
                          "London", "South East", "South West", "Scotland",
                          "Wales", "Northern Ireland"]},
    "income_band": {"desc": "Household income band (GBP per year).",
                    "domain": ["<40k", "40-70k", "70-100k", "100-150k", ">150k"]},
    "device_os": {"desc": "Mobile operating system.",
                  "domain": ["Android", "iOS"]},
    # app reference dimensions
    "genre": {"desc": "App genre.",
              "domain": ["RPG", "Strategy", "Casino", "Puzzle", "Shooter",
                         "Sports", "Card"]},
    "contains_lootboxes": {"desc": "Whether the app sells loot boxes / random-reward crates.",
                           "domain": [False, True]},
    "price_tier": {"desc": "App monetisation model.",
                   "domain": ["free", "freemium", "paid"]},
    "age_rating": {"desc": "App age rating (PEGI-style).",
                   "domain": [3, 7, 12, 16, 18]},
    # event / survey structural dimensions
    "event_type": {"desc": "Behavioural event type.",
                   "domain": ["session", "purchase", "lootbox_open", "ad_view"]},
    "wave": {"desc": "Survey wave (1 = baseline, 2 = six-month follow-up).",
             "domain": [1, 2]},
    # internal high-granularity filter (never grouped/returned)
    "age_years": {"desc": "Exact age in years (internal analysis variable)."},
    # measures
    "amount_gbp": {"desc": "Spend on a purchase or loot-box event (GBP)."},
    "ingame_currency": {"desc": "In-game currency granted by the event."},
    "total_spend_gbp": {"desc": "Per-donor total spend across purchase and loot-box events (GBP)."},
    "purchase_events": {"desc": "Per-donor count of purchase events."},
    "lootbox_events": {"desc": "Per-donor count of loot-box openings."},
    "pgsi_score": {"desc": "Problem Gambling Severity Index (0-27)."},
    "igds_score": {"desc": "Internet Gaming Disorder Scale (0-45)."},
    "wemwbs_score": {"desc": "Warwick-Edinburgh Mental Wellbeing Scale (14-70)."},
    "monthly_spend_selfreport": {"desc": "Self-reported monthly spend (GBP)."},
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
