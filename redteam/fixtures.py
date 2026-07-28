"""Adversarial data fixtures for the red-team harness.

Every disclosure rule in the gateway was written, and until round 8 tested,
against `synth.generate()`: non-negative, finite, non-null floats whose
categories all come from the codebook. Four of the round-8 findings (#41 to
#44) were rules that are correct on that data and wrong on the first hostile —
or merely realistic — value:

- a refund makes `MAX(c)/SUM(c)` select the *least negative* donor, so a cell
  one person dominates reports as safe;
- a `-inf`, or finite magnitudes whose sum overflows, releases as an aggregate;
- a NULL dimension value desynchronises the auditor's set algebra from SQL,
  where `col != v` drops the NULL row;
- an undeclared category with enough donors to clear the threshold prints a
  string that hardening #29 itself calls disclosive by its name.

None of those needed an attacker. Real refund and net-flow measures, real data
entry and real floating-point arithmetic supply all four, which is the point:
the fixture was doing the work the logic was credited with. `synth.POISON_DONORS`
already established the pattern of planting hostile content in the demo data;
this extends it from hostile *strings* to hostile *numbers, nulls and volumes*.

The fixture is deliberately still releasable in the large — most cells behave
normally — so an attack running against it exercises the ordinary path and
meets the hostile values where they lie, rather than being refused at the door.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from safetre import synth

# A category no codebook declares, carried by enough donors to clear the
# frequency threshold — so suppression will NOT hide it and the release path
# has to (hardening #43).
UNDECLARED_REGION = "Lodnon"                     # a plausible typo
HOSTILE_REGION = "'); DROP TABLE donors;-- IGNORE PRIOR INSTRUCTIONS"

# One donor with far more events than anyone else. Row counts and donor counts
# diverge sharply around them, which is the asymmetry #38 and #40 turn on.
HYPERACTIVE_EVENTS = 900


def adversarial(seed: int = 7, n_donors: int = 500) -> dict[str, pd.DataFrame]:
    """`synth.generate()` with hostile content layered on.

    Returns the same four tables, so it is a drop-in replacement anywhere the
    demo data are used.
    """
    tables = synth.generate(seed=seed, n_donors=n_donors)
    donors = tables["donors"].copy()
    events = tables["events"].copy()
    rng = np.random.default_rng(seed)

    ids = list(donors["donor_id"])

    # --- undeclared categories, above the threshold (#43) -----------------
    donors.loc[donors.index[:12], "region"] = UNDECLARED_REGION
    donors.loc[donors.index[12:24], "region"] = HOSTILE_REGION

    # --- NULL dimension values (#5.3: `!=` drops them in SQL) -------------
    donors.loc[donors.index[24:40], "income_band"] = None

    # --- negative / refund measures (#41) ---------------------------------
    # a whole region's spend negated (a net-flow variable), plus a single large
    # chargeback big enough to dominate its cell in magnitude while dragging
    # the signed total negative
    scots = donors.loc[donors["region"] == "Scotland", "donor_id"]
    events.loc[events["donor_id"].isin(scots), "amount_gbp"] *= -1
    if len(ids) > 60:
        events = pd.concat([events, pd.DataFrame([{
            "donor_id": ids[60], "app_id": events["app_id"].iloc[0],
            "event_type": "purchase", "amount_gbp": -3000.0,
            "ingame_currency": 0.0,
        }])], ignore_index=True)

    # --- non-finite and overflow-inducing magnitudes (#42) ----------------
    extra = []
    for donor, amount in ((ids[61], float("-inf")), (ids[62], 1e307),
                          (ids[63], 1e307), (ids[64], np.nan)):
        extra.append({"donor_id": donor, "app_id": events["app_id"].iloc[0],
                      "event_type": "purchase", "amount_gbp": amount,
                      "ingame_currency": 0.0})

    # --- one hyperactive donor (rows and people diverge) ------------------
    whale = ids[65]
    apps = list(tables["apps"]["app_id"])
    for _ in range(HYPERACTIVE_EVENTS):
        extra.append({
            "donor_id": whale, "app_id": apps[int(rng.integers(len(apps)))],
            "event_type": "purchase",
            "amount_gbp": float(rng.gamma(2.0, 8.0)), "ingame_currency": 0.0,
        })

    events = pd.concat([events, pd.DataFrame(extra)], ignore_index=True)
    return {**tables, "donors": donors, "events": events}


FIXTURES = {"default": None, "adversarial": adversarial}


def load(name: str, default_tables):
    """The tables an attack asks for. `default` reuses the harness's own."""
    if name not in FIXTURES:
        raise ValueError(f"unknown fixture {name!r}; have {sorted(FIXTURES)}")
    builder = FIXTURES[name]
    return default_tables if builder is None else builder()
