"""Procedure conformance: every statistical procedure must discharge the same
safety obligations before it can be admitted to the pipeline.

This is the executable half of `docs/verifiable-extensions.md`. It treats each
supported measure function (`count`, `mean`, `sum`, `corr`, …) as a *procedure*
that extends the trusted computing base, and enforces — enumerated from the
source of truth, not a hand-maintained list — that each one:

1. is declared here with its disclosure obligation (so a new `fn` added to the
   `Measure` schema fails CI until its obligation is stated); and
2. actually satisfies that obligation end-to-end.

The obligation that matters most: a procedure that reads a *sensitive
per-individual value* (mean/sum/corr) must carry an individual-influence control
(dominance for sum/mean, leave-one-out influence for corr) that the engine
attaches internally and the gateway drops before release. `count` reads no
per-individual value and carries none. This is the check that would have caught
the corr influence gap (hardening log #15).
"""

from __future__ import annotations

from typing import get_args

import pytest

from safetre import synth
from safetre.disclosure import (
    COUNT_COLUMNS, ROUND_BASE, DisclosurePolicy, leak_detector,
)
from safetre.engine import ROW_CAP, QueryEngine, compile_query
from safetre.procedures import REGISTRY
from safetre.query import CATALOGUE, Measure, QuerySpec
from safetre.schema import identifier_columns, sensitive_columns

# --- the procedure obligation table (the contract each procedure must satisfy) ---
# reads_individual_values: does the released statistic depend on a sensitive
#   per-donor value (so one donor can dominate it)?
# influence_control: the internal helper column that bounds single-donor
#   influence and MUST be dropped before release (None if not applicable).
PROCEDURES = {
    "count":  {"reads_individual_values": False, "influence_control": None},
    "mean":   {"reads_individual_values": True,  "influence_control": "dominance"},
    "sum":    {"reads_individual_values": True,  "influence_control": "dominance"},
    "sum_sq": {"reads_individual_values": True,  "influence_control": "dominance"},
    "sum_cube": {"reads_individual_values": True, "influence_control": "dominance"},
    "sum_quad": {"reads_individual_values": True, "influence_control": "dominance"},
    "corr":   {"reads_individual_values": True,  "influence_control": "influence"},
}

SUPPORTED_FNS = set(get_args(Measure.model_fields["fn"].annotation))


@pytest.fixture(scope="module")
def engine():
    return QueryEngine(synth.generate(seed=17))


def _representative_spec(fn: str, group_by):
    """A valid spec for `fn` on donor_spend (has a sensitive measure + age)."""
    ds = "donor_spend"
    measures = sorted(CATALOGUE[ds]["measures"])
    if fn == "count":
        measure = {"fn": fn}
    elif fn == "corr":
        measure = {"fn": fn, "x": "age_years", "y": measures[0]}
    else:
        measure = {"fn": fn, "column": measures[0]}
    return QuerySpec(dataset=ds, measure=measure, group_by=group_by)


def test_every_supported_fn_has_a_declared_obligation():
    # adding a new fn to the Measure schema without declaring its disclosure
    # obligation here fails the build — you cannot smuggle in an unverified
    # statistical procedure.
    assert SUPPORTED_FNS == set(PROCEDURES), (
        f"measure functions without a conformance obligation: "
        f"{SUPPORTED_FNS - set(PROCEDURES)}; "
        f"stale obligations: {set(PROCEDURES) - SUPPORTED_FNS}"
    )


def test_registry_is_the_schema_and_matches_declared_obligations():
    # R14: the registry is the sole dispatch point, so it must cover exactly
    # the schema's fns, and each procedure's self-declared obligation must
    # match the one declared (independently) in this suite.
    assert set(REGISTRY) == SUPPORTED_FNS
    for fn, obligation in PROCEDURES.items():
        proc = REGISTRY[fn]
        assert proc.fn == fn
        assert proc.reads_individual_values == obligation["reads_individual_values"]
        assert proc.influence_control == obligation["influence_control"]


# --- model procedures: the same bar, multi-query shape (R14/R15) ---------------
# fits_on_finalized_only: the fitter consumes gateway-finalized tables and
#   nothing else (P21) — enforced structurally by _handle_model and statically
#   by test_glm_noninterference.
# denies_on_suppression: any redacted/denied underlying aggregate denies the
#   whole model (P19).
MODEL_PROCEDURES = {
    "glm": {"multi_query": True, "fits_on_finalized_only": True,
            "denies_on_suppression": True},
    "anova": {"multi_query": True, "fits_on_finalized_only": True,
              "denies_on_suppression": True},
    "series": {"multi_query": True, "fits_on_finalized_only": True,
               "denies_on_suppression": True},
    "normality": {"multi_query": True, "fits_on_finalized_only": True,
                  "denies_on_suppression": True},
}


def test_every_model_tool_has_a_declared_obligation():
    from safetre.procedures import model_registry
    assert set(model_registry()) == set(MODEL_PROCEDURES), (
        "model tools without a conformance obligation: "
        f"{set(model_registry()) - set(MODEL_PROCEDURES)}; "
        f"stale obligations: {set(MODEL_PROCEDURES) - set(model_registry())}")


@pytest.mark.parametrize("tool", sorted(MODEL_PROCEDURES))
def test_model_procedure_inherits_through_valid_queryspecs(tool):
    # the inheritance theorem, executable form: every aggregate a model plans
    # is an ordinary valid QuerySpec, so O2 (SafeSQL shape), O3 (witnesses)
    # and O4 (lineage identity) hold for the model because they hold for
    # every QuerySpec — checked exhaustively in test_formal_glm_enumeration.
    from safetre.procedures import model_registry
    proc = model_registry()[tool]
    for point in proc.skeleton(CATALOGUE)[::37]:      # a spread sample; the
        spec = proc.validate(point)                   # full space is exhausted
        for agg in proc.plan_aggregates(spec):        # in the enumeration test
            assert isinstance(agg, QuerySpec)
        assert proc.cost(spec) == len(proc.plan_aggregates(spec))
        assert proc.model_key(spec)
        contract = proc.output_contract(spec)
        assert set(contract) >= {"output", "cells", "model"}


@pytest.mark.parametrize("fn", sorted(PROCEDURES))
def test_procedure_declares_a_complete_output_contract(fn):
    # R14: every released payload column must carry a declared disclosure
    # class — the gateway's treatment of an output is declared, not inferred
    # from column names (the gap behind hardening #25).
    proc = REGISTRY[fn]
    spec = _representative_spec(fn, group_by=["region"])
    contract = proc.output_contract(spec.measure)
    for column in proc.payload_columns(spec.measure):
        assert column in contract, f"{fn}: payload column {column!r} unclassified"
    assert all(v in {"cell_key", "count", "magnitude", "moment2", "moment3",
                     "moment4", "statistic", "p_value"}
               for v in contract.values())
    # frequency payloads must be declared as counts so rounding covers them
    if fn == "count":
        assert contract["n"] == "count"
    # a higher moment is not a magnitude: the same nominal dominance bound is a
    # far tighter rule on the powered scale, and the class is what selects it
    if fn == "sum_sq":
        assert contract["value"] == "moment2"
    if fn == "sum_cube":
        assert contract["value"] == "moment3"
    if fn == "sum_quad":
        assert contract["value"] == "moment4"


@pytest.mark.parametrize("fn", sorted(PROCEDURES))
def test_procedure_carries_declared_influence_control(engine, fn):
    obligation = PROCEDURES[fn]
    df = engine.run(_representative_spec(fn, group_by=["region"]))
    control = obligation["influence_control"]
    if obligation["reads_individual_values"]:
        assert control is not None, f"{fn} reads individual values but declares no control"
        assert control in df.columns, (
            f"{fn} must attach the internal '{control}' control column")
    else:
        # count reads no per-individual value: no influence control needed
        assert "dominance" not in df.columns and "influence" not in df.columns


@pytest.mark.parametrize("fn", sorted(PROCEDURES))
def test_procedure_release_drops_helpers_and_obeys_disclosure(engine, fn):
    # end-to-end: representative (over-granular) spec -> engine -> gateway.
    # whatever the procedure, the released frame must disclose nothing and must
    # not leak the internal control helper.
    group_by = [g for g in ("region", "age_band", "device_os")
                if g in CATALOGUE["donor_spend"]["dims"]]
    df = engine.run(_representative_spec(fn, group_by=group_by))
    released, action, _ = DisclosurePolicy().apply(df)
    if action == "deny":
        assert released is None
        return
    cols = {str(c).lower() for c in released.columns}
    # internal disclosure helpers are all dropped before release
    assert not (cols & {"dominance", "influence", "n_donors"})
    assert not (cols & identifier_columns())
    assert "free_text" not in cols and "age_years" not in cols
    assert not (cols & (sensitive_columns() - identifier_columns()))
    assert not leak_detector(released)                            # no residual risk
    for c in released.columns:
        if str(c).lower() in COUNT_COLUMNS:
            assert (released[c] >= DisclosurePolicy.DEFAULT_THRESHOLD).all()
            assert (released[c] % ROUND_BASE == 0).all()


@pytest.mark.parametrize("fn", sorted(PROCEDURES))
def test_procedure_compiles_to_safe_sql(engine, fn):
    plan = compile_query(_representative_spec(fn, group_by=["region"]))
    assert plan.source_view in {"donor_spend", "_donor_spend_u"}
    assert plan.sql.startswith("SELECT ")
    assert plan.sql.endswith(f" ORDER BY n DESC LIMIT {ROW_CAP}")
    assert plan.sql.count("?") == len(plan.params)
    assert ";" not in plan.sql
    assert "donor_id" not in plan.sql and "free_text" not in plan.sql
    padded = f" {plan.sql.upper()} "
    for verb in (" INSERT ", " UPDATE ", " DELETE ", " DROP ", " ALTER ", " CREATE "):
        assert verb not in padded
