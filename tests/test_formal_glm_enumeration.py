"""Exhaustive-enumeration formal check over the GLM model skeleton (R15/R16).

The model analogue of test_formal_enumeration: the no-filter GLMSpec space is
finite and small, so the decidable prohibitions are machine-checked over EVERY
point, not a sample. Compile-only — no engine execution — so the whole space
runs in well under a second.

Per skeleton point this checks:
- the spec validates (and the skeleton is exactly the admissible space:
  perturbing any point off-allowlist fails validation — spot-checked);
- P4/P8: no internal variable or off-catalogue column is expressible as a
  response or term; the family matches the catalogue's response map;
- the planned design-cell aggregates are all *valid QuerySpecs* — the
  inheritance theorem's executable form — and every compiled plan has the
  proven SafeSQL shape (single SELECT over a known view, bound params only,
  no DDL/DML, hard-forbidden columns absent).
"""

from __future__ import annotations

import re

from test_formal_enumeration import DDL_DML, HARD_FORBIDDEN, KNOWN_VIEWS

from safetre.engine import ROW_CAP, compile_query
from safetre.glm import GLMProcedure
from safetre.query import CATALOGUE, MAX_MODEL_TERMS, GLMSpec

INTERNAL_VARS = {"age_years"}

PROC = GLMProcedure()


def _skeleton_specs():
    for point in PROC.skeleton(CATALOGUE):
        yield GLMSpec(**point)


def test_glm_skeleton_is_enumerable_and_nonempty():
    points = PROC.skeleton(CATALOGUE)
    # finite and small — the premise that makes the model space provable
    assert 500 < len(points) < 2000, len(points)
    # and duplicate-free: the skeleton is a set, listed once
    seen = {(p["dataset"], p["family"], p["response"], tuple(p["terms"]))
            for p in points}
    assert len(seen) == len(points)


def test_exhaustive_glm_skeleton_is_admissible_and_compiles_safely():
    for spec in _skeleton_specs():
        ctx = (spec.dataset, spec.family, spec.response, spec.terms)

        # P4/P8: nothing internal or off-catalogue is expressible
        cat = CATALOGUE[spec.dataset]
        assert spec.response in cat["glm_responses"], ctx
        assert spec.family in cat["glm_responses"][spec.response], ctx
        assert not (set(spec.terms) & INTERNAL_VARS), ctx
        assert all(t in cat["dims"] for t in spec.terms), ctx
        assert 1 <= len(spec.terms) <= MAX_MODEL_TERMS, ctx

        # inheritance: every underlying aggregate is an ordinary, valid
        # QuerySpec, so P5-P7/rounding/lineage/budget apply literally
        aggregates = PROC.plan_aggregates(spec)
        assert len(aggregates) == len(PROC.table_roles(spec)), ctx
        for agg in aggregates:
            assert agg.dataset == spec.dataset, ctx
            assert agg.group_by == spec.terms, ctx
            plan = compile_query(agg)
            sql = plan.sql
            assert plan.source_view in KNOWN_VIEWS, ctx
            assert sql.startswith("SELECT "), ctx
            assert sql.endswith(f" ORDER BY n DESC LIMIT {ROW_CAP}"), ctx
            assert ";" not in sql, ctx
            assert sql.count("?") == len(plan.params), ctx
            padded = f" {sql.upper()} "
            for verb in DDL_DML:
                assert verb not in padded, (verb, ctx)
            assert re.findall(r'FROM\s+"([a-z0-9_]+)"', sql) == [plan.source_view], ctx
            for col in HARD_FORBIDDEN:
                assert not re.search(rf'"{col}"', sql), (col, ctx)
            for col in plan.output_columns:
                assert col not in HARD_FORBIDDEN | INTERNAL_VARS, (col, ctx)


def test_skeleton_is_exactly_the_admissible_space():
    # soundness spot-check of the enumeration itself: perturbing a skeleton
    # point off-allowlist must fail validation (the skeleton is not merely a
    # subset of the admissible space — its complement is inadmissible).
    import pytest
    point = PROC.skeleton(CATALOGUE)[0]
    for corrupt in (
        {**point, "response": "donor_id"},
        {**point, "response": "age_years"},
        {**point, "terms": ["age_years"]},
        {**point, "terms": point["terms"] + ["free_text"]},
        {**point, "family": "gamma"},
        {**point, "dataset": "secrets"},
    ):
        with pytest.raises(Exception):
            GLMSpec(**corrupt)

    # completeness: the skeleton size equals the closed-form count
    expected = 0
    for dataset, cat in CATALOGUE.items():
        dims = set(cat["dims"])
        for response, families in cat["glm_responses"].items():
            candidates = len(dims - {response})
            import math
            subsets = sum(math.comb(candidates, k)
                          for k in range(1, MAX_MODEL_TERMS + 1))
            expected += len(families) * subsets
    assert len(PROC.skeleton(CATALOGUE)) == expected
