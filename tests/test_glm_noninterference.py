"""Static noninterference checks on the model-fitting path (P21).

The reproducibility meta-test proves the released fit is a function of the
released artifacts; these checks pin the structural reason WHY that holds and
guard it against regression, test_invariants-style:

- `safetre/stats.py` (the fitter's numerics) imports nothing beyond the
  stdlib — it cannot open the database, read a view, or reach the engine;
- `safetre/glm.py` (the model procedure) never imports the engine, duckdb, or
  the service — it can only plan QuerySpecs and consume the DataFrames it is
  handed;
- the GLM fit entrypoints accept only (finalized tables, spec) — no engine
  handle, no connection, no path to rows.
"""

from __future__ import annotations

import ast
import inspect
import os

import safetre.anova
import safetre.series
import safetre.glm
import safetre.stats

_ALLOWED_STATS_IMPORTS = {"__future__", "math", "dataclasses", "typing"}
_FORBIDDEN_GLM_IMPORTS = {"duckdb", "safetre.engine", "engine", "safetre.service",
                          "service", "sqlite3", "socket", "requests", "httpx"}


def _module_imports(module) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            # relative imports resolve inside the package
            module_name = node.module or ""
            names.add(("safetre." + module_name) if node.level else module_name)
    return names


def test_stats_module_is_stdlib_only():
    imports = _module_imports(safetre.stats)
    assert imports <= _ALLOWED_STATS_IMPORTS, (
        f"safetre.stats grew imports beyond the stdlib allowlist: "
        f"{imports - _ALLOWED_STATS_IMPORTS} — the fitter's numerics must stay "
        "incapable of I/O (P21)")


def test_glm_module_never_touches_engine_or_database():
    imports = _module_imports(safetre.glm)
    assert not (imports & _FORBIDDEN_GLM_IMPORTS), (
        f"safetre.glm imports {imports & _FORBIDDEN_GLM_IMPORTS} — the model "
        "procedure must not be able to reach rows (P21)")
    # and nothing in the module source names the unit views
    source = inspect.getsource(safetre.glm)
    for view in ("_spend_u", "_donor_spend_u", "_wellbeing_u"):
        assert view not in source


def test_fit_entrypoints_take_only_finalized_frames():
    from safetre.glm import GLMProcedure, refit_from_artifact
    fit_params = list(inspect.signature(GLMProcedure.fit).parameters)
    assert fit_params == ["self", "finalized", "spec"]
    refit_params = list(inspect.signature(refit_from_artifact).parameters)
    assert refit_params == ["cells", "spec"]


def test_irls_signature_is_primitive_lists_only():
    from safetre.stats import irls_cells
    params = list(inspect.signature(irls_cells).parameters)
    assert params[:5] == ["design", "response", "weights", "family", "offset"]


def test_anova_module_never_touches_engine_or_database():
    # the new one-way ANOVA tool inherits the same P21 boundary as glm: it can
    # only plan QuerySpecs and consume the DataFrames it is handed.
    imports = _module_imports(safetre.anova)
    assert not (imports & _FORBIDDEN_GLM_IMPORTS), (
        f"safetre.anova imports {imports & _FORBIDDEN_GLM_IMPORTS} — the model "
        "procedure must not be able to reach rows (P21)")
    source = inspect.getsource(safetre.anova)
    for view in ("_spend_u", "_donor_spend_u", "_wellbeing_u"):
        assert view not in source


def test_anova_fit_entrypoints_take_only_finalized_frames():
    from safetre.anova import AnovaProcedure, refit_from_artifact
    assert list(inspect.signature(AnovaProcedure.fit).parameters) == \
        ["self", "finalized", "spec"]
    assert list(inspect.signature(refit_from_artifact).parameters) == \
        ["cells", "spec"]


def test_series_module_never_touches_engine_or_database():
    # the series tool inherits the same P21 boundary: it plans one QuerySpec
    # and consumes the finalized window table it is handed, stdlib numerics
    imports = _module_imports(safetre.series)
    assert not (imports & _FORBIDDEN_GLM_IMPORTS), (
        f"safetre.series imports {imports & _FORBIDDEN_GLM_IMPORTS} — the model "
        "procedure must not be able to reach rows (P21)")
    assert not (imports & {"numpy", "scipy"}), imports
    source = inspect.getsource(safetre.series)
    for view in ("_spend_u", "_donor_spend_u", "_wellbeing_u", "_bets_u", "_panel_u"):
        assert view not in source


def test_series_fit_entrypoints_take_only_finalized_frames():
    from safetre.series import SeriesProcedure, refit_from_artifact
    assert list(inspect.signature(SeriesProcedure.fit).parameters) == \
        ["self", "finalized", "spec"]
    assert list(inspect.signature(refit_from_artifact).parameters) == \
        ["cells", "spec"]


def test_glm_source_file_is_the_audited_one():
    # the AST checks above parse the module actually imported at runtime;
    # make sure that is the repository file, not a stray shadow copy
    assert os.path.samefile(
        inspect.getfile(safetre.glm),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "safetre", "glm.py"))
