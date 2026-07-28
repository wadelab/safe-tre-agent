"""Every model instance has an executable twin, and every twin exists (F7).

The known weak point of model-based verification is not that the models are
wrong — it is that nothing fails when they stop describing the code. #40 is the
worked example: `disclosure_policy.als` went on proving a sound bound over
donor cohorts for a round after the code had moved to rows, and CI stayed
green throughout, because the model's own commands all still passed. The model
was self-consistent and irrelevant.

`formal/correspondence.yaml` is the link, and these tests enforce it both ways:

- **model -> harness.** Every `run` in every `.als` is classified. An `attack`
  must name a twin that exists, so a satisfiable run cannot be the only thing
  claiming an attack is real. A run that is not in the file at all fails,
  which is what stops a new attack being added without one.
- **harness -> model.** Every twin named must resolve to a real test function
  or reproducer, so renaming or deleting one breaks the build rather than
  quietly orphaning the model instance it stood for.

Pure Python: no Alloy, no Lean, no Java. The `formal` CI job replays the models
themselves; this only has to check they and the harness still refer to each
other.
"""

from __future__ import annotations

import os
import re

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORMAL = os.path.join(ROOT, "formal")
TABLE = os.path.join(FORMAL, "correspondence.yaml")

_RUN = re.compile(r"^run\s+(\w+)", re.MULTILINE)
_KINDS = {"guard", "attack", "residual"}


def _table() -> dict:
    with open(TABLE) as fh:
        return yaml.safe_load(fh)


def _runs(model: str) -> set[str]:
    with open(os.path.join(FORMAL, model)) as fh:
        return set(_RUN.findall(fh.read()))


def _models() -> list[str]:
    return sorted(n for n in os.listdir(FORMAL) if n.endswith(".als"))


def test_every_model_is_in_the_table():
    missing = [m for m in _models() if m not in _table()]
    assert not missing, f"models with no correspondence entry: {missing}"


@pytest.mark.parametrize("model", _models())
def test_every_run_is_classified(model):
    """A `run` that nobody has classified is the gap this file exists to
    close: it is either a vacuity guard or something the code must prevent,
    and only one of those needs a reproducer."""
    declared = set(_table().get(model, {}))
    actual = _runs(model)
    assert actual - declared == set(), (
        f"{model}: runs with no entry in correspondence.yaml: "
        f"{sorted(actual - declared)}")
    assert declared - actual == set(), (
        f"{model}: correspondence.yaml names runs the model no longer has: "
        f"{sorted(declared - actual)}")


@pytest.mark.parametrize("model", _models())
def test_every_entry_is_well_formed(model):
    for name, entry in _table().get(model, {}).items():
        assert entry.get("kind") in _KINDS, f"{model}:{name} has no valid kind"
        if entry["kind"] == "attack":
            assert entry.get("twin"), (
                f"{model}:{name} is an attack with no executable twin — a "
                f"satisfiable run is then the only thing claiming it is real")
        if entry["kind"] == "residual":
            assert entry.get("twin") or entry.get("priced"), (
                f"{model}:{name} is a residual with neither a twin nor a "
                f"record pricing it, which is an undocumented gap with a "
                f"satisfiable run attached")
        if entry["kind"] == "guard":
            assert entry.get("note"), f"{model}:{name} guard needs a note"


def _twins() -> list[tuple[str, str, str]]:
    out = []
    for model, entries in _table().items():
        for name, entry in entries.items():
            twin = entry.get("twin")
            if twin:
                out.append((model, name, twin))
    return out


@pytest.mark.parametrize("model,name,twin", _twins(),
                         ids=[f"{m}:{n}" for m, n, _ in _twins()])
def test_every_twin_exists(model, name, twin):
    """The harness -> model direction. A reproducer that was renamed away
    leaves the model instance standing for nothing."""
    path, _, func = twin.partition("::")
    full = os.path.join(ROOT, path)
    assert os.path.exists(full), f"{model}:{name} names a missing file {path}"
    with open(full) as fh:
        source = fh.read()
    assert re.search(rf"^def {re.escape(func)}\b", source, re.MULTILINE), (
        f"{model}:{name} names {func!r}, which {path} does not define")


def test_every_priced_artifact_exists():
    for model, entries in _table().items():
        for name, entry in entries.items():
            priced = entry.get("priced")
            if priced:
                assert os.path.exists(os.path.join(ROOT, priced)), (
                    f"{model}:{name} prices a residual against {priced}, "
                    f"which does not exist")


def test_the_verdict_script_expects_every_run():
    """The third leg: a run classified here and declared in the model still
    has to be one `run_checks.py` requires, or CI would not notice it going
    unsatisfiable."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_checks", os.path.join(FORMAL, "run_checks.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    for model, entries in _table().items():
        expected = module.MODELS.get(model, {}).get("runs", set())
        missing = set(entries) - expected
        assert not missing, (
            f"{model}: run_checks.py does not require {sorted(missing)}, so "
            f"they could become unsatisfiable without failing CI")
