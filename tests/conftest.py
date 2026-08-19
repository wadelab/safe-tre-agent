"""Test session setup.

Starlette's TestClient presents peer host 'testclient'. The restricted-channel
check honours that only when SAFETRE_ALLOW_TEST_CLIENT is set — a deliberate
production-safe default (see safetre_web/channel.py). Enable it for the whole
test session here, before any test module imports the app.

The audit database is pinned here for the same reason: `safetre_web.app`
creates its `AuditLog` at import time from `SAFETRE_AUDIT_DB`, defaulting to
`audit.db` in the working directory. `tests/test_web.py` set that variable, but
only at its own import — so any test module that imported the app first (e.g.
`test_timing_channel.py`) got the default, and the suite wrote its corpus into
the developer's real audit log in the repository root. Found by a red-team pass
(2026-07-26): the local `audit.db` held a thousand rows of test traffic. A
tamper-evident log that ordinary test runs append to is not one anybody can
read as evidence, so the pin belongs where it cannot be missed — before any
module is imported.
"""

import os
import tempfile

os.environ.setdefault("SAFETRE_ALLOW_TEST_CLIENT", "1")

# The audit database is one-process-per-DB by construction: the HMAC chain's
# head-read and insert must be atomic, and the session budget and differencing
# lineage live in that process's memory (safetre/audit.py). Under `pytest-xdist`
# each worker is its own process but inherits the controller's environment, so a
# single `SAFETRE_AUDIT_DB` would be opened by every worker at once — the very
# collision the engine refuses (AuditDatabaseInUse). Give each xdist worker its
# own database. Pair this with `--dist loadfile` (see pyproject `addopts`) so a
# test file's process-global state — the web app's import-time audit log, the
# active dataset — never straddles two workers.
_worker = os.environ.get("PYTEST_XDIST_WORKER")
if _worker:
    os.environ["SAFETRE_AUDIT_DB"] = os.path.join(
        tempfile.mkdtemp(prefix=f"safetre-audit-{_worker}-"), "audit.db")
else:
    os.environ.setdefault("SAFETRE_AUDIT_DB",
                          os.path.join(tempfile.mkdtemp(prefix="safetre-audit-"), "audit.db"))
os.environ.setdefault("SAFETRE_AUDIT_KEY", "test-session-key")


import pytest  # noqa: E402 - after the pre-import environment pin above

# How big the default suite actually is, measured from this session's own
# collection. `docs/elif.md` quotes the number, so something has to check it.
# Counted here rather than by shelling out to a second `--collect-only` pass:
# module-level `importorskip` makes the collectable set depend on which
# optional groups are installed, so a subprocess can disagree with the run
# that spawned it (CI's exhaustive job reported 919 against the same tree's
# 969). The live session cannot disagree with itself.
COLLECTED: dict[str, object] = {}


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Record the default-suite size before any marker/keyword deselection.

    `tryfirst` puts this ahead of pytest's own `-m` / `-k` filtering, so the
    tally is the same whether the session is a default run or `-m slow`.
    """
    COLLECTED["default_suite"] = sum(
        1 for i in items if i.get_closest_marker("slow") is None)
    # Only a whole-tree run sees every test; a narrowed one must not be
    # mistaken for a shrinking suite.
    COLLECTED["whole_tree"] = (not config.getoption("file_or_dir")
                               and not config.option.keyword)


class RecordingLog:
    """An audit log that keeps what was written, so a test can assert the
    separation the gateway now enforces: the analyst sees one canonical
    refusal, the audit log still names the rule that fired and how many cells
    it fired on."""

    def __init__(self):
        self.records: list[dict] = []

    def append(self, **kwargs):
        self.records.append(kwargs)
        return "recorded"

    @property
    def last(self) -> dict:
        assert self.records, "nothing was written to the audit log"
        return self.records[-1]

    def rules(self) -> list[str]:
        return [f["rule"] for f in self.last["findings"]]

    def audit_details(self) -> str:
        return " ".join(f.get("audit_detail", "") for f in self.last["findings"])


@pytest.fixture
def audit_spy() -> RecordingLog:
    return RecordingLog()


# --------------------------------------------------------------------------- #
# verifiable research records                                                 #
# --------------------------------------------------------------------------- #
#
# Prefixed names, deliberately. A conftest fixture called `service` or `log`
# would be in scope for every test module in the suite, and several of them
# define their own; a shared harness must not decide what an unrelated module's
# `service` means. The helpers these build on live in `tests/vrr_harness.py`.

@pytest.fixture(scope="module")
def vrr_study():
    from studies.nightplay import generate as G
    return G.generate(n_people=2500)


@pytest.fixture
def vrr_service(vrr_study):
    import pathlib

    from safetre import dataset as dataset_mod
    from studies.nightplay import verify as V

    packaged = pathlib.Path(dataset_mod.__file__).with_name("demo_dataset.yaml")
    tables, _ = vrr_study
    dataset_mod.activate(dataset_mod.load_dataset(V.DEFINITION))
    try:
        yield V.build_service(tables)
    finally:
        dataset_mod.activate(dataset_mod.load_dataset(packaged))


@pytest.fixture
def vrr_manifests(vrr_study, vrr_service):
    from tests import vrr_harness

    tables, _ = vrr_study
    return vrr_harness.build_manifests(tables)


@pytest.fixture
def vrr_log(tmp_path):
    from safetre.audit import AuditLog
    return AuditLog(str(tmp_path / "vrr-audit.db"))


@pytest.fixture
def vrr_record(vrr_service, vrr_manifests, vrr_log):
    from tests import vrr_harness
    _, _, record = vrr_harness.build_record(vrr_service, vrr_manifests, vrr_log)
    return record
