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
os.environ.setdefault("SAFETRE_AUDIT_DB",
                      os.path.join(tempfile.mkdtemp(prefix="safetre-audit-"), "audit.db"))
os.environ.setdefault("SAFETRE_AUDIT_KEY", "test-session-key")


import pytest

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
