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
