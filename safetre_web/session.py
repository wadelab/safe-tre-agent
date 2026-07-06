"""Per-user sessions — what makes the session auditor real.

Each authenticated user gets one SessionAuditor that persists across requests,
so the differencing / query-budget controls actually accumulate over a
conversation (the CLI used a fresh auditor per call).

Concurrency matters here for *security*, not just correctness. FastAPI runs the
sync query handler in a threadpool, so two requests from the same identity can
run in parallel. The differencing-lineage and query-budget controls are a
check-then-act over shared mutable state (`observe_cohort` reads the cohort
history, `record_cohort` writes it, with engine work in between). Without
serialisation an attacker can fire the two halves of a differencing attack
concurrently and have both pass the lineage check before either records. So:

- `SessionStore.get` is guarded (no check-then-set race creating duplicate
  sessions / resetting an auditor), and
- each `Session` carries a `lock` the request handler holds across the whole
  `observe -> apply -> record_cohort` critical section.

Cross-user parallelism is preserved; only a single identity's requests serialise,
which matches how one researcher actually issues queries.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, field

from safetre.disclosure import SessionAuditor

# Cap distinct in-memory sessions. Under a Safe People allowlist this is never
# reached; it bounds memory if identity is not required (dev) or the allowlist is
# large. Eviction is least-recently-used.
MAX_SESSIONS = 4096


@dataclass
class Session:
    auditor: SessionAuditor
    lock: threading.Lock = field(default_factory=threading.Lock)
    history: list = field(default_factory=list)


class SessionStore:
    def __init__(self, *, threshold: int = 10, budget: int = 20,
                 max_sessions: int = MAX_SESSIONS):
        self._sessions: "OrderedDict[str, Session]" = OrderedDict()
        self._threshold = threshold
        self._budget = budget
        self._max_sessions = max_sessions
        self._lock = threading.Lock()

    def get(self, user: str) -> Session:
        with self._lock:
            sess = self._sessions.get(user)
            if sess is None:
                sess = Session(SessionAuditor(threshold=self._threshold, budget=self._budget))
                self._sessions[user] = sess
                if len(self._sessions) > self._max_sessions:
                    self._sessions.popitem(last=False)   # evict least-recently-used
            else:
                self._sessions.move_to_end(user)
            return sess
