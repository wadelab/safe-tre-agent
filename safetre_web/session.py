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
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from pydantic import ValidationError

from safetre.disclosure import SessionAuditor
from safetre.query import AnovaSpec, GLMSpec, QuerySpec

# Cap distinct in-memory sessions. Under a Safe People allowlist this is never
# reached; it bounds memory if identity is not required (dev) or the allowlist is
# large. Eviction is least-recently-used.
MAX_SESSIONS = 4096

# Findings that mean a request was refused BEFORE the engine ran, so it never
# reached `SessionAuditor.observe` and never spent budget. Everything else did.
# Used to rebuild `_spent` from the audit log: a row whose findings lie entirely
# within this set is a refusal decided from the REQUEST, which costs nothing.
_PRE_ENGINE_RULES = frozenset({
    "spec_rejected", "intent_block", "grouping_mismatch", "term_mismatch",
    "query_budget",
})

# Statuses whose cohort was recorded on the release path (`record_cohort` runs
# for both, just before the result goes out).
_RELEASED = frozenset({"released", "redacted"})


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

    def rehydrate(self, audit_log, window_hours: int, now: float | None = None) -> int:
        """Rebuild each identity's lineage and budget from the audit log.

        A session used to last exactly as long as the process, which is not a
        policy — it is an accident of where the state happened to live. A deploy
        or a crash therefore handed every analyst a fresh query budget and an
        empty differencing lineage, and the two halves of a differencing pair
        could simply be split across a restart. Reproduced over HTTP: a pair
        denied before a restart completed after one and recovered a single
        donor's exact spend, with every row of the attack sitting in the log
        throughout, unread (hardening #49).

        The log already holds everything needed. Each record carries the
        identity, the status and the validated spec, so a released cohort is
        its spec's normalized filters and the budget is the count of requests
        that got as far as the engine.

        Returns the number of sessions restored. Called once at startup;
        `window_hours` is `PolicyConfig.session_window_hours`.

        **What this does and does not restore.** The cohort lineage — the
        stronger control since hardening #40, which decides on the row-level
        difference between two releases — is rebuilt exactly. The cheap
        total-delta layer is not: it compares distinct-donor totals, and the
        audit row records an output *shape*, not that total. So after a restart
        the lineage layer is whole and the first-pass layer starts empty. That
        is a narrow residual, because every pair the totals layer catches
        between two different cohorts is also a pair the lineage layer sees,
        but it is a residual and not a rounding error.
        """
        now = time.time() if now is None else now
        cutoff = now - window_hours * 3600
        for record in audit_log.since(cutoff):
            user = record.get("user") or ""
            if not user or user == "system":
                continue
            status = record.get("status")
            rules = {f.get("rule") for f in (record.get("findings") or [])
                     if isinstance(f, dict)}
            session = self.get(user)

            # Budget: everything except a refusal decided from the REQUEST,
            # which never reached `observe`. An `error` row is charged, because
            # the log cannot say whether the exception preceded the engine and
            # over-charging is the safe direction.
            if status != "denied" or not (rules and rules <= _PRE_ENGINE_RULES):
                session.auditor._spent += 1

            # Lineage: the cohort of anything that actually went out.
            if status in _RELEASED and isinstance(record.get("spec"), dict):
                cohort = _cohort_of(record["spec"])
                if cohort is not None:
                    session.auditor.record_cohort(*cohort)
        return len(self._sessions)


def _cohort_of(spec: dict) -> tuple[str, tuple] | None:
    """The (dataset, normalized filters) a recorded spec released over.

    Rebuilt by re-validating the spec rather than by re-deriving the
    normalisation here: `normalized_filters` collapses single-element `in`
    lists to `==` and sorts, and a second implementation of that would drift
    from the first exactly when it mattered.
    """
    dataset = spec.get("dataset")
    if not dataset:
        return None
    payload = {k: v for k, v in spec.items() if k != "aggregates"}
    for model in (QuerySpec, GLMSpec, AnovaSpec):
        try:
            return dataset, model(**payload).normalized_filters()
        except (ValidationError, TypeError, ValueError):
            continue                          # not this shape; try the next
    return None
