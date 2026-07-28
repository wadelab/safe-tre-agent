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

import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from pydantic import ValidationError

from safetre.disclosure import SessionAuditor
from safetre.query import AnovaSpec, GLMSpec, QuerySpec

log = logging.getLogger("safetre.session")

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


class AuditChainUnverified(RuntimeError):
    """The audit chain did not verify, so it cannot be replayed into the
    session controls. Raised rather than logged: rehydration is the only thing
    standing between a restart and a fresh differencing lineage, and rebuilding
    it from rows nobody authenticated is how a *deletion* — which needs write
    access, not the key — becomes a released differencing pair."""


def _allow_unverified_rehydrate() -> bool:
    return os.environ.get("SAFETRE_ALLOW_UNVERIFIED_REHYDRATE", "") == "1"


def _restore_filters(filters) -> tuple:
    """JSON gives back lists; the auditor compares tuples.

    `normalized_filters` produces `(column, op, value)` atoms whose value is
    itself a tuple for an `in` filter, and cohort identity is tuple equality —
    so a list that merely looks the same would compare unequal and silently
    restore a cohort that never matches anything.
    """
    out = []
    for atom in filters:
        column, op, value = atom
        out.append((column, op, tuple(value) if isinstance(value, list) else value))
    return tuple(out)


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

    def rehydrate(self, audit_log, window_hours: int, now: float | None = None,
                  *, expected_head: str | None = None) -> int:
        """Rebuild each identity's lineage and budget from the audit log.

        A session used to last exactly as long as the process, which is not a
        policy — it is an accident of where the state happened to live. A deploy
        or a crash therefore handed every analyst a fresh query budget and an
        empty differencing lineage, and the two halves of a differencing pair
        could simply be split across a restart. Reproduced over HTTP: a pair
        denied before a restart completed after one and recovered a single
        donor's exact spend, with every row of the attack sitting in the log
        throughout, unread (hardening #49).

        The log holds everything needed, and since hardening #58 it holds it
        *authoritatively*: each record carries an `accounting` block — what the
        request cost the session and which cohorts it released over — written
        by the same code that did the live accounting and covered by the row's
        MAC. Replaying a record is therefore replay, not re-derivation.

        That distinction is the whole finding. The first version inferred both
        quantities from the record's shape, which meant two implementations of
        one cost model, and round 9 measured them disagreeing in opposite
        directions: a model charged once per planned aggregate live but one
        unit per record on replay (so every restart refunded roughly half of
        every model a user had run), while a pipeline error was free live and
        charged on replay. It also re-derived a released cohort by re-reading
        the model spec, which cannot recover a cohort the *procedure* added —
        a binomial's successes filter — so a restart forgot one and the
        differencing pair that used it was released (hardening #58).

        Returns the number of sessions restored. Called once at startup;
        `window_hours` is `PolicyConfig.session_window_hours`.

        **The chain is verified first, and a failure is fatal** (hardening
        #59). These rows are an *input* to two security controls, and deleting
        one — which needs write access to the database, not the key — drops a
        cohort from the lineage. `verify()` detects exactly that and was never
        consulted here. `SAFETRE_ALLOW_UNVERIFIED_REHYDRATE=1` overrides it
        loudly, for a developer with a stale database; it is an environment
        variable rather than a config key for the same reason
        `SAFETRE_ALLOW_UNSAFE_POLICY` is.

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
        if not audit_log.verify(expected_head=expected_head):
            if not _allow_unverified_rehydrate():
                raise AuditChainUnverified(
                    "the audit chain does not verify, so the session budget and "
                    "differencing lineage cannot be rebuilt from it; refusing to "
                    "start. Investigate the log (a deleted or edited row drops a "
                    "cohort from the lineage). Set "
                    "SAFETRE_ALLOW_UNVERIFIED_REHYDRATE=1 to start anyway with "
                    "session controls rebuilt from unauthenticated rows.")
            log.error("SAFETRE_ALLOW_UNVERIFIED_REHYDRATE=1: rebuilding session "
                      "controls from an audit chain that does NOT verify; the "
                      "differencing lineage may be missing cohorts")

        now = time.time() if now is None else now
        cutoff = now - window_hours * 3600
        for record in audit_log.since(cutoff):
            user = record.get("user") or ""
            if not user or user == "system":
                continue
            session = self.get(user)
            accounting = record.get("accounting")

            if isinstance(accounting, dict) and "cost" in accounting:
                session.auditor.charge(int(accounting["cost"]))
                for entry in accounting.get("cohorts") or []:
                    dataset, filters = entry
                    session.auditor.record_cohort(dataset, _restore_filters(filters))
                continue

            # Pre-#58 rows carry no accounting, so they are replayed by the
            # original heuristic. It is wrong in the two ways above, and kept
            # only because the alternative — refusing to replay them — would
            # rebuild an EMPTY lineage from a log that plainly holds cohorts,
            # which is the more dangerous of the two errors.
            self._rehydrate_legacy(session, record)
        return len(self._sessions)

    @staticmethod
    def _rehydrate_legacy(session: Session, record: dict) -> None:
        status = record.get("status")
        rules = {f.get("rule") for f in (record.get("findings") or [])
                 if isinstance(f, dict)}
        # Budget: everything except a refusal decided from the REQUEST, which
        # never reached `observe`. An `error` row is charged, because the log
        # cannot say whether the exception preceded the engine and over-charging
        # is the safe direction.
        if status != "denied" or not (rules and rules <= _PRE_ENGINE_RULES):
            session.auditor.charge()
        if status in _RELEASED and isinstance(record.get("spec"), dict):
            cohort = _cohort_of(record["spec"])
            if cohort is not None:
                session.auditor.record_cohort(*cohort)


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
