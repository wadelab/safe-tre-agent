"""Per-user sessions — what makes the session auditor real.

Each authenticated user gets one SessionAuditor that persists across requests,
so the differencing / query-budget controls actually accumulate over a
conversation (the CLI used a fresh auditor per call).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from safetre.disclosure import SessionAuditor


@dataclass
class Session:
    auditor: SessionAuditor
    history: list = field(default_factory=list)


class SessionStore:
    def __init__(self):
        self._sessions: dict[str, Session] = {}

    def get(self, user: str) -> Session:
        if user not in self._sessions:
            self._sessions[user] = Session(SessionAuditor())
        return self._sessions[user]
