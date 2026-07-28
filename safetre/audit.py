"""Append-only, HMAC-chained audit log (tamper-evident under a secret key).

A plain hash chain is NOT tamper-proof: anyone who can rewrite the database can
recompute every hash and pass verification. This log therefore chains records
with a keyed **HMAC-SHA256**. An attacker who rewrites the store but lacks the
key cannot forge a valid chain.

Two further requirements for real tamper-resistance (see docs/security.md):
  1. The key must live OFF the box that holds the log — e.g. provided via
     `SAFETRE_AUDIT_KEY` from a systemd `LoadCredential=`, never on disk.
  2. The chain head should be anchored off-box periodically; `verify(expected_head)`
     checks the recomputed head against that external anchor.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import warnings

GENESIS = "0" * 64


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _load_key(db_path: str) -> bytes:
    env = os.environ.get("SAFETRE_AUDIT_KEY")
    if env:
        return env.encode()
    # Dev fallback: a random key persisted beside the DB (0600). NOT tamper-proof
    # against a host compromise (key + log on the same box) — prod must set
    # SAFETRE_AUDIT_KEY from an off-box secret.
    if db_path in (":memory:", ""):
        return secrets.token_bytes(32)
    keyfile = db_path + ".key"
    if os.path.exists(keyfile):
        with open(keyfile, "rb") as fh:
            return fh.read()
    key = secrets.token_bytes(32)
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    warnings.warn(
        "SAFETRE_AUDIT_KEY not set; generated an on-disk dev key. For tamper-"
        "resistance set SAFETRE_AUDIT_KEY from an off-box secret and anchor the "
        "head off-box (see docs/security.md).", stacklevel=2)
    return key


class AuditLog:
    def __init__(self, path: str = "audit.db", key: bytes | None = None):
        self._key = key if key is not None else _load_key(path)
        self.con = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, user TEXT, request TEXT, spec TEXT,
                status TEXT, findings TEXT, output_shape TEXT,
                prev_mac TEXT, mac TEXT
            )""")
        # `accounting` (hardening #58) was added after the first chains were
        # written. It is added by migration and left NULL on existing rows, and
        # `_body` omits the key entirely when it is NULL — so every row written
        # before this column existed still MACs to exactly what it MACed then,
        # and an old chain keeps verifying. A column that changed the body of
        # historical rows would fail verification everywhere, which is the
        # constraint that shaped #55's answer too.
        cols = {row[1] for row in self.con.execute("PRAGMA table_info(records)")}
        if "accounting" not in cols:
            self.con.execute("ALTER TABLE records ADD COLUMN accounting TEXT")
        self.con.commit()

    def _mac(self, body: dict) -> str:
        return hmac.new(self._key, _canonical(body).encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _body(*, ts, user, request, spec, status, findings, output_shape,
              prev_mac, accounting) -> dict:
        """The MACed body. `accounting` is included only when present, so a
        pre-#58 row (NULL) reconstructs byte-identically to the body it was
        signed with."""
        body = {
            "ts": ts, "user": user, "request": request, "spec": spec,
            "status": status, "findings": findings,
            "output_shape": output_shape, "prev_mac": prev_mac,
        }
        if accounting is not None:
            body["accounting"] = accounting
        return body

    def _head_locked(self) -> str:
        row = self.con.execute("SELECT mac FROM records ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def head(self) -> str:
        with self._lock:
            return self._head_locked()

    def append(self, *, user: str, request: str, spec, status: str,
               findings, output_shape, accounting: dict | None = None) -> str:
        """`accounting` is what the request actually cost the session and which
        cohorts it actually released over — written by the code that did the
        live accounting, so a restart replays a record rather than re-deriving
        one (hardening #58). It is inside the MAC: an attacker who can edit the
        budget a row claims to have spent could reset a session's accumulation
        controls, so it needs the same tamper-evidence as the status."""
        with self._lock:                       # head-read + insert must be atomic
            prev = self._head_locked()
            body = self._body(
                ts=time.time(), user=user, request=request, spec=spec,
                status=status, findings=findings, output_shape=output_shape,
                prev_mac=prev, accounting=accounting)
            mac = self._mac(body)
            self.con.execute(
                "INSERT INTO records (ts,user,request,spec,status,findings,output_shape,"
                "prev_mac,mac,accounting) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (body["ts"], user, request, _canonical(spec), status,
                 _canonical(findings), _canonical(output_shape), prev, mac,
                 None if accounting is None else _canonical(accounting)),
            )
            self.con.commit()
            return mac

    def since(self, cutoff: float) -> list[dict]:
        """Every record written at or after `cutoff`, oldest first.

        The log is the only durable record of what a session has already been
        told, so it is also the only thing a restart can rebuild that session
        from (hardening #49). **This method does not authenticate anything.**

        It used to say that a tampered row "can only ever make the rebuilt
        session more restrictive or drop a cohort" — but dropping a cohort *is*
        the unsafe direction: it is precisely the differencing lineage, and
        deleting a row needs write access to the database, not a forged MAC.
        Round 9 measured it: delete the record of the first half of a
        differencing pair, restart, and the second half is released, with
        `verify()` reporting the broken chain to nobody. The tamper-evidence
        existed and was never consulted where it mattered.

        So the rule is now on the caller and enforced there: `SessionStore.
        rehydrate` verifies the chain before replaying it and fails closed
        (hardening #59). Any future caller that rebuilds a control from these
        rows owes the same gate.
        """
        with self._lock:
            rows = self.con.execute(
                "SELECT ts,user,request,spec,status,findings,accounting FROM records "
                "WHERE ts >= ? ORDER BY id", (cutoff,)).fetchall()
        out = []
        for ts, user, request, spec, status, findings, accounting in rows:
            try:
                out.append({"ts": ts, "user": user, "request": request,
                            "spec": json.loads(spec), "status": status,
                            "findings": json.loads(findings),
                            "accounting": (None if accounting is None
                                           else json.loads(accounting))})
            except (ValueError, TypeError):
                continue                      # a corrupt row is `verify`'s problem
        return out

    def verify(self, expected_head: str | None = None) -> bool:
        """Recompute the keyed chain. If `expected_head` (an off-box anchor) is
        given, the recomputed head must also equal it."""
        prev = GENESIS
        with self._lock:
            rows = self.con.execute(
                "SELECT ts,user,request,spec,status,findings,output_shape,prev_mac,mac,"
                "accounting FROM records ORDER BY id"
            ).fetchall()
        for (ts, user, request, spec, status, findings, shape, prev_mac, mac,
             accounting) in rows:
            if prev_mac != prev:
                return False
            # A tamperer who can write the DB can corrupt a row into malformed
            # JSON or a non-string MAC. Reconstructing the body must therefore
            # fail CLOSED: any decode/type error means the row cannot be
            # authenticated, which is exactly a verification failure (P15) — not
            # an exception that 500s the /api/audit/verify endpoint.
            try:
                body = self._body(
                    ts=ts, user=user, request=request, spec=json.loads(spec),
                    status=status, findings=json.loads(findings),
                    output_shape=json.loads(shape), prev_mac=prev_mac,
                    accounting=(None if accounting is None
                                else json.loads(accounting)))
                if not isinstance(mac, str) or not hmac.compare_digest(self._mac(body), mac):
                    return False
            except (ValueError, TypeError):
                return False
            prev = mac
        if expected_head is not None and not hmac.compare_digest(prev, expected_head):
            return False
        return True
