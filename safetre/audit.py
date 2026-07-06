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
        self.con.commit()

    def _mac(self, body: dict) -> str:
        return hmac.new(self._key, _canonical(body).encode(), hashlib.sha256).hexdigest()

    def _head_locked(self) -> str:
        row = self.con.execute("SELECT mac FROM records ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def head(self) -> str:
        with self._lock:
            return self._head_locked()

    def append(self, *, user: str, request: str, spec, status: str,
               findings, output_shape) -> str:
        with self._lock:                       # head-read + insert must be atomic
            prev = self._head_locked()
            body = {
                "ts": time.time(), "user": user, "request": request,
                "spec": spec, "status": status, "findings": findings,
                "output_shape": output_shape, "prev_mac": prev,
            }
            mac = self._mac(body)
            self.con.execute(
                "INSERT INTO records (ts,user,request,spec,status,findings,output_shape,prev_mac,mac)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (body["ts"], user, request, _canonical(spec), status,
                 _canonical(findings), _canonical(output_shape), prev, mac),
            )
            self.con.commit()
            return mac

    def verify(self, expected_head: str | None = None) -> bool:
        """Recompute the keyed chain. If `expected_head` (an off-box anchor) is
        given, the recomputed head must also equal it."""
        prev = GENESIS
        with self._lock:
            rows = self.con.execute(
                "SELECT ts,user,request,spec,status,findings,output_shape,prev_mac,mac"
                " FROM records ORDER BY id"
            ).fetchall()
        for ts, user, request, spec, status, findings, shape, prev_mac, mac in rows:
            if prev_mac != prev:
                return False
            # A tamperer who can write the DB can corrupt a row into malformed
            # JSON or a non-string MAC. Reconstructing the body must therefore
            # fail CLOSED: any decode/type error means the row cannot be
            # authenticated, which is exactly a verification failure (P15) — not
            # an exception that 500s the /api/audit/verify endpoint.
            try:
                body = {
                    "ts": ts, "user": user, "request": request,
                    "spec": json.loads(spec), "status": status,
                    "findings": json.loads(findings), "output_shape": json.loads(shape),
                    "prev_mac": prev_mac,
                }
                if not isinstance(mac, str) or not hmac.compare_digest(self._mac(body), mac):
                    return False
            except (ValueError, TypeError):
                return False
            prev = mac
        if expected_head is not None and not hmac.compare_digest(prev, expected_head):
            return False
        return True
