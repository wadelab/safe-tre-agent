"""Append-only, hash-chained audit log (tamper-evident).

Each record links to the previous via SHA-256, so any retroactive edit or
deletion breaks the chain and is detectable by `verify()`. Logs every request,
the validated spec, the decision, findings and the released shape — a Five Safes
requirement. In production the chain head is also mirrored off-box.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time

GENESIS = "0" * 64


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    def __init__(self, path: str = "audit.db"):
        # check_same_thread=False + a lock: FastAPI runs sync routes in a threadpool
        self.con = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, user TEXT, request TEXT, spec TEXT,
                status TEXT, findings TEXT, output_shape TEXT,
                prev_hash TEXT, hash TEXT
            )""")
        self.con.commit()

    def _head(self) -> str:
        row = self.con.execute("SELECT hash FROM records ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def append(self, *, user: str, request: str, spec, status: str,
               findings, output_shape) -> str:
        # serialise: head-read + insert must be atomic to keep the chain intact
        with self._lock:
            prev = self._head()
            body = {
                "ts": time.time(), "user": user, "request": request,
                "spec": spec, "status": status, "findings": findings,
                "output_shape": output_shape, "prev_hash": prev,
            }
            digest = hashlib.sha256(_canonical(body).encode()).hexdigest()
            self.con.execute(
                "INSERT INTO records (ts,user,request,spec,status,findings,output_shape,prev_hash,hash)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (body["ts"], user, request, _canonical(spec), status,
                 _canonical(findings), _canonical(output_shape), prev, digest),
            )
            self.con.commit()
            return digest

    def verify(self) -> bool:
        """Recompute the chain; return False if any record was tampered with."""
        prev = GENESIS
        with self._lock:
            rows = self.con.execute(
                "SELECT ts,user,request,spec,status,findings,output_shape,prev_hash,hash"
                " FROM records ORDER BY id"
            ).fetchall()
        for row in rows:
            ts, user, request, spec, status, findings, shape, prev_hash, h = row
            if prev_hash != prev:
                return False
            body = {
                "ts": ts, "user": user, "request": request,
                "spec": json.loads(spec), "status": status,
                "findings": json.loads(findings), "output_shape": json.loads(shape),
                "prev_hash": prev_hash,
            }
            if hashlib.sha256(_canonical(body).encode()).hexdigest() != h:
                return False
            prev = h
        return True
