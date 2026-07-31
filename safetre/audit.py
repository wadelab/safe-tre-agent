"""Append-only, HMAC-chained audit log (tamper-evident under a secret key).

A plain hash chain is NOT tamper-proof: anyone who can rewrite the database can
recompute every hash and pass verification. This log therefore chains records
with a keyed **HMAC-SHA256**. An attacker who rewrites the store but lacks the
key cannot forge a valid chain.

Two further requirements for real tamper-resistance (see docs/security.md):
  1. The key must live OFF the box that holds the log — e.g. provided via
     `SAFETRE_AUDIT_KEY` from a systemd `LoadCredential=`, never on disk.
  2. The chain head should be anchored off-box periodically; `verify(expected_head)`
     checks that the anchored head is still IN the chain.

**A chain cannot detect its own truncation.** Walking rows and checking that
each `prev_mac` matches the last MAC proves the rows present are consistent —
it says nothing about rows that are no longer there. Deleting the TAIL leaves a
perfectly valid chain from GENESIS, and hardening #59's verify-before-replay
gate therefore did not catch it: an attacker who released the first half of a
differencing pair, deleted that one row and waited for a restart got the second
half released, with `verify()` reporting the chain intact (round 10, #75).

Two answers, and only the second is a real control:

  * the HIGH-WATER MARK below — a sidecar file holding the head as of the last
    append, consulted by `verify()`. It lives on the same host, so an attacker
    who can write the database can usually write this too; what it does is turn
    a one-row DELETE into a two-file forgery, and make the DEFAULT deployment
    notice rather than accept it silently.
  * the off-box ANCHOR, which is the control that survives a host compromise
    and the reason `head()` is now reachable from the API: an operator cannot
    record a head they have no way to read.
"""

from __future__ import annotations

import fcntl
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


def _truthy_env(name: str) -> bool:
    """An override is an environment variable set to exactly `1`.

    Same shape as `SAFETRE_ALLOW_HOST_AUDIT_KEY` and
    `SAFETRE_ALLOW_UNVERIFIED_REHYDRATE`: a safety default that an operator can
    turn off has to be turned off deliberately, and an env var is harder to set
    by accident than a config key.
    """
    return os.environ.get(name) == "1"


class HostResidentAuditKey(RuntimeError):
    """Production asked for a tamper-evident log and got a key sitting next to
    it. Raised rather than warned: the chain's whole purpose is to survive a
    host compromise, and a compromise that finds both the log and the key can
    re-MAC a forged chain that `verify()` then accepts."""


class AuditDatabaseInUse(RuntimeError):
    """Another process already serves this audit database (hardening #81)."""


def claim_exclusive(path: str):
    """Take a process-lifetime exclusive claim on an audit database.

    **One application process per audit database, enforced rather than
    assumed.** `docs/security.md` states that the head-read and the insert
    "must be atomic" and prices the resulting lock contention as accepted —
    but the lock delivering that atomicity is a `threading.Lock` on the
    `AuditLog` object, which serialises threads inside one process and means
    nothing between two. Nothing anywhere checked, so `uvicorn --workers 2`,
    `WEB_CONCURRENCY`, or simply starting a second server on the same
    `SAFETRE_AUDIT_DB` was a supported-looking configuration that silently
    broke three controls at once (round 11, #81):

      * the CHAIN. Two writers read the same head and both append from it.
        Measured: 80 concurrent appends across two `AuditLog` objects, every
        request answered normally, no error raised to any caller, and
        `verify()` afterwards **False** — a log destroyed in ordinary
        operation and indistinguishable from tampering. Since #59 the next
        restart then refuses to boot on the unverifiable chain.
      * the SESSION STORE, which holds the query budget and the differencing
        lineage in memory. Two workers are two budgets, and a cohort recorded
        on one is invisible to the other, so the two halves of a differencing
        pair land on different workers and both release.
      * the RATE LIMITER, likewise per-process.

    An advisory `flock` on a sidecar is enough for the honest-operator case
    this is about, and the kernel releases it when the process dies, so a
    crash needs no cleanup and `scripts/restart_web.sh` (which waits for the
    old process to exit) is unaffected. It is taken by the APPLICATION at
    startup, not by `AuditLog.__init__`: the invariant is one *server* per
    database, and tests, the CLI and the harnesses legitimately construct
    several `AuditLog` objects over throwaway paths.

    Returns the open lock file, which the caller must keep referenced for the
    process lifetime — closing it drops the claim.
    """
    if path in (":memory:", ""):
        return None
    # Resolve first: the claim must be keyed on the DATABASE, not on how this
    # process spelled it. A relative path, an absolute one and a symlink to the
    # same file would otherwise take three different lock files and all three
    # proceed — which is the configuration this exists to refuse.
    lock_path = os.path.realpath(path) + ".lock"
    handle = open(lock_path, "a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.seek(0)
        holder = handle.read().strip() or "an unknown process"
        handle.close()
        raise AuditDatabaseInUse(
            f"{path} is already served by {holder}. One process per audit "
            "database: the HMAC chain's head-read and insert must be atomic, "
            "and the session budget and differencing lineage live in that "
            "process's memory. Run a single worker (no `--workers`, no "
            "WEB_CONCURRENCY), or give this instance its own SAFETRE_AUDIT_DB"
        ) from exc
    handle.seek(0)
    handle.truncate()
    handle.write(f"pid {os.getpid()}")
    handle.flush()
    return handle


def _load_key(db_path: str, require_external: bool = False) -> bytes:
    env = os.environ.get("SAFETRE_AUDIT_KEY")
    if env:
        return env.encode()
    if require_external and os.environ.get("SAFETRE_ALLOW_HOST_AUDIT_KEY") != "1":
        raise HostResidentAuditKey(
            f"SAFETRE_AUDIT_KEY is not set, so the audit chain would be signed "
            f"with a key generated beside the log at {db_path}.key — on the "
            f"same host, where a compromise that can rewrite the log can also "
            f"read the key and forge a chain that verifies. Refusing to start. "
            f"Supply the key from a secret this host does not otherwise hold "
            f"(see deploy/safetre-web.service), and anchor the chain head "
            f"off-box with SAFETRE_AUDIT_HEAD_ANCHOR so tampering stays "
            f"detectable even if the key is later compromised. "
            f"SAFETRE_ALLOW_HOST_AUDIT_KEY=1 overrides this for a "
            f"non-production deployment.")
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
    def __init__(self, path: str = "audit.db", key: bytes | None = None,
                 require_external_key: bool = False):
        """`require_external_key` refuses the dev fallback that generates a key
        beside the database. The web app passes it in production (hardening
        #65); the CLI and the tests do not, because a throwaway log with a
        throwaway key is exactly what they want."""
        self._key = key if key is not None else _load_key(path, require_external_key)
        self._path = path
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

    # --- the high-water mark ---------------------------------------------
    #
    # A single small file beside the database holding the head as of the last
    # append. It is not a secret (a MAC discloses nothing) and it is not the
    # off-box anchor; it exists so that removing rows from the DATABASE alone
    # stops verifying.

    def _mark_path(self) -> str | None:
        return None if self._path in (":memory:", "") else self._path + ".head"

    def _write_mark(self, head: str) -> None:
        path = self._mark_path()
        if path is None:
            return
        # A per-writer temp name (round 11 CI): a fixed `.tmp` is a shared
        # path, so two writers on one database raced — one renamed it and the
        # other's `os.replace` raised FileNotFoundError out of `append`. #81
        # refuses that configuration, but the mark must not be the thing that
        # detects it, and a crash mid-write must not leave a name a later
        # writer trips over.
        tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
        # fsync both the file and its directory: the rows are written under
        # `PRAGMA synchronous=FULL`, so without this a power cut can leave
        # durable rows beside a mark that never reached the platter, and a
        # zero-length mark reads as "no mark" — which is finding #82's
        # fail-open (round 11, #83).
        with open(tmp, "w") as fh:
            fh.write(head)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)          # atomic: never a half-written mark
        dir_fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    # A mark is 64 lowercase hex characters or it is not a mark. Anything else
    # is a verification FAILURE, never an exception: `verify` says the same of
    # a corrupt row, and the mark path had reintroduced exactly the behaviour
    # that rule exists to forbid — a non-UTF-8 sidecar raised
    # `UnicodeDecodeError` out of `/api/audit/verify` (round 11, #83).
    _MARK_MISSING = "missing"
    _MARK_INVALID = "invalid"

    def _read_mark(self) -> str:
        """The recorded high-water mark, `_MARK_MISSING`, or `_MARK_INVALID`.

        Absent and unreadable are DIFFERENT answers. Returning `None` for both
        meant `chmod 000` on the sidecar disabled the truncation check as
        effectively as deleting it, and deleting it was already too easy
        (#82).
        """
        path = self._mark_path()
        if path is None:
            return self._MARK_MISSING
        try:
            with open(path, "rb") as fh:
                raw = fh.read(256)
        except FileNotFoundError:
            return self._MARK_MISSING
        except OSError:
            return self._MARK_INVALID          # present and unreadable
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            return self._MARK_INVALID
        if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
            return self._MARK_INVALID
        return text

    def _head_locked(self) -> str:
        row = self.con.execute("SELECT mac FROM records ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def head(self) -> str:
        with self._lock:
            return self._head_locked()

    def append(self, *, user: str, request: str, spec, status: str,
               findings, output_shape, accounting: dict | None = None) -> str:
        """**`request` is stored verbatim and is UNTRUSTED CONTENT.** It is
        whatever the caller typed, up to 500 characters, and the chain proves
        only that it is the string that was submitted — not that a human
        composed it (hardening #50) and not that it is safe to render. Any
        future audit-log viewer that puts it on a page must escape it, and any
        tool that feeds it to a model must treat it as data rather than
        instruction: a stored prompt-injection payload is exactly the shape
        that fits here (round-9 V16, hardening #71). It is stored rather than
        sanitised on purpose — the log's job is to record what happened, and a
        cleaned-up record of a hostile request is a worse record.

        `accounting` is what the request actually cost the session and which
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
            # Fold the WAL back into the database file after every append
            # (round 10, #78). WAL keeps committed rows in `audit.db-wal` until
            # a checkpoint, so copying, restoring or backing up `audit.db`
            # alone — the classic SQLite mistake, and the exact scenario #65's
            # note describes — produced a log with ZERO rows that verified
            # happily. Measured: 5 rows live, 0 in the copy, `verify()` True.
            # This log is written once per request, so a checkpoint per append
            # is affordable and makes the file self-contained.
            self.con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._write_mark(mac)
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

        **The `request` field of every row returned here is untrusted content**
        — see `append`. Verifying the chain establishes that a row is authentic,
        which is a different claim from its contents being safe to render or to
        act on (hardening #71).
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

    def head_is_reachable(self) -> str:
        """The current head, for an operator to record off-box.

        Public because the anchor was unusable without it: the shipped unit
        told an operator to set `SAFETRE_AUDIT_HEAD_ANCHOR` to "the chain head
        from /api/audit/verify", and no route, script or command in the
        repository ever returned one (round 10, #75). A MAC discloses nothing
        about the rows it covers, so publishing it costs nothing.
        """
        return self.head()

    def verify(self, expected_head: str | None = None) -> bool:
        """Recompute the keyed chain, and check it has not been truncated.

        Three separate questions, and the original only asked the first:

        1. **Are the rows present consistent?** Each `prev_mac` must equal the
           previous row's MAC and every MAC must recompute.
        2. **Are any rows MISSING from the end?** A chain cannot answer this
           about itself — deleting the tail leaves a valid chain from GENESIS —
           so it is answered against the high-water mark written beside the
           database on every append. Same host, so not proof against an
           attacker who can write the directory; it turns a one-row DELETE into
           a two-file forgery, and makes the default deployment notice.

           **Absence of the mark is a failure, not a pass** (round 11, #82).
           The first version treated a missing mark as "no check to run", so
           `DELETE FROM records WHERE id > k; rm audit.db.head` — two
           operations, no key — restored the pre-#75 position, and a backup of
           `audit.db` alone left the mark behind, moving #78 one file over. A
           chain that has never been appended to since this check shipped
           genuinely has no mark; that case is the explicit
           `SAFETRE_ALLOW_UNMARKED_CHAIN=1`, and it is a migration step, not a
           posture.
        3. **Is this the chain the operator anchored?** `expected_head` must
           still appear IN the chain. It used to have to EQUAL the head, which
           made an anchor go stale on the very next append — including the
           app's own startup policy record — so the check was red for the whole
           life of every process after the first. An anchor names a point the
           chain must still contain; everything after it is growth, everything
           missing before it is tampering.

           **This check runs on every path.** The truncation branch used to
           `return` its own verdict, so a configured anchor was never consulted
           once the mark disagreed — which is precisely when it matters most
           (#82).
        """
        prev = GENESIS
        # The rows AND the mark are read under one acquisition. Reading the
        # mark after the recompute meant an append landing during a scan
        # advanced it past every MAC in the snapshot, so an intact chain
        # reported itself tampered — measured on a 200k-row chain, a 1.6 s
        # window, and `rehydrate` turns that into a refusal to boot (#84).
        with self._lock:
            rows = self.con.execute(
                "SELECT ts,user,request,spec,status,findings,output_shape,prev_mac,mac,"
                "accounting FROM records ORDER BY id"
            ).fetchall()
            mark = self._read_mark()
        seen_macs: list[str] = []
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
            seen_macs.append(mac)

        # (2) truncation, against the mark written on the last append.
        #
        # No early `return` anywhere in here: check (3) is the control that
        # survives a host compromise, and skipping it exactly when the mark
        # disagrees is skipping it exactly when it is needed (#82).
        if mark == self._MARK_INVALID:
            return False
        if mark == self._MARK_MISSING:
            # An empty chain has nothing to have lost. A non-empty one that
            # cannot show a mark is either pre-#75 or truncated, and the two
            # are indistinguishable from here, so it fails unless an operator
            # has said which it is.
            if seen_macs and not _truthy_env("SAFETRE_ALLOW_UNMARKED_CHAIN"):
                return False
        elif not any(hmac.compare_digest(m, mark) for m in seen_macs):
            # The mark names a MAC the chain no longer contains. Note there is
            # no GENESIS special case: `_write_mark` only ever writes a real
            # MAC, so a sidecar holding GENESIS is not a state any honest
            # deployment reaches — and treating it as "legitimately empty" let
            # a wipe of every row verify, anchor and all (#82).
            return False

        # (3) the off-box anchor: still present, not necessarily last
        if expected_head is not None and expected_head != GENESIS:
            if not any(hmac.compare_digest(m, expected_head) for m in seen_macs):
                return False
        return True
