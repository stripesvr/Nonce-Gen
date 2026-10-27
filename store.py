from __future__ import annotations

import base64
import secrets
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    nonce       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    guild_id    INTEGER,
    channel_id  INTEGER,
    package_id  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_nonces_user ON nonces(user_id, used_at);
CREATE INDEX IF NOT EXISTS idx_nonces_exp  ON nonces(expires_at);

CREATE TABLE IF NOT EXISTS verdicts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce       TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    package_id  TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    message     TEXT NOT NULL,
    claims      TEXT,
    created_at  INTEGER NOT NULL
);
"""


def new_nonce(nbytes: int = 16) -> str:
    """16 random bytes -> 22 char base64url, no padding. Inside Meta's 22..172 window."""
    raw = secrets.token_bytes(nbytes)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class Store:
    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA)
        self._db.commit()

    def issue_nonce(
        self,
        *,
        user_id: int,
        guild_id: int | None,
        channel_id: int | None,
        package_id: str,
        ttl: int = 900,
    ) -> dict:
        nonce = new_nonce()
        now = int(time.time())
        row = (nonce, user_id, guild_id, channel_id, package_id, now, now + ttl)
        with self._lock:
            self._db.execute(
                "INSERT INTO nonces (nonce, user_id, guild_id, channel_id, package_id, created_at, expires_at) "
                "VALUES (?,?,?,?,?,?,?)",
                row,
            )
            self._db.commit()
        return {
            "nonce": nonce,
            "user_id": user_id,
            "guild_id": guild_id,
            "channel_id": channel_id,
            "package_id": package_id,
            "created_at": now,
            "expires_at": now + ttl,
        }

    def lookup(self, nonce: str) -> dict | None:
        now = int(time.time())
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM nonces WHERE nonce = ? AND used_at IS NULL AND expires_at > ?",
                (nonce, now),
            ).fetchone()
        return dict(row) if row else None

    def latest_open(self, user_id: int) -> dict | None:
        now = int(time.time())
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM nonces WHERE user_id = ? AND used_at IS NULL AND expires_at > ? "
                "ORDER BY created_at DESC LIMIT 1",
                (user_id, now),
            ).fetchone()
        return dict(row) if row else None

    def burn(self, nonce: str) -> bool:
        """Atomic single-use. Rowcount 0 means already spent or expired."""
        now = int(time.time())
        with self._lock:
            cur = self._db.execute(
                "UPDATE nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL AND expires_at > ?",
                (now, nonce, now),
            )
            self._db.commit()
        return cur.rowcount == 1

    def record(
        self,
        *,
        nonce: str,
        user_id: int,
        package_id: str,
        ok: bool,
        message: str,
        claims_json: str | None = None,
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO verdicts (nonce, user_id, package_id, ok, message, claims, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (nonce, user_id, package_id, 1 if ok else 0, message, claims_json, int(time.time())),
            )
            self._db.commit()

    def last_verdict(self, user_id: int) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM verdicts WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (user_id,),
            ).fetchone()
        return dict(row) if row else None

    def purge(self, keep_seconds: int = 86400) -> None:
        cutoff = int(time.time()) - keep_seconds
        with self._lock:
            self._db.execute("DELETE FROM nonces WHERE expires_at < ?", (cutoff,))
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()
