"""API keys: generation, hashing and storage.

Key format:  agw_<prefix>_<secret>
  - prefix: 8 hex chars, stored in plain text. Used to look the key up and to
    identify it in logs and admin tools without exposing the secret.
  - secret: 32 random bytes, URL-safe base64. Never stored.

Only a SHA-256 hash of the full key is stored. A slow password hash (bcrypt,
argon2) is not needed: the secret has 256 bits of entropy, so it cannot be
brute-forced from the hash, and a slow hash would add latency to every request.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

KEY_TAG = "agw"
KNOWN_SCOPES = {"exec:run", "exec:read", "admin"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY,
    prefix       TEXT NOT NULL UNIQUE,
    key_hash     TEXT NOT NULL,
    name         TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    revoked_at   TEXT,
    last_used_at TEXT
);
"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def parse_key(raw_key: str) -> str | None:
    """Return the prefix of a well-formed key, or None."""
    parts = raw_key.split("_", 2)
    if len(parts) != 3:
        return None
    tag, prefix, secret = parts
    if tag != KEY_TAG or len(prefix) != 8 or not secret:
        return None
    if any(c not in "0123456789abcdef" for c in prefix):
        return None
    return prefix


@dataclass(frozen=True)
class ApiKey:
    prefix: str
    name: str
    scopes: frozenset[str]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "admin" in self.scopes


class InvalidScopeError(ValueError):
    pass


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _row_to_key(row: sqlite3.Row) -> ApiKey:
    return ApiKey(
        prefix=row["prefix"],
        name=row["name"],
        scopes=frozenset(row["scopes"].split()),
        created_at=_dt(row["created_at"]),
        expires_at=_dt(row["expires_at"]),
        revoked_at=_dt(row["revoked_at"]),
        last_used_at=_dt(row["last_used_at"]),
    )


class KeyStore:
    """SQLite-backed key store. Opens a short-lived connection per call."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        with closing(self._connect()) as conn, conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def create(self, name: str, scopes: set[str], expires_in_days: int | None = None) -> tuple[str, ApiKey]:
        """Create a key. Returns (raw_key, record). The raw key is shown once only."""
        unknown = set(scopes) - KNOWN_SCOPES
        if unknown:
            raise InvalidScopeError(f"unknown scope(s): {', '.join(sorted(unknown))}")
        if not scopes:
            raise InvalidScopeError("at least one scope is required")

        now = _now()
        expires = now + timedelta(days=expires_in_days) if expires_in_days else None
        with closing(self._connect()) as conn, conn:
            while True:
                prefix = secrets.token_hex(4)
                raw_key = f"{KEY_TAG}_{prefix}_{secrets.token_urlsafe(32)}"
                try:
                    conn.execute(
                        "INSERT INTO api_keys (prefix, key_hash, name, scopes, created_at, expires_at)"
                        " VALUES (?, ?, ?, ?, ?, ?)",
                        (prefix, hash_key(raw_key), name, " ".join(sorted(scopes)), now.isoformat(),
                         expires.isoformat() if expires else None),
                    )
                    break
                except sqlite3.IntegrityError:
                    continue  # prefix collision: try again
        return raw_key, self.get(prefix)

    def get(self, prefix: str) -> ApiKey | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE prefix = ?", (prefix,)).fetchone()
        return _row_to_key(row) if row else None

    def list(self) -> list[ApiKey]:
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at").fetchall()
        return [_row_to_key(r) for r in rows]

    def revoke(self, prefix: str) -> bool:
        with closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE prefix = ? AND revoked_at IS NULL",
                (_now().isoformat(), prefix),
            )
        return cur.rowcount == 1

    def verify(self, raw_key: str) -> tuple[ApiKey | None, str]:
        """Check a presented key. Returns (key, reason); key is None on failure.

        The reason is for the audit log only. Clients always get the same error,
        so they cannot tell a wrong secret from a revoked or unknown key.
        """
        prefix = parse_key(raw_key)
        if prefix is None:
            return None, "malformed"
        with closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT * FROM api_keys WHERE prefix = ?", (prefix,)).fetchone()
            if row is None:
                return None, "unknown_prefix"
            if not hmac.compare_digest(row["key_hash"], hash_key(raw_key)):
                return None, "bad_secret"
            key = _row_to_key(row)
            now = _now()
            if key.revoked_at is not None:
                return None, "revoked"
            if key.expires_at is not None and key.expires_at <= now:
                return None, "expired"
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE prefix = ?", (now.isoformat(), prefix))
        return key, "ok"
