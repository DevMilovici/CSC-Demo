"""SQLite persistence for what must survive a restart: accounts, email confirmations,
credentials and refresh tokens.

Short-lived state stays in memory in csc_server.py (access tokens, OTP codes, SADs, OAuth
transactions and codes, rate-limit counters): losing it on a restart only means signing in again.

Private keys and certificates stay as PEM files next to the database (pki.py); the credentials
table holds everything else about a credential. Tokens are stored as SHA-256 hashes, passwords and
PINs as the PBKDF2 hashes made by csc_server.hash_secret.

The schema is versioned with PRAGMA user_version: MIGRATIONS[i] upgrades version i to i + 1, and
runs automatically when the server starts. Never edit a migration that has shipped; append one.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path

MIGRATIONS = [
    # 1: accounts, email confirmations, credentials, refresh tokens
    """
    CREATE TABLE users (
        username      TEXT PRIMARY KEY,          -- lower-case email address ("alice" for the demo user)
        email         TEXT NOT NULL,
        given_name    TEXT NOT NULL,
        family_name   TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        verified      INTEGER NOT NULL DEFAULT 0,
        created_at    REAL NOT NULL
    );
    CREATE TABLE verifications (
        token_hash TEXT PRIMARY KEY,
        username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
        expires_at REAL NOT NULL,
        next_url   TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX verifications_username ON verifications(username);
    CREATE TABLE credentials (
        id          TEXT PRIMARY KEY,
        owner       TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
        description TEXT NOT NULL,
        policy_oid  TEXT,
        pin_hash    TEXT NOT NULL,
        scal        TEXT NOT NULL,
        expression  TEXT NOT NULL,
        multisign   INTEGER NOT NULL,
        enabled     INTEGER NOT NULL DEFAULT 1,
        failures    INTEGER NOT NULL DEFAULT 0,
        created_at  REAL NOT NULL
    );
    CREATE INDEX credentials_owner ON credentials(owner);
    CREATE TABLE refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
        expires_at REAL NOT NULL
    );
    """,
]
SCHEMA_VERSION = len(MIGRATIONS)


def token_hash(token: str) -> str:
    """Tokens are long random strings, so a plain SHA-256 is enough to store them safely."""
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # One connection shared by the server's event loop and its thread pool, guarded by a lock.
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")  # readers (admin.py) don't block the server
        self._migrate()

    def close(self) -> None:
        self.db.close()

    def _migrate(self) -> None:
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"{self.path} has schema version {version}, newer than this code "
                               f"({SCHEMA_VERSION}). Deploy the newer code, or restore a backup taken before.")
        for target in range(version + 1, SCHEMA_VERSION + 1):
            # One transaction per migration, including the version bump.
            self.db.executescript(f"BEGIN; {MIGRATIONS[target - 1]}; PRAGMA user_version = {target}; COMMIT;")

    def _one(self, sql: str, args=()) -> dict | None:
        with self.lock:
            row = self.db.execute(sql, args).fetchone()
        return dict(row) if row else None

    def _all(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def _write(self, sql: str, args=()) -> int:
        with self.lock, self.db:
            return self.db.execute(sql, args).rowcount

    # ------------------------------------------------------------------ users
    def user(self, username: str) -> dict | None:
        return self._one("SELECT * FROM users WHERE username = ?", (username,))

    def user_count(self) -> int:
        return self._one("SELECT count(*) AS n FROM users")["n"]

    def upsert_user(self, username: str, email: str, given_name: str, family_name: str,
                    password_hash: str, verified: bool) -> None:
        """Create or update an account in place (keeps its credentials)."""
        self._write("""
            INSERT INTO users (username, email, given_name, family_name, password_hash, verified, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET email = excluded.email, given_name = excluded.given_name,
                family_name = excluded.family_name, password_hash = excluded.password_hash,
                verified = excluded.verified""",
                    (username, email, given_name, family_name, password_hash, int(verified), time.time()))

    def create_unverified_user(self, username: str, email: str, given_name: str, family_name: str,
                               password_hash: str, verify_token: str, expires_at: float, next_url: str) -> None:
        """Sign-up: replace any older unconfirmed account for this address (its links stop working)."""
        with self.lock, self.db:
            self.db.execute("DELETE FROM users WHERE username = ? AND verified = 0", (username,))
            self.db.execute("""INSERT INTO users (username, email, given_name, family_name, password_hash,
                                                  verified, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)""",
                            (username, email, given_name, family_name, password_hash, time.time()))
            self.db.execute("INSERT INTO verifications (token_hash, username, expires_at, next_url) "
                            "VALUES (?, ?, ?, ?)", (token_hash(verify_token), username, expires_at, next_url))

    def delete_unverified_user(self, username: str) -> None:
        self._write("DELETE FROM users WHERE username = ? AND verified = 0", (username,))

    def delete_user(self, username: str) -> bool:
        """Delete an account with its credentials and tokens (the key files stay on disk)."""
        return self._write("DELETE FROM users WHERE username = ?", (username,)) > 0

    def confirm_email(self, token: str, now: float) -> tuple[str, str] | None:
        """Use a confirmation link once. Returns (username, next_url), or None if invalid or expired."""
        with self.lock, self.db:
            row = self.db.execute("SELECT username, expires_at, next_url FROM verifications WHERE token_hash = ?",
                                  (token_hash(token),)).fetchone()
            if row is None:
                return None
            self.db.execute("DELETE FROM verifications WHERE token_hash = ?", (token_hash(token),))
            if row["expires_at"] < now:
                return None
            self.db.execute("UPDATE users SET verified = 1 WHERE username = ?", (row["username"],))
            return row["username"], row["next_url"]

    def purge_expired(self, now: float) -> None:
        """Drop unconfirmed accounts whose links all expired, expired links, and expired refresh tokens."""
        with self.lock, self.db:
            self.db.execute("""DELETE FROM users WHERE verified = 0 AND NOT EXISTS (
                                   SELECT 1 FROM verifications v
                                   WHERE v.username = users.username AND v.expires_at >= ?)""", (now,))
            self.db.execute("DELETE FROM verifications WHERE expires_at < ?", (now,))
            self.db.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now,))

    # ------------------------------------------------------------ credentials
    def credential(self, credential_id: str) -> dict | None:
        return self._one("SELECT * FROM credentials WHERE id = ?", (credential_id,))

    def credentials_of(self, owner: str) -> list[dict]:
        return self._all("SELECT * FROM credentials WHERE owner = ? ORDER BY created_at, id", (owner,))

    def credential_count(self, owner: str) -> int:
        return self._one("SELECT count(*) AS n FROM credentials WHERE owner = ?", (owner,))["n"]

    def add_credential(self, credential_id: str, owner: str, description: str, policy_oid: str | None,
                       pin_hash: str, scal: str, expression: str, multisign: int) -> None:
        self._write("""INSERT INTO credentials (id, owner, description, policy_oid, pin_hash, scal, expression,
                                                multisign, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (credential_id, owner, description, policy_oid, pin_hash, scal, expression, multisign,
                     time.time()))

    def upsert_demo_credential(self, credential_id: str, owner: str, description: str, pin_hash: str,
                               scal: str, expression: str, multisign: int) -> None:
        """Built-in demo credentials are reset to their configured state (unlocked) on every start."""
        self._write("""
            INSERT INTO credentials (id, owner, description, policy_oid, pin_hash, scal, expression,
                                     multisign, created_at) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET description = excluded.description, pin_hash = excluded.pin_hash,
                scal = excluded.scal, expression = excluded.expression, multisign = excluded.multisign,
                enabled = 1, failures = 0""",
                    (credential_id, owner, description, pin_hash, scal, expression, multisign, time.time()))

    def record_auth_failure(self, credential_id: str, max_failures: int) -> bool:
        """Count a wrong PIN/code. Returns True if this failure locked the credential."""
        with self.lock, self.db:
            self.db.execute("""UPDATE credentials SET failures = failures + 1,
                                   enabled = CASE WHEN failures + 1 >= ? THEN 0 ELSE enabled END
                               WHERE id = ?""", (max_failures, credential_id))
            row = self.db.execute("SELECT enabled FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        return row is not None and not row["enabled"]

    def reset_failures(self, credential_id: str) -> None:
        self._write("UPDATE credentials SET failures = 0 WHERE id = ? AND failures > 0", (credential_id,))

    def unlock(self, credential_id: str) -> bool:
        return self._write("UPDATE credentials SET enabled = 1, failures = 0 WHERE id = ?", (credential_id,)) > 0

    # --------------------------------------------------------- refresh tokens
    def add_refresh_token(self, token: str, username: str, expires_at: float) -> None:
        self._write("INSERT INTO refresh_tokens (token_hash, username, expires_at) VALUES (?, ?, ?)",
                    (token_hash(token), username, expires_at))

    def refresh_token_user(self, token: str, now: float) -> str | None:
        row = self._one("SELECT username FROM refresh_tokens WHERE token_hash = ? AND expires_at >= ?",
                        (token_hash(token), now))
        return row["username"] if row else None

    def revoke_refresh_token(self, token: str) -> str | None:
        """Delete a refresh token. Returns its user, or None if it didn't exist."""
        with self.lock, self.db:
            row = self.db.execute("SELECT username FROM refresh_tokens WHERE token_hash = ?",
                                  (token_hash(token),)).fetchone()
            self.db.execute("DELETE FROM refresh_tokens WHERE token_hash = ?", (token_hash(token),))
        return row["username"] if row else None

    # ------------------------------------------------------------------ admin
    def users_overview(self) -> list[dict]:
        return self._all("""SELECT u.username, u.given_name, u.family_name, u.verified, u.created_at,
                                   count(c.id) AS credentials, coalesce(sum(c.enabled = 0), 0) AS locked
                            FROM users u LEFT JOIN credentials c ON c.owner = u.username
                            GROUP BY u.username ORDER BY u.created_at""")

    def backup_to(self, dest: str | Path) -> None:
        """Consistent copy of the live database (SQLite online backup API)."""
        target = sqlite3.connect(dest)
        try:
            with self.lock:
                self.db.backup(target)
        finally:
            target.close()
