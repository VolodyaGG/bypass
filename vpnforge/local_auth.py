"""Single-account authentication for the local control panel."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

SESSION_COOKIE = "bypass_session"
SESSION_SECONDS = 7 * 24 * 60 * 60
MIN_PASSWORD_LENGTH = 8


def _password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**17, r=8, p=1, maxmem=160 * 1024**2
    )


def _session_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class LocalAuth:
    def __init__(self, directory: Path) -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        self.path = directory / "auth.sqlite3"
        os.close(os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600))
        self.path.chmod(0o600)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS account (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    profile TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash BLOB PRIMARY KEY,
                    expires_at INTEGER NOT NULL
                );
            """)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path)) as db, db:
            yield db

    def configured(self) -> bool:
        with self._connect() as db:
            return db.execute("SELECT 1 FROM account WHERE id = 1").fetchone() is not None

    def create_account(self, profile: str, password: str) -> str | None:
        salt = secrets.token_bytes(16)
        digest = _password_hash(password, salt)
        with self._connect() as db:
            inserted = db.execute(
                "INSERT OR IGNORE INTO account VALUES (1, ?, ?, ?)", (profile, salt, digest)
            )
            if inserted.rowcount != 1:
                return None
            return self._new_session(db)

    def sign_in(self, profile: str, password: str) -> str | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT profile, salt, password_hash FROM account WHERE id = 1"
            ).fetchone()
            if row is None:
                return None
            saved_profile, salt, digest = row
            password_matches = hmac.compare_digest(_password_hash(password, salt), digest)
            if not password_matches or profile.casefold() != saved_profile.casefold():
                return None
            return self._new_session(db)

    def _new_session(self, db: sqlite3.Connection) -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        db.execute(
            "INSERT INTO sessions VALUES (?, ?)", (_session_hash(token), now + SESSION_SECONDS)
        )
        return token

    def profile_for(self, token: str) -> str | None:
        if len(token) != 43:
            return None
        with self._connect() as db:
            row = db.execute(
                """SELECT account.profile FROM account
                   WHERE account.id = 1 AND EXISTS (
                       SELECT 1 FROM sessions WHERE token_hash = ? AND expires_at > ?
                   )""",
                (_session_hash(token), int(time.time())),
            ).fetchone()
            return str(row[0]) if row is not None else None

    def sign_out(self, token: str) -> None:
        if len(token) == 43:
            with self._connect() as db:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (_session_hash(token),))
