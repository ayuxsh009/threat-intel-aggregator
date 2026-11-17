"""SQLite persistence for users, settings, scan history and analyst verdicts.

SQLite with WAL journaling handles several browser sessions writing at once,
which the old shared JSON file could not.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    username   TEXT,
    kind       TEXT,
    label      TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    username   TEXT,
    ioc        TEXT,
    type       TEXT,
    risk       TEXT,
    timestamp  TEXT,
    data       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_scans_session ON scans(session_id);
CREATE INDEX IF NOT EXISTS ix_scans_user ON scans(username);
CREATE INDEX IF NOT EXISTS ix_scans_ioc ON scans(ioc);
CREATE TABLE IF NOT EXISTS verdicts (
    ioc        TEXT PRIMARY KEY,
    type       TEXT,
    verdict    TEXT NOT NULL CHECK (verdict IN ('malicious', 'benign')),
    note       TEXT,
    username   TEXT,
    updated_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._tx() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)

    # -- plumbing -------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def _tx(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # -- users ----------------------------------------------------------
    def user_count(self) -> int:
        with self._tx() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def admin_count(self) -> int:
        with self._tx() as c:
            return c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]

    def get_user(self, username: str) -> dict | None:
        with self._tx() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self._tx() as c:
            rows = c.execute(
                "SELECT username, role, created_at FROM users ORDER BY role, username"
            ).fetchall()
        return [dict(r) for r in rows]

    def add_user(self, username: str, password_hash: str, role: str = "analyst") -> None:
        try:
            with self._tx() as c:
                c.execute(
                    "INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)",
                    (username, password_hash, role, _now()),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"User '{username}' already exists.") from exc

    def set_password_hash(self, username: str, password_hash: str) -> None:
        with self._tx() as c:
            c.execute("UPDATE users SET password_hash=? WHERE username=?", (password_hash, username))

    def set_role(self, username: str, role: str) -> None:
        with self._tx() as c:
            c.execute("UPDATE users SET role=? WHERE username=?", (role, username))

    def delete_user(self, username: str) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM users WHERE username=?", (username,))

    # -- settings -------------------------------------------------------
    def get_setting(self, key: str, default: str = "") -> str:
        with self._tx() as c:
            row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row and row[0] is not None else default

    def set_setting(self, key: str, value: str) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO settings(key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # -- scan sessions --------------------------------------------------
    def create_session(self, username: str, kind: str, label: str = "", created_at: str | None = None) -> str:
        sid = uuid.uuid4().hex[:12]
        with self._tx() as c:
            c.execute(
                "INSERT INTO sessions(id, username, kind, label, created_at) VALUES (?,?,?,?,?)",
                (sid, username, kind, label, created_at or _now()),
            )
        return sid

    def find_session(self, username: str, kind: str, label: str) -> str | None:
        with self._tx() as c:
            row = c.execute(
                "SELECT id FROM sessions WHERE username=? AND kind=? AND label=? ORDER BY created_at DESC LIMIT 1",
                (username, kind, label),
            ).fetchone()
        return row[0] if row else None

    def add_scan(self, session_id: str, username: str, result: dict) -> None:
        self.add_scans(session_id, username, [result])

    def add_scans(self, session_id: str, username: str, results: list[dict]) -> None:
        with self._tx() as c:
            c.executemany(
                "INSERT INTO scans(session_id, username, ioc, type, risk, timestamp, data) "
                "VALUES (?,?,?,?,?,?,?)",
                [
                    (session_id, username, r.get("ioc"), r.get("type"), r.get("risk"),
                     r.get("timestamp"), json.dumps(r, default=str))
                    for r in results
                ],
            )

    def list_sessions(self, username: str | None = None) -> list[dict]:
        """Sessions newest first, with per-risk counts. ``username=None`` = all users."""
        sql = """
            SELECT s.id, s.username, s.kind, s.label, s.created_at,
                   COUNT(sc.id) AS total,
                   SUM(sc.risk='High') AS high, SUM(sc.risk='Medium') AS medium,
                   SUM(sc.risk='Low') AS low, SUM(sc.risk='Legitimate') AS legitimate,
                   SUM(sc.risk='Unknown') AS unknown
            FROM sessions s JOIN scans sc ON sc.session_id = s.id
            WHERE (? IS NULL OR s.username = ?)
            GROUP BY s.id
            ORDER BY s.created_at DESC, s.rowid DESC
        """
        with self._tx() as c:
            rows = c.execute(sql, (username, username)).fetchall()
        return [dict(r) for r in rows]

    def get_session(self, session_id: str) -> dict | None:
        with self._tx() as c:
            row = c.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def session_results(self, session_id: str) -> list[dict]:
        with self._tx() as c:
            rows = c.execute(
                "SELECT data FROM scans WHERE session_id=? ORDER BY id", (session_id,)
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def scans(self, username: str | None = None) -> list[dict]:
        with self._tx() as c:
            rows = c.execute(
                "SELECT data FROM scans WHERE (? IS NULL OR username=?) ORDER BY id",
                (username, username),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def delete_session(self, session_id: str) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    def clear_history(self, username: str | None = None) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM sessions WHERE (? IS NULL OR username=?)", (username, username))

    # -- local intelligence ---------------------------------------------
    def ioc_history(self, ioc: str, limit: int = 50) -> list[dict]:
        """Earlier scans of one indicator across the workspace, newest first."""
        with self._tx() as c:
            rows = c.execute(
                "SELECT sc.session_id, s.label, s.created_at, sc.data FROM scans sc "
                "JOIN sessions s ON s.id = sc.session_id WHERE sc.ioc=? ORDER BY sc.id DESC LIMIT ?",
                (ioc, limit),
            ).fetchall()
        return [{"session_id": r[0], "label": r[1], "created_at": r[2], "result": json.loads(r[3])} for r in rows]

    # -- analyst verdicts -----------------------------------------------
    def set_verdict(self, ioc: str, verdict: str, *, ioc_type: str = "", note: str = "", username: str = "") -> None:
        if verdict not in ("malicious", "benign"):
            raise ValueError("verdict must be 'malicious' or 'benign'")
        with self._tx() as c:
            c.execute(
                "INSERT INTO verdicts(ioc, type, verdict, note, username, updated_at) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(ioc) DO UPDATE SET type=excluded.type, verdict=excluded.verdict, "
                "note=excluded.note, username=excluded.username, updated_at=excluded.updated_at",
                (ioc, ioc_type, verdict, note.strip(), username, _now()),
            )

    def get_verdict(self, ioc: str) -> dict | None:
        with self._tx() as c:
            row = c.execute("SELECT * FROM verdicts WHERE ioc=?", (ioc,)).fetchone()
        return dict(row) if row else None

    def list_verdicts(self, verdict: str | None = None) -> list[dict]:
        with self._tx() as c:
            rows = c.execute(
                "SELECT * FROM verdicts WHERE (? IS NULL OR verdict=?) ORDER BY updated_at DESC",
                (verdict, verdict),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_verdict(self, ioc: str) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM verdicts WHERE ioc=?", (ioc,))
