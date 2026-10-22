"""SQLite store for orgs, tokens, runs, findings and the audit log."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(org_id, name)
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    project_id TEXT NOT NULL REFERENCES projects(id),
    run_id TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    pack_path TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(org_id, run_id, manifest_sha256)
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs(id),
    project_id TEXT NOT NULL REFERENCES projects(id),
    scenario_id TEXT NOT NULL,
    title TEXT NOT NULL,
    owasp TEXT NOT NULL,
    severity TEXT,
    status TEXT NOT NULL,
    assignee TEXT,
    due_at TEXT,
    accepted_risk_reason TEXT,
    created_from_run_id TEXT NOT NULL,
    latest_run_id TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_events (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_open ON findings(org_id, project_id, scenario_id, status);
"""

_local = threading.local()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = getattr(_local, "conn", None)
        owned = conn is None
        if owned:
            conn = self.connect()
            _local.conn = conn
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if owned:
                conn.close()
                _local.conn = None

    def execute(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self.tx() as conn:
            return conn.execute(sql, args)

    def query(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self.tx() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def one(self, sql: str, args: tuple = ()) -> dict[str, Any] | None:
        rows = self.query(sql, args)
        return rows[0] if rows else None
