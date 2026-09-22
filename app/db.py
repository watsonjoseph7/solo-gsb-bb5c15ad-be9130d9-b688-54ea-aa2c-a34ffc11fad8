"""SQLite persistence and schema management."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS budgets (
    dataset_id TEXT PRIMARY KEY,
    total      REAL NOT NULL,
    used       REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS releases (
    id              TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    dataset_id      TEXT NOT NULL,
    query_id        TEXT NOT NULL,
    epsilon         REAL NOT NULL,
    sensitivity     REAL NOT NULL,
    true_value      REAL NOT NULL,
    noise           REAL NOT NULL,
    released_value  REAL NOT NULL,
    budget_used     REAL NOT NULL,
    budget_remaining REAL NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_releases_dataset ON releases(dataset_id);

CREATE TABLE IF NOT EXISTS transfers (
    id               TEXT PRIMARY KEY,
    source_dataset   TEXT NOT NULL,
    target_dataset   TEXT NOT NULL,
    epsilon          REAL NOT NULL,
    source_used      REAL NOT NULL,
    source_remaining REAL NOT NULL,
    target_used      REAL NOT NULL,
    target_remaining REAL NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_transfers_source ON transfers(source_dataset);
CREATE INDEX IF NOT EXISTS idx_transfers_target ON transfers(target_dataset);

-- API keys authenticate callers. Only the SHA-256 hash of the secret is
-- stored; the plaintext is returned exactly once at creation.
CREATE TABLE IF NOT EXISTS api_keys (
    key_id       TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,
    scope_json    TEXT NOT NULL DEFAULT '[]',
    expires_at    TEXT,
    revoked       INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(
        settings.database_path,
        timeout=10.0,
        isolation_level=None,  # autocommit; transactions are managed explicitly
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    # WAL allows concurrent readers while a writer holds the lock.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def immediate_transaction() -> Iterator[sqlite3.Connection]:
    """Open an IMMEDIATE write transaction.

    Acquires SQLite's reserved lock up-front, so concurrent requests racing
    for the last slice of a budget serialize: exactly one can commit a
    deduction, the others see the updated balance and fail with 402.
    """
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
