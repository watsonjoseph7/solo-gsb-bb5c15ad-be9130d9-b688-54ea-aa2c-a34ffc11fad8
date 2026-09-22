"""API-key generation, hashing and persistence.

A presented key has the shape ``<key_id>.<secret>``. Only the SHA-256
hex digest of the presented key is stored, so a database disclosure never
reveals usable credentials. Rows are looked up by the indexed ``key_id``
column; the stored digest is then compared in constant time.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timezone

from .db import connect, immediate_transaction

# "*" in the scope list grants access to every dataset.
WILDCARD_SCOPE = "*"


class ApiKeyIdExists(Exception):
    """A key with the requested key_id already exists."""


def new_key_id() -> str:
    return "ak_" + secrets.token_hex(12)


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_key(key_id: str, secret: str) -> str:
    """Hash the full presented credential (id and secret) with SHA-256."""
    return hashlib.sha256(f"{key_id}.{secret}".encode("utf-8")).hexdigest()


def normalize_scope(dataset_ids: list[str]) -> list[str]:
    """De-duplicate (keeping a stable order) and return the stored scope."""
    if WILDCARD_SCOPE in dataset_ids:
        return [WILDCARD_SCOPE]
    return sorted(set(dataset_ids))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_api_key(
    *,
    name: str,
    dataset_ids: list[str],
    expires_at: datetime,
    key_id: str | None = None,
) -> tuple[str, str, list[str]]:
    """Insert a new key inside an IMMEDIATE transaction.

    Returns ``(key_id, plaintext_secret, scope)``. The plaintext is only
    available from this return value. Raises :class:`ApiKeyIdExists` when a
    caller-supplied ``key_id`` already exists (a random id collision, which is
    astronomically unlikely, is retried with fresh randomness).
    """
    scope = normalize_scope(dataset_ids)
    expires_text = expires_at.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )

    # Retry a handful of times so an (astronomically unlikely) collision on a
    # generated id or hash cannot surface to the caller.
    for _ in range(3):
        chosen_id = key_id or new_key_id()
        secret = new_secret()
        try:
            with immediate_transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO api_keys (
                        key_id, name, key_hash, scope_json, expires_at, revoked
                    ) VALUES (?, ?, ?, ?, ?, 0)
                    """,
                    (
                        chosen_id,
                        name,
                        hash_key(chosen_id, secret),
                        json.dumps(scope),
                        expires_text,
                    ),
                )
            return chosen_id, secret, scope
        except sqlite3.IntegrityError:
            if key_id is not None:
                raise ApiKeyIdExists(chosen_id)
    raise ApiKeyIdExists("failed to allocate a unique random key id")


def revoke_api_key(key_id: str) -> bool:
    """Mark a key revoked; returns False when no such key exists."""
    with immediate_transaction() as conn:
        cur = conn.execute(
            "UPDATE api_keys SET revoked = 1 WHERE key_id = ? AND revoked = 0",
            (key_id,),
        )
        return cur.rowcount > 0


def lookup_api_key(
    presented_key: str,
) -> tuple[sqlite3.Row | None, str]:
    """Validate a presented credential's shape and look it up.

    Returns ``(row_or_None, computed_hash)``. When the shape is invalid or
    the key id is unknown, the row is ``None`` and the hash (of a
    server-side dummy value when no id was extractable) is returned so the
    caller can always perform a constant-time comparison.
    """
    key_id, sep, secret = presented_key.partition(".")
    if not sep or not key_id or not secret:
        return None, hashlib.sha256(b"invalid").hexdigest()

    computed_hash = hash_key(key_id, secret)
    # A short-lived read connection is enough; WAL keeps this concurrent
    # with writers creating/revoking keys.
    conn_ro = connect()
    try:
        row = conn_ro.execute(
            "SELECT * FROM api_keys WHERE key_id = ?",
            (key_id,),
        ).fetchone()
    finally:
        conn_ro.close()
    return row, computed_hash


def stored_hash_matches(row: sqlite3.Row, computed_hash: str) -> bool:
    return hmac.compare_digest(row["key_hash"], computed_hash)


def _parse_expiry(expires_at: str) -> datetime:
    # Keys are written with microsecond precision, but tolerate rows
    # produced without a fractional-second component.
    try:
        moment = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        moment = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ")
    return moment.replace(tzinfo=timezone.utc)


def is_active(row: sqlite3.Row, *, now: datetime | None = None) -> bool:
    if row["revoked"]:
        return False
    expires_at = row["expires_at"]
    if expires_at is None:
        return True
    moment = now or _now()
    return moment < _parse_expiry(expires_at)


def scope_of(row: sqlite3.Row) -> list[str]:
    return json.loads(row["scope_json"])


def scope_allows(scope: list[str], dataset_id: str) -> bool:
    return WILDCARD_SCOPE in scope or dataset_id in scope
