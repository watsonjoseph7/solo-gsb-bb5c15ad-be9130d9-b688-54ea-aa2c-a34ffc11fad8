"""Server-side key management.

The HMAC key used for deterministic noise comes from the ``DP_SERVER_KEY``
environment variable. When it is not provided, a random 32-byte key is
generated once and persisted (mode 0600) next to the database so that
restarts keep producing identical noise. Volatile storage (e.g. an
ephemeral container without a mounted volume) means the key rotates on
restart, so production deployments should set ``DP_SERVER_KEY`` explicitly.

The administrator API key (``DP_ADMIN_API_KEY``) used to create and
revoke data-plane API keys follows the same fallback: unset, a random key
is generated once and persisted (mode 0600) as ``admin_api_key`` next
to the database and printed once in the startup logs.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from .config import settings


def _resolve_or_create_secret(
    env_value: str, filename: str, nbytes: int = 32
) -> bytes:
    """Return an env-provided secret or load/create a persisted random one."""
    if env_value:
        return env_value.encode("utf-8")

    key_path = Path(settings.database_path).with_name(filename)
    if key_path.exists():
        return key_path.read_bytes()

    key = secrets.token_bytes(nbytes)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process/worker generated the key first.
        return key_path.read_bytes()
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def resolve_server_key() -> bytes:
    return _resolve_or_create_secret(settings.server_key, "server.key")


def resolve_admin_key() -> str:
    """Return the bootstrap administrator API key, generating one if unset."""
    if settings.admin_api_key:
        return settings.admin_api_key

    key_path = Path(settings.database_path).with_name("admin_api_key")
    if key_path.exists():
        return key_path.read_text(encoding="utf-8")

    key = "ak_admin_" + secrets.token_urlsafe(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process/worker generated the key first.
        return key_path.read_text(encoding="utf-8")
    try:
        os.write(fd, key.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return key
