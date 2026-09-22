"""API-key authentication and authorization.

Every route except the health and docs surface must present an ``X-API-Key``
header. Keys are either:

* the bootstrap **administrator** key (``DP_ADMIN_API_KEY``), which may
  manage keys and access every dataset; or
* a data-plane key stored (hashed) in the database, whose scope lists the
  dataset ids it may touch (``"*"`` = all datasets).

Verification uses constant-time comparisons and distinguishes "no/invalid
credential" (401) from "authenticated but outside scope" (403).
"""
from __future__ import annotations

import hmac

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from . import api_keys

API_KEY_HEADER = "X-API-Key"

# Served without credentials.
_PUBLIC_PATHS = frozenset({"/health", "/docs", "/openapi.json"})


class AuthError(Exception):
    def __init__(self, status_code: int, code: str, detail: str) -> None:
        self.status_code = status_code
        self.code = code
        self.detail = detail


class Principal:
    """An authenticated caller."""

    def __init__(self, *, is_admin: bool, scope: list[str]) -> None:
        self.is_admin = is_admin
        self.scope = scope

    def can_access(self, dataset_id: str) -> bool:
        return self.is_admin or api_keys.scope_allows(self.scope, dataset_id)

    def require_datasets(self, dataset_ids) -> None:
        for dataset_id in dataset_ids:
            if not self.can_access(dataset_id):
                raise AuthError(
                    status_code=403,
                    code="dataset_out_of_scope",
                    detail=(
                        f"API key is not authorized for dataset {dataset_id!r}"
                    ),
                )

    def require_admin(self) -> None:
        if not self.is_admin:
            raise AuthError(
                status_code=403,
                code="admin_required",
                detail="creating or revoking API keys requires the administrator key",
            )


# The administrator principal; data-plane principals are built per request.
ADMIN = Principal(is_admin=True, scope=[api_keys.WILDCARD_SCOPE])

_STATE_ATTR = "principal"


def authenticate(presented_key: str, admin_key: str) -> Principal:
    """Validate an X-API-Key value or raise :class:`AuthError` (401)."""
    if not presented_key:
        raise AuthError(
            status_code=401,
            code="missing_api_key",
            detail="missing X-API-Key header",
        )

    # The administrator key is compared first, in constant time, against the
    # presented credential. A dummy compare afterwards keeps the "not the admin
    # key" path indistinguishable when no database row exists.
    admin_match = _constant_time_eq(presented_key, admin_key)

    row, computed_hash = api_keys.lookup_api_key(presented_key)
    if admin_match:
        return ADMIN

    if row is None:
        # Burn a comparison against the hash of an invalid credential so the
        # unknown-id path takes comparable time to the wrong-secret path.
        _constant_time_eq(computed_hash, computed_hash)
        raise AuthError(
            status_code=401,
            code="invalid_api_key",
            detail="unknown or malformed API key",
        )

    if not api_keys.stored_hash_matches(row, computed_hash):
        raise AuthError(
            status_code=401,
            code="invalid_api_key",
            detail="API key does not match",
        )

    if not api_keys.is_active(row):
        if row["revoked"]:
            code = "key_revoked"
            detail = "API key has been revoked"
        else:
            code = "key_expired"
            detail = "API key has expired"
        raise AuthError(status_code=401, code=code, detail=detail)

    return Principal(is_admin=False, scope=api_keys.scope_of(row))


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def error_response(exc: AuthError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"error": exc.code, "message": exc.detail}},
        headers={"WWW-Authenticate": "ApiKey"},
    )


# Backwards-compatible internal alias.
_error_response = error_response

class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """Reject requests without a valid API key off the public surface."""

    def __init__(self, app, get_admin_key) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._get_admin_key = get_admin_key

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)
        try:
            principal = authenticate(
                request.headers.get(API_KEY_HEADER, ""), self._get_admin_key()
            )
        except AuthError as exc:
            return _error_response(exc)
        setattr(request.state, _STATE_ATTR, principal)
        return await call_next(request)


def principal_from(request: Request) -> Principal:
    principal = getattr(request.state, _STATE_ATTR, None)
    if principal is None:  # defensive: middleware must run first
        raise AuthError(
            status_code=401,
            code="missing_api_key",
            detail="missing X-API-Key header",
        )
    return principal
