"""FastAPI application: differential-privacy budget release service."""
from __future__ import annotations

import logging
import sqlite3
import uuid

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import api_keys, auth
from .config import settings
from .db import connect, immediate_transaction, init_db
from .privacy import derive_laplace_noise
from .schemas import (
    ApiKeyCreateRequest,
    ApiKeyResponse,
    BudgetResponse,
    HealthResponse,
    ReleaseRequest,
    ReleaseResponse,
    TransferRequest,
    TransferResponse,
)
from .security import resolve_admin_key, resolve_server_key

logger = logging.getLogger("dp-api")

app = FastAPI(
    title="Differential Privacy Budget Release API",
    version="1.0.0",
    description="Charges epsilon budgets transactionally and releases "
    "Laplace-noised aggregates with idempotent retries.",
    # /docs and /openapi.json stay public; redoc is not exposed so it
    # does not become an undocumented unauthenticated surface.
    docs_url="/docs",
    redoc_url=None,
)

# Resolved once at startup: env-supplied key, or a persisted random key.
_server_key: bytes = b""
# Bootstrap administrator API key for the /auth/keys endpoints. Resolved at
# startup; the middleware reads it through this accessor so it can be
# registered at import time (before the middleware stack is built).
_admin_key: str = ""


def _get_admin_key() -> str:
    return _admin_key


app.add_middleware(auth.ApiKeyAuthMiddleware, get_admin_key=_get_admin_key)

# Fields that must be identical when a release idempotency key is reused.
_REPLAY_FIELDS = (
    "dataset_id",
    "query_id",
    "epsilon",
    "sensitivity",
    "true_value",
)

# Fields that must be identical when a transfer_id is reused.
_TRANSFER_REPLAY_FIELDS = (
    "source_dataset",
    "target_dataset",
    "epsilon",
)

# Float tolerance when comparing a retry against the stored release/transfer.
_EPSILON_COMPARE_TOL = 1e-12


class _ReplayRelease(Exception):
    """Raised inside a transaction when a same-key race must be replayed."""

    def __init__(self, row: sqlite3.Row) -> None:
        self.row = row


class _ReplayTransfer(Exception):
    """Raised inside a transaction when a same-transfer_id race must be replayed."""

    def __init__(self, row: sqlite3.Row) -> None:
        self.row = row


@app.on_event("startup")
def _startup() -> None:
    global _server_key, _admin_key
    init_db()
    _server_key = resolve_server_key()
    _admin_key = resolve_admin_key()
    if not settings.admin_api_key:
        logger.warning(
            "DP_ADMIN_API_KEY is not set; a random administrator API key was "
            "generated and persisted next to the database (admin_api_key, mode "
            "0600). It is required to create/revoke API keys via "
            "POST/DELETE /auth/keys. Set DP_ADMIN_API_KEY explicitly for a "
            "stable, retrievable credential."
        )
    # The middleware was registered at import time and reads the resolved
    # administrator key lazily through _get_admin_key().
    if not _admin_key:
        raise RuntimeError(
            "administrator API key is empty; set DP_ADMIN_API_KEY or make the "
            "data directory writable so a key can be persisted"
        )


@app.exception_handler(auth.AuthError)
def _auth_error_handler(request: Request, exc: auth.AuthError) -> JSONResponse:
    return auth.error_response(exc)


@app.exception_handler(RequestValidationError)
def _validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # The default handler echoes rejected values in "ctx"/"input", which can
    # contain NaN/Infinity and crash strict JSON rendering; drop ctx and
    # replace non-finite floats with their textual token.
    def _sanitize(value):  # type: ignore[no-untyped-def]
        if isinstance(value, float):
            if value != value:
                return "NaN"
            if value == float("inf"):
                return "Infinity"
            if value == float("-inf"):
                return "-Infinity"
            return value
        if isinstance(value, dict):
            return {k: _sanitize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_sanitize(v) for v in value]
        return value

    safe_errors = []
    for error in exc.errors():
        error = {k: v for k, v in error.items() if k != "ctx"}
        safe_errors.append(_sanitize(error))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": safe_errors},
    )


@app.get("/health", response_model=HealthResponse, tags=["health"])
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post(
    "/auth/keys",
    response_model=ApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
)
def create_api_key(payload: ApiKeyCreateRequest, request: Request) -> ApiKeyResponse:
    """Create a data-plane API key. Requires the administrator key.

    The plaintext credential is returned exactly once (in ``api_key``);
    only its SHA-256 hash is persisted.
    """
    auth.principal_from(request).require_admin()
    try:
        key_id, secret, scope = api_keys.create_api_key(
            name=payload.name,
            dataset_ids=list(payload.dataset_ids),
            expires_at=payload.expires_at,
            key_id=payload.key_id,
        )
    except api_keys.ApiKeyIdExists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"key_id {payload.key_id!r} already exists",
        )
    return ApiKeyResponse(
        key_id=key_id,
        name=payload.name,
        api_key=f"{key_id}.{secret}",
        dataset_ids=scope,
        expires_at=payload.expires_at,
    )


@app.delete(
    "/auth/keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["auth"],
)
def revoke_api_key(key_id: str, request: Request) -> None:
    """Revoke an API key. Requires the administrator key."""
    auth.principal_from(request).require_admin()
    if not api_keys.revoke_api_key(key_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no active API key with key_id {key_id!r}",
        )


def _row_to_release(row: sqlite3.Row) -> ReleaseResponse:
    return ReleaseResponse(
        id=row["id"],
        idempotency_key=row["idempotency_key"],
        dataset_id=row["dataset_id"],
        query_id=row["query_id"],
        epsilon=row["epsilon"],
        sensitivity=row["sensitivity"],
        released_value=row["released_value"],
        noise=row["noise"],
        budget_used=row["budget_used"],
        budget_remaining=row["budget_remaining"],
    )


def _params_match(row: sqlite3.Row, req: object, fields: tuple[str, ...]) -> bool:
    for field in fields:
        stored = row[field]
        incoming = getattr(req, field)
        if isinstance(stored, float):
            if abs(stored - incoming) > _EPSILON_COMPARE_TOL * max(1.0, abs(stored), abs(incoming)):
                return False
        elif stored != incoming:
            return False
    return True


def _idempotency_key(request: Request, payload: ReleaseRequest) -> str:
    """Prefer the Idempotency-Key header, fall back to the request body."""
    header = request.headers.get("Idempotency-Key", "").strip()
    if header:
        if header != payload.idempotency_key:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Idempotency-Key header does not match idempotency_key in the body",
            )
        return header
    return payload.idempotency_key


@app.post(
    "/releases",
    response_model=ReleaseResponse,
    status_code=status.HTTP_200_OK,
    tags=["releases"],
)
def create_release(
    payload: ReleaseRequest, request: Request
) -> ReleaseResponse:
    idem_key = _idempotency_key(request, payload)
    auth.principal_from(request).require_datasets([payload.dataset_id])
    total_budget = settings.budget_for(payload.dataset_id)

    try:
        with immediate_transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM releases WHERE idempotency_key = ?",
                (idem_key,),
            ).fetchone()
            if existing is not None:
                if not _params_match(existing, payload, _REPLAY_FIELDS):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Idempotency key was already used with different parameters",
                    )
                # Identical retry: replay the stored release, no extra charge.
                # (A read-only transaction commits harmlessly on context exit.)
                return _row_to_release(existing)

            # Ensure a budget row exists and lock/freeze it for this transaction.
            # A budget row may have been created/changed by a transfer, so on
            # conflict do nothing: the configured total only seeds a new dataset.
            conn.execute(
                "INSERT INTO budgets (dataset_id, total, used) VALUES (?, ?, 0) "
                "ON CONFLICT(dataset_id) DO NOTHING",
                (payload.dataset_id, total_budget),
            )
            budget = conn.execute(
                "SELECT total, used FROM budgets WHERE dataset_id = ?",
                (payload.dataset_id,),
            ).fetchone()
            used = float(budget["used"])
            total = float(budget["total"])
            new_used = used + payload.epsilon
            # Tolerance covers binary float rounding when the request exactly
            # exhausts the remaining budget.
            if new_used > total + 1e-9:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail={
                        "error": "insufficient_privacy_budget",
                        "dataset_id": payload.dataset_id,
                        "total_budget": total,
                        "used_budget": used,
                        "remaining_budget": total - used,
                        "requested_epsilon": payload.epsilon,
                    },
                )

            noise = derive_laplace_noise(
                key=_server_key,
                dataset_id=payload.dataset_id,
                query_id=payload.query_id,
                epsilon=payload.epsilon,
                sensitivity=payload.sensitivity,
                idempotency_key=idem_key,
            )
            released_value = payload.true_value + noise
            remaining = total - new_used
            release_id = uuid.uuid4().hex

            conn.execute(
                "UPDATE budgets SET used = ? WHERE dataset_id = ?",
                (new_used, payload.dataset_id),
            )
            try:
                conn.execute(
                    """
                    INSERT INTO releases (
                        id, idempotency_key, dataset_id, query_id, epsilon,
                        sensitivity, true_value, noise, released_value,
                        budget_used, budget_remaining
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        release_id,
                        idem_key,
                        payload.dataset_id,
                        payload.query_id,
                        payload.epsilon,
                        payload.sensitivity,
                        payload.true_value,
                        noise,
                        released_value,
                        new_used,
                        remaining,
                    ),
                )
            except sqlite3.IntegrityError:
                # Lost a race against another transaction with the same key.
                winner = conn.execute(
                    "SELECT * FROM releases WHERE idempotency_key = ?",
                    (idem_key,),
                ).fetchone()
                if winner is not None and _params_match(winner, payload, _REPLAY_FIELDS):
                    # Same request won: roll back our duplicate deduction
                    # (context exit rolls back) and replay the winner.
                    raise _ReplayRelease(winner)
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key was already used with different parameters",
                )

            stored = conn.execute(
                "SELECT * FROM releases WHERE id = ?", (release_id,)
            ).fetchone()
            return _row_to_release(stored)
    except _ReplayRelease as replay:
        return _row_to_release(replay.row)


def _row_to_transfer(row: sqlite3.Row) -> TransferResponse:
    return TransferResponse(
        transfer_id=row["id"],
        source_dataset=row["source_dataset"],
        target_dataset=row["target_dataset"],
        epsilon=row["epsilon"],
        source=BudgetResponse(
            dataset_id=row["source_dataset"],
            used_budget=row["source_used"],
            remaining_budget=row["source_remaining"],
        ),
        target=BudgetResponse(
            dataset_id=row["target_dataset"],
            used_budget=row["target_used"],
            remaining_budget=row["target_remaining"],
        ),
    )


@app.post(
    "/budgets/transfer",
    response_model=TransferResponse,
    status_code=status.HTTP_200_OK,
    tags=["budgets"],
)
def transfer_budget(payload: TransferRequest, request: Request) -> TransferResponse:
    """Move unused epsilon quota from one dataset to another.

    Both balances are read and updated inside one ``BEGIN IMMEDIATE``
    transaction; any validation failure rolls the whole transfer back.
    """
    auth.principal_from(request).require_datasets(
        [payload.source_dataset, payload.target_dataset]
    )
    source_id = payload.source_dataset
    target_id = payload.target_dataset
    total_for_source = settings.budget_for(source_id)
    total_for_target = settings.budget_for(target_id)

    try:
        with immediate_transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM transfers WHERE id = ?",
                (payload.transfer_id,),
            ).fetchone()
            if existing is not None:
                if not _params_match(existing, payload, _TRANSFER_REPLAY_FIELDS):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="transfer_id was already used with different parameters",
                    )
                # Identical retry: replay the stored transfer, balances
                # are untouched.
                return _row_to_transfer(existing)

            # Seed any missing budget row with its configured total. Inserting
            # in a fixed (alphabetical) order keeps lock acquisition
            # deterministic across concurrent transfers.
            seed_ids = sorted(
                {(source_id, total_for_source), (target_id, total_for_target)}
            )
            for dataset_id, configured_total in seed_ids:
                conn.execute(
                    "INSERT INTO budgets (dataset_id, total, used) VALUES (?, ?, 0) "
                    "ON CONFLICT(dataset_id) DO NOTHING",
                    (dataset_id, configured_total),
                )

            # Read and freeze both balances within the write transaction.
            rows = conn.execute(
                "SELECT dataset_id, total, used FROM budgets "
                "WHERE dataset_id IN (?, ?)",
                (source_id, target_id),
            ).fetchall()
            balances = {row["dataset_id"]: row for row in rows}
            source = balances[source_id]
            target = balances[target_id]

            source_total = float(source["total"])
            source_used = float(source["used"])
            source_remaining = source_total - source_used
            epsilon = payload.epsilon
            # Tolerance covers binary float rounding when the transfer moves
            # exactly the remaining quota.
            if epsilon > source_remaining + 1e-9:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail={
                        "error": "insufficient_transferable_budget",
                        "source_dataset": source_id,
                        "target_dataset": target_id,
                        "transfer_id": payload.transfer_id,
                        "available_remaining": source_remaining,
                        "requested_epsilon": epsilon,
                    },
                )

            target_total = float(target["total"])
            target_used = float(target["used"])

            # Moving unused quota lowers the source's total and raises the
            # target's; used amounts never change.
            conn.execute(
                "UPDATE budgets SET total = total - ? WHERE dataset_id = ?",
                (epsilon, source_id),
            )
            conn.execute(
                "UPDATE budgets SET total = total + ? WHERE dataset_id = ?",
                (epsilon, target_id),
            )

            source_remaining_after = source_remaining - epsilon
            target_remaining_after = target_total - target_used + epsilon

            try:
                conn.execute(
                    """
                    INSERT INTO transfers (
                        id, source_dataset, target_dataset, epsilon,
                        source_used, source_remaining,
                        target_used, target_remaining
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.transfer_id,
                        source_id,
                        target_id,
                        epsilon,
                        source_used,
                        source_remaining_after,
                        target_used,
                        target_remaining_after,
                    ),
                )
            except sqlite3.IntegrityError:
                # Lost a race against another transaction with the same
                # transfer_id; roll back and replay the committed winner.
                winner = conn.execute(
                    "SELECT * FROM transfers WHERE id = ?",
                    (payload.transfer_id,),
                ).fetchone()
                if winner is not None and _params_match(winner, payload, _TRANSFER_REPLAY_FIELDS):
                    raise _ReplayTransfer(winner)
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="transfer_id was already used with different parameters",
                )

            stored = conn.execute(
                "SELECT * FROM transfers WHERE id = ?", (payload.transfer_id,)
            ).fetchone()
            return _row_to_transfer(stored)
    except _ReplayTransfer as replay:
        return _row_to_transfer(replay.row)


@app.get(
    "/budgets/{dataset_id}",
    response_model=BudgetResponse,
    tags=["budgets"],
)
def get_budget(dataset_id: str, request: Request) -> BudgetResponse:
    auth.principal_from(request).require_datasets([dataset_id])
    configured_total = settings.budget_for(dataset_id)
    conn = connect()
    try:
        row = conn.execute(
            "SELECT total, used FROM budgets WHERE dataset_id = ?",
            (dataset_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        total = configured_total
        used = 0.0
    else:
        # The stored total reflects quota moved in/out by transfers.
        total = float(row["total"])
        used = float(row["used"])
    return BudgetResponse(
        dataset_id=dataset_id,
        used_budget=used,
        remaining_budget=total - used,
    )



# Describe the X-API-Key header in OpenAPI (enables the "Authorize"
# button in /docs). Enforcement is the ApiKeyAuthMiddleware above;
# /health and /docs stay public.
def _openapi_with_security():  # type: ignore[no-untyped-def]
    schema = _default_openapi()
    schema.setdefault("components", {}).setdefault("securitySchemes", {})[
        "APIKeyHeader"
    ] = {
        "type": "apiKey",
        "in": "header",
        "name": auth.API_KEY_HEADER,
    }
    for path, methods in schema.get("paths", {}).items():
        if path == "/health":
            continue
        for operation in methods.values():
            if isinstance(operation, dict):
                operation["security"] = [{"APIKeyHeader": []}]
    return schema


_default_openapi = app.openapi
app.openapi = _openapi_with_security
