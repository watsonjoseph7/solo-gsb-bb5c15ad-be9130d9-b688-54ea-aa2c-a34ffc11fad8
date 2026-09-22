# Differential Privacy Budget Release API

A FastAPI + SQLite service that releases **Laplace-mechanism** noised query
answers while charging a per-dataset ε (epsilon) privacy budget.

- Budget is checked **and deducted inside a single SQLite transaction**
  (`BEGIN IMMEDIATE`), so concurrent requests racing for the last slice of a
  budget serialize — exactly one succeeds, the rest get `402`.
- Noise is **deterministic and reproducible**: derived from an
  HMAC-SHA256 keyed by a server-side secret over
  `(dataset, query, epsilon, sensitivity, idempotency key)`.
- **Idempotent** releases: retrying with the same idempotency key returns the
  *exact same* release (same `id`, same noise, same value) and never charges
  the budget twice. Reusing a key with different parameters returns `409`.
- **Budget transfers:** unused ε quota can be moved from one dataset to another
  with `POST /budgets/transfer`. Both balances are locked and updated in one
  SQLite transaction; transfers are idempotent on `transfer_id`.

## Endpoints

| Method | Path                    | Description                                             |
|--------|-------------------------|---------------------------------------------------------|
| POST   | `/releases`             | Validate budget, deduct ε, return a noised release      |
| POST   | `/budgets/transfer`     | Move unused ε quota from one dataset to another         |
| GET    | `/budgets/{dataset_id}` | Used and remaining budget only                          |
| POST   | `/auth/keys`            | Create an API key (administrator key only)              |
| DELETE | `/auth/keys/{key_id}`   | Revoke an API key (administrator key only)              |
| GET    | `/health`               | Health check                                            |
| GET    | `/docs`                 | Interactive Swagger UI                                  |

## Authentication

Every endpoint except `GET /health`, `GET /docs` and `GET /openapi.json`
requires an `X-API-Key` header. Requests without a valid key get `401`;
a valid key used outside its dataset scope gets `403`.

There are two kinds of keys:

- **Administrator key** — the bootstrap credential from `DP_ADMIN_API_KEY`
  (auto-generated once and persisted next to the database when unset). It can
  create/revoke keys and access every dataset.
- **Data-plane keys** — created with `POST /auth/keys`; each has a `key_id`,
  a name, a list of allowed `dataset_id`s (use `["*"]` for all datasets) and
  an expiry time. The secret is returned **exactly once** in the create
  response; only its SHA-256 hash is stored, comparisons are constant-time,
  and revoked/expired keys are rejected.

### `POST /auth/keys` (administrator key only)

```bash
curl -s -X POST http://localhost:8000/auth/keys \
  -H "X-API-Key: $DP_ADMIN_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"sales-service",
       "dataset_ids":["sales","marketing"],
       "expires_at":"2026-12-31T23:59:59Z"}'
```

`201` response — **save `api_key` now, it is never shown again**:

```json
{
  "key_id": "ak_293985a57e6c975a6a3cb50b",
  "name": "sales-service",
  "api_key": "ak_293985a57e6c975a6a3cb50b.8f...url-safe-secret",
  "dataset_ids": ["marketing", "sales"],
  "expires_at": "2026-12-31T23:59:59Z"
}
```

You may pass an explicit `key_id` (`[A-Za-z0-9_.-]{3,128}`); reusing one
returns `409`. Duplicate datasets are de-duplicated and the list is sorted.

Status codes: `201` created, `400/422` invalid body (past/naive `expires_at`,
empty scope, …), `401` missing/bad key, `403` not the administrator key,
`409` duplicate `key_id`.

### `DELETE /auth/keys/{key_id}` (administrator key only)

Returns `204` on the first successful revocation; deleting an unknown or
already-revoked key returns `404`. Revocation takes effect immediately.

### Using a data-plane key

```bash
curl -s http://localhost:8000/budgets/sales \
  -H "X-API-Key: ak_293985a57e6c975a6a3cb50b.8f..."
```

- `GET /budgets/{id}` and `POST /releases` require the key's scope to contain
  that `dataset_id`.
- `POST /budgets/transfer` requires **both** `source_dataset` and
  `target_dataset` to be in scope.
- Out-of-scope requests return `403` with
  `{"detail":{"error":"dataset_out_of_scope",...}}`.
- Revoked keys return `401` (`key_revoked`); expired keys return `401`
  (`key_expired`).

### `POST /releases`

Request body:

```json
{
  "dataset_id": "sales",
  "query_id": "daily-revenue-2026-09-22",
  "epsilon": 0.1,
  "sensitivity": 1.0,
  "true_value": 12345.67,
  "idempotency_key": "client-uuid-7f3a..."
}
```

You may also pass the key via the `Idempotency-Key` header; if both are sent
they must match (otherwise `409`).

`200` response:

```json
{
  "id": "d6e2db1798ca4ff78c293ae2e00ded34",
  "idempotency_key": "client-uuid-7f3a...",
  "dataset_id": "sales",
  "query_id": "daily-revenue-2026-09-22",
  "epsilon": 0.1,
  "sensitivity": 1.0,
  "released_value": 12340.2175,
  "noise": -5.4525,
  "budget_used": 0.3,
  "budget_remaining": 0.7
}
```

Status codes:

- `200` — release created, or identical idempotent retry replayed
- `409` — idempotency key already exists with different parameters
- `402` — remaining budget is smaller than the requested ε
- `422` — invalid request (ε/sensitivity ≤ 0, NaN/Infinity, bad id, …)

The released value is `true_value + noise` with
`noise ~ Laplace(0, sensitivity / epsilon)`.

### `GET /budgets/{dataset_id}`

Returns only used and remaining amounts (never released values):

```json
{
  "dataset_id": "sales",
  "used_budget": 0.3,
  "remaining_budget": 0.7
}
```

Unknown datasets report `used_budget = 0` and the configured total as
remaining. After a transfer, `remaining_budget` reflects the quota moved in
or out (only the *unused* part of a budget can ever move — already-spent ε
stays with its dataset).

### `POST /budgets/transfer`

Move unused ε quota from one dataset to another. The source's total drops and
the target's total rises by `epsilon`; used amounts on both sides are
untouched.

Request body:

```json
{
  "transfer_id": "client-uuid-9c1b...",
  "source_dataset": "sales",
  "target_dataset": "marketing",
  "epsilon": 0.2
}
```

`200` response:

```json
{
  "transfer_id": "client-uuid-9c1b...",
  "source_dataset": "sales",
  "target_dataset": "marketing",
  "epsilon": 0.2,
  "source": {
    "dataset_id": "sales",
    "used_budget": 0.3,
    "remaining_budget": 0.5
  },
  "target": {
    "dataset_id": "marketing",
    "used_budget": 0.0,
    "remaining_budget": 1.2
  }
}
```

Status codes:

- `200` — transfer applied, or identical idempotent retry replayed
- `409` — `transfer_id` already exists with different parameters
  (`source_dataset`, `target_dataset` or `epsilon` changed)
- `402` — source has less than `epsilon` unused quota remaining; the body
  identifies the source, the available remainder and the requested amount
- `422` — invalid request: same source and target, `epsilon ≤ 0`,
  NaN/Infinity, bad identifier, extra fields, …

**Idempotency.** Retrying with the same `transfer_id` *and the exact same
parameters* returns the original transfer result (balances frozen at the time
of the first transfer are echoed back) without moving any additional quota.
Reusing a `transfer_id` with changed parameters returns `409` and moves
nothing.

**Atomicity.** Both budget rows are seeded (for unknown datasets) and then
read and updated inside a single `BEGIN IMMEDIATE` transaction. If the source
cannot cover the transfer, the whole request rolls back; concurrent
transfers serialize on SQLite's write lock, so quota is never double-spent.

## Quick start with Docker Compose

Requirements: Docker with the Compose plugin.

```bash
# optional: set persistent keys (otherwise random ones are generated
# automatically and stored in the data volume)
export DP_SERVER_KEY=$(openssl rand -hex 32)
export DP_ADMIN_API_KEY=$(openssl rand -hex 32)

docker compose up --build -d
```

The API is then served at:

- **Base URL:** `http://localhost:8000`
- **Health check:** `http://localhost:8000/health`
- **Swagger UI:** `http://localhost:8000/docs` (use the **Authorize**
  button to enter an `X-API-Key`)
- **Port:** `8000` (host and container)

If `DP_ADMIN_API_KEY` was left unset, read the generated administrator key
once from the logs (or the `admin_api_key` file in the volume):

```bash
docker compose logs dp-api | grep -A2 'DP_ADMIN_API_KEY is not set'
docker compose exec dp-api sh -c 'cat /data/admin_api_key'
```

Logs and lifecycle:

```bash
docker compose logs -f
docker compose down            # keep data
docker compose down -v         # also delete the database volume
```

The SQLite database (`dp.db`), the auto-generated noise key (`server.key`,
mode `0600`) and, when `DP_ADMIN_API_KEY` is unset, the generated
administrator key (`admin_api_key`, mode `0600`) live in the named volume
`dp-data` mounted at `/data`.

## Configuration

All configuration is via environment variables:

| Variable             | Default      | Description                                                            |
|----------------------|--------------|------------------------------------------------------------------------|
| `DP_SERVER_KEY`      | *(generated)*| HMAC key for deterministic noise. Set it for stable noise across rebuilds. Generate: `openssl rand -hex 32`. |
| `DP_ADMIN_API_KEY`   | *(generated)*| Bootstrap administrator key for `POST/DELETE /auth/keys` and dataset access. Generate: `openssl rand -hex 32`. |
| `DP_TOTAL_BUDGET`    | `1.0`        | Total ε budget every dataset receives by default.                      |
| `DP_DATASET_BUDGETS`| *(empty)*    | Per-dataset overrides, e.g. `sales:0.5,users:2.0`; others fall back to `DP_TOTAL_BUDGET`. |
| `DATABASE_PATH`      | `/data/dp.db`| SQLite database file path.                                             |
| `APP_HOST`           | `0.0.0.0`    | Bind address.                                                          |
| `APP_PORT`           | `8000`       | Listen port.                                                           |

Copy `.env.example` to `.env` and adjust — Compose picks it up automatically.

> **Key management note:** if `DP_SERVER_KEY` is unset, a random 32-byte key
> is generated once and persisted next to the database. Deleting the volume
> (or running without one) rotates the key and changes future noise, so set
> `DP_SERVER_KEY` explicitly for production.

## Local development (without Docker)

Python 3.11+:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
DATABASE_PATH=./data/dp.db DP_TOTAL_BUDGET=1.0 DP_SERVER_KEY=dev-key \
  .venv/bin/uvicorn app.main:app --reload --port 8000
```

Run the test suite (starts a real uvicorn server on port 8765 against a
temporary database, including concurrency races):

```bash
.venv/bin/python -m unittest tests.test_api -v
```

## Try it

```bash
# /health is the only unauthenticated endpoint
curl -s http://localhost:8000/health

# Create a data-plane key with the administrator key (only time the secret
# is shown):
curl -s -X POST http://localhost:8000/auth/keys \
  -H "X-API-Key: $DP_ADMIN_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo","dataset_ids":["sales","marketing"],
       "expires_at":"2026-12-31T23:59:59Z"}'
# -> {"key_id":"ak_...", "api_key":"ak_....secret", ...}

API_KEY='ak_....secret'

curl -s -X POST http://localhost:8000/releases \
  -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"dataset_id":"sales","query_id":"q1","epsilon":0.3,
       "sensitivity":1.0,"true_value":42.0,"idempotency_key":"abc-123"}'

# repeat the exact request -> byte-identical response, budget charged once

curl -s http://localhost:8000/budgets/sales -H "X-API-Key: $API_KEY"

# move 0.2 of sales' unused quota to marketing (both must be in scope)
curl -s -X POST http://localhost:8000/budgets/transfer \
  -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"transfer_id":"tr-001","source_dataset":"sales",
       "target_dataset":"marketing","epsilon":0.2}'

# revoke the key (administrator only); subsequent calls get 401
curl -s -X DELETE http://localhost:8000/auth/keys/ak_... \
  -H "X-API-Key: $DP_ADMIN_API_KEY"
```

## Design notes

- **Concurrency:** each release runs in `BEGIN IMMEDIATE`, which takes
  SQLite's reserved lock at transaction start. Concurrent writers queue on
  `busy_timeout` and each reads the committed balance, so the total deducted
  never exceeds the configured budget.
- **Deterministic noise:** `u ∈ (0,1)` is derived from
  `HMAC-SHA256(key, "dp-release-v1" ␟ dataset ␟ query ␟ ε ␟ sensitivity ␟ key)`
  (56 bits), then inverted through the Laplace CDF. Same inputs ⇒ identical
  float noise, independent of the database or request timing.
- **Idempotency:** `idempotency_key` has a `UNIQUE` constraint. Retries replay
  the stored row; the lost side of a same-key insert race rolls back and
  replays the winner instead of double-charging. Transfers follow the same
  pattern on `transfers.id` (`transfer_id`): identical retries replay the
  stored balances, changed parameters get `409`.
- **Budget transfers:** unused quota is moved by adjusting the two rows'
  `total` columns inside one `BEGIN IMMEDIATE` transaction (`used` never
  changes, so ε already spent cannot be moved out). Budget rows are seeded in
  a fixed alphabetical order so crossing transfers always acquire locks in the
  same order and cannot deadlock. A release never overwrites a budget row
  created by a transfer — the configured total only seeds a brand-new dataset.
- **Privacy:** budget accounting is basic ε-sum bookkeeping with no
  composition niceties; release values are returned to the caller (this is a
  release service), while the budget endpoint exposes amounts only.
- **API-key auth:** an ASGI middleware enforces `X-API-Key` on every route
  except `/health`, `/docs` and `/openapi.json`. Presented credentials are
  `key_id.secret`; the DB stores only the SHA-256 of the whole credential and
  lookups go by `key_id`, followed by `hmac.compare_digest` (constant time).
  Authentication is read-only (WAL, so it never blocks budget writers), while
  key creation and revocation run in `BEGIN IMMEDIATE` transactions, which
  serializes concurrent creates/revokes safely under SQLite. Each key carries
  a dataset scope checked before releases, transfers (both sides) and budget
  reads; misses return `403`. Expiry is evaluated per request and revocation
  is immediate. The single bootstrap administrator key comes from
  `DP_ADMIN_API_KEY` or an auto-generated 0600 file and bypasses the database
  entirely.
