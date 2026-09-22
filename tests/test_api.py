"""End-to-end tests using a temporary SQLite database."""
from __future__ import annotations

import importlib
import os
import tempfile
import threading
import unittest
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Configure environment BEFORE importing the app.
_TMP = tempfile.mkdtemp(prefix="dp-api-tests-")
os.environ["DATABASE_PATH"] = str(Path(_TMP) / "test.db")
os.environ["DP_TOTAL_BUDGET"] = "1.0"
os.environ["DP_DATASET_BUDGETS"] = "tiny:0.5"
os.environ["DP_SERVER_KEY"] = "unit-test-server-key"
os.environ["DP_ADMIN_API_KEY"] = "unit-test-admin-key"

import uvicorn  # noqa: E402

from app import main as main_module  # noqa: E402

ADMIN_KEY = "unit-test-admin-key"
ADMIN_HEADERS = {"X-API-Key": ADMIN_KEY}


def _create_key(dataset_ids, *, name="test-key", ttl_seconds=3600):
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    ).isoformat()
    status, body = _request(
        "POST",
        "/auth/keys",
        {"name": name, "dataset_ids": list(dataset_ids), "expires_at": expires_at},
        ADMIN_HEADERS,
    )
    assert status == 201, body
    return body["api_key"]


def _request(method, path, body=None, headers=ADMIN_HEADERS):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else None


PORT = 8765

# One server for every test class in this module, started once on import.
_config = uvicorn.Config(
    main_module.app, host="127.0.0.1", port=PORT, log_level="error"
)
server = uvicorn.Server(_config)
_server_thread = threading.Thread(target=server.run, daemon=True)
_server_thread.start()
for _ in range(100):
    try:
        _request("GET", "/health", headers={})
        break
    except OSError:
        import time

        time.sleep(0.1)
else:
    raise RuntimeError("test server failed to start")


class ApiTests(unittest.TestCase):
    def test_01_health(self) -> None:
        status, body = _request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_02_release_charges_budget(self) -> None:
        status, body = _request(
            "POST",
            "/releases",
            {
                "dataset_id": "ds",
                "query_id": "count-men",
                "epsilon": 0.3,
                "sensitivity": 1.0,
                "true_value": 42.0,
                "idempotency_key": "k1",
            },
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["budget_used"], 0.3)
        self.assertAlmostEqual(body["budget_remaining"], 0.7, places=9)
        self.assertAlmostEqual(body["released_value"], 42.0 + body["noise"], places=9)

    def test_03_idempotent_replay_identical(self) -> None:
        payload = {
            "dataset_id": "ds",
            "query_id": "count-men",
            "epsilon": 0.3,
            "sensitivity": 1.0,
            "true_value": 42.0,
            "idempotency_key": "k1",
        }
        _, first = _request("POST", "/releases", payload)
        _, second = _request("POST", "/releases", payload)
        self.assertEqual(first, second)

        status, budget = _request("GET", "/budgets/ds")
        self.assertEqual(status, 200)
        self.assertEqual(set(budget), {"dataset_id", "used_budget", "remaining_budget"})
        self.assertAlmostEqual(budget["used_budget"], 0.3, places=9)

    def test_04_same_key_changed_params_conflict(self) -> None:
        status, body = _request(
            "POST",
            "/releases",
            {
                "dataset_id": "ds",
                "query_id": "count-men",
                "epsilon": 0.3,
                "sensitivity": 1.0,
                "true_value": 999.0,
                "idempotency_key": "k1",
            },
        )
        self.assertEqual(status, 409)

    def test_05_insufficient_budget(self) -> None:
        status, body = _request(
            "POST",
            "/releases",
            {
                "dataset_id": "ds",
                "query_id": "q",
                "epsilon": 0.9,
                "sensitivity": 1.0,
                "true_value": 1.0,
                "idempotency_key": "k2",
            },
        )
        self.assertEqual(status, 402)
        self.assertEqual(body["detail"]["error"], "insufficient_privacy_budget")

    def test_06_exact_remaining_succeeds(self) -> None:
        status, _ = _request(
            "POST",
            "/releases",
            {
                "dataset_id": "ds",
                "query_id": "q",
                "epsilon": 0.7,
                "sensitivity": 1.0,
                "true_value": 1.0,
                "idempotency_key": "k3",
            },
        )
        self.assertEqual(status, 200)

    def test_07_concurrent_race_for_last_slice(self) -> None:
        def call(i: int):
            return _request(
                "POST",
                "/releases",
                {
                    "dataset_id": "race",
                    "query_id": "q",
                    "epsilon": 1.0,
                    "sensitivity": 1.0,
                    "true_value": 1.0,
                    "idempotency_key": f"r{i}",
                },
            )[0]

        with ThreadPoolExecutor(max_workers=16) as pool:
            codes = list(pool.map(call, range(16)))
        self.assertEqual(codes.count(200), 1)
        self.assertEqual(codes.count(402), 15)

    def test_08_concurrent_identical_key_single_charge(self) -> None:
        def call(_i: int):
            return _request(
                "POST",
                "/releases",
                {
                    "dataset_id": "idem",
                    "query_id": "q",
                    "epsilon": 0.2,
                    "sensitivity": 1.0,
                    "true_value": 1.0,
                    "idempotency_key": "same",
                },
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(call, range(16)))
        self.assertTrue(all(code == 200 for code, _ in results))
        self.assertEqual(len({body["id"] for _, body in results}), 1)
        _, budget = _request("GET", "/budgets/idem")
        self.assertAlmostEqual(budget["used_budget"], 0.2, places=9)

    def test_08b_concurrent_same_key_race_with_budget_update(self) -> None:
        """Same-key fan-out against a fresh dataset: every request does the
        budget upsert before hitting the unique constraint, exercising the
        loser-rollback-and-replay path. Must still result in one release and
        a single charge."""
        payload = {
            "dataset_id": "idem2",
            "query_id": "q",
            "epsilon": 0.2,
            "sensitivity": 1.0,
            "true_value": 1.0,
            "idempotency_key": "same2",
        }

        def call(_i: int):
            return _request("POST", "/releases", payload)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(call, range(32)))
        statuses = [code for code, _ in results]
        self.assertTrue(all(code == 200 for code in statuses), statuses)
        self.assertEqual(len({body["id"] for _, body in results}), 1)
        _, budget = _request("GET", "/budgets/idem2")
        self.assertAlmostEqual(budget["used_budget"], 0.2, places=9)
        self.assertAlmostEqual(budget["remaining_budget"], 0.8, places=9)

    def test_09_per_dataset_budget(self) -> None:
        status, body = _request("GET", "/budgets/tiny")
        self.assertEqual(status, 200)
        self.assertAlmostEqual(body["remaining_budget"], 0.5, places=9)

    def test_10_validation(self) -> None:
        bad = [
            {"dataset_id": "d", "query_id": "q", "epsilon": 0, "sensitivity": 1,
             "true_value": 1, "idempotency_key": "x"},
            {"dataset_id": "d", "query_id": "q", "epsilon": 0.1, "sensitivity": 1,
             "true_value": float("nan"), "idempotency_key": "x"},
            {"dataset_id": "d", "query_id": "q", "epsilon": 0.1, "sensitivity": 1,
             "true_value": 1, "idempotency_key": "x", "extra": 2},
        ]
        for payload in bad:
            status, _ = _request("POST", "/releases", payload)
            self.assertEqual(status, 422)

    # --- budget transfers ---

    def test_11_transfer_moves_unused_quota(self) -> None:
        status, body = _request(
            "POST",
            "/budgets/transfer",
            {"transfer_id": "tr1", "source_dataset": "t11-src",
             "target_dataset": "t11-dst", "epsilon": 0.4},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["transfer_id"], "tr1")
        self.assertAlmostEqual(body["source"]["remaining_budget"], 0.6, places=9)
        self.assertEqual(body["source"]["used_budget"], 0.0)
        self.assertAlmostEqual(body["target"]["remaining_budget"], 1.4, places=9)
        self.assertEqual(body["target"]["used_budget"], 0.0)

        _, src = _request("GET", "/budgets/t11-src")
        self.assertAlmostEqual(src["remaining_budget"], 0.6, places=9)
        _, dst = _request("GET", "/budgets/t11-dst")
        self.assertAlmostEqual(dst["remaining_budget"], 1.4, places=9)

    def test_12_transfer_idempotent_replay(self) -> None:
        payload = {"transfer_id": "tr2", "source_dataset": "t12-src",
                   "target_dataset": "t12-dst", "epsilon": 0.1}
        _, first = _request("POST", "/budgets/transfer", payload)
        _, second = _request("POST", "/budgets/transfer", payload)
        self.assertEqual(first, second)

        # Replay must not move any extra quota.
        _, src = _request("GET", "/budgets/t12-src")
        self.assertAlmostEqual(src["remaining_budget"], 0.9, places=9)
        _, dst = _request("GET", "/budgets/t12-dst")
        self.assertAlmostEqual(dst["remaining_budget"], 1.1, places=9)

    def test_13_transfer_same_id_changed_params_conflict(self) -> None:
        # Establish the original transfer first.
        status, _ = _request(
            "POST",
            "/budgets/transfer",
            {"transfer_id": "tr3", "source_dataset": "t13-src",
             "target_dataset": "t13-dst", "epsilon": 0.1},
        )
        self.assertEqual(status, 200)

        for changed in (
            {"source_dataset": "t13-other"},
            {"target_dataset": "t13-other"},
            {"epsilon": 0.11},
        ):
            payload = {"transfer_id": "tr3", "source_dataset": "t13-src",
                       "target_dataset": "t13-dst", "epsilon": 0.1}
            payload.update(changed)
            status, _ = _request("POST", "/budgets/transfer", payload)
            self.assertEqual(status, 409, changed)

        # The conflicting attempts must not have moved anything beyond the
        # original 0.1.
        _, src = _request("GET", "/budgets/t13-src")
        self.assertAlmostEqual(src["remaining_budget"], 0.9, places=9)
        _, dst = _request("GET", "/budgets/t13-dst")
        self.assertAlmostEqual(dst["remaining_budget"], 1.1, places=9)

    def test_14_transfer_insufficient_source_balance(self) -> None:
        # Move half the quota away first, leaving 0.5.
        status, _ = _request(
            "POST",
            "/budgets/transfer",
            {"transfer_id": "tr4a", "source_dataset": "t14-src",
             "target_dataset": "t14-dst", "epsilon": 0.5},
        )
        self.assertEqual(status, 200)

        status, body = _request(
            "POST",
            "/budgets/transfer",
            {"transfer_id": "tr4b", "source_dataset": "t14-src",
             "target_dataset": "t14-dst", "epsilon": 0.6},
        )
        self.assertEqual(status, 402)
        self.assertEqual(body["detail"]["error"], "insufficient_transferable_budget")
        self.assertEqual(body["detail"]["source_dataset"], "t14-src")
        self.assertAlmostEqual(body["detail"]["available_remaining"], 0.5, places=9)
        self.assertAlmostEqual(body["detail"]["requested_epsilon"], 0.6, places=9)

        # Failed transfer changes nothing.
        _, src = _request("GET", "/budgets/t14-src")
        self.assertAlmostEqual(src["remaining_budget"], 0.5, places=9)

        # Transferring exactly the remaining quota is allowed.
        status, body = _request(
            "POST",
            "/budgets/transfer",
            {"transfer_id": "tr5", "source_dataset": "t14-src",
             "target_dataset": "t14-dst", "epsilon": 0.5},
        )
        self.assertEqual(status, 200, body)
        self.assertAlmostEqual(body["source"]["remaining_budget"], 0.0, places=9)
        self.assertAlmostEqual(body["target"]["remaining_budget"], 2.0, places=9)

    def test_15_transfer_same_source_and_target(self) -> None:
        status, body = _request(
            "POST",
            "/budgets/transfer",
            {"transfer_id": "tr6", "source_dataset": "t15",
             "target_dataset": "t15", "epsilon": 0.1},
        )
        self.assertEqual(status, 422)
        locs = [tuple(err["loc"]) for err in body["detail"]]
        self.assertIn(("body", "target_dataset"), locs)

    def test_16_transfer_validation(self) -> None:
        bad = [
            {"transfer_id": "x", "source_dataset": "a", "target_dataset": "b",
             "epsilon": 0},
            {"transfer_id": "x", "source_dataset": "a", "target_dataset": "b",
             "epsilon": -0.1},
            {"transfer_id": "x", "source_dataset": "a", "target_dataset": "b",
             "epsilon": float("nan")},
            {"transfer_id": "x", "source_dataset": "a", "target_dataset": "b",
             "epsilon": 0.1, "extra": 1},
            {"transfer_id": "", "source_dataset": "a", "target_dataset": "b",
             "epsilon": 0.1},
            {"transfer_id": "x", "source_dataset": "a", "target_dataset": "",
             "epsilon": 0.1},
        ]
        for payload in bad:
            status, _ = _request("POST", "/budgets/transfer", payload)
            self.assertEqual(status, 422, payload)

    def test_17_transfer_preserves_used_budget(self) -> None:
        # Spend 0.3 at pool (1.0 total -> 0.7 remaining), then move 0.5 out.
        status, _ = _request(
            "POST",
            "/releases",
            {"dataset_id": "pool", "query_id": "q", "epsilon": 0.3,
             "sensitivity": 1.0, "true_value": 1.0, "idempotency_key": "pool-k1"},
        )
        self.assertEqual(status, 200)
        status, body = _request(
            "POST",
            "/budgets/transfer",
            {"transfer_id": "tr7", "source_dataset": "pool",
             "target_dataset": "pool-dst", "epsilon": 0.5},
        )
        self.assertEqual(status, 200, body)
        self.assertAlmostEqual(body["source"]["used_budget"], 0.3, places=9)
        self.assertAlmostEqual(body["source"]["remaining_budget"], 0.2, places=9)
        self.assertEqual(body["target"]["used_budget"], 0.0)
        self.assertAlmostEqual(body["target"]["remaining_budget"], 1.5, places=9)

        # Already-spent epsilon cannot leave the source.
        status, _ = _request(
            "POST",
            "/budgets/transfer",
            {"transfer_id": "tr8", "source_dataset": "pool",
             "target_dataset": "pool-dst", "epsilon": 0.21},
        )
        self.assertEqual(status, 402)

        # The post-transfer total governs releases at both sides.
        status, body = _request(
            "POST",
            "/releases",
            {"dataset_id": "pool-dst", "query_id": "q", "epsilon": 1.5,
             "sensitivity": 1.0, "true_value": 1.0, "idempotency_key": "pool-k2"},
        )
        self.assertEqual(status, 200)
        self.assertAlmostEqual(body["budget_remaining"], 0.0, places=9)
        status, _ = _request(
            "POST",
            "/releases",
            {"dataset_id": "pool", "query_id": "q", "epsilon": 0.21,
             "sensitivity": 1.0, "true_value": 1.0, "idempotency_key": "pool-k3"},
        )
        self.assertEqual(status, 402)

    def test_18_concurrent_transfer_chain_serializes(self) -> None:
        """Ten 0.2 transfers chain -> chain2 out of a fresh 1.0 dataset;
        exactly five can succeed (draining it fully), the rest see 402."""
        def call(i: int):
            return _request(
                "POST",
                "/budgets/transfer",
                {"transfer_id": f"chain-{i}", "source_dataset": "chain",
                 "target_dataset": "chain2", "epsilon": 0.2},
            )[0]

        with ThreadPoolExecutor(max_workers=10) as pool:
            codes = list(pool.map(call, range(10)))
        self.assertEqual(sorted(codes), [200] * 5 + [402] * 5, codes)
        _, src = _request("GET", "/budgets/chain")
        self.assertAlmostEqual(src["remaining_budget"], 0.0, places=9)
        _, dst = _request("GET", "/budgets/chain2")
        self.assertAlmostEqual(dst["remaining_budget"], 2.0, places=9)

    def test_19_concurrent_same_transfer_id_single_move(self) -> None:
        payload = {"transfer_id": "same-tr", "source_dataset": "fan",
                   "target_dataset": "fan2", "epsilon": 0.2}

        def call(_i: int):
            return _request("POST", "/budgets/transfer", payload)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(call, range(16)))
        statuses = [code for code, _ in results]
        self.assertTrue(all(code == 200 for code in statuses), statuses)
        bodies = [body for _, body in results]
        self.assertEqual(len({b["transfer_id"] for b in bodies}), 1)
        _, src = _request("GET", "/budgets/fan")
        self.assertAlmostEqual(src["remaining_budget"], 0.8, places=9)
        _, dst = _request("GET", "/budgets/fan2")
        self.assertAlmostEqual(dst["remaining_budget"], 1.2, places=9)

    def test_20_concurrent_bidirectional_transfers(self) -> None:
        """Crossing transfers in both directions must never deadlock and the
        books must stay balanced: remaining quotas still sum to 2.0."""
        def call(i: int):
            if i % 2 == 0:
                payload = {"transfer_id": f"cross-{i}", "source_dataset": "x",
                           "target_dataset": "y", "epsilon": 0.05}
            else:
                payload = {"transfer_id": f"cross-{i}", "source_dataset": "y",
                           "target_dataset": "x", "epsilon": 0.05}
            return _request("POST", "/budgets/transfer", payload)[0]

        with ThreadPoolExecutor(max_workers=16) as pool:
            codes = list(pool.map(call, range(20)))
        self.assertTrue(all(code == 200 for code in codes), codes)
        _, x = _request("GET", "/budgets/x")
        _, y = _request("GET", "/budgets/y")
        self.assertAlmostEqual(x["remaining_budget"] + y["remaining_budget"], 2.0, places=9)



class AuthTests(unittest.TestCase):
    """X-API-Key authentication, scoping, revocation and expiry."""

    @staticmethod
    def _payload(dataset: str, key: str = "ak"):
        return {
            "dataset_id": dataset, "query_id": "q", "epsilon": 0.1,
            "sensitivity": 1.0, "true_value": 1.0, "idempotency_key": key,
        }

    # --- public surface ---

    def test_health_and_docs_need_no_key(self) -> None:
        for path in ("/health", "/docs", "/openapi.json"):
            req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}")
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200, path)

    def test_redoc_is_not_exposed(self) -> None:
        req = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/redoc",
            headers={"X-API-Key": ADMIN_KEY},
        )
        try:
            urllib.request.urlopen(req)
            self.fail("/redoc should not be served")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)

    def test_missing_key_is_401(self) -> None:
        for method, path, body in (
            ("GET", "/budgets/whatever", None),
            ("POST", "/releases", self._payload("whatever")),
            ("POST", "/budgets/transfer",
             {"transfer_id": "z", "source_dataset": "a",
              "target_dataset": "b", "epsilon": 0.1}),
            ("POST", "/auth/keys",
             {"name": "n", "dataset_ids": ["a"],
              "expires_at": "2030-01-01T00:00:00+00:00"}),
            ("DELETE", "/auth/keys/whatever", None),
        ):
            status, resp = _request(method, path, body, headers={})
            self.assertEqual(status, 401, (method, path, resp))
            self.assertEqual(resp["detail"]["error"], "missing_api_key")

    def test_unknown_and_malformed_keys_are_401(self) -> None:
        for bad in ("garbage", "ak_noseparator", ".secretonly",
                    "ak_doesnotexist.abcdef"):
            status, resp = _request(
                "GET", "/budgets/whatever", headers={"X-API-Key": bad}
            )
            self.assertEqual(status, 401, (bad, resp))
            self.assertEqual(resp["detail"]["error"], "invalid_api_key")

    def test_wrong_secret_is_401(self) -> None:
        key = _create_key(["auth-ws"])
        key_id = key.split(".", 1)[0]
        status, resp = _request(
            "GET", "/budgets/auth-ws",
            headers={"X-API-Key": key_id + ".not-the-secret"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(resp["detail"]["error"], "invalid_api_key")

    # --- key management ---

    def test_create_key_returns_plaintext_once(self) -> None:
        expires = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()
        status, body = _request(
            "POST", "/auth/keys",
            {"name": "once", "dataset_ids": ["a", "b", "a"],
             "expires_at": expires},
            ADMIN_HEADERS,
        )
        self.assertEqual(status, 201, body)
        self.assertTrue(body["key_id"].startswith("ak_"))
        self.assertEqual(body["dataset_ids"], ["a", "b"])  # de-duplicated/sorted
        self.assertIn(".", body["api_key"])
        self.assertTrue(body["api_key"].startswith(body["key_id"] + "."))
        self.assertEqual(body["name"], "once")
        # The secret part is never returned again: there is no list/get
        # endpoint and the stored hash is not the plaintext.
        import sqlite3
        conn = sqlite3.connect(os.environ["DATABASE_PATH"])
        row = conn.execute(
            "SELECT key_hash FROM api_keys WHERE key_id = ?",
            (body["key_id"],),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertNotIn(body["api_key"], row[0])
        secret = body["api_key"].split(".", 1)[1]
        self.assertNotIn(secret, row[0])
        self.assertEqual(len(row[0]), 64)  # SHA-256 hex

    def test_data_plane_key_cannot_manage_keys(self) -> None:
        key = _create_key(["*"])
        expires = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()
        status, resp = _request(
            "POST", "/auth/keys",
            {"name": "x", "dataset_ids": ["a"], "expires_at": expires},
            headers={"X-API-Key": key},
        )
        self.assertEqual(status, 403)
        self.assertEqual(resp["detail"]["error"], "admin_required")

    def test_create_key_validation(self) -> None:
        for bad_body in (
            {"name": "n", "dataset_ids": [],
             "expires_at": "2030-01-01T00:00:00+00:00"},
            {"name": "n", "dataset_ids": ["a"],
             "expires_at": "2000-01-01T00:00:00+00:00"},
            {"name": "n", "dataset_ids": ["a"],
             "expires_at": "2030-01-01T00:00:00"},  # naive datetime
            {"name": "n", "dataset_ids": ["a"],
             "expires_at": "2030-01-01T00:00:00+00:00", "extra": 1},
            {"name": "", "dataset_ids": ["a"],
             "expires_at": "2030-01-01T00:00:00+00:00"},
        ):
            status, _ = _request("POST", "/auth/keys", bad_body, ADMIN_HEADERS)
            self.assertEqual(status, 422, bad_body)

    def test_duplicate_explicit_key_id_conflicts(self) -> None:
        expires = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()
        body = {"name": "n", "key_id": "fixed-client-id",
                "dataset_ids": ["a"], "expires_at": expires}
        status, _ = _request("POST", "/auth/keys", body, ADMIN_HEADERS)
        self.assertEqual(status, 201)
        status, resp = _request("POST", "/auth/keys", body, ADMIN_HEADERS)
        self.assertEqual(status, 409)

    # --- scoping ---

    def test_scoped_key_allows_only_its_datasets(self) -> None:
        key = _create_key(["auth-allowed"])
        h = {"X-API-Key": key}
        self.assertEqual(
            _request("GET", "/budgets/auth-allowed", headers=h)[0], 200
        )
        status, resp = _request("GET", "/budgets/auth-denied", headers=h)
        self.assertEqual(status, 403)
        self.assertEqual(resp["detail"]["error"], "dataset_out_of_scope")

    def test_release_and_transfer_scope(self) -> None:
        key = _create_key(["auth-src", "auth-dst"])
        h = {"X-API-Key": key}
        status, _ = _request(
            "POST", "/releases",
            self._payload("auth-src", "auth-k1"), headers=h)
        self.assertEqual(status, 200)
        status, resp = _request(
            "POST", "/releases",
            self._payload("auth-other", "auth-k2"), headers=h)
        self.assertEqual(status, 403)
        self.assertEqual(resp["detail"]["error"], "dataset_out_of_scope")

        status, _ = _request(
            "POST", "/budgets/transfer",
            {"transfer_id": "auth-tr1", "source_dataset": "auth-src",
             "target_dataset": "auth-dst", "epsilon": 0.1}, headers=h)
        self.assertEqual(status, 200)
        # Both sides must be in scope.
        status, resp = _request(
            "POST", "/budgets/transfer",
            {"transfer_id": "auth-tr2", "source_dataset": "auth-src",
             "target_dataset": "auth-other", "epsilon": 0.1}, headers=h)
        self.assertEqual(status, 403)

    def test_wildcard_scope(self) -> None:
        key = _create_key(["*"])
        h = {"X-API-Key": key}
        for ds in ("auth-any-1", "auth-any-2"):
            self.assertEqual(
                _request("GET", f"/budgets/{ds}", headers=h)[0], 200
            )

    def test_admin_key_accesses_every_dataset(self) -> None:
        status, _ = _request("GET", "/budgets/admin-only-ds")
        self.assertEqual(status, 200)  # default headers carry the admin key

    # --- revocation and expiry ---

    def test_revoked_key_is_rejected_and_delete_idempotent(self) -> None:
        body_expires = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()
        status, body = _request(
            "POST", "/auth/keys",
            {"name": "rev", "dataset_ids": ["auth-rev"],
             "expires_at": body_expires},
            ADMIN_HEADERS,
        )
        self.assertEqual(status, 201, body)
        key = body["api_key"]
        key_id = body["key_id"]
        h = {"X-API-Key": key}
        self.assertEqual(_request("GET", "/budgets/auth-rev", headers=h)[0], 200)
        self.assertEqual(
            _request("DELETE", f"/auth/keys/{key_id}", headers=ADMIN_HEADERS)[0],
            204,
        )
        status, resp = _request("GET", "/budgets/auth-rev", headers=h)
        self.assertEqual(status, 401)
        self.assertEqual(resp["detail"]["error"], "key_revoked")
        # Revoking an unknown/already-revoked key is 404.
        self.assertEqual(
            _request("DELETE", f"/auth/keys/{key_id}", headers=ADMIN_HEADERS)[0],
            404,
        )
        self.assertEqual(
            _request("DELETE", "/auth/keys/never-existed",
                     headers=ADMIN_HEADERS)[0],
            404,
        )

    def test_expired_key_is_rejected(self) -> None:
        # 2-second TTL; wait out the expiry.
        key = _create_key(["auth-exp"], ttl_seconds=2)
        h = {"X-API-Key": key}
        self.assertEqual(_request("GET", "/budgets/auth-exp", headers=h)[0], 200)
        import time
        time.sleep(2.2)
        status, resp = _request("GET", "/budgets/auth-exp", headers=h)
        self.assertEqual(status, 401)
        self.assertEqual(resp["detail"]["error"], "key_expired")

    # --- SQLite concurrency ---

    def test_concurrent_key_creation(self) -> None:
        """Many parallel creates all succeed and yield unique credentials."""
        expires = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()

        def create(i):
            return _request(
                "POST", "/auth/keys",
                {"name": f"cc-{i}", "dataset_ids": [f"cc-{i}"],
                 "expires_at": expires},
                ADMIN_HEADERS,
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(create, range(24)))
        self.assertTrue(all(code == 201 for code, _ in results), results)
        ids = [body["key_id"] for _, body in results]
        secrets_ = [body["api_key"] for _, body in results]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(secrets_), len(set(secrets_)))
        # Every credential authenticates and only sees its own dataset.
        for _, body in results:
            h = {"X-API-Key": body["api_key"]}
            self.assertEqual(
                _request("GET", f"/budgets/{body['dataset_ids'][0]}",
                         headers=h)[0],
                200,
            )

    def test_concurrent_revocation_single_success(self) -> None:
        key = _create_key(["auth-race-revoke"])
        key_id = key.split(".", 1)[0]

        def revoke(_i):
            return _request(
                "DELETE", f"/auth/keys/{key_id}", headers=ADMIN_HEADERS
            )[0]

        with ThreadPoolExecutor(max_workers=16) as pool:
            codes = list(pool.map(revoke, range(16)))
        # Exactly one DELETE marks the key revoked; the rest get 404.
        self.assertEqual(codes.count(204), 1, codes)
        self.assertEqual(codes.count(404), 15, codes)
        status, resp = _request(
            "GET", "/budgets/auth-race-revoke", headers={"X-API-Key": key}
        )
        self.assertEqual(status, 401)
        self.assertEqual(resp["detail"]["error"], "key_revoked")

    def test_concurrent_requests_with_one_key(self) -> None:
        """Authenticating fan-out reads never block on each other (WAL)."""
        key = _create_key(["auth-fan"])
        h = {"X-API-Key": key}

        def call(i):
            return _request(
                "POST", "/releases",
                self._payload("auth-fan", f"auth-fan-{i}"), headers=h
            )[0]

        with ThreadPoolExecutor(max_workers=16) as pool:
            codes = list(pool.map(call, range(16)))
        # Budget 1.0, each 0.1 -> ten succeed, six get 402; none get 401/403.
        self.assertEqual(sorted(codes).count(200), 10, codes)
        self.assertNotIn(401, codes)
        self.assertNotIn(403, codes)



if __name__ == "__main__":
    unittest.main(verbosity=2)
