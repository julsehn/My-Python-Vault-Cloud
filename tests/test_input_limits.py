"""Tests for input validation limits (Part 8)."""
import hashlib
import os
import time
import unittest
from collections import defaultdict, deque

os.environ.setdefault("SESSION_SECRET", "test-secret-for-unit-tests")

from fastapi import status
from starlette.testclient import TestClient

from app.main import app, init_db, MAX_BLOB_BYTES, MAX_REQUEST_BODY_SIZE

from helpers import valid_blob

init_db()
client = TestClient(app)


def _register_user(client, username, password):
    return client.post(
        "/v1/auth/register",
        json={"username": username, "password": password, "email": f"{username}@example.com"},
    )


def _login(client, username, password):
    return client.post(
        "/v1/auth/login",
        json={"username": username, "password": password},
    )


class InputLimitsTests(unittest.TestCase):
    def test_request_body_too_large(self):
        """Request with Content-Length > MAX_REQUEST_BODY_SIZE returns 413."""
        large_body = "a" * (MAX_REQUEST_BODY_SIZE + 1)
        response = client.post(
            "/v1/auth/register",
            content=large_body.encode("utf-8"),
            headers={"content-length": str(len(large_body))},
        )
        self.assertEqual(response.status_code, 413)

    def test_register_password_too_long(self):
        """Registration with 129-character password returns 422."""
        long_password = "a" * 129
        username = f"test-user-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
        response = client.post(
            "/v1/auth/register",
            json={"username": username, "password": long_password},
        )
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def test_register_password_at_limit(self):
        """Registration with 128-character password succeeds."""
        password = "Aa1!" + "a" * 124
        username = f"test-user-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
        response = client.post(
            "/v1/auth/register",
            json={"username": username, "password": password, "email": f"{username}@example.com"},
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_login_password_too_long(self):
        """Login with 129-character password returns 422."""
        long_password = "a" * 129
        username = "any-username"
        response = client.post(
            "/v1/auth/login",
            json={"username": username, "password": long_password},
        )
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)

    def test_register_vault_duplicate_returns_409(self):
        """Registering the same vault_id twice returns 409 Conflict."""
        username = f"test-vault-user-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
        password = "securePassword123!"

        _register_user(client, username, password)
        login_response = _login(client, username, password)
        tokens = login_response.json()
        token = tokens["access_token"]

        vault_id = f"vault-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"

        first_response = client.post(
            "/v1/vaults",
            json={"vault_id": vault_id, "blob": valid_blob(b"encrypted-data")},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(first_response.status_code, status.HTTP_201_CREATED)

        second_response = client.post(
            "/v1/vaults",
            json={"vault_id": vault_id, "blob": valid_blob(b"encrypted-data-again")},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(second_response.status_code, status.HTTP_409_CONFLICT)

    def test_blob_size_exceeded_returns_413(self):
        """Uploading a vault with blob > MAX_BLOB_BYTES returns 413."""
        username = f"test-blob-user-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
        password = "securePassword123!"

        _register_user(client, username, password)
        login_response = _login(client, username, password)
        tokens = login_response.json()
        token = tokens["access_token"]

        vault_id = f"vault-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"

        large_blob = "a" * (MAX_BLOB_BYTES + 1)
        response = client.post(
            "/v1/vaults",
            json={"vault_id": vault_id, "blob": large_blob},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)


if __name__ == "__main__":
    unittest.main()