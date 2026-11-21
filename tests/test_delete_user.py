"""Tests for DELETE /v1/auth/me (account deletion) - clears vaults, user, and refresh tokens."""
import hashlib
import os
import sqlite3
import time
import unittest
from contextlib import closing

# Set up environment before importing main
os.environ.setdefault("SESSION_SECRET", "test-secret-for-unit-tests")

from fastapi import status
from starlette.testclient import TestClient

from app.main import app, init_db, get_db_connection

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


def _refresh(client, refresh_token):
    return client.post(
        "/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )


def _get_refresh_token_count(user_id):
    with closing(get_db_connection()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row[0]


class DeleteUserTests(unittest.TestCase):
    def test_delete_user_removes_vault_user_and_refresh_tokens(self):
        """
        Register -> DELETE /v1/auth/me returns 204 -> login fails with 401
        -> refresh with old token fails with 401 -> no rows left in refresh_tokens.
        """
        username = f"test-del-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
        password = "securePassword123!"

        # Register
        reg = _register_user(client, username, password)
        self.assertEqual(reg.status_code, status.HTTP_201_CREATED)
        reg_data = reg.json()
        user_id = reg_data["user_id"]
        refresh_token = reg_data["refresh_token"]

        # Login to get access token
        login = _login(client, username, password)
        self.assertEqual(login.status_code, status.HTTP_200_OK)
        login_data = login.json()
        access_token = login_data["access_token"]

        # Delete the user
        delete = client.delete(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(delete.status_code, status.HTTP_204_NO_CONTENT)

        # Login should fail with 401
        login_after = _login(client, username, password)
        self.assertEqual(login_after.status_code, status.HTTP_401_UNAUTHORIZED)

        # Refresh with old token should fail with 401
        refresh_after = _refresh(client, refresh_token)
        self.assertEqual(refresh_after.status_code, status.HTTP_401_UNAUTHORIZED)

        # No rows left in refresh_tokens for that user
        count = _get_refresh_token_count(user_id)
        self.assertEqual(count, 0)

    def test_delete_user_with_vault(self):
        """Delete a user who has uploaded a vault - vault should be deleted too."""
        username = f"test-del-vault-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
        password = "securePassword123!"

        # Register and login
        reg = _register_user(client, username, password)
        self.assertEqual(reg.status_code, status.HTTP_201_CREATED)
        login = _login(client, username, password)
        self.assertEqual(login.status_code, status.HTTP_200_OK)
        login_data = login.json()
        access_token = login_data["access_token"]

        # Upload a vault
        upload = client.put(
            "/v1/vault",
            json={"blob": valid_blob(b"encrypted-vault-data")},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(upload.status_code, status.HTTP_200_OK)

        # Verify vault exists
        get_vault = client.get(
            "/v1/vault",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(get_vault.status_code, status.HTTP_200_OK)

        # Delete the user
        delete = client.delete(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(delete.status_code, status.HTTP_204_NO_CONTENT)

        # Login again to check vault is gone
        login_after = _login(client, username, password)
        # User should be deleted, so login fails
        self.assertEqual(login_after.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_user_without_vault(self):
        """Delete a user who registered but never uploaded a vault."""
        username = f"test-del-novault-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"
        password = "securePassword123!"

        # Register and login
        reg = _register_user(client, username, password)
        self.assertEqual(reg.status_code, status.HTTP_201_CREATED)
        login = _login(client, username, password)
        self.assertEqual(login.status_code, status.HTTP_200_OK)
        login_data = login.json()
        access_token = login_data["access_token"]

        # Verify vault does not exist
        get_vault = client.get(
            "/v1/vault",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(get_vault.status_code, status.HTTP_404_NOT_FOUND)

        # Delete the user (should work even without vault)
        delete = client.delete(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(delete.status_code, status.HTTP_204_NO_CONTENT)

        # Login should fail
        login_after = _login(client, username, password)
        self.assertEqual(login_after.status_code, status.HTTP_401_UNAUTHORIZED)


if __name__ == "__main__":
    unittest.main()
