"""Regression tests for the 2026-11 security review findings."""
import hashlib
import time
import unittest
from contextlib import closing

from fastapi import status
from starlette.testclient import TestClient

from app.main import app, get_db_connection

from helpers import valid_blob

client = TestClient(app)


def _unique(prefix: str) -> str:
    return f"{prefix}-{hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:10]}"


def _register(username: str, password: str = "securePassword123!"):
    return client.post(
        "/v1/auth/register",
        json={"username": username, "password": password},
    )


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TokenIdentityTests(unittest.TestCase):
    def test_old_access_token_is_rejected_after_username_reuse(self):
        username = _unique("reuse")
        first = _register(username)
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        old_token = first.json()["access_token"]
        old_refresh = first.json()["refresh_token"]

        self.assertEqual(
            client.delete("/v1/auth/me", headers=_auth(old_token)).status_code,
            status.HTTP_204_NO_CONTENT,
        )

        second = _register(username, "anotherPassword123!")
        self.assertEqual(second.status_code, status.HTTP_201_CREATED)

        self.assertEqual(
            client.get("/v1/auth/me", headers=_auth(old_token)).status_code,
            status.HTTP_401_UNAUTHORIZED,
        )
        self.assertEqual(
            client.post("/v1/auth/refresh", json={"refresh_token": old_refresh}).status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_jwt_subject_is_the_immutable_user_id(self):
        username = _unique("subject")
        response = _register(username)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        body = response.json()

        import jwt

        from app.main import ALGORITHM, SECRET_KEY

        payload = jwt.decode(body["access_token"], SECRET_KEY, algorithms=[ALGORITHM])
        self.assertEqual(payload["sub"], str(body["user_id"]))
        self.assertNotEqual(payload["sub"], username)


class VaultAuthorizationTests(unittest.TestCase):
    def test_cross_user_vault_is_not_accessible(self):
        owner_name = _unique("owner")
        attacker_name = _unique("attacker")
        owner = _register(owner_name).json()
        attacker = _register(attacker_name).json()

        upload = client.put(
            "/v1/vault",
            json={"blob": valid_blob(b"owner-secret")},
            headers=_auth(owner["access_token"]),
        )
        self.assertEqual(upload.status_code, status.HTTP_200_OK)
        vault_id = upload.json()["vault_id"]

        self.assertEqual(
            client.get(f"/v1/vaults/{vault_id}", headers=_auth(attacker["access_token"])).status_code,
            status.HTTP_404_NOT_FOUND,
        )
        self.assertEqual(
            client.put(
                f"/v1/vaults/{vault_id}",
                json={"blob": valid_blob(b"attacker"), "expected_version": 1},
                headers=_auth(attacker["access_token"]),
            ).status_code,
            status.HTTP_409_CONFLICT,
        )
        self.assertEqual(
            client.delete(f"/v1/vaults/{vault_id}", headers=_auth(attacker["access_token"])).status_code,
            status.HTTP_404_NOT_FOUND,
        )
        still_there = client.get("/v1/vault", headers=_auth(owner["access_token"]))
        self.assertEqual(still_there.status_code, status.HTTP_200_OK)
        self.assertEqual(still_there.json()["version"], 1)

    def test_orphan_vault_is_not_claimable(self):
        # Legacy databases can still contain rows whose user_id is NULL.
        # The new schema forbids it, so exercise the storage layer directly
        # against a temporary legacy database.
        import sqlite3
        import tempfile
        from pathlib import Path

        from app import main as cloud

        vault_id = "vault_orphan_legacy_1"
        legacy_dir = Path(tempfile.mkdtemp(prefix="sherlock-legacy-"))
        legacy_db = legacy_dir / "vaults.db"
        with sqlite3.connect(legacy_db) as conn:
            conn.execute(
                "CREATE TABLE vaults (vault_id TEXT PRIMARY KEY, user_id INTEGER, "
                "token_digest TEXT NOT NULL, blob TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, "
                "updated_at TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO vaults VALUES (?, NULL, 'test', ?, 1, '2026-01-01T00:00:00+00:00')",
                (vault_id, valid_blob(b"orphan")),
            )
            conn.commit()

        original_path = cloud.DB_PATH
        original_dir = cloud.DB_DIR
        cloud.DB_PATH = legacy_db
        cloud.DB_DIR = legacy_dir
        try:
            self.assertIsNone(cloud.vault_storage.get_vault_by_id(vault_id, user_id=1))
            with self.assertRaises(Exception) as error:
                cloud.vault_storage.upsert_vault(
                    vault_id=vault_id,
                    blob=valid_blob(b"claim"),
                    user_id=1,
                    expected_version=1,
                )
            self.assertEqual(getattr(error.exception, "status_code", None), 409)
        finally:
            cloud.DB_PATH = original_path
            cloud.DB_DIR = original_dir


class VaultVersionTests(unittest.TestCase):
    def test_overwrite_requires_the_current_version(self):
        username = _unique("version")
        user = _register(username).json()
        headers = _auth(user["access_token"])

        first = client.put("/v1/vault", json={"blob": valid_blob(b"v1")}, headers=headers)
        self.assertEqual(first.status_code, status.HTTP_200_OK)
        self.assertEqual(first.json()["version"], 1)

        blind = client.put("/v1/vault", json={"blob": valid_blob(b"blind")}, headers=headers)
        self.assertEqual(blind.status_code, status.HTTP_409_CONFLICT)

        updated = client.put(
            "/v1/vault",
            json={"blob": valid_blob(b"v2"), "expected_version": 1},
            headers=headers,
        )
        self.assertEqual(updated.status_code, status.HTTP_200_OK)
        self.assertEqual(updated.json()["version"], 2)

        stale = client.put(
            "/v1/vault",
            json={"blob": valid_blob(b"stale"), "expected_version": 1},
            headers=headers,
        )
        self.assertEqual(stale.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(client.get("/v1/vault", headers=headers).json()["version"], 2)


class BlobValidationTests(unittest.TestCase):
    def test_empty_and_malformed_blobs_are_rejected(self):
        username = _unique("blob")
        user = _register(username).json()
        headers = _auth(user["access_token"])
        vault_id = f"vault-{hashlib.sha256(username.encode()).hexdigest()[:8]}"

        for blob in ("", "not json", '{"salt":"AA==","nonce":"AA==","ciphertext":"AA==","version":"1"}'):
            response = client.post(
                "/v1/vaults",
                json={"vault_id": vault_id, "blob": blob},
                headers=headers,
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                msg=f"blob should be rejected: {blob[:20]!r}",
            )

        accepted = client.post(
            "/v1/vaults",
            json={"vault_id": vault_id, "blob": valid_blob()},
            headers=headers,
        )
        self.assertEqual(accepted.status_code, status.HTTP_201_CREATED)


if __name__ == "__main__":
    unittest.main()
