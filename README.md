# Password Manager Cloud API

Encrypted vault storage for SherLock, deployed on Railway with a persistent
SQLite volume. Encryption and decryption happen only in the desktop client; the
server stores ciphertext and account metadata.

## Security model

- Account passwords are hashed with Argon2id; only the hash is stored.
- Access tokens are short-lived HS256 JWTs (15 minutes). Their `sub` claim is
  the immutable numeric user id, never the username.
- Refresh tokens are random 48-byte values stored only as SHA-256 hashes and
  can be revoked per account (`token_version`).
- A vault belongs to exactly one user. Foreign ids return `404` and cannot be
  claimed or overwritten.
- The server validates the encrypted-vault envelope (`version`, base64 salt,
  nonce and ciphertext) without decrypting it.
- Updates require `expected_version`; the conditional `UPDATE` and the version
  check are atomic, so two clients cannot silently overwrite each other.
- Default vault ids are random. They are not derived from the username.
- Authentication attempts are rate-limited per key. Set `TRUST_PROXY=1` behind
  Railway's edge so the limits use the forwarded client IP.

## Account endpoints

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/auth/register` | Create an account and return access/refresh tokens plus `vault_id`. |
| `POST` | `/v1/auth/login` | Exchange username/password for tokens. |
| `POST` | `/v1/auth/refresh` | Exchange a refresh token for a new access token. |
| `POST` | `/v1/auth/logout` | Revoke all refresh tokens for the account. |
| `GET` | `/v1/auth/me` | Current account and vault summary. |
| `DELETE` | `/v1/auth/me` | Delete the account, its vault and its refresh tokens. |

## Vault endpoints

All vault calls use `Authorization: Bearer <access_token>`.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/vault` | Download the account's vault. |
| `PUT` | `/v1/vault` | Create the first vault or update it with `expected_version`. |
| `GET` | `/v1/vaults/{vault_id}` | Download an explicit vault (owner only). |
| `PUT` | `/v1/vaults/{vault_id}` | Update an explicit vault (owner only, `expected_version` required). |
| `POST` | `/v1/vaults` | Create an explicit vault id (owner only). |
| `DELETE` | `/v1/vaults/{vault_id}` | Delete an explicit vault (owner only). |

Example update:

```http
PUT /v1/vault
Content-Type: application/json
Authorization: Bearer {access_token}

{
  "blob": "{\"salt\":\"...\",\"nonce\":\"...\",\"ciphertext\":\"...\",\"version\":\"1\"}",
  "expected_version": 3
}
```

`expected_version` is mandatory when the vault already exists. A missing or
stale version returns `409`; the client should download or resolve the conflict.

## Configuration

- `SESSION_SECRET` (required): stable secret used to sign JWTs. Rotating it
  signs everyone out.
- `DB_DIR`: directory for `vaults.db` (defaults to `/data` when it exists).
- `CORS_ORIGINS`: optional comma-separated allow-list. No wildcard default.
- `MAX_BLOB_BYTES`: maximum encrypted vault size (default 10 MB).
- `MAX_REQUEST_BODY_SIZE`: maximum HTTP body (default 12 MB).
- `TRUST_PROXY`: set to `1` only when a trusted reverse proxy sets
  `X-Forwarded-For` (Railway does).

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DB_DIR="$(mktemp -d)"
uvicorn app.main:app --reload --port 8000
```

Tests use an isolated temporary database and clean rate-limit state:

```bash
python -m pytest -q
```

## Database

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    vault_id TEXT
);

CREATE TABLE vaults (
    vault_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_digest TEXT NOT NULL,
    blob TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
```

`token_digest` is a legacy column; authentication no longer uses it. Vault rows
with a `NULL` owner are treated as inaccessible and are never auto-claimed.
Older databases are backed up to `vaults.db.bak-<timestamp>` before a schema
upgrade.
