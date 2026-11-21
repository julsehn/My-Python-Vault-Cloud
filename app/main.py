"""Password Manager Cloud API - FastAPI Backend for Railway.

Official Cloud synchronization backend:
- Zero-knowledge storage: only stores encrypted blobs and user authentication credentials.
- Client-side encryption ensures user passwords are never known by the server.
"""
import base64
import binascii
import json
import os
import re
import sqlite3
import hashlib
import ipaddress
import secrets
import shutil
import time
from collections import defaultdict, deque
from contextlib import closing
from threading import Lock
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.exceptions import RequestValidationError
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, timedelta, timezone
from pathlib import Path
import jwt
from argon2 import PasswordHasher, exceptions as argon2_exceptions

# JWT & Security Configuration
SECRET_KEY = os.environ.get("SESSION_SECRET") or os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SESSION_SECRET must be configured before starting the cloud API")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30
PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# A fixed hash keeps the login path timing-similar for unknown usernames.
DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash("sherlock-timing-equalizer")
AUTH_RATE_LIMIT = 10
AUTH_RATE_WINDOW_SECONDS = 900
REFRESH_RATE_LIMIT = 120
REFRESH_IP_RATE_LIMIT = 300
MAX_RATE_LIMIT_KEYS = 10_000
# Railway terminates TLS at its edge and sets X-Forwarded-For. Only trust that
# header when the deployment explicitly declares a trusted proxy.
TRUST_PROXY = os.environ.get("TRUST_PROXY", "").lower() in {"1", "true", "yes"}
_auth_attempts: dict[str, deque[float]] = defaultdict(deque)
_auth_attempts_lock = Lock()

# Database Configuration
raw_db_dir = os.environ.get("DB_DIR", "/data" if os.path.exists("/data") else ".")
DB_DIR = Path(raw_db_dir)
try:
    DB_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    DB_DIR = Path(".")
DB_PATH = DB_DIR / "vaults.db"

MAX_BLOB_BYTES = int(os.environ.get("MAX_BLOB_BYTES", str(10 * 1024 * 1024)))
MAX_REQUEST_BODY_SIZE = int(os.environ.get("MAX_REQUEST_BODY_SIZE", str(12 * 1024 * 1024)))
VAULT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


def get_db_connection() -> sqlite3.Connection:
    """Get a database connection with WAL mode."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Initialize database tables with automatic migration."""
    with closing(get_db_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                token_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                vault_id TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vaults (
                vault_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_digest TEXT NOT NULL,
                blob TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            )
            """
        )
        # Older databases need a few columns. Several workers can start at
        # the same time, so re-check and tolerate a concurrent ALTER.
        def add_column(table: str, column: str, definition: str) -> None:
            columns = {
                row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
            }
            if column in columns:
                return
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
            except sqlite3.OperationalError as error:
                if "duplicate column name" not in str(error).lower():
                    raise

        # Never assign a default owner: a vault without an owner stays
        # inaccessible.
        add_column("vaults", "user_id", "user_id INTEGER")
        add_column("users", "token_version", "token_version INTEGER NOT NULL DEFAULT 0")
        add_column("users", "vault_id", "vault_id TEXT")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vaults_user ON vaults(user_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)"
        )
        conn.commit()


def backup_db_before_migration() -> None:
    """Keep a copy of an older database before the schema is upgraded."""
    if not DB_PATH.exists():
        return
    try:
        with sqlite3.connect(DB_PATH) as conn:
            vaults = {row[1] for row in conn.execute("PRAGMA table_info(vaults)")}
            users = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    except sqlite3.Error:
        return
    if not vaults or not users:
        return
    if "user_id" in vaults and "token_version" in users and "vault_id" in users:
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = DB_PATH.with_name(f"{DB_PATH.name}.bak-{stamp}")
    try:
        shutil.copy2(DB_PATH, backup_path)
    except OSError:
        pass


backup_db_before_migration()

# Run DB initialization
init_db()


def hash_password(password: str) -> str:
    """Hash account passwords with Argon2id."""
    return PASSWORD_HASHER.hash(password)


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify Argon2id account password hashes."""
    if stored_hash.startswith("$argon2id$"):
        try:
            return PASSWORD_HASHER.verify(stored_hash, plain_password)
        except argon2_exceptions.VerificationError:
            return False
    return False


def client_ip(request: Request) -> str:
    """Return the client IP, trusting the proxy header only when configured.

    With one trusted reverse proxy the closest (last) address is the one the
    proxy observed. Validate it so a forged header cannot become a rate-limit
    key or grow the in-memory map with arbitrary strings.
    """
    if TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            candidate = forwarded.rsplit(",", 1)[-1].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass
    return request.client.host if request.client else "unknown"


def enforce_auth_rate_limit(
    key: str,
    limit: int = AUTH_RATE_LIMIT,
    window_seconds: int = AUTH_RATE_WINDOW_SECONDS,
) -> None:
    now = time.monotonic()
    with _auth_attempts_lock:
        attempts = _auth_attempts[key]
        while attempts and now - attempts[0] >= window_seconds:
            attempts.popleft()
        if len(attempts) >= limit:
            raise HTTPException(status_code=429, detail="Massa intents. Torna-ho a provar més tard.")
        attempts.append(now)

        if len(_auth_attempts) > MAX_RATE_LIMIT_KEYS:
            for stale_key in [
                existing
                for existing, values in _auth_attempts.items()
                if not values or now - values[-1] >= window_seconds
            ]:
                _auth_attempts.pop(stale_key, None)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = int(time.time()) + REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    with closing(get_db_connection()) as conn:
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, expires_at),
        )
        conn.commit()
    return token


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="El token ha caducat")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invàlid")


def get_user_by_username(username: str) -> Optional[dict]:
    with closing(get_db_connection()) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    with closing(get_db_connection()) as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def compute_user_vault_id(user_id: int, _username: str = "") -> str:
    """Return the user's vault id, creating an unpredictable one on first use.

    The id used to be derived from the sequential user id and the public
    username, which let an attacker pre-register a victim's id. It is now
    random and stored server-side.
    """
    with closing(get_db_connection()) as conn:
        user = conn.execute(
            "SELECT vault_id FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        existing = conn.execute(
            "SELECT vault_id FROM vaults WHERE user_id = ? ORDER BY updated_at DESC, version DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        vault_id = (
            existing["vault_id"]
            if existing
            else (user["vault_id"] if user and user["vault_id"] else None)
        )
        if not vault_id:
            vault_id = f"vault_{secrets.token_hex(16)}"
        if not user or user["vault_id"] != vault_id:
            conn.execute(
                "UPDATE users SET vault_id = ? WHERE id = ?", (vault_id, user_id)
            )
            conn.commit()
        return vault_id


# Storage Manager
class VaultStorage:
    def __init__(self):
        pass

    def get_vault_by_user_id(self, user_id: int) -> Optional[dict]:
        with closing(get_db_connection()) as conn:
            row = conn.execute(
                "SELECT * FROM vaults WHERE user_id = ? ORDER BY updated_at DESC, version DESC LIMIT 1",
                (user_id,),
            ).fetchone()
            if row:
                return dict(row)
            return None

    def get_vault_by_id(self, vault_id: str, user_id: Optional[int] = None) -> Optional[dict]:
        with closing(get_db_connection()) as conn:
            row = conn.execute("SELECT * FROM vaults WHERE vault_id = ?", (vault_id,)).fetchone()
            if not row:
                return None
            res = dict(row)
            if user_id is not None:
                owner = res.get("user_id")
                # A vault without an owner is not claimable by anyone.
                if owner is None or owner != user_id:
                    return None
            return res

    def upsert_vault(self, vault_id: str, blob: str, user_id: int, expected_version: Optional[int] = None) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        token_digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()

        with closing(get_db_connection()) as conn:
            current = conn.execute("SELECT * FROM vaults WHERE vault_id = ?", (vault_id,)).fetchone()
            if current:
                owner = current["user_id"]
                if owner is None or owner != user_id:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Aquest identificador ja està en ús",
                    )
                if expected_version is None:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Cal la versió del núvol per sobreescriure una SherLock existent",
                    )
                new_version = current["version"] + 1
                cursor = conn.execute(
                    """
                    UPDATE vaults
                    SET blob = ?, version = version + 1, updated_at = ?, user_id = ?
                    WHERE vault_id = ? AND version = ?
                    """,
                    (blob, now, user_id, vault_id, expected_version),
                )
                if cursor.rowcount != 1:
                    conn.rollback()
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Conflicte de versió: la SherLock ha canviat mentrestant",
                    )
                conn.commit()
                return {
                    "vault_id": vault_id,
                    "blob": blob,
                    "version": new_version,
                    "updated_at": now,
                }
            try:
                conn.execute(
                    """
                    INSERT INTO vaults (vault_id, token_digest, blob, version, updated_at, user_id)
                    VALUES (?, ?, ?, 1, ?, ?)
                    """,
                    (vault_id, token_digest, blob, now, user_id),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Aquest identificador ja està en ús",
                )
            return {
                "vault_id": vault_id,
                "blob": blob,
                "version": 1,
                "updated_at": now,
            }

    def delete_vault(self, vault_id: str, user_id: int) -> bool:
        with closing(get_db_connection()) as conn:
            current = conn.execute("SELECT * FROM vaults WHERE vault_id = ?", (vault_id,)).fetchone()
            if not current or current["user_id"] is None or current["user_id"] != user_id:
                return False
            cursor = conn.execute(
                "DELETE FROM vaults WHERE vault_id = ? AND user_id = ?",
                (vault_id, user_id),
            )
            conn.commit()
            return cursor.rowcount == 1


vault_storage = VaultStorage()

# App Definition
app = FastAPI(
    title="SherLock Cloud API",
    description="Oficial Railway Synchronization Backend - Zero-knowledge encrypted vault storage",
    version="1.1.0",
)

@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(_request: Request, exc: RequestValidationError):
    """Never echo request values (passwords, blobs) in validation errors."""
    errors = [
        {"loc": error.get("loc"), "msg": error.get("msg"), "type": error.get("type")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})

cors_origins = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def check_request_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    # Mutating requests must declare their size; this closes the chunked-body
    # bypass of the Content-Length check.
    if request.method in {"POST", "PUT", "PATCH"} and content_length is None:
        return JSONResponse(status_code=411, content={"detail": "Cal Content-Length"})
    if content_length is not None:
        try:
            size = int(content_length)
            if size < 0 or size > MAX_REQUEST_BODY_SIZE:
                return JSONResponse(status_code=413, content={"detail": "Contingut massa gran"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Content-Length invàlid"})
    return await call_next(request)


security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    """Validate Bearer JWT token and return authenticated user."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticació requerida (falta token Bearer)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_token(token)
    subject = payload.get("sub")
    try:
        user_id = int(subject)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no vàlid")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuari no trobat")
    if payload.get("ver") != user.get("token_version", 0):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessió revocada")
    return user


def validate_vault_id(vault_id: str) -> str:
    if not VAULT_ID_PATTERN.fullmatch(vault_id):
        raise HTTPException(status_code=400, detail="Format d'identificador de SherLock invàlid")
    return vault_id


def check_blob_size(blob: str) -> None:
    if len(blob.encode("utf-8")) > MAX_BLOB_BYTES:
        raise HTTPException(status_code=413, detail="La SherLock encriptada és massa gran")


def validate_blob(blob: str) -> None:
    """Validate the encrypted vault envelope without decrypting it.

    The server never sees plaintext, but it can still refuse empty or
    malformed blobs that would later crash a client or erase local data.
    """
    check_blob_size(blob)
    if len(blob) < 128:
        raise HTTPException(status_code=422, detail="La SherLock encriptada és buida o massa curta")
    try:
        envelope = json.loads(blob)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="La SherLock encriptada no és un JSON vàlid")
    if not isinstance(envelope, dict) or envelope.get("version") != "1":
        raise HTTPException(status_code=422, detail="Format de SherLock no suportat")
    for field, expected_length in (("salt", 16), ("nonce", 12)):
        value = envelope.get(field)
        if not isinstance(value, str):
            raise HTTPException(status_code=422, detail=f"Falta el camp {field} de la SherLock")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=422, detail=f"El camp {field} no és base64 vàlid")
        if len(decoded) != expected_length:
            raise HTTPException(status_code=422, detail=f"El camp {field} té una longitud incorrecta")
    ciphertext = envelope.get("ciphertext")
    if not isinstance(ciphertext, str):
        raise HTTPException(status_code=422, detail="Falta el camp ciphertext de la SherLock")
    try:
        decoded_ciphertext = base64.b64decode(ciphertext, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=422, detail="El camp ciphertext no és base64 vàlid")
    if len(decoded_ciphertext) < 17:
        raise HTTPException(status_code=422, detail="La SherLock encriptada és massa curta")


# Request & Response Models
class RegisterVaultRequest(BaseModel):
    vault_id: str = Field(..., min_length=1)
    blob: str = Field(...)
    token: Optional[str] = None


class GetVaultResponse(BaseModel):
    vault_id: str
    blob: str
    version: int
    updated_at: str


class VaultBlobRequest(BaseModel):
    blob: str = Field(...)
    expected_version: Optional[int] = Field(default=None, ge=0)


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=12, max_length=128)
    email: Optional[EmailStr] = None


class UserLoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(..., max_length=128)


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=32, max_length=256)


class UserResponse(BaseModel):
    user_id: int
    username: str
    email: Optional[str] = None
    access_token: str
    refresh_token: str
    vault_id: str
    token_type: str = "bearer"


# Routes
@app.get("/")
@app.get("/healthz")
async def health_check():
    """Health check endpoint for Railway and clients."""
    return {"status": "ok", "service": "SherLock Cloud API (Railway)", "version": "1.1.0"}


@app.get("/v1/auth/check-username/{username}")
async def check_username_availability(username: str, http_request: Request):
    """Check if a username is already taken. Returns available: true/false."""
    enforce_auth_rate_limit(f"username-check:{client_ip(http_request)}", limit=60)
    if len(username) < 3 or len(username) > 50:
        return {"available": False, "reason": "invalid_length"}
    existing = get_user_by_username(username)
    if existing:
        return {"available": False, "reason": "taken"}
    return {"available": True}


@app.post("/v1/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(payload: UserRegisterRequest, http_request: Request):
    """Register a new user account on the official Railway cloud."""
    enforce_auth_rate_limit(f"register:{client_ip(http_request)}")
    existing = get_user_by_username(payload.username)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Aquest nom d'usuari ja existeix")

    now = datetime.now(timezone.utc).isoformat()
    p_hash = await run_in_threadpool(hash_password, payload.password)

    with closing(get_db_connection()) as conn:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, email, created_at) VALUES (?, ?, ?, ?)",
            (payload.username, p_hash, payload.email, now),
        )
        conn.commit()
        user_id = cursor.lastrowid

    token = create_access_token(data={"sub": str(user_id), "ver": 0})
    refresh_token = create_refresh_token(user_id)
    vault_id = compute_user_vault_id(user_id, payload.username)

    return UserResponse(
        user_id=user_id,
        username=payload.username,
        email=payload.email,
        access_token=token,
        refresh_token=refresh_token,
        vault_id=vault_id,
        token_type="bearer",
    )


@app.post("/v1/auth/login", response_model=UserResponse)
async def login_user(payload: UserLoginRequest, http_request: Request):
    """Authenticate with username and password, returning JWT access token."""
    enforce_auth_rate_limit(f"login:{client_ip(http_request)}:{payload.username.casefold()}")
    user = get_user_by_username(payload.username)
    stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    password_ok = await run_in_threadpool(verify_password, payload.password, stored_hash)
    if not user or not password_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuari o contrasenya incorrectes")

    token = create_access_token(
        data={"sub": str(user["id"]), "ver": user.get("token_version", 0)}
    )
    refresh_token = create_refresh_token(user["id"])
    vault_id = compute_user_vault_id(user["id"], user["username"])

    return UserResponse(
        user_id=user["id"],
        username=user["username"],
        email=user["email"],
        access_token=token,
        refresh_token=refresh_token,
        vault_id=vault_id,
        token_type="bearer",
    )


@app.post("/v1/auth/refresh", response_model=UserResponse)
async def refresh_access_token(payload: RefreshTokenRequest, http_request: Request):
    token_hash = hashlib.sha256(payload.refresh_token.encode("utf-8")).hexdigest()
    enforce_auth_rate_limit(f"refresh-token:{token_hash[:32]}", limit=REFRESH_RATE_LIMIT)
    enforce_auth_rate_limit(
        f"refresh-ip:{client_ip(http_request)}",
        limit=REFRESH_IP_RATE_LIMIT,
    )
    with closing(get_db_connection()) as conn:
        row = conn.execute(
            "SELECT * FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
    if not row or row["revoked_at"] is not None or row["expires_at"] <= int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invàlid")
    user = get_user_by_id(row["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuari no trobat")
    return UserResponse(
        user_id=user["id"],
        username=user["username"],
        email=user["email"],
        access_token=create_access_token(
            data={"sub": str(user["id"]), "ver": user.get("token_version", 0)}
        ),
        refresh_token=payload.refresh_token,
        vault_id=compute_user_vault_id(user["id"], user["username"]),
        token_type="bearer",
    )


@app.post("/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_refresh_token(payload: RefreshTokenRequest):
    token_hash = hashlib.sha256(payload.refresh_token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with closing(get_db_connection()) as conn:
        row = conn.execute(
            "SELECT user_id FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                (now, row["user_id"]),
            )
            conn.execute(
                "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
                (row["user_id"],),
            )
            conn.commit()
    return None


@app.get("/v1/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    """Get current authenticated user info and associated vault."""
    vault_id = compute_user_vault_id(user["id"], user["username"])
    vault = vault_storage.get_vault_by_user_id(user["id"])
    return {
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "vault_id": vault_id,
        "has_vault": vault is not None,
        "vault_version": vault["version"] if vault else 0,
        "updated_at": vault["updated_at"] if vault else None,
    }


@app.delete("/v1/auth/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_me(user: dict = Depends(get_current_user)):
    """Delete the current authenticated user and all their vaults (GDPR right to erasure)."""
    user_id = user["id"]
    with closing(get_db_connection()) as conn:
        conn.execute(
            "UPDATE users SET token_version = token_version + 1 WHERE id = ?", (user_id,)
        )
        conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM vaults WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    return None


# User-centric vault endpoints (no manual vault_id needed!)
@app.get("/v1/vault", response_model=GetVaultResponse)
async def get_my_vault(user: dict = Depends(get_current_user)):
    """Retrieve the current user's encrypted vault."""
    vault = vault_storage.get_vault_by_user_id(user["id"])
    if not vault:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Encara no hi ha cap SherLock desada per aquest usuari")
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


@app.put("/v1/vault", response_model=GetVaultResponse)
async def upload_my_vault(
    payload: VaultBlobRequest,
    user: dict = Depends(get_current_user),
):
    """Upload or sync the current user's encrypted vault."""
    validate_blob(payload.blob)
    vault_id = compute_user_vault_id(user["id"], user["username"])
    vault = vault_storage.upsert_vault(
        vault_id=vault_id,
        blob=payload.blob,
        user_id=user["id"],
        expected_version=payload.expected_version,
    )
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


# Explicit vault_id endpoints
@app.post("/v1/vaults", response_model=GetVaultResponse, status_code=status.HTTP_201_CREATED)
async def register_vault(
    request: RegisterVaultRequest,
    user: dict = Depends(get_current_user),
):
    """Register or initialize a vault with a specific ID."""
    v_id = validate_vault_id(request.vault_id)
    validate_blob(request.blob)

    existing = vault_storage.get_vault_by_id(v_id, user_id=user["id"])
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Aquest identificador de SherLock ja existeix per a aquest usuari",
        )

    vault = vault_storage.upsert_vault(
        vault_id=v_id,
        blob=request.blob,
        user_id=user["id"],
        expected_version=None,
    )
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


@app.get("/v1/vaults/{vault_id}", response_model=GetVaultResponse)
async def get_vault(
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Download encrypted vault by ID."""
    v_id = validate_vault_id(vault_id)
    vault = vault_storage.get_vault_by_id(v_id, user_id=user["id"])
    if not vault:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SherLock no trobat")
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


@app.put("/v1/vaults/{vault_id}", response_model=GetVaultResponse)
async def upload_vault(
    payload: VaultBlobRequest,
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Upload or update encrypted vault by ID."""
    v_id = validate_vault_id(vault_id)
    validate_blob(payload.blob)
    vault = vault_storage.upsert_vault(
        vault_id=v_id,
        blob=payload.blob,
        user_id=user["id"],
        expected_version=payload.expected_version,
    )
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


@app.delete("/v1/vaults/{vault_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vault(
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Delete a vault from Railway cloud."""
    v_id = validate_vault_id(vault_id)
    deleted = vault_storage.delete_vault(v_id, user["id"])
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SherLock no trobat")
    return None


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
