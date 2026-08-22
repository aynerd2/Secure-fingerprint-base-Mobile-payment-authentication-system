"""
SFMPAS backend — FIDO2-style transaction authorisation with CBN KYC tiering.

Endpoints
---------
    POST /register              enrol a user + their EC P-256 public key
    POST /authenticate/begin    issue a signing challenge, resolve the KYC tier
    POST /authenticate/complete verify the assertion, record the transaction
    GET  /transactions          transaction history for a user

Database
--------
PostgreSQL, reached via the DATABASE_URL environment variable that Render sets
automatically when a database is linked to the service. Falls back to discrete
PG* / DB_* variables for local development.

The schema is applied on startup from schema.sql: Render does not run init
scripts against a managed database, so the application bootstraps itself. Every
statement in that file is idempotent, so restarts and redeploys are safe.

Privacy
-------
No fingerprint image, template, or minutiae ever reaches this service. The
handset matches the finger locally and signs a server-issued challenge with a
Keystore-held private key; only the PUBLIC key and the signature cross the wire.

Crypto contract with the Android client
---------------------------------------
    key       EC P-256 ("secp256r1"), public half as X.509 SubjectPublicKeyInfo,
              base64 — exactly what Java's `PublicKey.getEncoded()` returns.
    signature "SHA256withECDSA" as produced by java.security.Signature, i.e.
              DER-encoded ASN.1 (r, s), base64.
    payload   the raw bytes of the base64-decoded `challenge` from
              /authenticate/begin — nothing prepended, appended, or re-hashed.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import secrets
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Optional

import psycopg2
import psycopg2.extras
import psycopg2.pool
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def database_dsn() -> str:
    """
    Render injects DATABASE_URL when a database is linked to the service.

    Render (like Heroku) still hands out the legacy `postgres://` scheme in some
    places; SQLAlchemy rejects that, and while psycopg2 accepts it we normalise
    anyway so the value is safe to reuse elsewhere.
    """
    url = os.getenv("DATABASE_URL")
    if url:
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        return url

    # Local development fallback.
    host = os.getenv("PGHOST", os.getenv("DB_HOST", "127.0.0.1"))
    port = os.getenv("PGPORT", os.getenv("DB_PORT", "5432"))
    user = os.getenv("PGUSER", os.getenv("DB_USER", "sfmpas"))
    password = os.getenv("PGPASSWORD", os.getenv("DB_PASSWORD", "sfmpas_dev_password"))
    name = os.getenv("PGDATABASE", os.getenv("DB_NAME", "sfmpas"))
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


DATABASE_DSN = database_dsn()
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "300"))
CHALLENGE_BYTES = 32
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "900"))
DB_STARTUP_RETRIES = int(os.getenv("DB_STARTUP_RETRIES", "30"))
APPLY_SCHEMA_ON_STARTUP = os.getenv("APPLY_SCHEMA_ON_STARTUP", "true").lower() == "true"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("sfmpas")

# ---------------------------------------------------------------------------
# CBN KYC tiering
# ---------------------------------------------------------------------------

TIER_1_CEILING = 50_000
TIER_2_CEILING = 200_000


class KycTier(str, Enum):
    TIER_1 = "TIER_1"
    TIER_2 = "TIER_2"
    TIER_3 = "TIER_3"

    @property
    def requirement(self) -> str:
        return {
            KycTier.TIER_1: "Fingerprint only",
            KycTier.TIER_2: "Fingerprint + liveness check",
            KycTier.TIER_3: "Fingerprint + liveness + enhanced verification",
        }[self]

    @property
    def requires_liveness(self) -> bool:
        return self is not KycTier.TIER_1

    @property
    def requires_enhanced(self) -> bool:
        return self is KycTier.TIER_3


def tier_for_amount(amount_naira: int) -> KycTier:
    """
    Below 50,000        -> Tier 1
    50,000 .. 200,000   -> Tier 2   (both bounds inclusive)
    Above 200,000       -> Tier 3

    Mirrors KycTier.forAmount() in the Android client exactly; the two must not
    drift or the device and server will disagree about what was required.
    """
    if amount_naira < TIER_1_CEILING:
        return KycTier.TIER_1
    if amount_naira <= TIER_2_CEILING:
        return KycTier.TIER_2
    return KycTier.TIER_3


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def init_pool() -> None:
    """Create the connection pool, waiting for PostgreSQL to accept connections."""
    global _pool
    last_error: Optional[Exception] = None
    for attempt in range(1, DB_STARTUP_RETRIES + 1):
        try:
            _pool = psycopg2.pool.ThreadedConnectionPool(1, 8, dsn=DATABASE_DSN)
            with get_cursor() as (cur, _):
                cur.execute("SELECT 1 AS ok")
                cur.fetchall()
            safe = DATABASE_DSN.split("@")[-1]          # never log credentials
            log.info("connected to PostgreSQL at %s", safe)
            return
        except Exception as exc:  # noqa: BLE001 - startup wait is intentionally broad
            last_error = exc
            log.warning("PostgreSQL not ready (attempt %d/%d): %s",
                        attempt, DB_STARTUP_RETRIES, exc)
            time.sleep(2)
    raise RuntimeError(
        f"could not reach PostgreSQL after {DB_STARTUP_RETRIES} attempts: {last_error}"
    )


@contextmanager
def get_cursor() -> Iterator[tuple[Any, Any]]:
    """Yields (cursor, connection). Commits on success, rolls back on error."""
    if _pool is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database not initialised",
        )
    conn = _pool.getconn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield cur, conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        _pool.putconn(conn)


def apply_schema() -> None:
    """
    Run schema.sql. Render does not execute init scripts for managed databases,
    so the service creates its own tables. Every statement is idempotent.
    """
    if not APPLY_SCHEMA_ON_STARTUP:
        log.info("APPLY_SCHEMA_ON_STARTUP=false — skipping schema bootstrap")
        return
    if not SCHEMA_PATH.exists():
        log.warning("schema.sql not found at %s — skipping bootstrap", SCHEMA_PATH)
        return
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with get_cursor() as (cur, _):
        cur.execute(sql)
    log.info("schema applied from %s", SCHEMA_PATH.name)


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def load_public_key(public_key_b64: str) -> ec.EllipticCurvePublicKey:
    """Decode a base64 X.509 SubjectPublicKeyInfo EC P-256 key."""
    try:
        der = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"public_key is not valid base64: {exc}") from exc
    try:
        key = serialization.load_der_public_key(der)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"public_key is not a valid X.509 SPKI key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "public_key must be an EC key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"expected curve secp256r1, got {key.curve.name}")
    return key


def verify_assertion(public_key_b64: str, challenge_b64: str, assertion_b64: str) -> bool:
    """
    Verify a SHA256withECDSA signature over the raw challenge bytes.

    Returns False for a well-formed but incorrect signature; raises 400 only when
    the inputs are malformed, so a forged signature is a verdict rather than an
    error.
    """
    key = load_public_key(public_key_b64)
    try:
        challenge = base64.b64decode(challenge_b64, validate=True)
        signature = base64.b64decode(assertion_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"challenge/assertion is not valid base64: {exc}") from exc
    if not signature:
        return False
    try:
        key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception as exc:  # malformed DER etc. -> treat as a failed assertion
        log.info("assertion rejected (%s): %s", type(exc).__name__, exc)
        return False


def issue_receipt(user_id: str, transaction_id: str, amount: int) -> str:
    """Short-lived signed receipt the client can present to downstream services."""
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": user_id,
            "txn": transaction_id,
            "amt": amount,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=JWT_TTL_SECONDS)).timestamp()),
            "iss": "sfmpas-backend",
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class Occupation(str, Enum):
    GENERAL_USER = "GENERAL_USER"
    MANUAL_LABOUR_WORKER = "MANUAL_LABOUR_WORKER"


class RegisterRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    username: str = Field(..., min_length=1, max_length=128)
    phone_number: str = Field(..., min_length=7, max_length=32)
    occupation: Occupation = Occupation.GENERAL_USER
    public_key: str = Field(..., description="EC P-256 SPKI DER, base64")

    @field_validator("phone_number")
    @classmethod
    def _digits(cls, v: str) -> str:
        if sum(c.isdigit() for c in v) < 7:
            raise ValueError("phone_number must contain at least 7 digits")
        return v


class RegisterResponse(BaseModel):
    user_id: str
    username: str
    occupation: Occupation
    registered_at: datetime
    key_algorithm: str = "EC secp256r1 / SHA256withECDSA"
    replaced_existing: bool


class AuthBeginRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    amount_naira: int = Field(..., gt=0)


class AuthBeginResponse(BaseModel):
    challenge_id: str
    challenge: str = Field(..., description="base64; sign these raw bytes")
    tier: KycTier
    requirement: str
    requires_liveness: bool
    requires_enhanced: bool
    expires_at: datetime
    signing_algorithm: str = "SHA256withECDSA"


class AuthCompleteRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    assertion: str = Field(..., description="base64 DER ECDSA signature")
    amount_naira: int = Field(..., gt=0)
    recipient: str = Field(..., min_length=1, max_length=128)
    # Optional: pins the assertion to one challenge. Omit and the newest live
    # challenge for this user is used, which is what the four-field contract in
    # the brief implies.
    challenge_id: Optional[str] = None
    liveness_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class AuthCompleteResponse(BaseModel):
    verdict: str
    transaction_id: str
    user_id: str
    amount_naira: int
    recipient: str
    tier: KycTier
    liveness_score: Optional[float]
    created_at: datetime
    receipt: Optional[str] = None
    reason: Optional[str] = None


class TransactionOut(BaseModel):
    transaction_id: str
    user_id: str
    amount_naira: int
    recipient: str
    tier: KycTier
    liveness_score: Optional[float]
    verdict: str
    assertion: Optional[str]
    reason: Optional[str]
    created_at: datetime


class TransactionsResponse(BaseModel):
    user_id: str
    count: int
    transactions: list[TransactionOut]


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

API_DESCRIPTION = """
Backend for **SFMPAS** — a fingerprint payment authentication system with
on-device presentation attack detection (liveness) and CBN KYC tiering.

### What this service does, and does not, hold

**No fingerprint image, template, or minutiae ever reaches this service.** The
handset matches the finger locally with Android `BiometricPrompt` and signs a
server-issued challenge using a non-exportable Keystore key. Only an EC P-256
**public** key and an ECDSA signature cross the network. The database schema
contains no `BYTEA` column anywhere — the guarantee is structural, not a
convention.

---

### The full flow, registration to payment

**1 · Enrolment — once per device**

The app generates an EC P-256 key pair inside the Android Keystore. The private
half is non-exportable and biometric-gated: a signature can only be produced
inside a successful fingerprint ceremony. The public half is sent to
`POST /register` and stored against the user.

**2 · Starting a payment**

The user enters an amount and a recipient. The app calls
`POST /authenticate/begin`, which resolves the **CBN KYC tier** from the amount
and returns a single-use challenge:

| Amount | Tier | Required factors |
|---|---|---|
| below ₦50,000 | `TIER_1` | Fingerprint only |
| ₦50,000 – ₦200,000 | `TIER_2` | Fingerprint + liveness |
| above ₦200,000 | `TIER_3` | Fingerprint + liveness + enhanced verification |

Both boundary values fall in Tier 2. The challenge is 32 CSPRNG bytes, bound to
one user **and one amount**, single-use, and expiring in 5 minutes. Any older
live challenge for that user is superseded.

**3 · On-device verification**

The app scores the captured print with its TFLite PAD model (a scalar in
`[0,1]`; ≥ 0.5 means genuine) and then prompts for the fingerprint. On success,
the Keystore key signs the **raw decoded challenge bytes** — nothing prepended,
appended, or re-hashed. Tier 3 adds a second confirmation that also accepts the
device credential.

**4 · Server authorisation**

`POST /authenticate/complete` verifies the signature against the stored public
key and checks that the challenge is unused, unexpired, and bound to the amount
being claimed. Every terminating path writes a transaction row — **approved and
rejected alike** — so the log is a complete audit trail. `GET /transactions`
reads it back.

---

### Crypto contract

| Item | Format |
|---|---|
| Key | EC P-256 (`secp256r1`), X.509 SubjectPublicKeyInfo, base64 — exactly Java's `PublicKey.getEncoded()` |
| Signature | `SHA256withECDSA`, DER-encoded ASN.1 `(r, s)`, base64 |
| Signed payload | the raw bytes of the base64-decoded `challenge` from `/authenticate/begin` |

---

⚠️ **Research prototype.** This is MSc dissertation work with a mock ledger,
permissive demo CORS, and no independent security audit. See `SECURITY.md`
before deploying anything derived from it.
"""

TAGS_METADATA = [
    {
        "name": "auth",
        "description": (
            "Enrolment and the two-step challenge/response authorisation flow. "
            "Call `/register` once per device, then `/authenticate/begin` and "
            "`/authenticate/complete` for every payment."
        ),
    },
    {
        "name": "transactions",
        "description": "Audit history — both approved and rejected attempts.",
    },
    {
        "name": "ops",
        "description": "Liveness and readiness probes for the hosting platform.",
    },
]

app = FastAPI(
    title="SFMPAS Backend API",
    version="1.1.0",
    description=API_DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    contact={"name": "Ayobami Ogunlade", "url": "https://github.com/"},
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
    swagger_ui_parameters={"defaultModelsExpandDepth": 1, "docExpansion": "list"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # demo/user-study convenience; tighten for production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_pool()
    apply_schema()


@app.get(
    "/health",
    tags=["ops"],
    summary="Liveness and database readiness probe",
    response_description="Service and database status.",
    responses={
        200: {
            "description": "Service up and the database reachable.",
            "content": {"application/json": {
                "example": {"status": "ok", "database": "up"}}},
        },
        503: {
            "description": "Database unreachable.",
            "content": {"application/json": {
                "example": {"detail": "database unavailable: connection refused"}}},
        },
    },
)
def health() -> dict[str, Any]:
    """
    Report whether the service is up and can reach its database.

    **When to call it.** As the hosting platform's health check, and — usefully
    for this deployment — to wake the service before a user session. Render's
    free tier suspends a web service after ~15 minutes idle, and the first
    request afterwards pays a cold start of roughly 50 seconds. Hitting this
    endpoint first moves that delay off the payment path.

    Executes `SELECT 1` rather than merely reporting process liveness, so a
    running service with a broken database reports `503` instead of a
    misleading `200`.
    """
    try:
        with get_cursor() as (cur, _):
            cur.execute("SELECT 1 AS ok")
            cur.fetchall()
        return {"status": "ok", "database": "up"}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            f"database unavailable: {exc}") from exc


# ------------------------------------------------------------------ /register

@app.post(
    "/register",
    response_model=RegisterResponse,
    tags=["auth"],
    summary="Enrol a user and their device public key",
    response_description="The stored enrolment record.",
    responses={
        200: {
            "description": "Enrolled (or re-enrolled).",
            "content": {"application/json": {"example": {
                "user_id": "sfmpas-a1b2c3d4e5f6",
                "username": "Ayobami Ogunlade",
                "occupation": "GENERAL_USER",
                "registered_at": "2025-08-22T07:14:03.221Z",
                "key_algorithm": "EC secp256r1 / SHA256withECDSA",
                "replaced_existing": False,
            }}},
        },
        400: {
            "description": "`public_key` is not valid base64, not an X.509 SPKI "
                           "key, not an EC key, or not on curve secp256r1.",
            "content": {"application/json": {"example": {
                "detail": "expected curve secp256r1, got secp384r1"}}},
        },
        422: {"description": "Validation error — missing field, or a phone "
                             "number with fewer than 7 digits."},
        503: {"description": "Database unavailable."},
    },
)
def register(req: RegisterRequest) -> RegisterResponse:
    """
    Enrol a user and the **public** half of their device credential.

    **When to call it.** Once per device, immediately after the Android app has
    generated its Keystore key pair during registration. The app may also retry
    this lazily before a payment if the original attempt happened offline.

    **What it stores.** Name, phone number, occupation, and the EC P-256 public
    key. No biometric data — the public key cannot reconstruct a fingerprint.

    **Idempotent.** Re-registering the same `user_id` **replaces** the stored
    key and returns `replaced_existing: true`. This is required, not incidental:
    adding a new fingerprint on the handset invalidates the Keystore key
    (`setInvalidatedByBiometricEnrollment`), so the device must be able to enrol
    a fresh one without losing its identity.

    The key is parsed and validated before the database is touched, so a
    malformed key never produces a half-written row.
    """
    load_public_key(req.public_key)   # reject malformed keys before touching the DB

    with get_cursor() as (cur, _):
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (req.user_id,))
        existing = cur.fetchone() is not None

        # Re-registration replaces the key: a handset that re-enrols biometrics
        # invalidates its Keystore key and must be able to enrol a fresh one.
        cur.execute(
            """
            INSERT INTO users (user_id, username, phone_number, occupation, public_key)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                username     = EXCLUDED.username,
                phone_number = EXCLUDED.phone_number,
                occupation   = EXCLUDED.occupation,
                public_key   = EXCLUDED.public_key
            RETURNING user_id, username, occupation, registered_at
            """,
            (req.user_id, req.username, req.phone_number,
             req.occupation.value, req.public_key),
        )
        row = cur.fetchone()

    log.info("registered user_id=%s (replaced=%s)", req.user_id, existing)
    return RegisterResponse(
        user_id=row["user_id"],
        username=row["username"],
        occupation=Occupation(row["occupation"]),
        registered_at=row["registered_at"],
        replaced_existing=existing,
    )


# -------------------------------------------------------- /authenticate/begin

@app.post(
    "/authenticate/begin",
    response_model=AuthBeginResponse,
    tags=["auth"],
    summary="Resolve the KYC tier and issue a signing challenge",
    response_description="The challenge to sign, and the factors this tier requires.",
    responses={
        200: {
            "description": "Challenge issued.",
            "content": {"application/json": {"example": {
                "challenge_id": "9f1c4e7a-2b3d-4c5e-8f9a-0b1c2d3e4f5a",
                "challenge": "T2hFQ0RTQWNoYWxsZW5nZTMyYnl0ZXNyYW5kb20xMjM0NTY3OD0=",
                "tier": "TIER_2",
                "requirement": "Fingerprint + liveness check",
                "requires_liveness": True,
                "requires_enhanced": False,
                "expires_at": "2025-08-22T07:19:03.400Z",
                "signing_algorithm": "SHA256withECDSA",
            }}},
        },
        404: {
            "description": "Unknown `user_id` — call `/register` first.",
            "content": {"application/json": {"example": {
                "detail": "unknown user_id 'sfmpas-a1b2c3d4e5f6' — register first"}}},
        },
        422: {"description": "Validation error — `amount_naira` must be > 0."},
        503: {"description": "Database unavailable."},
    },
)
def authenticate_begin(req: AuthBeginRequest) -> AuthBeginResponse:
    """
    Start an authorisation: resolve the tier, issue a single-use challenge.

    **When to call it.** Immediately before showing the fingerprint prompt —
    *not* after. The device must sign a challenge the server generated; a
    device-chosen value would make the signature worthless, since a captured
    assertion could be replayed or a payload signed that the server never
    issued.

    **Tier resolution** (mirrors `KycTier.forAmount()` in the Android client):

    | Amount | Tier | Required factors |
    |---|---|---|
    | below ₦50,000 | `TIER_1` | Fingerprint only |
    | ₦50,000 – ₦200,000 | `TIER_2` | Fingerprint + liveness |
    | above ₦200,000 | `TIER_3` | Fingerprint + liveness + enhanced |

    Both boundary values fall in Tier 2. The server is authoritative here — the
    client computes a tier for display, but this value is what gets bound to the
    challenge and enforced at `/authenticate/complete`.

    **Challenge properties.** 32 bytes from a CSPRNG, base64. Bound to this
    `user_id` **and** this `amount_naira`. Single-use. Expires in
    `CHALLENGE_TTL_SECONDS` (default 300). Issuing a new challenge marks any
    older live one for the same user as consumed, so only the newest is valid.

    **What to sign.** Base64-decode `challenge` and sign those raw bytes with
    `SHA256withECDSA` — nothing prepended, appended, or re-hashed.
    """
    with get_cursor() as (cur, _):
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (req.user_id,))
        if cur.fetchone() is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"unknown user_id '{req.user_id}' — register first")

        tier = tier_for_amount(req.amount_naira)
        challenge_id = str(uuid.uuid4())
        challenge = base64.b64encode(secrets.token_bytes(CHALLENGE_BYTES)).decode()
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=CHALLENGE_TTL_SECONDS)

        # Supersede any older live challenges so only the newest can be used.
        cur.execute(
            "UPDATE auth_challenges SET consumed = TRUE "
            "WHERE user_id = %s AND consumed = FALSE",
            (req.user_id,),
        )
        cur.execute(
            """
            INSERT INTO auth_challenges
                (challenge_id, user_id, challenge, amount_naira, tier, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (challenge_id, req.user_id, challenge, req.amount_naira,
             tier.value, expires_at),
        )

    log.info("challenge issued user_id=%s amount=%s tier=%s",
             req.user_id, req.amount_naira, tier.value)
    return AuthBeginResponse(
        challenge_id=challenge_id,
        challenge=challenge,
        tier=tier,
        requirement=tier.requirement,
        requires_liveness=tier.requires_liveness,
        requires_enhanced=tier.requires_enhanced,
        expires_at=expires_at,
    )


# ----------------------------------------------------- /authenticate/complete

def _record_transaction(
    cur: Any, *, user_id: str, amount: int, recipient: str, tier: KycTier,
    liveness: Optional[float], verdict: str, assertion: Optional[str],
    reason: Optional[str],
) -> tuple[str, datetime]:
    transaction_id = str(uuid.uuid4())
    cur.execute(
        """
        INSERT INTO transactions
            (transaction_id, user_id, amount_naira, recipient, tier,
             liveness_score, verdict, assertion, reason)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING created_at
        """,
        (transaction_id, user_id, amount, recipient, tier.value,
         liveness, verdict, assertion, reason),
    )
    return transaction_id, cur.fetchone()["created_at"]


@app.post(
    "/authenticate/complete",
    response_model=AuthCompleteResponse,
    tags=["auth"],
    summary="Verify the signed assertion and record the transaction",
    response_description="The authorisation verdict and the recorded transaction.",
    responses={
        200: {
            "description": "Signature valid — payment authorised.",
            "content": {"application/json": {"example": {
                "verdict": "APPROVED",
                "transaction_id": "3c8e1d90-77aa-4b21-9f0e-5d6c7b8a9e01",
                "user_id": "sfmpas-a1b2c3d4e5f6",
                "amount_naira": 75000,
                "recipient": "Adaeze Okafor",
                "tier": "TIER_2",
                "liveness_score": 0.999578,
                "created_at": "2025-08-22T07:15:11.902Z",
                "receipt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "reason": None,
            }}},
        },
        401: {
            "description": "Signature verification failed against the stored key.",
            "content": {"application/json": {"example": {"detail": {
                "verdict": "REJECTED",
                "reason": "signature verification failed",
                "transaction_id": "5a2b8c31-0d4e-4f6a-9b8c-1d2e3f4a5b6c",
            }}}},
        },
        403: {
            "description": "Liveness below threshold at Tier 2 or Tier 3.",
            "content": {"application/json": {"example": {"detail": {
                "verdict": "REJECTED",
                "reason": "presentation attack detected (liveness 0.0000 < 0.50)",
                "transaction_id": "7c4d9e02-…",
            }}}},
        },
        404: {"description": "Unknown `user_id`."},
        408: {
            "description": "Challenge expired.",
            "content": {"application/json": {"example": {"detail": {
                "verdict": "REJECTED", "reason": "challenge expired",
                "transaction_id": "…"}}}},
        },
        409: {
            "description": "No active challenge, challenge already used "
                           "(replay), or the amount does not match the one the "
                           "challenge authorised.",
            "content": {"application/json": {"example": {"detail": {
                "verdict": "REJECTED",
                "reason": "challenge already used (replay rejected)",
                "transaction_id": "…"}}}},
        },
        422: {"description": "Validation error — `liveness_score` outside [0,1], "
                             "non-positive amount, or a missing field."},
        503: {"description": "Database unavailable."},
    },
)
def authenticate_complete(req: AuthCompleteRequest) -> AuthCompleteResponse:
    """
    Verify the device's assertion and record the outcome.

    **When to call it.** After the fingerprint ceremony has produced a signature
    over the challenge from `/authenticate/begin`, and after any Tier 3 enhanced
    confirmation has passed.

    **Checks performed, in order.** Each failure is recorded and returned with a
    distinct status code so the client can tell a refusal from an outage:

    1. User exists → else `404`
    2. An active challenge exists → else `409`
    3. Not already consumed → else `409` *(replay)*
    4. Not expired → else `408`
    5. `amount_naira` matches the amount bound at `/begin` → else `409`
    6. At Tier 2/3, `liveness_score` ≥ 0.5 when supplied → else `403`
    7. Signature verifies against the stored public key → else `401`

    On success the challenge is burned before the transaction is written, so a
    concurrent retry cannot double-spend it.

    **Every path writes a row.** Rejections are recorded too — the transaction
    log is an audit trail, not a success log, and a burst of rejections is
    exactly the signal worth keeping.

    **`challenge_id` is optional.** Supply it to pin the assertion to one
    specific challenge. Omit it and the newest live challenge for the user is
    used, which matches the four-field contract the Android client sends.

    **Returns a receipt.** A short-lived signed JWT the client can present to a
    downstream service as proof of authorisation.
    """
    with get_cursor() as (cur, conn):
        cur.execute(
            "SELECT user_id, public_key FROM users WHERE user_id = %s",
            (req.user_id,),
        )
        user = cur.fetchone()
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"unknown user_id '{req.user_id}'")

        # Fetch the pinned challenge, or the newest live one for this user.
        if req.challenge_id:
            cur.execute(
                "SELECT * FROM auth_challenges "
                "WHERE challenge_id = %s AND user_id = %s",
                (req.challenge_id, req.user_id),
            )
        else:
            cur.execute(
                "SELECT * FROM auth_challenges "
                "WHERE user_id = %s AND consumed = FALSE "
                "ORDER BY created_at DESC LIMIT 1",
                (req.user_id,),
            )
        challenge_row = cur.fetchone()

        tier = tier_for_amount(req.amount_naira)

        def reject(reason: str, code: int = status.HTTP_401_UNAUTHORIZED):
            txn_id, _created = _record_transaction(
                cur, user_id=req.user_id, amount=req.amount_naira,
                recipient=req.recipient, tier=tier, liveness=req.liveness_score,
                verdict="REJECTED", assertion=req.assertion, reason=reason,
            )
            # Commit the audit row before raising: the surrounding context
            # manager rolls back on exception, which would otherwise erase the
            # record of the rejection. Rolling back an already-committed
            # transaction is a no-op.
            conn.commit()
            log.info("REJECTED user_id=%s txn=%s reason=%s",
                     req.user_id, txn_id, reason)
            raise HTTPException(code, detail={
                "verdict": "REJECTED", "reason": reason, "transaction_id": txn_id,
            })

        if challenge_row is None:
            reject("no active challenge — call /authenticate/begin first",
                   status.HTTP_409_CONFLICT)
        if challenge_row["consumed"]:
            reject("challenge already used (replay rejected)", status.HTTP_409_CONFLICT)

        expires_at = challenge_row["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            reject("challenge expired", status.HTTP_408_REQUEST_TIMEOUT)

        # The amount is bound at /begin; a mismatch means the signed challenge
        # authorises a different payment than the one being submitted.
        if int(challenge_row["amount_naira"]) != req.amount_naira:
            reject(
                f"amount mismatch: challenge authorised "
                f"{challenge_row['amount_naira']}, request claims {req.amount_naira}",
                status.HTTP_409_CONFLICT,
            )

        # Tier 2/3 require a passing liveness score when one is supplied.
        tier = KycTier(challenge_row["tier"])
        if tier.requires_liveness and req.liveness_score is not None \
                and req.liveness_score < 0.5:
            reject(f"presentation attack detected (liveness "
                   f"{req.liveness_score:.4f} < 0.50)", status.HTTP_403_FORBIDDEN)

        if not verify_assertion(user["public_key"], challenge_row["challenge"],
                                req.assertion):
            reject("signature verification failed")

        # Success: burn the challenge, then record the approval.
        cur.execute(
            "UPDATE auth_challenges SET consumed = TRUE WHERE challenge_id = %s",
            (challenge_row["challenge_id"],),
        )
        txn_id, created = _record_transaction(
            cur, user_id=req.user_id, amount=req.amount_naira,
            recipient=req.recipient, tier=tier, liveness=req.liveness_score,
            verdict="APPROVED", assertion=req.assertion, reason=None,
        )

    log.info("APPROVED user_id=%s txn=%s amount=%s tier=%s",
             req.user_id, txn_id, req.amount_naira, tier.value)
    return AuthCompleteResponse(
        verdict="APPROVED",
        transaction_id=txn_id,
        user_id=req.user_id,
        amount_naira=req.amount_naira,
        recipient=req.recipient,
        tier=tier,
        liveness_score=req.liveness_score,
        created_at=created,
        receipt=issue_receipt(req.user_id, txn_id, req.amount_naira),
    )


# -------------------------------------------------------------- /transactions

@app.get(
    "/transactions",
    response_model=TransactionsResponse,
    tags=["transactions"],
    summary="Read a user's transaction history",
    response_description="Authorisation attempts, newest first.",
    responses={
        200: {
            "description": "History returned (may be empty).",
            "content": {"application/json": {"example": {
                "user_id": "sfmpas-a1b2c3d4e5f6",
                "count": 2,
                "transactions": [
                    {
                        "transaction_id": "3c8e1d90-77aa-4b21-9f0e-5d6c7b8a9e01",
                        "user_id": "sfmpas-a1b2c3d4e5f6",
                        "amount_naira": 75000,
                        "recipient": "Adaeze Okafor",
                        "tier": "TIER_2",
                        "liveness_score": 0.999578,
                        "verdict": "APPROVED",
                        "assertion": "MEQCIH8x...",
                        "reason": None,
                        "created_at": "2025-08-22T07:15:11.902Z",
                    },
                    {
                        "transaction_id": "b7a2f014-3c5d-4e6f-8a9b-0c1d2e3f4a5b",
                        "user_id": "sfmpas-a1b2c3d4e5f6",
                        "amount_naira": 210000,
                        "recipient": "Tayo",
                        "tier": "TIER_3",
                        "liveness_score": 0.000016,
                        "verdict": "REJECTED",
                        "assertion": None,
                        "reason": "presentation attack detected "
                                  "(liveness 0.0000 < 0.50)",
                        "created_at": "2025-08-22T07:02:44.118Z",
                    },
                ],
            }}},
        },
        404: {
            "description": "Unknown `user_id`.",
            "content": {"application/json": {"example": {
                "detail": "unknown user_id 'sfmpas-a1b2c3d4e5f6'"}}},
        },
        422: {"description": "Invalid pagination — `limit` must be 1–500 and "
                             "`offset` ≥ 0."},
        503: {"description": "Database unavailable."},
    },
)
def transactions(
    user_id: str = Query(
        ..., min_length=1, max_length=64,
        description="The user whose history to read.",
        examples=["sfmpas-a1b2c3d4e5f6"],
    ),
    limit: int = Query(50, ge=1, le=500, description="Maximum rows to return."),
    offset: int = Query(0, ge=0, description="Rows to skip, for pagination."),
) -> TransactionsResponse:
    """
    Return a user's authorisation history, newest first.

    **When to call it.** To populate a history view, or to audit a user study
    session afterwards.

    Includes **both approved and rejected** attempts, each with the liveness
    score the device reported and, for rejections, the reason. That makes the
    endpoint useful for analysis as well as display: rejection reasons
    distinguish a presentation attack from an expired challenge or a bad
    signature.

    ⚠️ **No authentication.** In this research build anyone holding a `user_id`
    can read that user's history. A production deployment must put an
    authorisation check in front of this endpoint — see `SECURITY.md`.
    """
    with get_cursor() as (cur, _):
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if cur.fetchone() is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"unknown user_id '{user_id}'")
        cur.execute(
            """
            SELECT transaction_id, user_id, amount_naira, recipient, tier,
                   liveness_score, verdict, assertion, reason, created_at
            FROM transactions
            WHERE user_id = %s
            ORDER BY created_at DESC, transaction_id DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, limit, offset),
        )
        rows = cur.fetchall()

    return TransactionsResponse(
        user_id=user_id,
        count=len(rows),
        transactions=[TransactionOut(**dict(row)) for row in rows],
    )


if __name__ == "__main__":
    import uvicorn

    # Render supplies PORT; 10000 is its default for web services.
    uvicorn.run("main:app", host="0.0.0.0",
                port=int(os.getenv("PORT", "10000")), reload=False)
