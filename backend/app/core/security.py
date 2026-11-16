"""Security Architecture Foundations & Cryptographic Standards.

Module: backend.app.core.security
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 (TRD/SRS) Section 5: Security Architecture
- AMSC-DOC-005 (Database & API Schema) Section 5: Authentication & API Conventions
- Master Implementation Specification: M1 Day 2 Authentication Baseline
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import argon2
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import AuthenticationError

# --- Cryptographic Constants & Algorithm Standards ---
RECOMMENDED_PASSWORD_HASH_ALGORITHM = "argon2id"
TOKEN_TYPE = "Bearer"
DEFAULT_JWT_ALGORITHM = "HS256"
MIN_SECRET_LENGTH_BYTES = 32
JWT_ISSUER = "amsc-api"
JWT_AUDIENCE = "amsc-client"

# Invariant: MD5, SHA-1, and plain SHA-256 are strictly prohibited for password storage
PROHIBITED_HASH_ALGORITHMS = {"md5", "sha1", "sha256"}

# Argon2id hasher configured per RFC 9106 recommended interactive profiles
# time_cost=2, memory_cost=19456 KiB (~19MB), parallelism=1
_password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    type=argon2.Type.ID,
)

# Pre-computed dummy hash for timing-attack mitigation when user is not found
_DUMMY_ARGON2_HASH = _password_hasher.hash("amsc-timing-mitigation-dummy-password")


# ============================================================================
# 1. Password Hashing & Verification (Argon2id)
# ============================================================================

def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id with automatic salt generation.

    Never stores or returns plaintext.
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2id hash.

    Fails safely on corrupted, mismatched, or unsupported hash strings.
    """
    if not plain_password or not hashed_password:
        return False

    # Prohibit legacy or unsafe hashes
    if not hashed_password.startswith("$argon2"):
        return False

    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def dummy_verify_password() -> None:
    """Perform dummy Argon2id verification to equalize response timing when user is not found."""
    try:
        _password_hasher.verify(_DUMMY_ARGON2_HASH, "wrong-password")
    except Exception:
        pass


def needs_rehash(hashed_password: str) -> bool:
    """Check if the stored hash requires rehashing due to parameter updates."""
    try:
        return _password_hasher.check_needs_rehash(hashed_password)
    except Exception:
        return True


# ============================================================================
# 2. JWT Generation & Verification (HS256)
# ============================================================================

def create_access_token(
    user_id: str,
    tenant_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
    settings: Optional[Settings] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a signed HMAC-SHA256 JWT containing verified user and tenant claims."""
    cfg = settings or get_settings()

    if not cfg.JWT_SECRET or len(cfg.JWT_SECRET) < 32:
        raise ValueError("JWT_SECRET must be configured and at least 32 characters.")

    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=cfg.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "role": str(role),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": uuid.uuid4().hex,
        "token_use": "access",
    }

    if additional_claims:
        # Prevent overriding critical security claims
        reserved_keys = {"sub", "tenant_id", "role", "iss", "aud", "iat", "nbf", "exp", "jti", "token_use"}
        safe_additional = {k: v for k, v in additional_claims.items() if k not in reserved_keys}
        payload.update(safe_additional)

    encoded = jwt.encode(payload, cfg.JWT_SECRET, algorithm=DEFAULT_JWT_ALGORITHM)
    return encoded


def decode_access_token(
    token: str,
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Decode, verify signature, and validate claims of an incoming JWT.

    Strictly enforces algorithm HS256, expiration, issuer, audience, and required claims.
    Fails closed on any signature mismatch, malformed token, or expired timestamp.
    """
    cfg = settings or get_settings()

    if not cfg.JWT_SECRET:
        raise AuthenticationError("Authentication service configuration error.")

    try:
        payload = jwt.decode(
            token,
            cfg.JWT_SECRET,
            algorithms=[DEFAULT_JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": ["sub", "tenant_id", "role", "exp", "iat", "nbf", "iss", "aud", "jti"],
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_signature": True,
            },
        )

        if payload.get("token_use") != "access":
            raise AuthenticationError("Invalid token purpose.")

        return payload

    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Authentication token has expired.")
    except jwt.InvalidAlgorithmError:
        raise AuthenticationError("Invalid token signing algorithm.")
    except jwt.InvalidIssuerError:
        raise AuthenticationError("Invalid token issuer.")
    except jwt.InvalidAudienceError:
        raise AuthenticationError("Invalid token audience.")
    except jwt.InvalidSignatureError:
        raise AuthenticationError("Invalid token signature.")
    except jwt.DecodeError:
        raise AuthenticationError("Malformed authentication token.")
    except jwt.PyJWTError:
        raise AuthenticationError("Invalid authentication credentials.")
