"""Security Architecture Foundations & Cryptographic Standards.

Module: backend.app.core.security
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 (TRD/SRS) Section 5: Security Architecture
- AMSC-DOC-005 (Database & API Schema) Section 5: Authentication & API Conventions
- Master Implementation Specification: M1 Day 2 Authentication Baseline
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

import argon2
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt

from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import AuthenticationError, SecurityDependencyError

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

# Dedicated bounded thread pool for Argon2 operations to keep event loop responsive
# Bounded to 4 worker threads to prevent thread explosion under attack
_AUTH_WORKER_COUNT = 4
_auth_thread_pool: Optional[ThreadPoolExecutor] = None


def get_auth_executor(max_workers: int = _AUTH_WORKER_COUNT) -> ThreadPoolExecutor:
    """Return dedicated singleton ThreadPoolExecutor for Argon2 operations."""
    global _auth_thread_pool
    if _auth_thread_pool is None:
        _auth_thread_pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="amsc-argon2",
        )
    return _auth_thread_pool


def shutdown_auth_executor() -> None:
    """Gracefully terminate dedicated auth thread pool during app shutdown."""
    global _auth_thread_pool
    if _auth_thread_pool is not None:
        _auth_thread_pool.shutdown(wait=False)
        _auth_thread_pool = None


def get_auth_semaphore(max_concurrency: int = 8) -> asyncio.Semaphore:
    """Return per-event-loop semaphore bounding concurrent Argon2 operations.

    Binding to the active event loop avoids cross-loop future binding contamination
    in async tests and multi-loop environments.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.Semaphore(max_concurrency)

    if not hasattr(loop, "_amsc_auth_semaphore") or getattr(loop, "_amsc_auth_concurrency", None) != max_concurrency:
        loop._amsc_auth_semaphore = asyncio.Semaphore(max_concurrency)
        loop._amsc_auth_concurrency = max_concurrency
    return loop._amsc_auth_semaphore


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
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if not plain_password or not hashed_password:
        return False

    # Prohibit legacy or unsafe hashes
    if not hashed_password.startswith("$argon2"):
        return False

    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


def dummy_verify_password() -> None:
    """Perform dummy Argon2id verification to equalize response timing when user is not found."""
    try:
        _password_hasher.verify(_DUMMY_ARGON2_HASH, "wrong-password")
    except Exception:
        pass


async def verify_password_async(
    plain_password: str,
    hashed_password: str,
    max_concurrency: int = 8,
) -> bool:
    """Verify a password against Argon2id hash off the event loop with bounded concurrency.

    Offloads CPU/memory-intensive Argon2id operations to a dedicated bounded thread pool
    so the asyncio event loop remains responsive.
    """
    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False
    if not plain_password or not hashed_password:
        return False
    if not hashed_password.startswith("$argon2"):
        return False

    sem = get_auth_semaphore(max_concurrency)
    executor = get_auth_executor()
    loop = asyncio.get_running_loop()

    try:
        async with sem:
            return await loop.run_in_executor(
                executor, verify_password, plain_password, hashed_password
            )
    except Exception:
        return False


async def dummy_verify_password_async(max_concurrency: int = 8) -> None:
    """Perform dummy Argon2id verification off event loop to equalize response timing."""
    sem = get_auth_semaphore(max_concurrency)
    executor = get_auth_executor()
    loop = asyncio.get_running_loop()

    try:
        async with sem:
            await loop.run_in_executor(executor, dummy_verify_password)
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
#
# Production Lifecycle & Revocation Architecture Note:
# ----------------------------------------------------
# 1. Unique Token Identifier (jti):
#    Every access token generated below contains a cryptographically unique
#    UUIDv4 'jti' claim. However, the presence of a 'jti' claim alone does NOT
#    provide revocation. Revocation requires an active, stateful check against
#    a revocation registry (such as an M7 distributed Redis blocklist with TTL
#    equal to the remaining token lifetime, or an M6 database session table).
#    Until an external revocation store is wired into the token validation path,
#    token invalidation relies strictly on short expiration windows (exp).
#
# 2. Key Rotation Requirements:
#    In the current baseline, tokens are signed using a symmetric secret key
#    (JWT_SECRET). For production key rotation:
#    - Introduce a key identifier ('kid') in the JWT header.
#    - Maintain a keyring supporting the current active signing key and previous
#      valid keys for graceful verification during rotation periods.
#    - Implement an emergency key revocation and rollover runbook to revoke all
#      tokens signed with a compromised secret key.
# ============================================================================

# ============================================================================
# 2. Token Revocation Store Protocol & KeyRing Lifecycle (GAP-007 & GAP-014)
# ============================================================================

@runtime_checkable
class RevocationStoreProtocol(Protocol):
    """Protocol defining token revocation and session lifecycle contract (GAP-007)."""

    async def revoke_token(self, jti: str, expires_at: int, reason: Optional[str] = None) -> None:
        ...

    async def is_token_revoked(self, jti: str) -> bool:
        ...

    async def revoke_user_sessions(self, user_id: str, tenant_id: str, reason: Optional[str] = None) -> None:
        ...

    async def is_user_revoked(self, user_id: str, tenant_id: str, issued_at: int) -> bool:
        ...


class InMemoryRevocationStore:
    """Thread-safe in-memory session and token revocation store for dev and testing (GAP-007)."""

    def __init__(self) -> None:
        self._revoked_jtis: Dict[str, int] = {}
        self._user_revocations: Dict[Tuple[str, str], int] = {}
        self.is_available: bool = True

    async def revoke_token(self, jti: str, expires_at: int, reason: Optional[str] = None) -> None:
        if not self.is_available:
            raise SecurityDependencyError("Revocation verification service is unavailable.")
        self._revoked_jtis[jti] = expires_at

    async def is_token_revoked(self, jti: str) -> bool:
        if not self.is_available:
            raise SecurityDependencyError("Revocation verification service is unavailable.")
        now = int(datetime.now(timezone.utc).timestamp())
        # Evict expired entries
        expired = [k for k, exp in self._revoked_jtis.items() if exp < now]
        for k in expired:
            del self._revoked_jtis[k]
        return jti in self._revoked_jtis

    async def revoke_user_sessions(self, user_id: str, tenant_id: str, reason: Optional[str] = None) -> None:
        if not self.is_available:
            raise SecurityDependencyError("Revocation verification service is unavailable.")
        now = int(datetime.now(timezone.utc).timestamp())
        self._user_revocations[(user_id, tenant_id)] = now

    async def is_user_revoked(self, user_id: str, tenant_id: str, issued_at: int) -> bool:
        if not self.is_available:
            raise SecurityDependencyError("Revocation verification service is unavailable.")
        revoked_at = self._user_revocations.get((user_id, tenant_id))
        if revoked_at is not None and issued_at <= revoked_at:
            return True
        return False


class RedisRevocationStore:
    """Approved distributed Redis token and session revocation store (GAP-007 / M7 Contract).

    Persists revoked JTIs with TTL and records user-level session revocation timestamps
    across multiple distributed application instances.
    """

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        failure_policy: str = "fail_closed",
    ) -> None:
        self.redis_client = redis_client
        self.failure_policy = failure_policy
        self.is_available: bool = True
        # Local state fallback for mock testing when redis_client is None
        self._revoked_jtis: Dict[str, int] = {}
        self._user_revocations: Dict[Tuple[str, str], int] = {}

    async def revoke_token(self, jti: str, expires_at: int, reason: Optional[str] = None) -> None:
        """Revoke a single token by JTI until its expiration timestamp."""
        if not self.is_available:
            raise SecurityDependencyError("Revocation verification service is unavailable.")

        now = int(datetime.now(timezone.utc).timestamp())
        ttl = max(1, expires_at - now)

        if self.redis_client is not None:
            try:
                import asyncio
                import inspect
                set_fn = getattr(self.redis_client, "set", None)
                if set_fn is not None:
                    res = set_fn(f"jwt:revoked:{jti}", str(expires_at), ex=ttl)
                    if inspect.isawaitable(res) or asyncio.iscoroutine(res):
                        await res
                    return
            except Exception as exc:
                if self.failure_policy == "fail_closed":
                    raise SecurityDependencyError("Revocation service unavailable.") from exc

        self._revoked_jtis[jti] = expires_at

    async def is_token_revoked(self, jti: str) -> bool:
        """Check whether a token JTI has been revoked."""
        if not self.is_available:
            raise SecurityDependencyError("Revocation verification service is unavailable.")

        if self.redis_client is not None:
            try:
                import asyncio
                import inspect
                exists_fn = getattr(self.redis_client, "exists", None)
                if exists_fn is not None:
                    res = exists_fn(f"jwt:revoked:{jti}")
                    if inspect.isawaitable(res) or asyncio.iscoroutine(res):
                        res = await res
                    return bool(res)
            except Exception as exc:
                if self.failure_policy == "fail_closed":
                    raise SecurityDependencyError("Revocation service unavailable.") from exc

        now = int(datetime.now(timezone.utc).timestamp())
        expired = [k for k, exp in self._revoked_jtis.items() if exp < now]
        for k in expired:
            del self._revoked_jtis[k]
        return jti in self._revoked_jtis

    async def revoke_user_sessions(self, user_id: str, tenant_id: str, reason: Optional[str] = None) -> None:
        """Revoke all active sessions for a user issued before now."""
        if not self.is_available:
            raise SecurityDependencyError("Revocation verification service is unavailable.")

        now = int(datetime.now(timezone.utc).timestamp())

        if self.redis_client is not None:
            try:
                import asyncio
                import inspect
                set_fn = getattr(self.redis_client, "set", None)
                if set_fn is not None:
                    # Keep user revocation marker for 7 days (or max token lifetime)
                    res = set_fn(f"jwt:user_revoked:{tenant_id}:{user_id}", str(now), ex=604800)
                    if inspect.isawaitable(res) or asyncio.iscoroutine(res):
                        await res
                    return
            except Exception as exc:
                if self.failure_policy == "fail_closed":
                    raise SecurityDependencyError("Revocation service unavailable.") from exc

        self._user_revocations[(user_id, tenant_id)] = now

    async def is_user_revoked(self, user_id: str, tenant_id: str, issued_at: int) -> bool:
        """Check whether user sessions issued at 'issued_at' were invalidated."""
        if not self.is_available:
            raise SecurityDependencyError("Revocation verification service is unavailable.")

        if self.redis_client is not None:
            try:
                import asyncio
                import inspect
                get_fn = getattr(self.redis_client, "get", None)
                if get_fn is not None:
                    res = get_fn(f"jwt:user_revoked:{tenant_id}:{user_id}")
                    if inspect.isawaitable(res) or asyncio.iscoroutine(res):
                        res = await res
                    if res is not None:
                        revoked_at = int(res)
                        return issued_at <= revoked_at
                    return False
            except Exception as exc:
                if self.failure_policy == "fail_closed":
                    raise SecurityDependencyError("Revocation service unavailable.") from exc

        revoked_at = self._user_revocations.get((user_id, tenant_id))
        if revoked_at is not None and issued_at <= revoked_at:
            return True
        return False


_default_revocation_store: Optional[RevocationStoreProtocol] = None


def get_default_revocation_store() -> RevocationStoreProtocol:
    global _default_revocation_store
    if _default_revocation_store is None:
        _default_revocation_store = InMemoryRevocationStore()
    return _default_revocation_store


def set_default_revocation_store(store: Optional[RevocationStoreProtocol]) -> None:
    global _default_revocation_store
    _default_revocation_store = store


# --- Cryptographic Keyring & Rotation (GAP-014) ---

DEFAULT_KID = "k-current"


class KeyRing:
    """Cryptographic keyring managing active, rotated, and retired HS256 keys (GAP-014)."""

    def __init__(self, active_kid: str, keys: Dict[str, Dict[str, Any]]) -> None:
        self.active_kid = active_kid
        # keys: {kid: {"secret": str, "status": "active"|"valid"|"retired"|"compromised", "algorithm": "HS256", "valid_until": int | None}}
        self.keys = keys

    def get_signing_key(self) -> Tuple[str, str]:
        """Return (active_kid, secret) for token signing."""
        if self.active_kid not in self.keys:
            raise ValueError(f"Active kid '{self.active_kid}' not found in keyring.")
        info = self.keys[self.active_kid]
        if info.get("status") != "active":
            raise ValueError(f"Active key '{self.active_kid}' is not in 'active' status.")
        return self.active_kid, info["secret"]

    def get_verification_key(self, kid: Optional[str]) -> Tuple[str, str]:
        """Return (secret, algorithm) for verification, enforcing key status allowlist and rotation overlap periods."""
        if not kid:
            # Backward compatibility for legacy tokens without kid header
            info = self.keys.get(self.active_kid)
            if not info or info.get("status") not in ("active", "valid"):
                raise AuthenticationError("Token signing key is invalid or retired.")
            return info["secret"], info.get("algorithm", DEFAULT_JWT_ALGORITHM)

        if kid not in self.keys:
            raise AuthenticationError("Unknown key identifier.")

        info = self.keys[kid]
        status = info.get("status", "valid")
        if status == "compromised":
            raise AuthenticationError("Token signing key has been invalidated (compromised).")
        if status == "retired":
            raise AuthenticationError("Token signing key has been invalidated (retired).")
        if status not in ("active", "valid"):
            raise AuthenticationError(f"Token signing key is not authorized ({status}).")

        # Overlap period validation (Finding D / GAP-014)
        valid_until = info.get("valid_until") or info.get("expires_at")
        if valid_until is not None:
            now_ts = int(datetime.now(timezone.utc).timestamp())
            if now_ts > int(valid_until):
                raise AuthenticationError(f"Token signing key overlap period has expired for key '{kid}'.")

        return info["secret"], info.get("algorithm", DEFAULT_JWT_ALGORITHM)

    def retire_key(self, kid: str) -> None:
        """Mark a rotated key as retired after its overlap period has concluded."""
        if kid in self.keys:
            self.keys[kid]["status"] = "retired"

    def invalidate_key(self, kid: str, reason: str = "compromised") -> None:
        """Emergency invalidation of a key."""
        if kid in self.keys:
            self.keys[kid]["status"] = reason

    def add_key(self, kid: str, secret: str, status: str = "valid", algorithm: str = DEFAULT_JWT_ALGORITHM) -> None:
        """Register a key into the keyring for rotation overlap."""
        self.keys[kid] = {"secret": secret, "status": status, "algorithm": algorithm}


_default_keyring: Optional[KeyRing] = None


def get_keyring(settings: Optional[Settings] = None) -> KeyRing:
    """Return active cryptographic keyring configured from settings."""
    global _default_keyring
    if settings is None and _default_keyring is not None:
        return _default_keyring

    cfg = settings or get_settings()
    active_kid = getattr(cfg, "JWT_ACTIVE_KID", DEFAULT_KID)

    keys: Dict[str, Dict[str, Any]] = {
        active_kid: {
            "secret": cfg.JWT_SECRET,
            "status": "active",
            "algorithm": DEFAULT_JWT_ALGORITHM,
        }
    }
    keyring_config = getattr(cfg, "JWT_KEYRING_CONFIG", None)
    if keyring_config:
        try:
            extra = json.loads(keyring_config) if isinstance(keyring_config, str) else keyring_config
            if isinstance(extra, dict):
                if "keys" in extra and isinstance(extra["keys"], dict):
                    keys.update(extra["keys"])
                else:
                    keys.update(extra)
                if "active_kid" in extra:
                    active_kid = extra["active_kid"]
        except Exception:
            pass

    keyring = KeyRing(active_kid=active_kid, keys=keys)
    if settings is None:
        _default_keyring = keyring
    return keyring


def set_keyring(keyring: Optional[KeyRing]) -> None:
    global _default_keyring
    _default_keyring = keyring


# ============================================================================
# 3. JWT Generation & Verification (HS256 with Key Rotation)
# ============================================================================

def create_access_token(
    user_id: str,
    tenant_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
    settings: Optional[Settings] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a signed HMAC-SHA256 JWT containing verified user and tenant claims and active kid."""
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

    keyring = get_keyring(cfg)
    active_kid, secret = keyring.get_signing_key()
    headers = {"kid": active_kid}

    encoded = jwt.encode(payload, secret, algorithm=DEFAULT_JWT_ALGORITHM, headers=headers)
    return encoded


def decode_access_token(
    token: str,
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Decode, verify signature, and validate claims of an incoming JWT.

    Strictly enforces algorithm HS256, expiration, issuer, audience, kid allowlist, and required claims.
    Fails closed on any signature mismatch, malformed token, unknown kid, or expired timestamp.
    """
    cfg = settings or get_settings()

    if not cfg.JWT_SECRET:
        raise AuthenticationError("Authentication service configuration error.")

    # 1. Inspect unverified header for algorithm and kid allowlisting (no algorithm negotiation)
    try:
        unverified_headers = jwt.get_unverified_header(token)
    except Exception:
        raise AuthenticationError("Malformed authentication token header.")

    alg = unverified_headers.get("alg")
    if alg != DEFAULT_JWT_ALGORITHM:
        raise AuthenticationError("Invalid token signing algorithm.")

    kid = unverified_headers.get("kid")
    keyring = get_keyring(cfg)
    secret, algorithm = keyring.get_verification_key(kid)

    if algorithm != DEFAULT_JWT_ALGORITHM:
        raise AuthenticationError("Invalid token signing algorithm.")

    try:
        payload = jwt.decode(
            token,
            secret,
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
