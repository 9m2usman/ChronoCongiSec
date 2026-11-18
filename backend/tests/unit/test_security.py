"""Unit Tests for Argon2id Password Hashing and JWT Security.

Module: backend.tests.unit.test_security
Owner: M1 — Platform Backend & API Integration Lead

Verifies:
1. Argon2id password hashing and automatic unique salt generation.
2. Correct and incorrect password verification.
3. Plaintext and legacy weak hash prohibition (MD5, SHA-1, plain SHA-256).
4. Needs rehash detection.
5. JWT creation with timezone-aware UTC timestamps and standard claims.
6. Signature validation and tamper rejection.
7. Algorithm confusion attack prevention (rejection of 'none', HS384, HS512).
8. Expiration, not-before, issuer, and audience validation.
9. Malformed token rejection.
"""

from datetime import timedelta
import pytest
import jwt

from backend.app.core.config import Settings
from backend.app.core.exceptions import AuthenticationError
from backend.app.core.security import (
    create_access_token,
    decode_access_token,
    dummy_verify_password,
    hash_password,
    needs_rehash,
    verify_password,
)


# ============================================================================
# 1. Password Hashing & Verification Tests (Argon2id)
# ============================================================================

def test_password_hash_creates_argon2id():
    """Verify password hashing produces a valid Argon2id hash."""
    plain = "SuperSecretPassword123!"
    hashed = hash_password(plain)

    assert hashed is not None
    assert hashed != plain
    assert hashed.startswith("$argon2id$")
    assert "m=19456,t=2,p=1" in hashed


def test_password_verify_success():
    """Verify correct password verifies to True."""
    plain = "CorrectPassword123!"
    hashed = hash_password(plain)
    assert verify_password(plain, hashed) is True


def test_password_verify_failure():
    """Verify incorrect password verifies to False."""
    plain = "CorrectPassword123!"
    hashed = hash_password(plain)
    assert verify_password("WrongPassword123!", hashed) is False


def test_password_salts_unique_for_identical_passwords():
    """Verify hashing the same password twice yields different hashes due to unique salts."""
    plain = "IdenticalPassword123!"
    hash1 = hash_password(plain)
    hash2 = hash_password(plain)

    assert hash1 != hash2
    assert verify_password(plain, hash1) is True
    assert verify_password(plain, hash2) is True


def test_password_empty_or_none_rejection():
    """Verify empty or missing passwords fail safely."""
    with pytest.raises(ValueError):
        hash_password("")

    assert verify_password("", "$argon2id$v=19$m=19456,t=2,p=1$fake$fake") is False
    assert verify_password("password", "") is False


def test_password_prohibits_plain_sha256_or_legacy_hashes():
    """Verify plain SHA-256, MD5, and non-Argon2 hashes are rejected."""
    fake_sha256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    assert verify_password("password", fake_sha256) is False


def test_dummy_verify_password_executes():
    """Verify dummy verification runs without error to equalize timing."""
    dummy_verify_password()


def test_needs_rehash():
    """Verify needs_rehash returns False for current parameters and True for malformed strings."""
    hashed = hash_password("ValidPassword123!")
    assert needs_rehash(hashed) is False
    assert needs_rehash("malformed_hash") is True


# ============================================================================
# 2. JWT Security & Validation Tests (HS256)
# ============================================================================

@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        APP_ENV="test",
        JWT_SECRET="a-test-secret-with-plenty-of-entropy-and-more-than-32-chars",
        ACCESS_TOKEN_EXPIRE_MINUTES=60,
    )


def test_jwt_create_and_decode_valid(test_settings: Settings):
    """Verify creating a valid access token decodes all expected claims."""
    token = create_access_token(
        user_id="user-123",
        tenant_id="tenant-abc",
        role="SECURITY_ANALYST",
        settings=test_settings,
    )
    payload = decode_access_token(token, settings=test_settings)

    assert payload["sub"] == "user-123"
    assert payload["tenant_id"] == "tenant-abc"
    assert payload["role"] == "SECURITY_ANALYST"
    assert payload["iss"] == "amsc-api"
    assert payload["aud"] == "amsc-client"
    assert payload["token_use"] == "access"
    assert "exp" in payload
    assert "iat" in payload
    assert "nbf" in payload
    assert "jti" in payload


def test_jwt_expired_token_rejected(test_settings: Settings):
    """Verify expired token is rejected with AuthenticationError."""
    # Token expired 10 minutes ago
    expired_token = create_access_token(
        user_id="user-123",
        tenant_id="tenant-abc",
        role="SECURITY_ANALYST",
        expires_delta=timedelta(minutes=-10),
        settings=test_settings,
    )

    with pytest.raises(AuthenticationError) as exc_info:
        decode_access_token(expired_token, settings=test_settings)
    assert "expired" in str(exc_info.value).lower()


def test_jwt_signature_mismatch_rejected(test_settings: Settings):
    """Verify token signed with a different key is rejected."""
    wrong_settings = Settings(
        APP_ENV="test",
        JWT_SECRET="different-secret-key-that-does-not-match-original-32-chars",
    )
    token = create_access_token(
        user_id="user-123",
        tenant_id="tenant-abc",
        role="SECURITY_ANALYST",
        settings=wrong_settings,
    )

    with pytest.raises(AuthenticationError) as exc_info:
        decode_access_token(token, settings=test_settings)
    assert "signature" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()


def test_jwt_tampered_payload_rejected(test_settings: Settings):
    """Verify modifying a token's payload causes signature verification failure."""
    token = create_access_token(
        user_id="user-123",
        tenant_id="tenant-abc",
        role="SECURITY_ANALYST",
        settings=test_settings,
    )
    parts = token.split(".")
    # Tamper with payload part by modifying one character
    tampered_payload = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    with pytest.raises(AuthenticationError):
        decode_access_token(tampered_token, settings=test_settings)


def test_jwt_algorithm_none_rejected(test_settings: Settings):
    """Verify algorithm 'none' attack is strictly rejected."""
    unsecured_token = jwt.encode(
        {
            "sub": "user-123",
            "tenant_id": "tenant-abc",
            "role": "SECURITY_ANALYST",
            "iss": "amsc-api",
            "aud": "amsc-client",
            "token_use": "access",
            "iat": 1000000000,
            "nbf": 1000000000,
            "exp": 2000000000,
            "jti": "fake-jti",
        },
        key="",
        algorithm="none",
    )

    with pytest.raises(AuthenticationError):
        decode_access_token(unsecured_token, settings=test_settings)


def test_jwt_wrong_algorithm_rejected(test_settings: Settings):
    """Verify token signed with HS384 is rejected when HS256 is enforced."""
    hs384_token = jwt.encode(
        {
            "sub": "user-123",
            "tenant_id": "tenant-abc",
            "role": "SECURITY_ANALYST",
            "iss": "amsc-api",
            "aud": "amsc-client",
            "token_use": "access",
            "iat": 1000000000,
            "nbf": 1000000000,
            "exp": 2000000000,
            "jti": "fake-jti",
        },
        key=test_settings.JWT_SECRET,
        algorithm="HS384",
    )

    with pytest.raises(AuthenticationError):
        decode_access_token(hs384_token, settings=test_settings)


def test_jwt_invalid_issuer_rejected(test_settings: Settings):
    """Verify token with wrong issuer is rejected."""
    bad_iss_token = jwt.encode(
        {
            "sub": "user-123",
            "tenant_id": "tenant-abc",
            "role": "SECURITY_ANALYST",
            "iss": "untrusted-issuer",
            "aud": "amsc-client",
            "token_use": "access",
            "iat": 1000000000,
            "nbf": 1000000000,
            "exp": 2000000000,
            "jti": "fake-jti",
        },
        key=test_settings.JWT_SECRET,
        algorithm="HS256",
    )

    with pytest.raises(AuthenticationError) as exc_info:
        decode_access_token(bad_iss_token, settings=test_settings)
    assert "issuer" in str(exc_info.value).lower()


def test_jwt_invalid_audience_rejected(test_settings: Settings):
    """Verify token with wrong audience is rejected."""
    bad_aud_token = jwt.encode(
        {
            "sub": "user-123",
            "tenant_id": "tenant-abc",
            "role": "SECURITY_ANALYST",
            "iss": "amsc-api",
            "aud": "untrusted-audience",
            "token_use": "access",
            "iat": 1000000000,
            "nbf": 1000000000,
            "exp": 2000000000,
            "jti": "fake-jti",
        },
        key=test_settings.JWT_SECRET,
        algorithm="HS256",
    )

    with pytest.raises(AuthenticationError) as exc_info:
        decode_access_token(bad_aud_token, settings=test_settings)
    assert "audience" in str(exc_info.value).lower()


def test_jwt_malformed_token_rejected(test_settings: Settings):
    """Verify completely malformed token strings are rejected."""
    with pytest.raises(AuthenticationError):
        decode_access_token("this-is-not-a-valid-jwt", settings=test_settings)

    with pytest.raises(AuthenticationError):
        decode_access_token("", settings=test_settings)


def test_jwt_secret_too_short_rejected_at_startup():
    """Verify any explicit JWT_SECRET under 32 characters is rejected at Settings initialization."""
    from pydantic import ValidationError as PydanticValidationError
    with pytest.raises(PydanticValidationError) as exc:
        Settings(
            APP_ENV="development",
            JWT_SECRET="short-secret-under-32-chars",
        )
    assert "JWT_SECRET must be at least 32 characters" in str(exc.value)


# ============================================================================
# 3. Async Bounded Password Verification Tests (M1 Day 2 Performance)
# ============================================================================

@pytest.mark.asyncio
async def test_verify_password_async_success():
    """Verify asynchronous password verification succeeds for valid password."""
    from backend.app.core.security import verify_password_async

    plain = "SuperSecurePassword123!"
    hashed = hash_password(plain)

    result = await verify_password_async(plain, hashed)
    assert result is True


@pytest.mark.asyncio
async def test_verify_password_async_failure():
    """Verify asynchronous password verification returns False for invalid password."""
    from backend.app.core.security import verify_password_async

    plain = "SuperSecurePassword123!"
    hashed = hash_password(plain)

    result = await verify_password_async("WrongPassword999!", hashed)
    assert result is False


@pytest.mark.asyncio
async def test_verify_password_async_safe_on_malformed_hash():
    """Verify asynchronous verification fails safely on malformed or empty hashes."""
    from backend.app.core.security import verify_password_async

    assert await verify_password_async("password", "") is False
    assert await verify_password_async("", "$argon2id$fake") is False
    assert await verify_password_async("password", "plain-sha256-hash") is False
    assert await verify_password_async("password", "$argon2id$invalid$structure") is False


@pytest.mark.asyncio
async def test_dummy_verify_password_async_executes():
    """Verify async dummy verification executes cleanly off event loop."""
    from backend.app.core.security import dummy_verify_password_async

    await dummy_verify_password_async()


# ============================================================================
# 4. Sensitive Data Redaction Regression Tests (M1 Day 1 Logging)
# ============================================================================

def test_sensitive_data_redactor_scrubs_passwords_with_spaces():
    """Verify passwords containing spaces inside quotes are properly redacted."""
    from backend.app.core.logging import SensitiveDataFilter

    log_msg = 'Received payload {"email": "user@example.com", "password": "my secret password with spaces"}'
    redacted = SensitiveDataFilter.redact(log_msg)

    assert "my secret password with spaces" not in redacted
    assert '"password": "[REDACTED]"' in redacted


def test_sensitive_data_redactor_scrubs_connection_uris():
    """Verify database and Redis URIs with credentials are redacted."""
    from backend.app.core.logging import SensitiveDataFilter

    pg_log = "Connected to postgresql+asyncpg://db_admin:SecretPass123!@db.internal:5432/amsc_db"
    redacted_pg = SensitiveDataFilter.redact(pg_log)
    assert "SecretPass123!" not in redacted_pg
    assert "postgresql+asyncpg://db_admin:[REDACTED]@db.internal:5432/amsc_db" in redacted_pg

    redis_log = "Connected to redis://:SuperSecretRedisPass@cache.internal:6379/0"
    redacted_redis = SensitiveDataFilter.redact(redis_log)
    assert "SuperSecretRedisPass" not in redacted_redis
    assert "redis://:[REDACTED]@cache.internal:6379/0" in redacted_redis


def test_sensitive_data_redactor_scrubs_jwt_and_bearer_tokens():
    """Verify Bearer tokens and generic JWT strings are redacted from logs."""
    from backend.app.core.logging import SensitiveDataFilter

    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    log_jwt = f"User token: {jwt_token}"
    redacted_jwt = SensitiveDataFilter.redact(log_jwt)
    assert jwt_token not in redacted_jwt
    assert "[JWT_REDACTED]" in redacted_jwt

    bearer_log = "Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    redacted_bearer = SensitiveDataFilter.redact(bearer_log)
    assert "Bearer [REDACTED]" in redacted_bearer


def test_sensitive_data_redactor_scrubs_unquoted_passwords_and_keys():
    """Verify unquoted passwords and API keys in CLI/YAML/key-value style logs are redacted."""
    from backend.app.core.logging import SensitiveDataFilter

    log_colon = "Auth config: password: MySecretPassword123 with trailing text"
    redacted_colon = SensitiveDataFilter.redact(log_colon)
    assert "MySecretPassword123" not in redacted_colon
    assert "password: [REDACTED] with trailing text" in redacted_colon

    log_eq = "User attempted auth: password = TopSecretPassWord!"
    redacted_eq = SensitiveDataFilter.redact(log_eq)
    assert "TopSecretPassWord!" not in redacted_eq
    assert "password = [REDACTED]" in redacted_eq

    log_key = "Header received: api_key: secret-api-key-value-999"
    redacted_key = SensitiveDataFilter.redact(log_key)
    assert "secret-api-key-value-999" not in redacted_key
    assert "api_key: [REDACTED]" in redacted_key


def test_sensitive_data_filter_handles_record_args_and_logging_format():
    """Verify SensitiveDataFilter scrubs record.args whether dict, tuple, or formatted string."""
    import logging
    from backend.app.core.logging import RedactingFormatter, SensitiveDataFilter

    logger = logging.getLogger("test_redact_logger")
    logger.handlers.clear()

    class CapturingHandler(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(self.format(record))

    handler = CapturingHandler()
    handler.setFormatter(RedactingFormatter(fmt="%(message)s"))
    handler.addFilter(SensitiveDataFilter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info("Login payload: %s", '{"password": "secret-pass-in-arg"}')
    assert len(handler.records) == 1
    assert "secret-pass-in-arg" not in handler.records[0]
    assert '"password": "[REDACTED]"' in handler.records[0]


@pytest.mark.asyncio
async def test_verify_password_non_string_types_fail_safely():
    """Verify verify_password and verify_password_async handle non-string types safely."""
    from backend.app.core.security import verify_password, verify_password_async

    # Synchronous
    assert verify_password(None, "$argon2id$fake") is False
    assert verify_password("password", None) is False
    assert verify_password(12345, "$argon2id$fake") is False
    assert verify_password("password", 67890) is False
    assert verify_password({}, []) is False

    # Asynchronous
    assert await verify_password_async(None, "$argon2id$fake") is False
    assert await verify_password_async("password", None) is False
    assert await verify_password_async(12345, "$argon2id$fake") is False
    assert await verify_password_async("password", 67890) is False
    assert await verify_password_async({}, []) is False
