"""Security Architecture Foundations & Cryptographic Standards.

Module: backend.app.core.security
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- Master Implementation Specification Section 9: Security Requirements (Non-Negotiable)
- Section 9.2: Password storage — Argon2id or bcrypt (Never plain SHA-256)
- Section 9.3: JWT token signing & verification standards

Notice:
Full authentication flows (token generation, password hashing, verification)
are scheduled for M1 Day 2. This module establishes cryptographic constants
and architecture guardrails for the platform.
"""

# Cryptographic Algorithm Standards
RECOMMENDED_PASSWORD_HASH_ALGORITHM = "argon2id"
FALLBACK_PASSWORD_HASH_ALGORITHM = "bcrypt"
BCRYPT_MIN_ROUNDS = 12

# JWT Security Constraints
TOKEN_TYPE = "Bearer"
DEFAULT_JWT_ALGORITHM = "HS256"
MIN_SECRET_LENGTH_BYTES = 32

# Invariant: Plain SHA-256 is strictly prohibited for password hashing
PROHIBITED_HASH_ALGORITHMS = {"md5", "sha1", "sha256"}
