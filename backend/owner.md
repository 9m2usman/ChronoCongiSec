
# Backend Ownership & M1 Integration Architecture

**Platform coordinator:** M1 (Platform Backend & API Integration Lead)

| Module | Owner | Scope & Responsibility |
|---|---|---|
| `core/` | M1 | Application factory, lifecycle, configuration, exceptions, security, dependencies, logging |
| `api/auth.py` | M1 | Authentication endpoints (`/api/v1/auth/login`, `/api/v1/auth/me`), rate limiting enforcement |
| `api/tenants.py` | M1 | Tenancy catalog endpoints (`/api/v1/tenants`, `/api/v1/tenants/{id}`) |
| `api/agents.py` | M1 | Agent registration and management API contract |
| `gateway/` | M2 | Agent runtime execution, tool adapters, tool proxy |
| `api/gateway.py` | M2 | Gateway execution endpoints |
| `memory/` | M3 | Ephemeral & working memory state, ChromaDB/pgvector persistence |
| `knowledge/` | M3 | KnowledgeLine document ingestion, chunking, provenance tree |
| `api/memory.py` | M3 | Memory retrieval and mutation routes |
| `api/chronimem.py`| M3 | Temporal knowledge graph routes |
| `security/` | M4 | Policy engine, RBAC evaluator, threat detection, quarantine (`security/quarantine.py`) |
| `recovery/` | M4 | Rollback engine, point-in-time recovery, audit logs |
| `api/incident_management.py` | M1 | Authenticated incident & evidence API contracts, quarantine integration & forensic access |
| `api/security.py` | M4 | Security verification and policy administration routes |
| `api/incidents.py`| M4 | Incident reporting and triage domain logic |
| `api/recovery.py` | M4 | Recovery and rollback trigger routes |
| `database/` | M6 | PostgreSQL async SQLAlchemy engine, base models, Alembic migrations |
| `alembic/` | M6 | Migration scripts exclusively owned by M6 |
| `workers/` | M7 | Celery/Redis background worker infrastructure and scheduled tasks |

---

## 1. M1 Authentication & Environment Architecture

### A. Environment Separation (Dev vs. Test vs. Production)
* **Local Development (`APP_ENV=development`):**
  * `ALLOW_IN_MEMORY_AUTH=true` and `AUTH_BACKEND=in_memory_demo` permitted.
  * Explicit demo repository seeded with canonical Company A, B, and C accounts.
  * In-memory rate limiting enabled by default.
* **Automated Testing (`APP_ENV=test`):**
  * Isolated in-memory repository fixtures per test runner.
  * Ephemeral rate limiter instances per `create_app()` test fixture.
* **Production (`APP_ENV=production`):**
  * **Strictly forbids demo authentication.** `ALLOW_IN_MEMORY_AUTH` must be `false` and `AUTH_BACKEND` must be `database` (Pydantic validator raises `ValueError` on startup).
  * Application startup lifespan verifies a real database repository (`app.state.auth_repo`) is configured; fails fast with `RuntimeError` if missing or if a demo repo is attached.
  * `JWT_SECRET` must be provisioned externally with $\ge 32$ characters ($\ge 256$ bits entropy) and cannot contain placeholder terms.
  * `DATABASE_URL` must point to a real remote database instance (rejects `amsc_dev_password` and `localhost`).
  * `REDIS_URL` must point to a real remote Redis instance (rejects `localhost`).

### B. Secrets Management
* Cryptographic JWT secrets are read from the environment (`JWT_SECRET`).
* Secrets are never logged or exposed in tracebacks (enforced by `RedactingFormatter` and `SensitiveDataFilter`).
* In development/test, a random high-entropy secret is generated automatically if omitted.
* In production, secrets must be provisioned from a secure vault or secret manager (e.g. AWS Secrets Manager, GCP Secret Manager, Vault).

### C. Password Hashing (Argon2id)
* Uses `argon2-cffi` adhering to OWASP recommended baseline parameters:
  * Memory cost: $19,456\text{ KiB}$ ($\sim 19\text{ MB}$)
  * Time cost: $2$ iterations
  * Parallelism: $1$ thread
* Constant-time `dummy_verify_password()` executes on nonexistent user lookups to prevent username enumeration timing discrepancies.

---

## 2. Cross-Team Integration Contracts

### A. M6 — PostgreSQL Database Repository Interface
M1 defines the repository contract protocol in `backend/app/tenancy/context.py` (`AuthRepositoryProtocol`).
To complete live database authentication:
1. M6 implements `AuthRepositoryProtocol` backed by async SQLAlchemy sessions for `users`, `tenants`, and `memberships`.
2. M6 registers their instance on `app.state.auth_repo` during application lifespan or overrides `get_auth_repo` in `backend/app/core/dependencies.py`.
3. If PostgreSQL fails or is unreachable, the system fails closed (returns `503 Service Unavailable` with `SECURITY_DEPENDENCY_UNAVAILABLE`), **never** falling back to demo credentials.

### B. M7 — Distributed Rate Limiting & Redis
M1 defines the rate limiting interface protocol in `backend/app/core/dependencies.py` (`RateLimiterProtocol`).
1. M7 provides a Redis-backed sliding-window implementation supporting keys:
   * `login:ip:<client_ip>` (source IP throttling, max 10/min)
   * `login:account:<email>` (target account throttling, max 5/min)
2. M7 registers their implementation on `app.state.rate_limiter`.
3. If Redis fails, the system executes according to `settings.RATE_LIMIT_REDIS_FAILURE_POLICY`:
   * Default `fail_closed`: Throws `SecurityDependencyError` (HTTP 503) to prevent unlimited brute-force attacks during Redis outages.

### C. M4 — Security Policy & RBAC Engine
1. M1 authenticates the user, validates tenant membership, and stores the verified `TenantContext` on `request.state.tenant_context`.
2. M1 provides the `require_roles(*roles)` authorization dependency in `backend/app/core/dependencies.py`.
3. M4 hooks their fine-grained policy evaluation engine and attribute-based access control (ABAC) into `require_roles` or as an additional route dependency using `TenantContext`.

### D. M5 — Frontend API Contracts
* OpenAPI documentation generated at `/openapi.json` and interactive docs at `/docs`.
* `POST /api/v1/auth/login` returns `{access_token, token_type, expires_in, user, tenant_context}`.
* `GET /api/v1/auth/me` returns identity, active tenant, and roles.
* Standardized error response envelope strictly enforced across all 4xx/5xx responses:
  ```json
  {
    "error": {
      "code": "ERROR_CODE",
      "message": "Sanitized safe error message",
      "request_id": "req-...",
      "details": null
    }
  }
  ```

---

## 3. Remaining Limitations & Non-Implemented Features
* **Individual Token Revocation:** JWTs are stateless with a 60-minute lifetime. Immediate token revocation or session denylisting awaits M7's Redis infrastructure or M6's session table.
* **Live PostgreSQL Execution:** Blocked on M6's pending SQLAlchemy models and Alembic migrations.
* **Live Redis Rate Limiting:** Blocked on M7's pending Redis container and distributed sliding-window implementation.

