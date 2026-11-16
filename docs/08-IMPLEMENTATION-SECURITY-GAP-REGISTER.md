# AMSC Document 08 — Implementation Security Gap Register
### Authoritative Audit, Gap Tracking & Remediation Evidence Register

**Document Identifier:** AMSC-DOC-008  
**Status:** Living Audit Register  
**Review Baseline:** M1 Day 1, M1 Day 2, M3 Day 1  

---

## 1. Overview & Governance Rules

This register tracks all identified security gaps, architectural weaknesses, and compliance findings across the ChronoCongiSec codebase. 

### Governance Rules:
1. Findings are classified by urgency:
   - **P0:** Immediate Sprint Blocker (Must fix before Day 3/Day 4 vertical slice and any deployment).
   - **P1:** Release Gate Hardening (Must fix before production release of the corresponding feature).
   - **P2:** Important Enterprise Hardening.
   - **P3:** Future Capability / Post-MVP Optimization.
2. A finding is marked `RESOLVED` **ONLY** after code implementation, automated negative regression tests pass, and independent verification is documented.
3. Unresolved findings must **NEVER** be removed or hidden.

---

## 2. P0 Security Gaps (Active Milestone Remediation)

### [GAP-001] Normal Memory Retrieval Exposes Non-TRUSTED States
- **Severity:** HIGH / P0 Blocker
- **Primary Owner:** M3 (Memory) / M1 (API)
- **Affected Files:** `backend/app/memory/service.py`, `backend/app/memory/repository.py`, `backend/app/api/memory.py`
- **Current Behavior:** Retrieval filters `exclude_quarantined=True`, which excludes `QUARANTINED` and `REJECTED`, but returns `UNVERIFIED`, `SUSPICIOUS`, and `SUPERSEDED` records. Callers can also manipulate `trust_state` query parameters.
- **Required Behavior:** Normal agent retrieval returns ONLY eligible `TRUSTED` memory records. Any record in `UNVERIFIED`, `SUSPICIOUS`, `QUARANTINED`, `REJECTED`, or `SUPERSEDED` state is strictly excluded. Querying for unsafe trust states is prohibited.
- **Status:** **IN PROGRESS (Active Remediation Branch `fix/p0-memory-security-single-company`)**

---

### [GAP-002] Updating Memory Preserves Trust of New Unvalidated Content
- **Severity:** HIGH / P0 Blocker
- **Primary Owner:** M3 (Memory) / M4 (Security Engine) / M6 (DB)
- **Affected Files:** `backend/app/memory/service.py`
- **Current Behavior:** `update_memory()` appends a new version but leaves `record.trust_state` unchanged. A previously `TRUSTED` record remains `TRUSTED` when updated with unvetted content.
- **Required Behavior:** Updating memory creates a new immutable version and automatically invalidates the record's trust eligibility, setting `record.trust_state = UNVERIFIED`. The updated memory cannot be retrieved as `TRUSTED` until M4 validates it. Historical versions, checksums, and audit decisions remain immutable.
- **Status:** **IN PROGRESS (Active Remediation Branch `fix/p0-memory-security-single-company`)**

---

### [GAP-003] Memory Ingestion Accepts Arbitrary Unvalidated Agent and Source Identifiers
- **Severity:** HIGH / P0 Blocker
- **Primary Owner:** M3 (Memory) / M1 (API) / M6 (DB)
- **Affected Files:** `backend/app/memory/service.py`, `backend/app/memory/models.py`, `backend/app/memory/repository.py`, `backend/app/api/memory.py`
- **Current Behavior:** `MemoryIngestRequest` accepts arbitrary `agent_id` and `source_id` strings without verifying existence, company ownership, or active status.
- **Required Behavior:** Ingestion must independently verify:
  1. `agent_id`: exists, belongs to authenticated company, and is `ACTIVE`.
  2. `source_id`: exists, belongs to authenticated company, and is `ACTIVE`.
  3. `parent_record_id`: belongs to authenticated company, is not `QUARANTINED` or `REJECTED`, and satisfies DAG cycle and depth limits.
  Unowned, inactive, or cross-company references must be rejected with HTTP 400 (`ValidationError`) or HTTP 404 (`MemoryNotFoundError`).
- **Status:** **IN PROGRESS (Active Remediation Branch `fix/p0-memory-security-single-company`)**

---

### [GAP-004] Memory Detail Endpoint Exposes Non-TRUSTED Records
- **Severity:** HIGH / P0 Blocker
- **Primary Owner:** M3 (Memory) / M1 (API)
- **Affected Files:** `backend/app/memory/service.py`, `backend/app/api/memory.py`
- **Current Behavior:** `get_memory_detail()` and `GET /api/v1/memory/{id}` block `QUARANTINED` and `REJECTED` records, but return `UNVERIFIED`, `SUSPICIOUS`, and `SUPERSEDED` records.
- **Required Behavior:** Normal agent detail access applies the exact same trust invariant as list retrieval. Only eligible `TRUSTED` records are returned. Non-TRUSTED records return HTTP 404 (`MemoryNotFoundError`). Forensic access is reserved for authorized M4 workflows.
- **Status:** **IN PROGRESS (Active Remediation Branch `fix/p0-memory-security-single-company`)**

---

## 3. P1 Security Gaps (Release Gate Hardening)

| Gap ID | Description | Affected Modules | Primary Owner | Target Milestone |
|---|---|---|---|---|
| **GAP-005** | Reverse-proxy client IP extraction and trusted proxy allowlist configuration. | `core/config.py`, `api/auth.py` | M1 / M7 | Milestone 4 |
| **GAP-006** | Browser HTTP security response headers (`X-Frame-Options`, `CSP`, `HSTS`). | `main.py` | M1 | Milestone 4 |
| **GAP-007** | OpenAPI / Swagger UI public exposure gating in production (`APP_ENV=production`). | `core/config.py`, `main.py` | M1 | Milestone 4 |
| **GAP-008** | Redis-backed JWT revocation denylist (`jti`) and `/auth/logout` endpoint (RFC 8725). | `core/security.py`, `api/auth.py` | M1 / M7 | Milestone 4 |
| **GAP-009** | Post-auth account rate limit incrementing to prevent targeted account lockout DoS. | `api/auth.py` | M1 | Milestone 4 |
| **GAP-010** | Atomic database transaction encapsulation and row-level locking for memory updates. | `memory/service.py`, `database/` | M3 / M6 | Milestone 4 |
| **GAP-011** | Pre-ingestion credential and PII screening hook on memory content. | `memory/service.py`, `security/` | M3 / M4 | Milestone 4 |

---

## 4. P2 / P3 Security Gaps (Enterprise Hardening & Future Capabilities)

| Gap ID | Description | Affected Modules | Primary Owner | Priority |
|---|---|---|---|---|
| **GAP-012** | Hashing of corporate email identifiers in Redis rate-limiter keys. | `api/auth.py` | M1 | P2 |
| **GAP-013** | Conversion of Pydantic secret fields to `SecretStr` to prevent log leakage. | `core/config.py` | M1 | P2 |
| **GAP-014** | Production enforcement of TLS for PostgreSQL (`ssl=require`) and Redis (`rediss://`). | `core/config.py` | M1 / M6 / M7 | P2 |
| **GAP-015** | Dedicated health readiness probe (`/health/ready`) verifying DB and cache connectivity. | `main.py` | M1 / M7 | P2 |
| **GAP-016** | KMS-backed HMAC-SHA256 signatures for tamper-evident memory non-repudiation. | `memory/hashing.py`, `database/` | M3 / M4 / M6 | P2 |
| **GAP-017** | Hourly signed Merkle tree checkpoints for append-only audit verification. | `recovery/`, `audit/` | M3 / M4 | P3 |
| **GAP-018** | SPIFFE/SPIRE agent workload cryptographic identities. | `gateway/`, `agents/` | M2 / M1 | P3 |
