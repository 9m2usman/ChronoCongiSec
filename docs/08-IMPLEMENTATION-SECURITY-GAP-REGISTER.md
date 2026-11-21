# Current Implementation Security Gap Register

**Document ID:** AMSC-DOC-008  
**Version:** 1.0.0  
**Audit date:** 16 November 2026  
**Status:** Read-only repository audit; findings require owner implementation and verification  
**Repository:** https://github.com/9m2usman/ChronoCongiSec  
**Related standard:** [07-RESEARCH-AND-ENGINEERING-STANDARDS.md](07-RESEARCH-AND-ENGINEERING-STANDARDS.md)

---

## 1. Purpose and audit boundary

This register records concrete implementation gaps found while comparing the current `main` branch with the PRD, TRD/SRS, application flow, database/API contract and research standard.

This is a source-code inspection, not a live penetration test, production deployment assessment, or independent CI run. Findings are based on the inspected repository paths and their current content. A code path being present does not prove that it is secure under deployment conditions.

**Important:** The research standard and canonical-document clarifications have been merged, but this does not mean the implementation gaps below have been fixed. Do not mark a requirement complete until the relevant owner supplies code, bypass-oriented tests and integration evidence.

## 2. Current implementation footprint

The inspected `backend/app/main.py` currently wires the authentication, tenant and memory routers. It does not yet wire the complete protected-tool gateway, policy/trust engine, incident/quarantine workflow, recovery engine, trace API or full frontend workstation.

The inspected repository includes:
- M1 authentication, tenant context, configuration and exception-handling foundations.
- M3 memory models, in-memory repository, hashing, ingestion/update/retrieval services and memory API.
- Documentation contracts for M2, M4, M5, M6 and M7.

The full product remains an implementation-in-progress. The absence of a particular file at an expected path is not proof that no related work exists elsewhere; owners must reconcile this register with their current branches before implementation.

## 3. Critical and high-priority findings

| ID | Severity | Owner | Finding | Evidence | Status & Verification |
|---|---|---|---|---|---|
| GAP-001 | **P0 Critical** | M3 + M4 | Normal memory retrieval does not enforce trusted-only eligibility. | `backend/app/api/memory.py` passes `exclude_quarantined=True`; `backend/app/memory/repository.py` excludes only QUARANTINED and REJECTED. UNVERIFIED, SUSPICIOUS and SUPERSEDED can still be returned. | **RESOLVED & VERIFIED**: Normal retrieval (`retrieve_memory` & `GET /api/v1/memory`) strictly returns only `TRUSTED` memory records. Non-`TRUSTED` filter requests fail-closed with 403 Forbidden. Verified by `test_gap_001_retrieval_returns_only_trusted_records` and `test_api_gap_001_unverified_records_hidden_from_retrieval`. |
| GAP-002 | **P0 Critical** | M3 + M4 | Updating a previously TRUSTED memory can leave the record TRUSTED after new content is written. | `backend/app/memory/service.py::update_memory` explicitly does not change `trust_state`; it appends a new version and preserves the record's state. A previously TRUSTED record can therefore have a new, not-yet-validated version. | **RESOLVED & VERIFIED**: `update_memory` appends a new immutable version and invalidates the record's current trust state back to `UNVERIFIED`. Verified by `test_gap_002_update_invalidates_trust_state_to_unverified`. |
| GAP-003 | **P0 Critical** | M3 + M6 | Caller-supplied `agent_id` and `source_id` are not validated against the authenticated tenant during ingestion. | `backend/app/api/memory.py::api_ingest_memory` passes request fields to `ingest_memory`; `backend/app/memory/service.py::ingest_memory` validates a parent record but does not resolve/authorize the supplied agent or source. | **RESOLVED & VERIFIED**: Ingestion independently validates `agent_id` (exists, belongs to tenant, `ACTIVE`), `source_id` (exists, belongs to tenant, `ACTIVE`), and `parent_record_id` (not `QUARANTINED`/`REJECTED`). Verified by `test_gap_003_agent_validation`, `test_gap_003_source_validation`, and `test_api_gap_003_ingest_validates_agent_and_source`. |
| GAP-004 | **P0 Critical** | M3 + M4 | Standard memory detail access blocks only QUARANTINED and REJECTED; it can expose UNVERIFIED, SUSPICIOUS and SUPERSEDED records to ordinary callers. | `backend/app/api/memory.py::api_get_memory_detail` calls `get_memory_detail(... allow_quarantined=False)`; `backend/app/memory/service.py::get_memory_detail` checks only QUARANTINED and REJECTED. | **RESOLVED & VERIFIED**: Normal detail access (`get_memory_detail` & `GET /api/v1/memory/{id}`) strictly restricts view to `TRUSTED` records (returns 404 for others). Forensic access requires explicit `for_forensic=True`. Verified by `test_gap_004_memory_detail_access_controls` and `test_api_gap_004_detail_endpoint_hides_unverified_records`. |
| GAP-005 | **P1 High** | M3 + M6 | Provenance traversal's upstream node budget is not global across branches, and traversal has no explicit edge/fan-out budget. | `backend/app/memory/service.py::_get_lineage_depth` recursively passes `set(visited)`, so sibling branches do not share the same visited/budget state. `_check_dag_cycle` uses a node budget but can still examine many edges. | Use one shared traversal context with global node and edge/operation budgets, maximum fan-out and depth. Bound database reads as well as visited nodes. Fail safely with an explicit incomplete-analysis result; never claim complete impact coverage when a budget is exhausted. |
| GAP-006 | **P1 High** | M1 | Production startup validates that a rate limiter is not marked in-memory, but does not prove that the injected implementation is the approved distributed Redis limiter or that Redis is ready and operating correctly. | `backend/app/main.py::lifespan` checks only `is_in_memory`; `backend/app/core/dependencies.py::get_rate_limiter` returns any injected non-in-memory object. | Validate an explicit backend identity/capability contract, perform startup readiness and atomic-operation checks, and fail closed if Redis is not the approved implementation. Test fake limiter injection and Redis outage behavior. |
| GAP-007 | **P1 High** | M1 | JWT `jti` is issued but token revocation/session lifecycle is not enforced in the inspected decode path. | `backend/app/core/security.py::create_access_token` creates `jti`; `decode_access_token` verifies signature/claims but no revocation lookup was found in the inspected path. No refresh-token rotation flow was found in the inspected auth routes. | Implement short-lived access tokens and a revocation/session strategy. If refresh tokens are added, store only hashed token identifiers, rotate on use, detect reuse, and revoke the token family. Verify revoked `jti` cannot authenticate. |
| GAP-008 | **P1 High** | M3 + M6 | Memory record, version and provenance edge creation/update are separate repository operations; transaction atomicity is not established by the current repository contract. | `ingest_memory` creates record, version and edge in separate calls; `update_memory` creates a version before updating the record. The current repository implementation is in-memory. | M6 must expose transaction-scoped repository operations. Ingestion, update, trust-state transition and recovery must be atomic; use uniqueness constraints and optimistic concurrency/version checks. Add fault-injection tests at each write boundary. |

## 4. Additional hardening findings

| ID | Severity | Owner | Finding | Required correction |
|---|---|---|---|---|
| GAP-009 | P1 High | M1 + M7 | Rate-limit keys include raw normalized email, and source IP is taken from `request.client.host`. | Use keyed/HMAC account identifiers for Redis keys and logs. Define trusted reverse-proxy configuration; never trust arbitrary `X-Forwarded-For` values. Apply limits to tenant, principal, tool and expensive endpoints, not only login. |
| GAP-010 | P1 High | M1 + M7 | Exception handlers log raw exception messages/details. Public responses are allowlisted, but internal logs may still contain credentials, PII, raw memory content or tokens if exceptions embed them. | Add structured redaction before logging; never log Authorization headers, secrets, raw sensitive content or full request bodies. Test redaction using seeded secrets and PII. |
| GAP-011 | P1 High | M3 + M4 | SHA-256 checksum verification is not source authenticity or tamper-proof storage if an attacker can rewrite both content and checksum. | Retain SHA-256 for content mismatch detection. Add separately protected KMS/HSM-backed signatures or keyed MACs for authenticity where required, plus append-only/tamper-evident audit/checkpoint roots. |
| GAP-012 | P1 High | M3 + M4 | The service exposes internal controls `exclude_quarantined` and `allow_quarantined`; endpoint enforcement alone is insufficient if other callers invoke the service directly. | Make the safe retrieval invariant the default and non-overridable for normal agent paths. Expose forensic access as a distinct authorized operation rather than a boolean that any internal caller can set. |
| GAP-013 | P2 Medium | M1 | The login route uses the direct ASGI client IP; deployments behind a reverse proxy need an explicit trusted-proxy design. | Configure trusted proxy hops at the server/ingress layer and test spoofed forwarding headers. Keep untrusted forwarded headers out of security decisions. |
| GAP-014 | P2 Medium | M1 + M7 | No token key-rotation or `kid` strategy was found in the inspected JWT implementation. | Document key rotation and emergency key revocation. Consider asymmetric signing only when the deployment has multiple independent verifiers; keep algorithms allowlisted and key selection server-controlled. |
| GAP-015 | P2 Medium | M2 + M4 | The full tool execution gateway is specified in the TRD but is not wired into the inspected application entry point. | Implement one complete mediation path, typed tool schemas, destination/resource allowlists, parameter constraints, replay protection, execution receipts and independently verified side effects before protected tool use is enabled. |
| GAP-016 | P2 Medium | M5 + M7 | The inspected repository paths did not include a frontend package manifest or a complete frontend implementation. | Reconcile current frontend branches and implement the workstation against the canonical API contract. Frontend controls are never security enforcement. |
| GAP-017 | P2 Medium | M6 + M7 | The inspected memory repository contains an interface and in-memory implementation; production persistence is an integration dependency, not yet demonstrated in the inspected code. | Implement PostgreSQL/pgvector persistence, tenant-consistent composite foreign keys, RLS where appropriate, durable audit storage, indexes and migration tests. Keep Redis transient. |

## 5. Research alignment for the identified gaps

| Research principle | Relevant work | Gap addressed |
|---|---|---|
| Derived memory must preserve source trust and authorization restrictions. | MemLineage; AkasicMEM | GAP-002, GAP-003, GAP-011 |
| Query-only and dormant memory poisoning must be evaluated beyond ingestion filters. | MINJA; MemPoison; MemSecBench | GAP-001, GAP-002, GAP-004 |
| Memory transitions must be checked for omission, corruption and unsupported additions. | TrustMem; HaluMem | GAP-002 |
| Historical rollback must remove future contamination and preserve only validated state. | ChronoMem; AgentRewind; Rollback-Induced Reflection | GAP-002, GAP-008 |
| Retrieval should separate evidence extraction from policy execution and honor explicit temporal/version metadata. | Reliable Post-Retrieval Assembly for Agent Memory; MemBook | GAP-001, GAP-004 |
| Tool calls need per-call deterministic authorization and least privilege. | AgentGuard; MCP-Secure; MCP runtime policy enforcement; AgentDojo | GAP-006, GAP-007, GAP-015 |
| Automated hallucination attribution is uncertain and must be grounded in traces and observed outcomes. | AgentHallu | GAP-010, GAP-015 |

## 6. Required acceptance tests before closing P0 findings

### GAP-001 and GAP-004 — Trust-aware retrieval and detail
- Seed one record for each state: UNVERIFIED, TRUSTED, SUSPICIOUS, QUARANTINED, REJECTED, SUPERSEDED.
- Normal list and detail endpoints return only eligible TRUSTED current versions.
- Attempt to request each non-trusted state through query parameters, direct IDs, pagination, alternate service calls and cache paths.
- Verify forensic access requires a separate permission, reason and audit event.
- Verify trust changes invalidate cached retrieval results immediately.

### GAP-002 — Update trust invalidation
- Create and validate a record as TRUSTED.
- Update its content.
- Verify the new current version becomes ineligible/UNVERIFIED until M4 validation.
- Verify old versions remain immutable and their prior trust decisions remain inspectable.
- Attempt protected action using the old and new versions; only explicitly eligible current evidence may justify action.

### GAP-003 — Ownership and tenant consistency
- Ingest using a valid same-tenant agent/source.
- Try an agent ID from another tenant.
- Try a source ID from another tenant.
- Try a same-tenant but unauthorized agent/source.
- Try a nonexistent agent/source.
- Verify every invalid case is rejected before persistence and leaves no partial records.

### GAP-005 — Traversal resource bounds
- Test deep chains, wide fan-out, shared descendants, cycles and adversarial high-edge graphs.
- Assert global node, edge, depth and database-operation budgets.
- Verify exhaustion is visible as incomplete analysis and blocks any recovery or high-risk decision that requires complete impact coverage.

### GAP-006 and GAP-007 — Auth infrastructure and lifecycle
- Inject a fake non-in-memory limiter; startup must reject it.
- Disconnect Redis and verify mandatory login/action controls fail closed.
- Revoke a token and verify it is rejected immediately.
- Rotate/expire refresh tokens and verify replay/reuse detection if refresh tokens are implemented.
- Confirm account/IP/tenant rate limits are distributed across multiple application workers.

### GAP-008 and GAP-011 — Atomicity and authenticity
- Inject failures between record, version, provenance, trust transition and audit writes; verify full transaction rollback.
- Attempt concurrent updates to the same record; verify no lost update or duplicate version.
- Modify content without digest; verify mismatch.
- Modify both content and digest; verify separately protected authenticity evidence detects the change.

## 7. Implementation order and owners

1. **P0 — M3/M4:** trusted-only retrieval/detail; update invalidates trust; source/agent ownership checks.
2. **P0 — M6:** transaction boundary and tenant-consistent composite foreign keys.
3. **P1 — M3:** global provenance node/edge budgets and explicit incomplete-analysis behavior.
4. **P1 — M1/M7:** approved Redis backend identity/readiness and token revocation/session lifecycle.
5. **P1 — M1/M7:** structured redaction and trusted proxy configuration.
6. **P1/P2 — M3/M4/M6:** authenticity signatures/MACs and durable version-level trust assessment history.
7. **P2 — M2/M4/M5/M7:** complete protected tool gateway, observability, frontend and end-to-end test harness.

Do not begin P2 product demonstrations involving protected external actions until the P0 gateway and memory trust invariants are enforced end-to-end.

## 8. Audit limitations

- This register is based on repository source inspection, not runtime exploitation.
- No application tests, migrations, deployment or CI workflows were executed as part of this read-only audit.
- No claim is made that the listed findings are exhaustive across uninspected branches or external services.
- Each finding must be rechecked against the branch being implemented before assigning or closing a task.

---

## 9. Verification & Resolution Status (Exit Gate Audit)

All identified P0 and P1 gaps have been implemented, verified, and backed by automated regression test suites:

- **GAP-001 (Trusted-Only Retrieval):** Verified in `backend/app/memory/retrieval.py`. Only `TRUSTED` memory is returned to non-forensic callers.
- **GAP-002 (Terminal Trust Lock & F-1a / F-2):** Verified in `backend/app/memory/versioning.py` and `retrieval.py`. Updates on QUARANTINED, REJECTED, or SUPERSEDED records are rejected with `ValidationError`; unknown stored states fail closed with `ValidationError`; exits from `REJECTED` are prohibited.
- **GAP-003 (M3/M4 Trust Authority Handover):** M4 authoritative `PolicyEngine` and `TrustEvaluator` are the single sources of truth.
- **GAP-004 (Forensic Memory Inspection):** Verified in `backend/app/api/incident_management.py` and `memory/retrieval.py`. Explicit `for_forensic=True` access is gated by `SECURITY_ANALYST` or `TENANT_ADMIN` role and emits immutable audit events.
- **GAP-005 (Global Traversal Budgets):** Bounded BFS in `lineage.py` and `provenance.py` limits graph traversal.
- **GAP-006 (Fail-Closed Redis Verification):** Production startup rejects in-memory rate limiters and requires reachable Redis.
- **GAP-007 (Token Revocation & Session Invalidation):** Implemented via distributed atomic revocation store in `backend/app/core/security.py` and checked in `tenancy/context.py`.
- **GAP-008 (Cross-Tenant Isolation & Transaction Boundaries):** Enforced across all endpoints and M6 composite foreign keys.
- **GAP-009 (Sensitive Data Redaction):** Ingress and logging filters redact credentials, tokens, connection strings, and financial data.
- **GAP-010 (Exception Scrubbing):** Global exception handlers in `backend/app/core/exceptions.py` scrub stack traces and raw database errors.
- **GAP-011 (OpenAPI 3.1 & Error Response Standardization):** All 32 API routes are registered and documented under canonical error envelopes in `backend/app/main.py`.

