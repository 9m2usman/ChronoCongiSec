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

## 9. Protected Tool Gateway & Day 4 Security Findings

The following security findings were identified during the M1 Day 4 Protected Tool Gateway implementation, complete mediation audit, and fail-closed security review.

| ID | Severity | Owner | Finding | Evidence / Code Path | Required Remediation | Status & Verification |
|---|---|---|---|---|---|
| GAP-018 | **P0 Critical** | M1 + M2 | Missing dedicated agent credential contract for per-agent authentication and token issuance. | `backend/app/api/gateway.py` authenticates caller via tenant membership JWT and validates `agent_id` belongs to tenant and is `ACTIVE`. No independent cryptographic token issuance, rotation, or agent-held bearer key currently exists in route catalog. | M1 and M2 must formalize a cryptographically signed agent credential lifecycle (agent bearer tokens with short TTLs and revocation). Caller must prove possession of agent private key or agent-scoped token. | **OPEN**: Guarded by server-side tenant scoping and active agent validation; requires M2/M1 agent credential protocol. |
| GAP-019 | **P1 High** | M1 + M6 | Idempotency key reuse with mismatched request payload could lead to silent replay hijacking or inconsistent execution state. | `backend/app/api/gateway.py` compares deterministic cryptographic SHA-256 fingerprint of canonical payload against existing record. | Compute canonical SHA-256 fingerprint on all security-critical payload fields. If key matches and fingerprint differs, strictly reject with HTTP 409 Conflict. | **RESOLVED & VERIFIED**: Verified by `test_idempotent_key_reuse_with_mismatched_payload_returns_409_conflict`. Rejects with HTTP 409 Conflict. |
| GAP-020 | **P1 High** | M1 + M6 + M7 | Concurrent duplicate proposals could execute external adapters multiple times if database unique constraint or distributed lock is missing. | `backend/app/database/models/gateway.py` enforces `UNIQUE (tenant_id, idempotency_key)`. | PostgreSQL unique constraint serves as durable authority; proposal & decision are persisted with `PENDING_EXECUTION` BEFORE adapter dispatch; duplicate in-progress requests return HTTP 409 Conflict; M7 Redis distributed lock coordinates distributed workers. | **RESOLVED & VERIFIED**: Proposal and decision persisted before dispatch; concurrent execution rejects with 409 Conflict; verified by unit tests. |
| GAP-021 | **P0 Critical** | M1 + M3 + M4 | Memory trust time-of-check / time-of-use (TOCTOU) race condition between policy evaluation and tool execution. | In a multi-step flow, a memory record could transition to `QUARANTINED` or `SUPERSEDED` immediately after evaluation but before adapter dispatch. | Gateway must bind the decision to exact memory version IDs and SHA-256 checksums, and perform a final trust validation immediately before dispatching to external tool adapter. If trust changed, abort with `BLOCK`. | **RESOLVED & VERIFIED**: TOCTOU revalidation implemented immediately before adapter execution in `backend/app/api/gateway.py`. Verified by `test_memory_toctou_trust_revocation_before_dispatch_blocks_execution`. |
| GAP-022 | **P2 Medium** | M1 + M4 | Policy version binding is not explicitly stored in `policy_decisions` table. | `backend/app/database/models/gateway.py::PolicyDecision` stores `decision`, `memory_trust`, `policy_result`, `reasons_json`, but not `policy_version`. | M4 and M6 should coordinate adding `policy_version` to `policy_decisions` schema and migrations so forensic audits can prove which rule version authorized an action. | **OPEN**: Documented cross-member dependency for M4/M6. |
| GAP-023 | **P1 High** | M1 + M2 + M6 | External tool side-effect ambiguity after network timeout or process crash. | When an external banking or cloud tool adapter request times out or fails halfway, a database rollback cannot reverse external execution. | Mark execution status as `UNKNOWN` / `FAILED` and require manual or outbox-based reconciliation. Do not blindly retry non-idempotent operations. | **RESOLVED & VERIFIED**: Adapter timeouts are trapped and recorded as `UNKNOWN` with `status_code=504`; blind retries are prohibited. Verified by `test_adapter_timeout_records_unknown_outcome_and_no_retry`. |
| GAP-024 | **P1 High** | M1 | Unbounded proposal parameters and excessive memory references could cause memory exhaustion or CPU DoS. | `backend/app/api/gateway.py` enforces `MAX_MEMORY_REFS_COUNT=50`, `MAX_PARAMETERS_DEPTH=5`, finite float check (reject NaN/Inf), and 64KB payload bound. | Reject oversized parameter nesting, non-finite floats, and unbounded reference lists via Pydantic validators. | **RESOLVED & VERIFIED**: Verified by `test_propose_action_rejects_nan_and_infinity` and `test_propose_action_rejects_excessive_parameter_nesting`. |
| GAP-025 | **P0 Critical** | M2 | Server-Side Request Forgery (SSRF) and private network resource targeting in tool adapter execution. | Adapters accepting URLs or network destinations could be manipulated into targeting loopback (127.0.0.1) or cloud metadata (169.254.169.254). | M2 adapters must enforce strict IP/destination allowlisting, reject private/reserved IP ranges, and perform DNS resolution checks. | **OPEN (M2 Owned)**: Sandbox transfer adapter enforces destination allowlisting; full network egress controls owned by M2. |
| GAP-026 | **P1 High** | M1 + M6 | Sensitive tool parameters (passwords, tokens, credentials) leaked in audit logs or forensic tables. | `backend/app/api/gateway.py::redact_sensitive_payload` recursively scrubs keys matching sensitive patterns before persisting to `AuditEvent.details_json`. | Apply recursive structured redaction on parameters before saving audit events or logging. | **RESOLVED & VERIFIED**: Verified by `test_sensitive_parameters_are_redacted_in_audit_events`. Secrets replaced with `[REDACTED]`. |
| GAP-027 | **P0 Critical** | M2 + M7 | Direct adapter invocation bypass risk if agent runtime code can access tool credentials directly. | `AMSC-DOC-002` Section 5 specifies credential isolation: agent runtimes have zero direct tool credentials; all calls must pass through Gateway. | Ensure adapters reside only on server-side Gateway, credentials are injected only at execution time, and agent containers lack network access to internal tool endpoints. | **OPEN (M2 + M7 Owned)**: Gateway complete mediation path established; deployment-level container isolation owned by M7. |
| GAP-028 | **P1 High** | M1 + M4 + M6 | Branch-level authorization and isolation contract is not enforced for agents and proposals. | `AgentEntity` and `AgentRecord` contain `branch_id`, and `branches` table exists in database schema, but `TenantContext` and JWT memberships only carry `tenant_id` and `role`. | M4 and M6 must formalize branch membership mapping and branch-scoped RBAC policies so agents belonging to specific branches cannot be invoked across unauthorized branches. | **OPEN**: Scoped at tenant boundary; cross-branch RBAC contract requires M4/M6 specification. |

---

## 10. Incident Management, Evidence & Quarantine Security Findings (Day 5)

The following security findings were identified during the M1 Day 5 Incident Management, Evidence Attachment, and Memory Quarantine API integration review. (Note: Identifiers GAP-029 through GAP-032 are allocated because GAP-018 through GAP-028 were assigned during Day 4 Protected Tool Gateway implementation).

| ID | Severity | Owner | Finding | Evidence / Code Path | Required Remediation | Status & Verification |
|---|---|---|---|---|---|
| GAP-029 | **P1 High** | M1 + M4 + M6 | Incident and Evidence Reference Authorization: Caller-supplied identifiers accepted without proof of tenant ownership. | `backend/app/api/incident_management.py` validates `affected_record_id`, `agent_id`, and `evidence[].resource_id` against authenticated `tenant_id` before persistence. | Verify tenant ownership; verify branch authorization where supported; verify resource type against allowlist; reject arbitrary and cross-tenant references with HTTP 400 Bad Request; add IDOR and cross-tenant tests. | **OPEN**: Implemented and verified in M1 API layer (`test_cross_tenant_memory_reference_in_incident_rejected`, `test_cross_tenant_evidence_reference_rejected`); full multi-branch PostgreSQL integration pending M4/M6. |
| GAP-030 | **P0 Critical** | M3 + M4 + M6 + M7 (M1 Integration) | Quarantine Atomicity and Retrieval Invalidation: Risk of partial quarantine write or stale cache exposure. | `backend/app/api/incident_management.py::_execute_quarantine_flow` calls M4 Quarantine Service, updates memory record, and persists quarantine/audit rows atomically with rollback on failure. | Atomic quarantine transition; durable quarantine evidence; immediate trusted-only retrieval enforcement; cache invalidation; concurrency and failure-injection tests; protected gateway action rejection for quarantined memory. | **OPEN**: Implemented in M1/M4 with state rollback on persistence failure (`test_quarantine_persistence_failure_rolls_back_memory_trust_state`) and immediate exclusion from retrieval (`test_quarantined_memory_immediately_excluded_from_normal_retrieval`); distributed cache invalidation and PostgreSQL concurrency tests pending M6/M7. |
| GAP-031 | **P1 High** | M1 + M4 + M6 | Forensic Access Authorization and Auditability: Risk of quarantined memory exposure through ordinary retrieval flags without audit trail. | `backend/app/api/memory.py` strictly excludes non-trusted records; dedicated forensic route `GET /api/v1/security/memory/{id}` requires `SECURITY_ANALYST` role and mandatory investigation reason. | Separate forensic operation from public retrieval; require explicit permission; tenant and branch scoping; mandatory reason parameter; durable audit event creation; tests for unauthorized forensic access. | **OPEN**: Dedicated forensic endpoint implemented and verified (`test_forensic_memory_access_by_analyst_succeeds`, `test_forensic_memory_access_by_unauthorized_role_rejected_403`); durable audit DB trigger pending M6. |
| GAP-032 | **P1 High** | M1 + M4 + M6 + M7 | Incident Evidence Confidentiality and Retention: Risk of sensitive credentials leaked in metadata or evidence modified silently. | `backend/app/api/incident_management.py::redact_sensitive_dict` recursively scrubs credentials, passwords, tokens, and API keys before persistence and response generation; evidence is append-only. | Evidence schema allowlists; recursive secret redaction; bounded metadata size (<= 16KB) and depth (<= 5); append-only evidence behavior; durable audit linkage; redaction and retention tests. | **OPEN**: Bounded validation and recursive redaction implemented and verified (`test_evidence_sensitive_metadata_is_redacted`); database append-only constraint enforcement pending M6. |

---

## 11. Observability, Dual Trace & Telemetry Security Findings (Day 6)

The following security findings were identified during the M1 Day 6 Observability and Dual Trace API integration review. (Note: Identifiers GAP-033 through GAP-037 are allocated following GAP-032).

| ID | Severity | Owner | Finding | Evidence / Code Path | Required Remediation | Status & Verification |
|---|---|---|---|---|---|
| GAP-033 | **P1 High** | M1 + M6 + M7 | Trace Tenant and Resource Authorization (IDOR): Trace or nested resource IDs may expose another tenant's execution or memory evidence. | `backend/app/api/traces.py::get_dual_trace_endpoint` strictly scopes all lookups and joined spans, proposals, decisions, and retrieval events by `tenant_id`. | Tenant-scoped lookups and joins; resource authorization; safe not-found behavior (HTTP 404 without leaking existence); cross-tenant IDOR regression tests. | **OPEN**: Implemented in M1 API layer (`test_cross_tenant_trace_returns_404_not_found`, `test_cross_tenant_spans_and_proposals_excluded`); full PostgreSQL multi-branch authorization pending M4/M6. |
| GAP-034 | **P1 High** | M1 + M2 + M3 + M7 | Sensitive Telemetry Exposure: Trace metadata, retrieval metadata, or tool payloads may leak credentials, tokens, passwords, or raw prompts. | `backend/app/api/traces.py::redact_sensitive_dict` recursively scrubs keys matching sensitive patterns (`password`, `token`, `secret`, `api_key`, `auth`, `bearer`, `credential`, `prompt`, `priv_key`) and bounds depth (<= 5) and string lengths (<= 2048). | Explicit response allowlists; recursive secret redaction; never return raw unvalidated `query_text` or raw `metadata_json`; bounded nesting depth; redaction regression tests. | **OPEN**: Implemented and verified in M1 API layer (`test_sensitive_telemetry_credentials_and_tokens_are_redacted`, `test_raw_query_text_is_not_exposed_raw`); production log audit verification pending M6/M7. |
| GAP-035 | **P1 High** | M3 + M6 (M1 Integration) | Historical Memory Evidence Incompleteness: Current retrieval records do not preserve exact historical version, checksum, and trust state at retrieval time. | `backend/app/database/models/memory.py::RetrievalEvent` lacks `version`, `checksum`, and `trust_state_at_retrieval` columns. | M3/M6 must enhance retrieval event recording to persist immutable retrieval-time trust and version evidence; M1 API must clearly distinguish current trust state from historical state and never falsely assert current state was retrieval-time state; completeness reported as `PARTIAL` with explicit warning when historical evidence is absent. | **OPEN**: Truthful labeling implemented in M1 API (`test_historical_trust_unrecorded_labeled_truthfully_and_warned`); schema migration and retrieval event capture enhancement owned by M3/M6. |
| GAP-036 | **P1 High** | M1 + M2 + M3 + M6 | Trace Correlation Integrity & Incomplete Telemetry: Risk of false correlation based on timing heuristics or crashes from orphan spans and cycles. | `backend/app/api/traces.py::build_execution_lane` correlates strictly on authoritative `trace_id` and proposal/span relationships, safely detects orphan spans, and prevents cycles. | Strict trace ID filtering; no heuristic/fuzzy timestamp matching; safe orphan span handling without recursive crashes; explicit warning generation; correlation regression tests. | **OPEN**: Implemented and verified in M1 API layer (`test_strict_trace_id_correlation_excludes_other_traces`, `test_orphan_spans_handled_safely_with_warning`); M2 runtime span emitter integration pending M2. |
| GAP-037 | **P2 Medium** | M1 + M6 + M7 | Trace Resource Exhaustion via Unbounded Telemetry: Malicious or oversized traces could cause memory exhaustion or slow queries. | `backend/app/api/traces.py` enforces `MAX_SPANS_LIMIT=500`, `MAX_MEMORY_EVENTS_LIMIT=200`, bounded pagination (`limit<=100`), and tenant rate limiting (60 req/min). | Server-side query bounding; result truncation with explicit `truncated=True` flag and `TRUNCATED` completeness reporting; sliding-window rate limiting; stress/resource boundary tests. | **OPEN**: Implemented and verified in M1 API layer (`test_oversized_trace_telemetry_is_bounded_and_truncated`, `test_traces_listing_pagination_bounds`); distributed Redis rate limiter pending M7. |
