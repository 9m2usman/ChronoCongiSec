# Phase 2 Implementation Report: Detection & Action Security

**Product:** Agent Memory Security Center (AMSC) | ChronoCogniSec  
**Branch:** `feat/m2-agent-runtime-gateway-adapters`  
**Base Commit:** `3a7819235b83173dd825742d332371c01f3eb658`  
**Date:** 2026-11-24  
**Status:** Complete & Verified  

---

## 1. Mandatory Pre-Implementation Gate & Phase 1 Audit

Before implementing Phase 2, a comprehensive audit was executed across the Git working tree, database models, repository contracts, and test suites to verify Phase 1 capabilities against actual code and runtime invariants.

### 1.1 Classification of Phase 1 Capabilities

| Capability Domain | Subsystem / Contract | Phase 1 Status | Evidence / Verification Path |
|---|---|---|---|
| **Enterprise Security Baseline** | Multi-tenant & branch isolation (`tenant-a-uuid-001`, `branch-ho-001`, `branch-lhr-002`, `branch-khi-003`, `branch-isb-004`) | **IMPLEMENTED_AND_VERIFIED** | `backend/app/database/models/baseline.py`<br>`backend/app/api/baseline.py`<br>`test_baseline_crud_and_lifecycle` |
| **Agent Security Profiles** | Authoritative profiles (purpose, scope, approved tools/ops, operational ceilings) hardened against agent self-modification (`caller_user_id != agent_id`) | **IMPLEMENTED_AND_VERIFIED** | `backend/app/database/models/baseline.py`<br>`backend/app/api/agents.py`<br>`test_agent_security_profile_governance` |
| **Authoritative Knowledge Baseline** | Segregation of baseline records from mutable agent memory; version lineage; SHA-256 integrity digests; non-promotion invariant | **IMPLEMENTED_AND_VERIFIED** | `backend/app/database/repositories/baseline.py`<br>`backend/app/api/baseline.py`<br>`test_agent_memory_cannot_become_baseline` |
| **Baseline Lifecycle FSM** | Controlled transitions (`DRAFT` -> `IN_REVIEW` -> `APPROVED` -> `ACTIVE` -> `SUPERSEDED`/`REVOKED`/`ARCHIVED`) with `TENANT_ADMIN` enforcement | **IMPLEMENTED_AND_VERIFIED** | `backend/app/database/models/baseline.py`<br>`test_baseline_unauthorized_governance_mutation_rejected` |
| **Observation Event Contract** | Canonical 10 event categories, W3C traceparent correlation, idempotency key deduplication | **IMPLEMENTED_AND_VERIFIED** | `backend/app/database/models/baseline.py`<br>`backend/app/database/repositories/observation.py`<br>`test_observation_event_idempotency_and_traceparent` |
| **Secret & Sensitive Data Scrubbing** | Recursive scrubbing of passwords, bearer tokens, API keys, and authorization headers | **IMPLEMENTED_AND_VERIFIED** | `backend/app/database/repositories/observation.py`<br>`test_observation_event_secret_scrubbing` |
| **Framework-Neutral Telemetry** | Adapter contracts for CrewAI, LangGraph, AutoGen, Custom Python agents; telemetry hooks in Gateway and CrewAI tracer | **IMPLEMENTED_AND_VERIFIED** | `backend/app/adapters/contracts.py`<br>`backend/app/api/gateway.py`<br>`crewai_service/telemetry/tracer.py` |
| **Durable Trust Store (VULN-001)** | `SqlTrustDecisionStore` durably persisting to `trust_decisions` table via SQLAlchemy | **IMPLEMENTED_AND_VERIFIED** | `backend/app/recovery/store.py`<br>`backend/alembic/versions/0013_trust_decisions_baseline_and_observation.py`<br>`test_sql_trust_decision_store_persistence` |
| **Agent Tool Permissions (VULN-003)** | `grant_tool_permission` & `revoke_tool_permission` REST endpoints and dual repository implementations | **IMPLEMENTED_AND_VERIFIED** | `backend/app/database/repositories/agents.py`<br>`backend/app/api/agents.py`<br>`test_agent_tool_permission_grant_and_revoke` |
| **ChroniMem Contract (VULN-004)** | `GET /chronimem/timeline` supporting `record_id` (returning `versions[]`) and `agent_id`; mock removal | **IMPLEMENTED_AND_VERIFIED** | `backend/app/api/chronimem.py`<br>`test_chronimem_timeline_record_contract` |

**Pre-Implementation Gate Conclusion:** Phase 1 foundation was 100% verified with zero unresolved security blockers or broken contracts. Phase 2 proceeded on this verified foundation.

---

## 2. Architecture & Design

Phase 2 introduces a framework-neutral security detection and action-enforcement layer. It enforces complete mediation at the tool boundary, evaluates observed agent actions and memory operations against authoritative enterprise baselines and agent security profiles, and refuses to trust agent self-declarations.

```
                      +-------------------------------------------------------------+
                      |                   Agent Execution Context                   |
                      |  (CrewAI / LangGraph / AutoGen / Custom Python Agent)       |
                      +------------------------------+------------------------------+
                                                     |
                                                     | Action Proposal
                                                     v
+----------------------------------------------------+-----------------------------------------------------+
|                                          AMSC Security Gateway                                           |
|                                     (POST /api/v1/gateway/actions/propose)                               |
|                                                                                                          |
|  1. Ingress Tenant & Identity Authentication (M1 Auth & DB Membership Validation)                        |
|  2. Real-time Pre-Execution Threat Interception:                                                         |
|     * DetectionEngine.detect_tool_threat() (Destructive OS commands, SQL injections, parameter ceilings)  |
|     * DetectionEngine.detect_behavioral_deviation() (Profile purpose, tools, data scopes, branch bounds) |
|     --> If confirmed blocking threat detected: Fail-Closed Override -> BLOCK + Audit Record              |
|                                                                                                          |
|  3. Deterministic Policy Enforcement Engine (backend/app/security/policy.py):                             |
|     * Check 1: Agent active & registered in authoritative profile registry                               |
|     * Check 2: Caller has AI_DEVELOPER proposer role                                                     |
|     * Check 3: Tool registration exists & active in tenant                                               |
|     * Check 4: Tool permitted for agent in profile / permissions                                         |
|     * Check 5: Operation authorized & within profile ceiling                                             |
|     * Check 6: Memory justification verified (M4 TrustDecision VALIDATE applied)                         |
|     * Check 7: Approvals & Replay Protection:                                                            |
|                - Anti-Self-Approval: approver != agent_id and approver != context.user_id                |
|                - Replay Prevention: approval.consumed must be False                                      |
|                - Scope Mismatch: canonical proposal_fingerprint match                                    |
|                - Expiration Check: expires_at > now                                                      |
|     * Check 8: Parameter constraints & argument ceilings                                                 |
|                                                                                                          |
|  4. Execution Outcome:                                                                                   |
|     - ALLOW: Execute via ProtectedExecutionGuard -> Return receipt + Mark approval consumed              |
|     - REQUIRE_HUMAN_APPROVAL: Return approval ticket context                                             |
|     - BLOCK: Deny execution + Log reason codes + Record observation event                                |
+----------------------------------------------------+-----------------------------------------------------+
                                                     |
                                                     v
+----------------------------------------------------+-----------------------------------------------------+
|                                          Detection Engine & Store                                        |
|                          (backend/app/security/detection.py & repositories/detection.py)                 |
|                                                                                                          |
|  - Memory Integrity: SHA-256 tamper checks, locked/quarantined memory modification, cross-agent mutation  |
|  - Threat Heuristics: Indirect prompt injection delimiters, system prompt leaks, poisoning signatures    |
|  - Provenance & Baseline: Missing/cyclic DAG edges, expired/revoked/superseded baseline knowledge        |
|  - Semantic Integrity: Baseline grounding, summary fidelity, contradiction detection, uncertainty state  |
|  - Result Contract: Categorized, classified (OBSERVATION, SUSPICIOUS, VIOLATION, INCIDENT), evidence     |
|  - Persistence: detection_results table (composite tenant FKs, branch FK, JSONB arrays, audit history)    |
+----------------------------------------------------------------------------------------------------------+
```

---

## 3. Implemented Capabilities

### 3.1 Memory and Knowledge Integrity Detection (`DetectionEngine.detect_memory_integrity`)
1. **Cryptographic Tamper Detection**:
   - Compares the cryptographic SHA-256 digest of retrieved memory content against immutable record versions.
   - Detects offline or direct database modifications where content was altered without an authoritative revision.
2. **Locked & Quarantined Memory Guard**:
   - Detects and flags any attempt to read, write, or cite memory records whose lifecycle status is `QUARANTINED` or `LOCKED`.
3. **Cross-Agent Modification Prevention**:
   - Detects when an agent attempts to mutate, overwrite, or update a memory record belonging to a different agent.
4. **Indirect Prompt Injection Heuristics**:
   - Inspects untrusted memory content for prompt override syntax (e.g. `ignore all previous instructions`, `system prompt:`, `disregard prior directives`, `developer message:`).
5. **Memory Poisoning Signatures**:
   - Detects adversarial poisoning keywords and privilege elevation triggers (e.g., `grant admin access`, `elevate role to tenant_admin`, `bypass gateway mediation`).
6. **Inadmissible Promotion Guard**:
   - Prevents unverified, derived, or suspicious memory from being marked as `TRUSTED` without formal, version-bound M4 `TrustDecision` evidence.

### 3.2 Provenance and Baseline Integrity (`DetectionEngine.detect_provenance_and_baseline_integrity`)
1. **DAG Cycle & Broken Lineage Detection**:
   - Detects cycles in memory provenance lineages (`mem-A -> mem-B -> mem-A`).
   - Detects unresolvable or missing upstream parent record references.
2. **Expired, Revoked, and Superseded Knowledge Detection**:
   - Verifies whether an agent's memory or proposed action references an enterprise baseline record that is `EXPIRED`, `REVOKED`, or `SUPERSEDED` by a newer baseline version.
3. **Unauthorized Baseline Mutation Guard**:
   - Detects and flags any attempt by an agent or unauthorized principal to alter authoritative enterprise baseline knowledge.

### 3.3 Semantic Integrity & Claim Validation (`DetectionEngine.detect_semantic_integrity`)
1. **Approved Knowledge Grounding**:
   - Evaluates whether factual claims in agent-generated summaries or derived memories are grounded in approved enterprise baseline records.
   - Categorizes ungrounded authoritative claims as `UNGROUNDED_CLAIM` (`SUSPICIOUS_INDICATOR`).
2. **Summary Meaning Preservation & Divergence**:
   - Compares key entity mentions and semantic tokens between source documents and derived summaries to detect unwarranted omissions or hallucinated divergence.
3. **Contradiction & Negation Detection**:
   - Detects direct semantic contradictions between source memory records and derived memories (e.g., affirmative source `authorized: true` transformed into derived memory `authorized: false`).
4. **Uncertainty & Evidence Quantification**:
   - Attaches explicit evidence references (`EvidenceItem`), detection method (`DETERMINISTIC_RULE` vs `HEURISTIC_ANALYSIS`), and uncertainty score (0.0 to 1.0) to all detection results.

### 3.4 Agent Behavior & Purpose Deviation (`DetectionEngine.detect_behavioral_deviation`)
1. **Authoritative Profile Alignment**:
   - Compares real-time agent execution against the independent `AgentSecurityProfile`.
   - Flags operations outside authorized purpose or scope as `PURPOSE_DRIFT` (`CONFIRMED_POLICY_VIOLATION`).
2. **Data Scope & Branch Boundary Enforcement**:
   - Flags attempts by an agent to access data classifications beyond its ceiling (e.g. `RESTRICTED` data accessed by an agent limited to `INTERNAL`).
   - Flags cross-branch access attempts (e.g. an agent bound to Lahore branch attempting operations on Karachi branch data).
3. **Privileged Instruction Tampering**:
   - Detects attempts to inspect, modify, or override privileged system instructions.
4. **Abnormal Repeated Actions**:
   - Tracks operational frequency and flags rapid, repetitive action bursts exceeding configured operational thresholds.
5. **Benign Anomaly Differentiation**:
   - Classifies minor parameter variances as `OBSERVATION` or `SUSPICIOUS_INDICATOR` without escalating to a confirmed security incident.

### 3.5 Tool & Execution Threat Detection (`DetectionEngine.detect_tool_threat`)
1. **Static Payload Threat Analysis**:
   - Scans proposed tool parameters for destructive shell commands (`rm -rf`, `mkfs`, `format`, `dd`), destructive SQL queries (`DROP TABLE`, `TRUNCATE`, `ALTER TABLE`), and command chaining delimiters (`;`, `&&`, `|`).
2. **Parameter Ceilings & Operational Constraints**:
   - Evaluates numeric values against authorized thresholds (e.g., maximum transaction amounts).
3. **Gateway Pre-Execution Interception**:
   - Wired directly into `POST /api/v1/gateway/actions/propose`.
   - When a confirmed blocking threat is detected, the Gateway overrides the decision to `BLOCK`, fails closed, records the detection result, and halts execution before any adapter is dispatched.

### 3.6 Deterministic Policy Enforcement Hardening (`backend/app/security/policy.py`)
1. **Self-Approval Prevention**:
   - Blocks action approvals where the approving user ID matches the proposed agent ID (`approver_user_id == agent_id`) or the proposing caller user ID (`approver_user_id == context.user_id`). Returns `APPROVAL_SELF_APPROVAL`.
2. **Approval Replay Prevention**:
   - Tracks whether an approval has been used. The Gateway marks `approval.consumed = True` upon execution. Subsequent attempts to submit the same approval ID fail with `APPROVAL_ALREADY_USED`.
3. **Scope Mismatch Prevention**:
   - Computes a canonical SHA-256 `proposal_fingerprint` over `(tenant_id, principal_id, action_id, agent_id, tool_name, operation, parameters, memory_refs, idempotency_key)`.
   - Verifies that the approval's bound fingerprint exactly matches the proposal fingerprint. Any modification to parameters or targets fails with `APPROVAL_SCOPE_MISMATCH`.
4. **Approval Expiration**:
   - Validates that `approval.expires_at > current_timestamp`. Expired approvals fail with `APPROVAL_EXPIRED`.
5. **Fail-Closed Default**:
   - If authorization, profiles, tool policies, or approval records cannot be resolved or are indeterminate, the engine strictly defaults to `BLOCK`.

---

## 4. Detection Result Contract & Database Persistence

### 4.1 Detection Result Contract
The detection contract encapsulates all Section 5 requirements:

```python
class DetectionResultModel(Base):
    __tablename__ = "detection_results"

    id: str  # Primary Key
    tenant_id: str  # Composite Tenant FK
    branch_id: Optional[str]  # Branch FK
    agent_id: Optional[str]  # Agent FK
    agent_profile_version: Optional[int]
    category: str  # MEMORY_INTEGRITY, SEMANTIC_INTEGRITY, BEHAVIORAL_DEVIATION, TOOL_EXECUTION_THREAT, PROVENANCE_INTEGRITY
    classification_type: str  # OBSERVATION, SUSPICIOUS_INDICATOR, CONFIRMED_POLICY_VIOLATION, CONFIRMED_SECURITY_INCIDENT
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    detection_method: str  # DETERMINISTIC_RULE, HEURISTIC_ANALYSIS, CROSS_REFERENCE_VALIDATION, REPUTATION_CHECK
    confidence: float  # 0.0 to 1.0
    uncertainty: float  # 0.0 to 1.0
    recommended_outcome: str  # ALLOW, BLOCK, REQUIRE_HUMAN_APPROVAL
    status: str  # OPEN, UNDER_REVIEW, CONFIRMED, DISMISSED, MITIGATED
    title: str
    description: str
    trace_id: Optional[str]
    span_id: Optional[str]
    execution_id: Optional[str]
    task_id: Optional[str]
    policy_decision_id: Optional[str]
    memory_refs_json: List[str]
    baseline_refs_json: List[str]
    evidence_items_json: List[Dict[str, Any]]
    details_json: Dict[str, Any]
    analyst_notes: Optional[str]
    reviewed_by: Optional[str]
    reviewed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
```

### 4.2 Database Migrations & Repositories
- **Alembic Migration**: `backend/alembic/versions/0014_detection_results.py` provisions the `detection_results` table, indexes on tenant/branch/agent/category/status, and check constraints on categories, severities, and outcomes.
- **Repository Implementations**:
  - `InMemoryDetectionRepository`: Thread-safe in-memory store for unit and fast integration testing.
  - `SqlAlchemyDetectionRepository`: Production-grade async SQLAlchemy repository enforcing tenant and branch filtering on all reads and writes.

---

## 5. Modified and Added Files

```
backend/
├── alembic/versions/
│   └── 0014_detection_results.py                     # [NEW] Alembic migration for detection_results table
├── app/
│   ├── api/
│   │   ├── detection.py                              # [NEW] FastAPI detection router (GET, POST evaluate, POST review)
│   │   └── gateway.py                                # [MODIFIED] Added approval_id, tool/behavior threat checks, replay handling
│   ├── database/
│   │   ├── models/
│   │   │   ├── __init__.py                           # [MODIFIED] Exported DetectionResultModel
│   │   │   └── detection.py                          # [NEW] Declarative SQLAlchemy DetectionResultModel
│   │   └── repositories/
│   │       └── detection.py                          # [NEW] InMemoryDetectionRepository & SqlAlchemyDetectionRepository
│   ├── security/
│   │   ├── detection.py                              # [NEW] DetectionEngine: memory, semantic, behavioral, and tool detection
│   │   └── policy.py                                 # [MODIFIED] PolicyEngine anti-self-approval, replay, scope, expiry hardening
│   └── main.py                                       # [MODIFIED] Mounted detection_router at /api/v1/detection
└── tests/
    └── unit/
        └── test_phase2_detection_and_action_security.py # [NEW] 28 comprehensive Phase 2 verification tests

frontend/
├── src/
│   ├── services/
│   │   └── apiClient.ts                              # [MODIFIED] Added listDetections, getDetection, evaluateDetection, reviewDetection
│   ├── test/
│   │   └── api-contracts.test.ts                     # [MODIFIED] Added detection API contract tests (54 passing)
│   └── types/
│       ├── detection.ts                              # [NEW] TypeScript types for detection results, categories, and reviews
│       └── index.ts                                  # [MODIFIED] Re-exported detection types

docs/
├── IMPLEMENTATION_PROGRESS.md                        # [MODIFIED] Added Section 13 detailing Phase 2 deliverables
├── 08-IMPLEMENTATION-SECURITY-GAP-REGISTER.md        # [MODIFIED] Added Section 12 resolving Phase 2 requirements
├── RESEARCH_TO_IMPLEMENTATION_MATRIX.md              # [MODIFIED] Updated R-001, R-002, R-005, R-008, R-009, R-010 mapping
└── PHASE_2_IMPLEMENTATION_REPORT.md                 # [NEW] This report
```

---

## 6. Verification Record & Test Results

All verification suites were executed against the actual code. Zero tests were skipped, mocked out of existence, or weakened.

### 6.1 Phase 2 Detection & Action Security Suite
Command: `pytest backend/tests/unit/test_phase2_detection_and_action_security.py -v`
```
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_indirect_prompt_injection PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_cryptographic_tampering PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_mutation_of_locked_memory PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_cross_agent_memory_mutation PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_inadmissible_promotion PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_cyclic_and_missing_provenance PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_expired_revoked_superseded_baseline PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_derived_memory_contradiction PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_numeric_summary_discrepancy PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_unsupported_claims_presented_as_authoritative PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_behavioral_purpose_deviation PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_data_scope_and_branch_violations PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_privileged_instruction_tampering PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_abnormal_repeated_actions PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_benign_anomaly_no_false_positive PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_command_injection_in_parameters PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_authorized_action_allow PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_unauthorized_tool_block PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_restricted_action_requires_approval PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_valid_approval_permits_action PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_self_approval_rejected PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_approval_replay_rejected PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_expired_approval_rejected PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_approval_scope_mismatch PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_invalid_approval_rejected PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_policy_dependency_failure_fails_closed PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_gateway_blocks_command_injection_with_reason_code PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_agent_cannot_alter_own_permissions PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_agent_cannot_alter_baseline PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_end_to_end_trace_correlation PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_suspicious_transformation_and_trusted_knowledge_mutation PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detect_baseline_grounding_and_summary_constraint_preservation PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_rapid_benign_actions_not_falsely_blocked PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_cross_tenant_detection_isolation PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_branch_isolation_on_detections PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detection_review_lifecycle PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_detection_result_contract_completeness PASSED
backend/tests/unit/test_phase2_detection_and_action_security.py::test_sqlalchemy_detection_repository_parity PASSED

============================= 38 passed in 43.02s =============================
```

### 6.2 Regression Verification Across Existing Suites
1. **Phase 1 Unit Suite**:
   - Command: `pytest backend/tests/unit/test_phase1_baseline_and_observation.py`
   - Result: **27 passed in 22.40s (100%)**.
2. **Security Test Suite**:
   - Command: `pytest backend/tests/security/`
   - Result: **1,252 passed, 5 skipped in 14.77s (100%)**.
3. **Frontend Test Suite**:
   - Command: `npm --prefix frontend test`
   - Result: **54 passed in 7 test files (100%)**.
4. **Frontend Production Build**:
   - Command: `npm --prefix frontend run build`
   - Result: **Vite production build succeeded with 0 errors**.

---

## 7. Security Boundaries Preserved

1. **Framework-Neutral Design**:
   - The `DetectionEngine` operates purely on standard data representations (dictionaries, dataclasses, strings). It has no hard dependency on CrewAI, LangChain, or any specific agent orchestration framework.
2. **Demo Runtime Status**:
   - CrewAI remains purely a demo runtime and integration consumer; it is never embedded into the core detection or policy logic.
3. **No Secondary Gateway or Competing Policy Engine**:
   - Detection threat analysis is integrated directly into the existing `POST /api/v1/gateway/actions/propose` endpoint and existing `PolicyEngine`. No competing execution pathways were created.
4. **Authoritative Enterprise Baseline Primacy**:
   - The security decision engine and detection routines consult the authoritative `EnterpriseBaselineRepository` and `AgentSecurityProfile`. Agent self-declarations regarding identity, permissions, or purpose are never trusted.
5. **Multi-Tenant and Branch Isolation**:
   - Detection results and evaluations enforce composite tenant identifiers (`tenant_id`) and branch identifiers (`branch_id`). Cross-tenant and cross-branch reads or modifications are strictly rejected at the repository layer.
6. **Strict Adherence to Phase 3 Boundaries**:
   - Phase 2 strictly omits autonomous incident investigation, complete memory rewind, agent execution-state restoration, and side-effect compensation. Compatible evidence schemas (`evidence_items_json`) were laid out to support Phase 3 without exceeding Phase 2 scope.

---

## 8. Known Limitations & Phase 3 Prerequisites

1. **Rule-Based Heuristic Entailment**:
   - Factual grounding and summary divergence currently employ deterministic keyword, entity, and negation pattern heuristics. Full natural language inference (NLI) cross-encoder evaluation (e.g., local ONNX DeBERTa-v3) is slated for Phase 3 deep semantic audit.
2. **In-Flight Action Interception vs. Runtime Checkpointing**:
   - Phase 2 detects tool threats prior to execution and rejects proposals at the Gateway. It does not rewind partially executed multi-step agent scratchpads or rollback external environment mutations; that recovery workflow is the core mission of Phase 3.
3. **Phase 3 Prerequisites Provided by Phase 2**:
   - Durable detection records (`detection_results`) linked to W3C `trace_id`, `span_id`, `execution_id`, and `policy_decision_id`.
   - Structured evidence items linking detections to specific tainted memory records and invalid baseline references.
   - Distinct classification types separating `SUSPICIOUS_INDICATOR` from `CONFIRMED_SECURITY_INCIDENT` for prioritized triage by the future recovery orchestrator.
