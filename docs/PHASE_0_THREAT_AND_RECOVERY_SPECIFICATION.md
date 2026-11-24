# Phase 0 — Threat Model, Dual Trace & Recovery Specification

**Document ID:** AMSC-DOC-P0-002  
**Version:** 1.0.0  
**Audit & Specification Date:** 2026-11-24  
**Author:** Principal Software Architect, Senior Application Security Engineer, AI Agent Security Researcher & Database Security Engineer  
**Status:** Approved Phase 0 Specification  
**Repository:** `https://github.com/9m2usman/ChronoCongiSec`

---

## 1. Threat Model & Trust Boundaries

AMSC governs autonomous AI agents operating within corporate environments. AI agents are dynamic, probabilistic systems that execute external tools, read long-term episodic memory, process user inputs, and produce side effects. The AMSC threat model divides the architecture into three strict trust zones:

```
[ UNTRUSTED ZONE ]
External Agents (CrewAI, LangGraph, AutoGen, Custom HTTP)
User Prompts | Ingested Documents | Webhooks | Third-Party Tool Returns | Model Outputs
         │
         ▼  (Strict Complete Mediation / Mutual TLS / W3C Trace Context)
[ MEDIATION ZONE (PEP) ]
AMSC API Gateway (`POST /gateway/actions/propose`)
Tenant Context Extractor | Rate Limiter | Header Sanitizer | Parameter Validator
         │
         ▼  (Internal Service Bus / Authenticated TenantContext)
[ TRUSTED CORE (PDP & PERSISTENCE) ]
PolicyEngine (Deterministic) | TrustEvaluator (State Machine) | QuarantineWorkflow
PostgreSQL Database (Composite FKs, Append-Only Triggers, Hash-Chained Audit)
Approved Company Security Baseline (Independent & Versioned)
```

### 1.1 The Approved Company Baseline Invariant
**Core Architectural Rule:** The approved company baseline must be independently controlled, versioned, and immutable to agent influence.

Under no circumstances may mutable, derived, or potentially poisoned agent memory redefine, expand, or alter the enterprise security baseline:
1. **Tool Registrations & Permissions:** An agent cannot grant itself access to a tool, modify its allowed operations, or relax its parameter ceilings through memory writes, system prompt manipulation, or tool output injection.
2. **Deterministic Security Policies:** Policies evaluated by M4 `PolicyEngine` (agent status, tool whitelist, operation whitelist, parameter ceilings, approval thresholds, memory trust requirements) reside in server-side configuration and versioned database tables, never in agent episodic memory or vector stores.
3. **Tenant & Branch Boundaries:** Tenant and branch scopes are derived exclusively from cryptographically verified server-side JWT claims (`TenantContext`), never from client-provided headers or tool arguments.

---

## 2. Attack Scenarios & Business Impact

AMSC is specifically engineered to detect, contain, and recover from eight primary threat vectors:

### 2.1 Threat Vectors & Attack Scenarios

```
+---------------------------------------------------------------------------------------------------+
| 1. Memory Poisoning & Indirect Prompt Injection                                                   |
|    Attacker places an adversarial payload in a data source (e.g. ticket, customer email, wiki).   |
|    During RAG ingestion or compaction, the malicious instruction is stored in long-term memory.  |
|    When retrieved by an agent, the instruction hijacks the agent's goal to exfiltrate data or     |
|    divert funds.                                                                                  |
+---------------------------------------------------------------------------------------------------+
| 2. Unsupported or Hallucinated Claims                                                             |
|    Agent confabulates a non-existent authorization, invoice approval, or regulatory rule not      |
|    grounded in any authoritative source. If executed, unauthorized financial or legal damage      |
|    occurs.                                                                                        |
+---------------------------------------------------------------------------------------------------+
| 3. Stale or Superseded Knowledge Exploitation                                                     |
|    An agent retrieves obsolete vendor banking information or deprecated security credentials      |
|    that have been superseded by newer records, causing payments or credentials to route to        |
|    expired destinations.                                                                          |
+---------------------------------------------------------------------------------------------------+
| 4. Semantic Drift across Transformations & Compactions                                            |
|    As memory chunks undergo summarization, compaction, or consolidation, subtle semantic shifts   |
|    invert negation, drop critical qualifiers, or inflate permissions, creating false trust.      |
+---------------------------------------------------------------------------------------------------+
| 5. Agent Goal and Purpose Deviation                                                               |
|    Agent deviates from its registered departmental purpose (e.g., Customer Support agent attempts |
|    to execute wire transfers or modify HR records) via multi-turn instruction drift.              |
+---------------------------------------------------------------------------------------------------+
| 6. Scope Violations & Lateral Movement                                                            |
|    Agent attempts cross-tenant memory access, unauthorized tool parameter escalation, or illegal  |
|    branch hopping.                                                                                |
+---------------------------------------------------------------------------------------------------+
| 7. High-Frequency or Anomalous Action Sequences                                                   |
|    Compromised agent loops or executes rapid automated resource drains (e.g. spamming micro-funds |
|    transfers under parameter ceilings).                                                           |
+---------------------------------------------------------------------------------------------------+
| 8. Replay & Idempotency Tampering                                                                 |
|    Attacker captures a valid tool proposal and attempts to replay it, or alters parameters while   |
|    reusing an existing idempotency key to bypass policy checks.                                    |
+---------------------------------------------------------------------------------------------------+
```

### 2.2 Impact Classification & Verdicts
Every protected tool proposal submitted to the Gateway must evaluate to one of three canonical outcomes:
- `ALLOW`: All mandatory checks pass. The action is authorized and immediately dispatched to the server-side adapter.
- `BLOCK`: One or more mandatory checks fail, untrusted memory is cited, parameter ceilings are violated, or security dependencies are unavailable. The proposal is rejected fail-closed; the adapter is never called.
- `REQUIRE_HUMAN_APPROVAL`: The proposal is permissible under policy but exceeds automated risk thresholds (e.g., funds transfer > $500). Execution is suspended until an authorized human operator grants approval via a cryptographic grant.

---

## 3. Detection vs. Enforcement Responsibilities

A fundamental architectural failure of modern AI security systems is delegating authorization decisions to probabilistic models. AMSC strictly separates **Probabilistic Intelligence** from **Deterministic Policy Enforcement**:

```
+------------------------------------------+    +------------------------------------------+
|      PROBABILISTIC INTELLIGENCE          |    |     DETERMINISTIC POLICY ENFORCEMENT     |
|       (Signals & Triage Only)            |    |       (Authoritative & Binding)          |
+------------------------------------------+    +------------------------------------------+
| - NLI / Natural Language Inference       |    | - Agent Status Check (ACTIVE vs ISOLATED)|
| - Embedding Vector Similarity            |    | - Tool Whitelist (Assigned to agent)     |
| - Prompt Injection Classifiers           |    | - Operation Whitelist (Permitted action) |
| - Semantic Divergence / Drift Scoring    |    | - Parameter Ceilings (Hard numeric max)  |
| - Anomaly / Frequency Baselines          |    | - Human Approval Thresholds              |
| - Evidence Graph Clustering              |    | - Memory Trust Validation (State Machine)|
+------------------------------------------+    +------------------------------------------+
                     │                                               │
                     ▼                                               ▼
         PRODUCES EVIDENCE METADATA                     PRODUCES BINDING VERDICT:
     (Can only BLOCK or Flag Suspicious)                [ ALLOW | BLOCK | APPROVAL ]
```

### 3.3 The Zero-Override Principle
1. **ML models never authorize:** An ML model, semantic similarity score, or LLM judge can **NEVER** grant permission to execute an action or elevate an agent's privilege.
2. **ML models provide signals only:** An ML signal can only cause a transition to `SUSPICIOUS`, trigger `BLOCK`, or request human review.
3. **Mandatory deterministic policies cannot be overridden:** Even if an ML model reports a 99.9% benign score, if an agent is unassigned to a tool, if a parameter exceeds a ceiling, or if a cited memory record is `UNVERIFIED` or `QUARANTINED`, the gateway **MUST FAIL CLOSED** with `BLOCK`.

---

## 4. Dual Trace Specification: Fact vs. Execution Lanes

Dual Trace is the foundational forensic and observability substrate of AMSC. It treats agent activity as two parallel, correlated evidence streams: the **Fact/Knowledge Trace** and the **Execution/Scene Trace**.

```
FACT / KNOWLEDGE TRACE                            EXECUTION / SCENE TRACE
(Evidence & Lineage)                              (Action & Environment)
┌───────────────────────────────────────┐        ┌───────────────────────────────────────┐
│ Authoritative Source & Provenance URI │        │ Agent Identity, Runtime & Version     │
│ Ingestion Timestamp & Content SHA-256 │        │ W3C Trace Context (traceparent)       │
│ Derived Claims & Transformations      │◄──────►│ User Task / Prompt Context            │
│ Memory Versions & Evolution History   │        │ Retrieved Memory References (IDs)     │
│ Trust State History & Transitions     │        │ Tool Proposal & Validated Arguments   │
│ Forensic Access Audit Trails          │        │ Deterministic Policy Decision & Reason│
│ Graph Lineage & Dependency Closure    │        │ Server Adapter Execution Receipt      │
└───────────────────────────────────────┘        └───────────────────────────────────────┘
                    ▲                                                ▲
                    └───────────────── CORRELATED BY ────────────────┘
                            - W3C trace_id (`00-{trace_id}-{span_id}-01`)
                            - memory_record_id & version_id
                            - proposal_id & action_id
```

### 4.1 Causal Influence vs. Temporal Proximity
**Critical Forensic Principle:** Temporal proximity does not establish causal influence. The fact that a memory record was retrieved 50 milliseconds before a tool proposal does not prove that the memory caused the proposal.

To establish true causal attribution during an incident investigation, AMSC requires concrete causal evidence:
1. **Explicit Reference Array (`memory_refs`):** The agent runtime must submit the specific memory chunk IDs cited in the agent's thought chain or context window.
2. **Context Window Attestation:** The adapter or agent harness logs the exact prompt payload delivered to the LLM, demonstrating that the memory was present in the model's active context.
3. **Parameter Derivation:** The proposal parameters (e.g. destination account, routing number, address) must exhibit semantic or string correspondence to entities contained within the cited memory version.
4. **Counterfactual Validation:** During investigation, the proposed action is evaluated in a dry-run harness with the suspect memory removed from the prompt context to confirm whether the proposed action changes.

### 4.2 Data Model Contracts

#### 4.2.1 Fact / Knowledge Lane Item
```json
{
  "id": "ret-7a8f9b2c",
  "record_id": "mem-e5d1a8f4-6721-4f12-a89b-90c7d23a54b1",
  "timestamp": "2026-11-24T02:15:30.120Z",
  "time_display": "02:15:30 UTC",
  "label": "Vendor Disbursement Policy Ch. 4",
  "trust_state": "QUARANTINED",
  "historical_trust_state": "TRUSTED",
  "current_trust_state": "QUARANTINED",
  "checksum": "a3b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
  "version": 2,
  "source_uri": "s3://corp-policies/finance/2026/vendor_disbursement.pdf",
  "query_text_redacted": "vendor wire routing instructions for account [REDACTED]"
}
```

#### 4.2.2 Execution / Scene Lane Item
```json
{
  "id": "prop-4f9a0c12",
  "trace_id": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
  "timestamp": "2026-11-24T02:15:30.250Z",
  "time_display": "02:15:30 UTC",
  "agent_id": "agent-finance-disbursement-01",
  "agent_name": "Finance Accounts Payable Agent",
  "action_label": "Propose Corporate Wire Transfer",
  "action_detail": "Transfer funds to vendor disbursement account",
  "memory_ref": "mem-e5d1a8f4-6721-4f12-a89b-90c7d23a54b1",
  "status": "BLOCKED",
  "details": {
    "tool_name": "sandbox_transfer",
    "operation": "transfer_funds",
    "parameters": {
      "destination": "acc-sbx-corp-disbursement",
      "amount": 15000.00,
      "currency": "USD"
    }
  },
  "duration_ms": 14,
  "operation": "transfer_funds",
  "policy_decision": "BLOCK",
  "approval_status": "NONE",
  "execution_status": "NOT_EXECUTED",
  "reasons": [
    "REFERENCED_UNTRUSTED_MEMORY",
    "CEILING_EXCEEDED"
  ]
}
```

---

## 5. Complete Recovery Architecture

Restoring a database record or rewinding memory state is only a fraction of true enterprise recovery. When an agent is compromised or acts upon poisoned memory, it produces effects across multiple layers of reality.

```
                                  ENTERPRISE RECOVERY PLANE
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. Memory & Knowledge Checkpoints                                                           │
│    Immutable version pointers in PostgreSQL. Restore appends a NEW version with checkpoint   │
│    content and resets trust to UNVERIFIED. Never rolls back version numbers.                │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. Agent Execution & Context Checkpoints                                                    │
│    Agent execution state, active scratchpad, thought chain, and prompt template snapshots.   │
│    Compromised agent execution runs are aborted and re-initialized from verified baselines.  │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. External Resource & Environment Checkpoints                                              │
│    Controlled test environments, sandboxes, and virtualized resources can be reverted to     │
│    snapshots.                                                                               │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ 4. External Action Journal & Side-Effect Ledger                                             │
│    Durable log of all executed tool calls, destination systems, transaction IDs, and receipt│
│    payloads. Cites specific memory records that justified each call.                         │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ 5. Compensating Actions Engine                                                              │
│    Dispatches business reversal workflows for actions that cannot be literally undone:      │
│    - Reversible: Local database changes, memory pointers, unexecuted proposals.             │
│    - Compensatable: Payment reversal / refund APIs, resource teardown, account disablement. │
│    - Irreversible: Outbound emails sent, external data exports, webhooks to third parties.  │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ 6. Independent Post-Recovery Verification                                                   │
│    Re-evaluates the failed action against the restored state; verifies no tainted memory is │
│    marked TRUSTED; ensures regression test suites pass before resuming agent execution.     │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Categorization of Tool Operations

| Category | Definition | Examples | Recovery Mechanism |
|---|---|---|---|
| **Reversible** | State exists entirely within systems under AMSC transaction control. | Memory records, version pointers, internal approvals, database rows. | **Literal Rollback:** Transaction rollback or appending new restoring version in PostgreSQL. |
| **Compensatable** | External operations that cannot be undone by DB rollback, but possess explicit reversal or offsetting APIs. | Bank transfers, cloud infrastructure provisioning, CRM record updates. | **Compensating Action Dispatch:** Invoke partner cancellation/refund API (e.g. `POST /payments/{id}/refund`), record compensating receipt in journal. |
| **Irreversible** | Real-world side effects that cannot be reversed or offset through an API. | External email sent, customer SMS broadcast, secret key exfiltrated. | **Containment & Incident Protocol:** Flag as `IRREVERSIBLE_ACTION_LOGGED`, initiate immediate human-in-the-loop incident response, issue revocation alerts. |

### 5.2 The 7-Step Recovery Execution Protocol
All recovery operations executed by `RecoveryService` (`backend/app/recovery/orchestrator.py`) must follow this mandatory fail-closed sequence:
1. **Authorization & Concurrency Lock:** Caller must possess `SECURITY_ANALYST` or `TENANT_ADMIN` role. An atomic lock is acquired for `(tenant_id, recovery_plan_id)`.
2. **Pre-Recovery State Snapshot:** Before modifying any state, capture an immutable pre-recovery snapshot of all affected memory records, version pointers, and active agent statuses.
3. **Mandatory Containment:** Every affected memory record that is not already `QUARANTINED` or `REJECTED` is transitioned to `QUARANTINED` via M4 `TrustEvaluator`. If containment fails on any single record, **the entire recovery aborts immediately**.
4. **Atomic Version Rollback:** Execute in a single PostgreSQL transaction:
   - For each affected record, retrieve the checkpointed content.
   - Insert a **NEW** version row (incrementing `version_number = current_version + 1`).
   - Update `memory_records.current_version` to point to the new version row.
   - **Never move version counters backward or delete intermediate versions.**
5. **Reset Trust Disposition:** Set the restored record's `trust_state` to `UNVERIFIED` via `RECOVERY_RESTORE` (T-17). **A restored memory record is NEVER automatically marked `TRUSTED`.** Promoting it to `TRUSTED` requires independent analyst re-validation.
6. **Compensating Action Execution:** For each executed tool action recorded in the external action journal that cited an affected record:
   - If compensatable: dispatch registered compensating adapter.
   - If irreversible: emit high-priority security alert and record in audit chain.
7. **Post-Condition Verification & Hash-Chained Audit:**
   - Verify every restored record matches the checkpoint content checksum.
   - Verify all intermediary contaminated versions remain preserved and immutable.
   - Append an immutable audit event to M6 `audit_events` with SHA-256 hash chaining. If audit logging fails, the plan status is marked `RECONCILIATION_REQUIRED`.

---

## 6. Failure Modes, Fail-Closed Behavior & Human Approval

### 6.1 Complete Fail-Closed Matrix

| System Condition | Gateway Behavior | Returned HTTP Status | Logged Reason Code |
|---|---|---|---|
| Evaluation Timeout (> 2000 ms) | Reject proposal | HTTP 403 Forbidden | `POLICY_EVALUATION_TIMEOUT` |
| Database Unreachable / Offline | Reject proposal | HTTP 503 Service Unavailable | `DATABASE_UNAVAILABLE` |
| Redis Limiter Offline (Production) | Refuse startup / reject requests | HTTP 503 Service Unavailable | `SECURITY_DEPENDENCY_ERROR` |
| Agent ID Not Found / Cross-Tenant | Reject proposal | HTTP 404 Not Found (Identical) | `AGENT_NOT_REGISTERED` |
| Agent in `ISOLATED` Status | Reject proposal | HTTP 403 Forbidden | `AGENT_ISOLATED` |
| Tool Not Assigned to Agent | Reject proposal | HTTP 403 Forbidden | `TOOL_NOT_ASSIGNED` |
| Operation Not on Whitelist | Reject proposal | HTTP 403 Forbidden | `OPERATION_DENIED` |
| Parameter Above Hard Ceiling | Reject proposal | HTTP 403 Forbidden | `CEILING_EXCEEDED` |
| Memory Ref is `UNVERIFIED` / `QUARANTINED` | Reject proposal | HTTP 403 Forbidden | `REFERENCED_UNTRUSTED_MEMORY` |
| Idempotency Key Reused with Changed Body | Reject proposal | HTTP 409 Conflict | `IDEMPOTENCY_PAYLOAD_MISMATCH` |
| Parameter Nesting Depth > 5 | Reject proposal | HTTP 422 Unprocessable Content | `PARAMETER_DEPTH_EXCEEDED` |
| Parameter NaN or Infinity | Reject proposal | HTTP 422 Unprocessable Content | `PARAMETER_NON_FINITE` |

### 6.2 Human Approval Security Protocol (`REQUIRE_HUMAN_APPROVAL`)
When a proposal is otherwise valid but exceeds standard autonomous risk thresholds (e.g. wire transfer > $500.00), the Gateway issues a `REQUIRE_HUMAN_APPROVAL` verdict:
1. **Creation of Pending Approval Record:** An approval record is created in `approvals` with a cryptographically generated approval ID and an expiration timestamp (maximum 60 minutes).
2. **Actor Separation of Duties:** The human approver must possess `TENANT_ADMIN` or `SECURITY_ANALYST` role and **must not be the actor who registered or configured the proposing agent**.
3. **Single-Use Consumption:** Once an approval is granted, executing the action atomically marks the approval `CONSUMED`. Replaying the same approval ID for subsequent execution proposals is rejected with `APPROVAL_ALREADY_CONSUMED` (HTTP 409).
4. **Fail-Closed Expiry:** If an approval is neither approved nor rejected within the TTL window, it automatically transitions to `EXPIRED`. Any subsequent execution attempt fails closed.

---

## 7. Security Tests & Measurable Acceptance Criteria

To ensure continuous security verification, Phase 0 establishes the following testable criteria:

1. **Complete Mediation (G4 Gate):**
   - Attempt direct adapter invocation without gateway context: **Must return 403 Forbidden**.
   - Propose tool with NaN / Infinity / 10MB payload: **Must return 422 Unprocessable**.
   - Propose tool exceeding parameter ceiling: **Must return 403 with `CEILING_EXCEEDED`**.
2. **Memory Trust Invariants (F-1 / F-2 Gate):**
   - Ingest memory chunk: **Must be stored as `UNVERIFIED`**.
   - Query normal `GET /api/v1/memory`: **Must strictly return only `TRUSTED` records**.
   - Request `GET /api/v1/memory?trust_state=QUARANTINED`: **Must return 403 Forbidden**.
   - Update `TRUSTED` record: **Must append new version and reset record to `UNVERIFIED`**.
   - Attempt to update `QUARANTINED` or `REJECTED` record: **Must return 400 Validation Error**.
3. **Dual Trace Integrity (D-1 Gate):**
   - Propagate valid W3C `traceparent`: **Response must echo matching 32-hex trace ID**.
   - Query Dual Trace endpoint: **Must return `execution_lane`, `memory_lane`, and `CompletenessReport`**.
   - Check sensitive fields (passwords, tokens, private keys): **Must be replaced with `[REDACTED]`**.
4. **Recovery Safety (R-1 Gate):**
   - Execute recovery on compromised record: **Pre-recovery snapshot must be committed first**.
   - Contaminated records: **Must be quarantined before rollback begins**.
   - Rollback execution: **Must append version `current_version + 1` and reset state to `UNVERIFIED`**.
   - Side effects: **Compensatable actions must dispatch refund/compensation; irreversible actions must emit security alerts**.
