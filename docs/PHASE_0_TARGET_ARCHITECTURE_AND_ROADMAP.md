# Phase 0 — Target Architecture, ML Strategy & Implementation Roadmap

**Document ID:** AMSC-DOC-P0-003  
**Version:** 1.0.0  
**Date:** 2026-11-24  
**Author:** Principal Software Architect, Senior Application Security Engineer, AI Agent Security Researcher & DevSecOps Engineer  
**Status:** Approved Phase 0 Target Architecture & Roadmap  
**Repository:** `https://github.com/9m2usman/ChronoCongiSec`

---

## 1. Target Architecture & Ten Boundary Domains

The Agent Memory Security Center (AMSC) is a framework-neutral security and recovery control plane. It integrates with existing corporate AI agents without requiring companies to re-platform their agent infrastructure. The target architecture is organized around ten strictly defined component boundaries:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                            1. EXTERNAL AGENT INTEGRATION & ADAPTERS                             │
│   CrewAI Adapter │ LangGraph Adapter │ AutoGen Adapter │ Raw HTTP SDK │ Custom Python/Node SDK │
└────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │ Tool Proposals, Telemetry & Memory Context
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                         2. AGENT IDENTITY, PURPOSE & ENTERPRISE BASELINE                        │
│   Agent Directory │ Departmental Scopes │ Versioned Prompts │ Tool Whitelists │ Ceilings        │
└────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
                                                 ▼
┌──────────────────────────────────────┐                   ┌──────────────────────────────────────┐
│  3. OBSERVATION & DURABLE TELEMETRY  │                   │    4. MEMORY & KNOWLEDGE INTEGRITY   │
│  W3C Traceparent Context Propagation │                   │  Source Authority & Cryptographic MAC│
│  Dual Trace Engine (Execution Lane)  │◄─────────────────►│  Lineage Graph & Traversal Budgets  │
│  Append-Only Hash-Chained Audit Log  │                   │  Dual Trace Engine (Fact Lane)       │
└──────────────────────────────────────┘                   └──────────────────────────────────────┘
                   │                                                           │
                   └─────────────────────────────┬─────────────────────────────┘
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              5. SECURITY INTELLIGENCE & DETECTION                               │
│   NLI Claim Verification │ Injection Classifier │ Anomaly Baselines │ Semantic Drift Monitor    │
│   (Probabilistic Signals Only — Never Overrides Deterministic Policies — Never Authorizes)      │
└────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                            6. DETERMINISTIC POLICY ENFORCEMENT (PDP)                            │
│   PolicyEngine (Check 0–6) │ Parameter Ceilings │ Trust State Machine │ Complete Mediation      │
│   Verdicts: [ ALLOW | BLOCK | REQUIRE_HUMAN_APPROVAL ] │ Single-Use Cryptographic Approvals     │
└────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
                                                 ▼
┌──────────────────────────────────────┐                   ┌──────────────────────────────────────┐
│  7. INCIDENT INVESTIGATION & EVIDENCE│                   │ 8. MEMORY, EXECUTION & RECOVERY      │
│  Quarantine Workflow (Restrict-Only) │                   │  Pre-Recovery Snapshot Capture       │
│  Forensic Audited Inspection Routes  │◄─────────────────►│  Atomic Version Rollback (New Ver)   │
│  Root-Cause Attribution & Blast Rad. │                   │  Compensating Action Dispatcher      │
└──────────────────────────────────────┘                   └──────────────────────────────────────┘
                   │                                                           │
                   └─────────────────────────────┬─────────────────────────────┘
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              9. INDEPENDENT RECOVERY VERIFICATION                               │
│   Counterfactual Dry-Run Replay │ Blast Radius Containment Check │ State Integrity Validation   │
└────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                           10. AUDIT, GOVERNANCE & OPERATOR INTERFACES                           │
│   React 19 Workstation │ SecOps Dashboard │ Forensic Graph Explorer │ Approval Workbench        │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Detailed Boundary Responsibilities

1. **External Agent Integration & Adapters:** Exposes a framework-neutral integration protocol (HTTP/REST, JSON-RPC, or in-process ASGI). Adapters for CrewAI, LangGraph, AutoGen, and custom runtimes translate agent-specific tool calls into canonical AMSC proposals.
2. **Agent Identity, Purpose & Approved Company Baseline:** Manages versioned agent definitions, declared departmental purposes, allowed tool assignments, parameter limits, and branch memberships. The approved baseline is independently controlled by enterprise administrators and cannot be altered by agent memory.
3. **Observation & Durable Telemetry:** Collects, sanitizes, redacts, and correlates execution and memory telemetry across W3C `traceparent` contexts. Implements append-only, tamper-evident audit storage in PostgreSQL.
4. **Memory & Knowledge Integrity:** Governs the ingestion, hashing, chunking, and lineage tracking of facts and episodic memories. Enforces the multidimensional trust model and bounds provenance graph traversals.
5. **Security Intelligence & Detection:** Hosts probabilistic analysis components (NLI, embeddings, anomaly scoring). Produces evidence signals and forensic triage metadata. Strictly prohibited from independently granting authorization.
6. **Deterministic Policy Enforcement:** Evaluates 8 sequential, fail-closed policy checks before any tool adapter can execute. Single-point Policy Enforcement Point (PEP) and Policy Decision Point (PDP).
7. **Incident Investigation & Evidence Correlation:** Manages the security incident lifecycle, restrict-only quarantine workflows, and audited forensic memory inspection.
8. **Memory, Execution & External-State Recovery:** Coordinates atomic checkpoint rollbacks, pre-recovery snapshot preservation, and external compensating action dispatching.
9. **Independent Recovery Verification:** Executes post-recovery validation suites to verify that contaminated state has been neutralized and cannot recur prior to returning agents to active service.
10. **Audit, Governance & Operator Interfaces:** Provides web workstation interfaces for security analysts, tenant administrators, and compliance auditors with role-based access control and live API connectivity.

---

## 2. Framework-Neutral Integration Contract

AMSC does not require agents to be built using any specific library. Any agent framework communicates with AMSC via four standard message schemas:

### 2.1 Action Proposal Request (`POST /api/v1/gateway/actions/propose`)
```json
{
  "action_id": "act-wire-20261124-001",
  "agent_id": "agent-finance-01",
  "tool_name": "corporate_wire_transfer",
  "operation": "transfer_funds",
  "parameters": {
    "destination_account": "acc-vendor-disbursement-09",
    "amount": 450.00,
    "currency": "USD",
    "memo": "Invoice INV-2026-9021"
  },
  "memory_refs": [
    "mem-7a8f9b2c-3d4e-5f6a-7b8c-9d0e1f2a3b4c"
  ],
  "idempotency_key": "idem-wire-20261124-001",
  "trace_id": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"
}
```

### 2.2 Policy Decision Response
```json
{
  "decision_id": "dec-e1f2a3b4c5d6",
  "proposal_id": "prop-4f9a0c12",
  "decision": "ALLOW",
  "policy_result": "PERMITTED",
  "reasons": [
    "ALL_CHECKS_PASSED"
  ],
  "evaluated_at": "2026-11-24T02:15:30.250Z",
  "policy_version": "amsc-policy/1.0.0",
  "execution_status": "EXECUTED",
  "result": {
    "transaction_id": "tx-sbx-9a8b7c6d",
    "status": "SUCCESS",
    "transferred_amount": 450.00
  }
}
```

### 2.3 Framework Adapter Matrix

| Framework | Integration Mechanism | Status | Notes |
|---|---|---|---|
| **CrewAI** | Native `tool` wrapper calling `ChronoCogniSecClient` | `IMPLEMENTED_AND_VERIFIED` | Production-ready test double & simulation in `crewai_service/`. |
| **LangGraph** | Custom `BaseTool` / LangChain `@tool` invoking Gateway HTTP API | Planned (Phase 5) | Framework-neutral Gateway endpoints are 100% compatible. |
| **AutoGen** | Conversational tool proxy intercepting function execution | Planned (Phase 5) | Function calls mapped to `ActionProposalRequest`. |
| **Raw HTTP / REST** | Standard authenticated REST calls (`curl`, `fetch`, `requests`) | `IMPLEMENTED_AND_VERIFIED` | Active on all 14 backend routers. |

---

## 3. Machine Learning Strategy & Evaluation Requirements

AMSC uses ML exclusively for **Probabilistic Intelligence** (evidence extraction, anomaly detection, candidate retrieval, drift monitoring). It never participates in authorization decisions.

### 3.1 Model Portfolio Evaluation

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. Source-Grounded Natural Language Inference (NLI) & Claim Verification                         │
│    - Problem Solved: Detect when an agent's proposed action or memory claim contradicts or lacks │
│      support in authoritative ground-truth documents.                                            │
│    - Why Deterministic Fails: Lexical keyword search fails across paraphrased or reworded text.   │
│    - Candidate Pretrained Models: `MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli` (Apache 2.0).   │
│    - Resource & Latency: GPU: ~35 ms; CPU (quantized ONNX): ~85 ms. Bounded timeout: 200 ms.     │
│    - Risk Management: Never authorizes. High contradiction probability triggers `SUSPICIOUS`.   │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. Dense Semantic Embeddings for Candidate Retrieval                                             │
│    - Problem Solved: Fast semantic indexing of knowledge chunks and lineage nodes.               │
│    - Why Deterministic Fails: Exact string matching misses conceptual synonyms in policies.     │
│    - Candidate Pretrained Models: `sentence-transformers/all-MiniLM-L6-v2` (Apache 2.0).         │
│    - Resource & Latency: CPU ONNX runtime: ~12 ms per 512 tokens. Dimension: 384.               │
│    - Risk Management: Embeddings only propose candidates; deterministic checks validate trust.   │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. Memory Poisoning & Indirect Injection Classifier                                              │
│    - Problem Solved: Detect jailbreak patterns, delimiter hijacking, and hidden instructions     │
│      within ingested memory chunks.                                                              │
│    - Why Deterministic Fails: Adversarial prompt variations easily evade static regex filters.   │
│    - Candidate Pretrained Models: `protectai/deberta-v3-base-prompt-injection-v2` (Apache 2.0).  │
│    - Resource & Latency: ONNX CPU: ~45 ms.                                                       │
│    - Risk Management: Detection flags chunk as `SUSPICIOUS` and notifies SecOps; zero false ALLOW│
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 4. Behavioral & Action Sequence Anomaly Detector                                                 │
│    - Problem Solved: Detect rapid micro-transactions, abnormal call sequences, or department     │
│      scope deviations.                                                                           │
│    - Why Deterministic Fails: Individual actions may sit below ceilings; only pattern is toxic.  │
│    - Candidate Architecture: Unsupervised Isolation Forest or Sequence Markov Model.             │
│    - Resource & Latency: Lightweight CPU inference: < 5 ms.                                      │
│    - Risk Management: Score > threshold triggers `REQUIRE_HUMAN_APPROVAL` on subsequent proposals.│
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Model Governance & Lifecycle Invariants
1. **Model Versioning:** All models deployed to AMSC must be version-pinned with cryptographic checksums and registered in `model_registry`.
2. **Local-First Inference:** Production models must execute locally via ONNX Runtime or local PyTorch containers without external cloud API dependencies.
3. **Graceful Degradation:** If an ML model times out or crashes, the system must log an alert, record the signal as `UNAVAILABLE`, and continue deterministic policy evaluation without failing open.

---

## 4. Technology Compatibility Assessment

| Technology Subsystem | Current Repository State | Target Assessment | Compatibility & Implementation Decision |
|---|---|---|---|
| **Python Runtime** | `3.14.10` local host; `3.12` in CI & Dockerfile | `EXTEND` | Target Python `3.12` as authoritative baseline for compatibility with PyTorch/ONNX and CrewAI. Local development must align to 3.12 via `.venv`. |
| **FastAPI & Pydantic** | FastAPI `0.162.4`, Pydantic `2.14.3` | `REUSE` | Stable, modern Pydantic v2 implementation. Fully preserved across all endpoints. |
| **SQLAlchemy & Alembic** | SQLAlchemy `2.1.8`, Alembic `1.20.1` | `EXTEND` | 12 Alembic migrations exist. Must add migration 0013 for `trust_decisions` table to eliminate the in-memory `SqlTrustDecisionStore` illusion. |
| **PostgreSQL Database** | PostgreSQL 16 (Docker compose `postgres:16-alpine`) | `REUSE` | Primary durable persistence for relational schemas, composite keys, and hash-chained audit events. |
| **Redis & Rate Limiting** | Redis 7 (Docker compose `redis:7-alpine`) | `EXTEND` | Add `redis>=5.0.0` to `backend/requirements.txt` to eliminate production startup failure. |
| **Event Workers** | In-process `OutboxProcessor` (`SELECT FOR UPDATE SKIP LOCKED`) | `REUSE` | Keep in-process outbox processing. Do NOT introduce Celery or RabbitMQ during Phases 1–3. |
| **Frontend Workstation** | React 19, Vite 6, Tailwind CSS, Zustand | `EXTEND` | Align ChroniMem query contract, remove hardcoded fixture fallbacks on 403, preserve 12 screens. |
| **Agent Runtimes** | Custom CrewAI test double in `crewai_service/` | `EXTEND` | Retain CrewAI harness for testing; introduce LangGraph adapter in Phase 5. |
| **ML Inference Engine** | Empty scaffolding (`ml/` .gitkeep only) | `INTRODUCE` | Introduce ONNX Runtime CPU (`onnxruntime>=1.19.0`) in Phase 3 for zero-override intelligence. |

---

## 5. Phased Implementation Roadmap (Phases 1–5)

To maintain focus, quality, and architectural stability, all implementation will be executed sequentially by a single engineer across Phases 1 through 5.

```
PHASE 0: Architecture, Research Reconciliation & Audit (COMPLETE)
   │
   ▼
PHASE 1: Core Framework-Neutral Gateway & Durable Persistence
   │
   ▼
PHASE 2: Memory Integrity, Provenance & Ingestion Hardening
   │
   ▼
PHASE 3: Security Intelligence & Probabilistic Detection
   │
   ▼
PHASE 4: Complete Recovery & Side-Effect Compensation Engine
   │
   ▼
PHASE 5: Multi-Framework Adapters, Enterprise Governance & Production Hardening
```

---

### Phase 1: Core Framework-Neutral Gateway & Durable Persistence

**Objective:** Solidify the Gateway as the single framework-neutral control plane, eliminate the pseudo-persistent trust store illusion, resolve database gaps, and fix contract mismatches.

- **Scope & Deliverables:**
  1. **True PostgreSQL `TrustDecisionStore`:**
     - Author Alembic migration `0013_trust_decisions_table.py` (`id`, `tenant_id`, `record_id`, `from_state`, `to_state`, `operation`, `actor_id`, `reason_code`, `evidence_json`, `created_at`).
     - Implement genuine `SqlAlchemyTrustDecisionStore` in `backend/app/database/repositories/` and wire into `backend/app/security/runtime.py`.
  2. **Agent Tool Permissions Administration:**
     - Add `SqlAlchemyAgentRepository.grant_tool_permission` and `revoke_tool_permission`.
     - Expose audited REST routes: `POST /api/v1/agents/{id}/permissions` and `DELETE /api/v1/agents/{id}/permissions/{tool_id}`.
  3. **ChroniMem Contract Alignment:**
     - Update `backend/app/api/chronimem.py` to accept optional `record_id` and return record version history when `record_id` is supplied.
     - Update `frontend/src/services/apiClient.ts` to consume live response without fixture fallback.
  4. **Redis Dependency Pinning:**
     - Add `redis>=5.0.0` to `backend/requirements.txt` and verify production startup ping.
  5. **Deprecate Dead Package:**
     - Formally remove or archive `src/chronocongisec/` to prevent codebase duplication.
- **Prerequisites:** Phase 0 Audit approval.
- **Tests & Verification:**
  - Automated migration test executing migration 0013 against PostgreSQL.
  - Contract tests in `backend/tests/security/test_trust_store_contract.py` passing against PostgreSQL.
  - Integration tests for tool permission assignment and immediate Gateway policy enforcement.
- **Risks:** PostgreSQL schema migration lock contention.
- **Exit Criteria:** Zero in-memory stores in production paths; ChroniMem live API working in frontend; Redis driver verified; all unit and database tests pass.

---

### Phase 2: Memory Integrity, Provenance & Ingestion Hardening

**Objective:** Implement multi-channel ingestion per MPBench research, establish cryptographic authenticity beyond SHA-256 digests, and harden provenance traversal budgets.

- **Scope & Deliverables:**
  1. **Multi-Channel Write Ingestion (MPBench Alignment):**
     - Extend `MemoryIngestRequest` to record write channel: `EXPLICIT_INSTRUCTION`, `SYSTEM_PROMPT_DRIVEN`, `COMPACTION_DRIVEN`, `EXPERIENCE_TO_PROCEDURE`.
     - Enforce channel-specific validation rules and source integrity requirements.
  2. **Cryptographic Authenticity (HMAC / KMS Signatures):**
     - Add keyed HMAC signatures (`HMAC-SHA256`) to memory versions using tenant-isolated keys to detect tamper attacks where both content and digest are modified.
  3. **Global Provenance Traversal Hardening:**
     - Enforce shared visited node and edge budgets across distributed database queries to prevent high-fanout graph traversal denial-of-service.
  4. **Staleness & Supersession Engine:**
     - Automate detection of superseded memory versions and enforce deterministic `SUPERSEDE` transitions.
- **Prerequisites:** Phase 1 complete.
- **Tests & Verification:**
  - Adversarial injection tests across all 4 write channels.
  - Cryptographic tamper tests (tampered content vs tampered content + digest).
  - Graph traversal stress tests on 1,000-node DAGs asserting memory limits.
- **Risks:** Performance overhead of cryptographic signing on high-throughput ingestion.
- **Exit Criteria:** Multi-channel provenance fully recorded; HMAC tamper detection verified; traversal budgets fail closed safely.

---

### Phase 3: Security Intelligence & Probabilistic Detection

**Objective:** Implement local ONNX-based security models for NLI claim verification, prompt injection detection, and behavioral anomaly baselines without compromising deterministic enforcement.

- **Scope & Deliverables:**
  1. **Local Model Runtime Setup:**
     - Configure `onnxruntime` environment with CPU quantization support.
  2. **Source-Grounded NLI Claim Verifier:**
     - Implement DeBERTa-v3 ONNX inference engine to compare agent thought claims against authoritative sources.
     - Contradiction signals automatically flag memory as `SUSPICIOUS`.
  3. **Memory Injection Classifier:**
     - Deploy quantized prompt injection detector on ingestion pipeline.
  4. **Behavioral Anomaly Engine:**
     - Track agent action frequency, parameter variances, and tool call sequence transitions.
- **Prerequisites:** Phase 2 complete.
- **Tests & Verification:**
  - Benchmark evaluation against MPBench and AgentDojo datasets.
  - Latency validation: NLI inference < 100 ms, Injection check < 50 ms.
  - Zero-override regression test: Assert deterministic policy blocks action even when ML model emits benign score.
- **Risks:** Model latency exceeding Gateway SLA; false positive spikes on novel vocabulary.
- **Exit Criteria:** ML pipelines running locally via ONNX; zero override of deterministic checks; latency within SLA bounds.

---

### Phase 4: Complete Recovery & Side-Effect Compensation Engine

**Objective:** Expand recovery beyond memory version rollbacks to include agent context checkpoints, external action journals, and compensating actions.

- **Scope & Deliverables:**
  1. **External Action Journal:**
     - Record all executed tool side effects with transaction IDs, cited memory refs, and registered compensation handlers.
  2. **Compensating Action Dispatcher:**
     - Implement registered compensation adapters (e.g. refunding disbursements, de-provisioning temporary resources).
  3. **Agent Context Checkpoint Integration:**
     - Checkpoint agent execution scratchpads and active prompt contexts; abort tainted runs upon recovery execution.
  4. **Post-Recovery Verification Harness:**
     - Automated counterfactual re-execution verifying that the unsafe tool proposal does not recur after state rollback.
- **Prerequisites:** Phase 3 complete.
- **Tests & Verification:**
  - End-to-end recovery test: Seed poisoned memory -> trigger transfer -> contain & rollback -> verify compensation dispatch -> verify post-condition regression test passes.
- **Risks:** Third-party external API failure during compensation execution.
- **Exit Criteria:** Reversible, compensatable, and irreversible actions handled truthfully; compensating actions logged; post-recovery verification passes.

---

### Phase 5: Multi-Framework Adapters, Enterprise Governance & Production Hardening

**Objective:** Deliver production-ready adapters for LangGraph and AutoGen, enforce PostgreSQL Row-Level Security (RLS) with the restricted app role, and harden the frontend workstation.

- **Scope & Deliverables:**
  1. **LangGraph & AutoGen Adapters:**
     - Provide drop-in Python packages enabling LangGraph and AutoGen agents to propose actions through AMSC.
  2. **PostgreSQL RLS & App Role Enforcement:**
     - Enable RLS policies across all tenant tables and execute application connections strictly using the unprivileged `amsc_app` role.
  3. **Frontend Workstation Hardening:**
     - Remove all development fixture fallbacks; implement live WebSocket telemetry updates for Dual Trace.
  4. **Production Deployment Suite:**
     - Multi-node Docker Compose and Helm charts with distributed Redis rate limiting and TLS termination.
- **Prerequisites:** Phase 4 complete.
- **Tests & Verification:**
  - Cross-framework test suite running identical test scenarios across CrewAI, LangGraph, and AutoGen.
  - SQL injection and RLS bypass penetration testing against `amsc_app` role.
  - End-to-end CI pipeline executing against real PostgreSQL and Redis containers.
- **Risks:** Latency introduced by distributed network hops.
- **Exit Criteria:** 100% test pass rate across all 3 agent frameworks; RLS verified on PostgreSQL; production deployment passes security audit.
