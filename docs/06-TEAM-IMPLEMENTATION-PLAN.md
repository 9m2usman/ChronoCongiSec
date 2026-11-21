# Agent Memory Security Center (AMSC)
## Document 06: Seven-Person, Seven-Day Implementation Plan

**Document Identifier:** `AMSC-DOC-006`  
**Version:** 1.0.0  
**Status:** Approved Delivery Matrix  
**Target:** 7-Day End-to-End Vertical Slice MVP + Post-MVP Hardening Roadmap  
**Author:** Lead Engineering Project Planner & Technical Delivery Council  
**Repository Target:** https://github.com/9m2usman/ChronoCongiSec

---

## 1. Team Ownership & Responsibility Allocation

| Member Code | Role Title | Core Technical Domain | Primary Deliverables |
|---|---|---|---|
| **M1** | Platform Backend & API Integration Lead | FastAPI architecture, Authentication, Tenancy Context, OpenAPI contracts, Routing | Ingress routing, JWT/API key auth, tenant middleware, standardized errors, shared contract enforcement. |
| **M2** | Agent Runtime & Gateway Adapters Lead | Agent protocol, Ingress Gateway proposal handling, Server-side Tool Adapters | Agent proposal protocol, sandbox mock tool adapters (wire transfer, cloud infra), credential isolation. |
| **M3** | Knowledge & Memory Systems Lead | Ingestion pipelines, SHA-256 Hashing, Versioning, Provenance Graphs, Checkpoints | Cryptographic content hasher, memory version tree, provenance graph edge traversals, checkpoint snapshotting. |
| **M4** | Security Engine & Incident Lead | Policy Engine, Rule Matrix, Memory Trust Validation, Quarantine Engine, Rewind Logic | Deterministic rule evaluator, fail-closed handlers, memory trust scoring, quarantine state machine, rollback calculator. |
| **M5** | Frontend & UX Engineering Lead | React 19, TypeScript, Tailwind CSS, shadcn/ui, Workstation Shell, All 11 Screens | Complete responsive UI, interactive dashboards, state managers, Dual Trace scrubber, React Flow knowledge graph. |
| **M6** | Database Architect & Governance Lead | PostgreSQL DDL, Alembic migrations, Multi-Tenant constraints, RBAC, Audit Logging | Relational schema, composite tenant indexes, foreign key cascades, append-only audit persistence, isolation tests. |
| **M7** | DevOps, Testing & QA Lead | Docker, Redis, CI/CD pipelines, Test Runners, Multi-Tenant isolation & Security tests | Containerized local orchestration, automated pytest suite, cross-tenant security test harness, seed fixtures, demo scripts. |

---

## 2. Member Ownership Boundaries & Interfaces

### Member M1: Platform Backend & API Integration Lead
- **Responsibilities:** Owns the FastAPI application lifecycle, global middlewares, routing structure, OpenAPI canonical contract generation, and cross-module error handling.
- **Inputs Required:** Schema definitions from M6; Policy engine hooks from M4; Gateway routes from M2; Memory routes from M3.
- **Deliverables:** `backend/app/main.py`, `backend/app/core/`, `backend/app/api/auth.py`, `backend/app/api/tenants.py`.
- **Testing Responsibilities:** HTTP status code validation, authentication tests, tenant header assertion tests.
- **Constraint:** M1 must not change API route signatures or response models without written agreement from M5 (Frontend Lead).

### Member M2: Agent Runtime & Gateway Adapters Lead
- **Responsibilities:** Owns the tool action proposal protocol and isolated server-side tool execution adapters. Guarantees that agent runtimes have zero direct credentials.
- **Inputs Required:** Agent permissions from M6; Policy decision results from M4; Database session from M1.
- **Deliverables:** `backend/app/gateway/adapters.py`, `backend/app/api/gateway.py`, simulated agent proposal scripts.
- **Testing Responsibilities:** Idempotency tests, adapter timeout tests, parameter constraint tests.
- **Constraint:** M2 must not permit any direct tool invocation path that bypasses M4's policy checks.

### Member M3: Knowledge & Memory Systems Lead
- **Responsibilities:** Owns knowledge ingestion, cryptographic content hashing, version incrementing, provenance graph modeling, and checkpoint snapshotting.
- **Inputs Required:** Memory tables from M6; Tenant context from M1.
- **Deliverables:** `backend/app/memory/`, `backend/app/knowledge/`, `backend/app/api/memory.py`, `backend/app/api/chronimem.py`.
- **Testing Responsibilities:** SHA-256 hash collision checks, provenance DAG acyclicity tests, retrieval exclusion tests.
- **Constraint:** M3 must not modify memory trust states without routing through M4's quarantine engine.

### Member M4: Security Engine & Incident Lead
- **Responsibilities:** Owns the deterministic policy evaluation engine, memory trust verification, threat classification, quarantine workflows, and blast-radius rollback calculation.
- **Inputs Required:** Memory records from M3; Tool permissions from M6; Action proposals from M2.
- **Deliverables:** `backend/app/security/policy.py`, `backend/app/api/security.py`, `backend/app/api/recovery.py`.
- **Testing Responsibilities:** Fail-closed injection tests, memory trust failure tests, pre-recovery state snapshot preservation tests.
- **Constraint:** M4 must never allow a proposal to pass if any referenced memory is `SUSPICIOUS` or `QUARANTINED`.

### Member M5: Frontend & UX Engineering Lead
- **Responsibilities:** Owns the entire client application, responsive layouts, design tokens, state management (TanStack Query + Zustand), and all 11 core workstation screens.
- **Inputs Required:** OpenAPI specification from M1; Seed fixture data from M7.
- **Deliverables:** `frontend/src/` (All components, layouts, screens, stores, hooks, services).
- **Testing Responsibilities:** Visual accessibility (WCAG AA), responsive layout verification, client-side form validation.
- **Constraint:** M5 must consume published backend API contracts and must never invent unofficial routes or mock business decisions in UI code.

### Member M6: Database Architect & Governance Lead
- **Responsibilities:** Owns PostgreSQL relational schemas, Alembic migrations, composite foreign key constraints, tenant isolation enforcement, RBAC mapping, and append-only audit persistence.
- **Inputs Required:** Entity requirements from all subsystem leads (M1-M4).
- **Deliverables:** Database migrations, SQLAlchemy declarative models, repository tenant scoping methods.
- **Testing Responsibilities:** Migration roll-forward/roll-back tests, database foreign key constraint violation tests.
- **Constraint:** M6 must ensure that all tenant-owned tables enforce non-nullable `tenant_id` foreign keys.

### Member M7: DevOps, Testing & QA Lead
- **Responsibilities:** Owns Docker containerization, local development stack orchestration, automated CI test runner execution, security penetration testing, and demo scenario scripts.
- **Inputs Required:** Service code from M1-M6; Tool adapters from M2; Seed data requirements from M4.
- **Deliverables:** `docker-compose.yml`, `Dockerfile`, `backend/tests/`, test execution reports, demo runner script.
- **Testing Responsibilities:** Multi-tenant isolation test suite, gateway bypass penetration testing, end-to-end demo execution.
- **Constraint:** M7 has veto power over any pull request that breaks tenant isolation or introduces a security gateway bypass.

---

## 3. Seven-Day Detailed Execution Schedule

```text
+-------+------------------------------------------------------------------------------------+
| Day   | Milestone / Deliverable                                                            |
+-------+------------------------------------------------------------------------------------+
| Day 1 | Architecture, Contracts, Schema DDL & Shared Development Baseline (Exit Gate G1)  |
| Day 2 | Foundation: Auth, Tenancy Context, DB Repositories & UI Shell (Exit Gate G2)       |
| Day 3 | Knowledge Ingestion, Lineage, Agent Registry & Explorer (Exit Gate G3)             |
| Day 4 | Protected Tool Gateway & Fail-Closed Enforcement Vertical Slice (Exit Gate G4 - P0)|
| Day 5 | Forensics, Quarantine, ChroniMem Diffing & Rollback Engine (Exit Gate G5)          |
| Day 6 | Observability, Dual Trace, Knowledge Graph & 3 Demos (Exit Gate G6)                |
| Day 7 | Hardening, Security Validation, End-to-End Test Suite & Handover (Exit Gate G7)    |
+-------+------------------------------------------------------------------------------------+
```

---

### Day 1: Architecture, Contracts & Shared Baseline

| Member | Tasks | Expected Deliverable | Dependencies | Exit Criteria |
|---|---|---|---|---|
| **M1** | Bootstrap FastAPI project, setup CORS, exception handlers, health endpoint. | `main.py`, `core/config.py`, `/health` | None | Local server boots, returns 200 on `/health`. |
| **M2** | Specify `ActionProposal` schema, define sandbox mock adapter interfaces. | Proposal & Execution schemas | M1 API baseline | Tool schema approved by M1 and M4. |
| **M3** | Define memory record, versioning, and provenance edge models. | Memory data models | M6 Schema | Cryptographic hashing utility passes unit test. |
| **M4** | Design deterministic policy state machine and memory trust check protocol. | Policy evaluation matrix | M2 Proposal schema | Fail-closed default logic approved. |
| **M5** | Initialize React/Vite/TS project, install Tailwind CSS, setup folder structure. | Frontend project foundation | None | Clean build, Tailwind styles render. |
| **M6** | Finalize PostgreSQL DDL, draft tables for users, tenants, agents, memory, tools. | Initial Alembic migration | M1-M4 requirements | Schema applies cleanly to blank database. |
| **M7** | Create Docker Compose file for PostgreSQL and Redis, configure pytest harness. | `docker-compose.yml`, CI skeleton | M1, M6 | `docker compose up` brings up DB and cache. |

**Exit Gate G1:** All seven members have a functioning local environment, agreed version matrix, and locked shared contracts.

---

### Day 2: Foundation (Auth, Tenancy Context & UI Shell)

| Member | Tasks | Expected Deliverable | Dependencies | Exit Criteria |
|---|---|---|---|---|
| **M1** | Implement JWT authentication, `/auth/login`, and `TenantContext` middleware. | `api/auth.py`, `tenancy/context.py` | M6 Users table | Valid login returns signed JWT with tenant ID. |
| **M2** | Implement mock `sandbox_transfer` adapter with server-side credential isolation. | `gateway/adapters.py` | None | Adapter executes wire mock with transaction ID. |
| **M3** | Implement `/api/v1/memory` basic ingestion and retrieval endpoints. | `api/memory.py` | M6 Memory tables | Ingesting memory assigns version 1 and SHA-256. |
| **M4** | Implement basic RBAC check (`TENANT_ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`). | RBAC evaluator | M1 Auth context | Unauthorized roles rejected with 403. |
| **M5** | Build responsive App Shell: collapsible sidebar, top navigation, tenant dropdown. | AppShell layout component | M1 Auth contract | Navigation renders all 11 screen links. |
| **M6** | Add composite tenant unique constraints and indexes to relational tables. | Hardened DB migration | M1, M3 | Cross-tenant foreign key inserts fail in DB. |
| **M7** | Implement seed database script with single-company enterprise fixtures (Head Office, Lahore, Karachi, Islamabad branches). | `core/seed.py` | M1, M6 | Seed script populates enterprise organization and branch fixtures. |

**Exit Gate G2:** User can sign in, select an authorized company/branch workspace, and view scoped resources.

---

### Day 3: Knowledge, Lineage & Agent Registry

| Member | Tasks | Expected Deliverable | Dependencies | Exit Criteria |
|---|---|---|---|---|
| **M1** | Expose Agent CRUD endpoints (`GET /agents`, `POST /agents`, `GET /agents/{id}`). | `api/agents.py` | M6 Agent tables | Agent registration persists configuration version. |
| **M2** | Implement agent tool permission assignment endpoint (`PUT /agents/{id}/permissions`). | Permission assigner | M1, M6 | Tool operational limits stored in DB. |
| **M3** | Build provenance edge creation logic (`DERIVED_FROM`, `TRANSFORMED_INTO`). | Provenance edge builder | M6 Tables | Child records link to parent with edge records. |
| **M4** | Implement trust state machine (`UNVERIFIED`, `TRUSTED`, `SUSPICIOUS`, `QUARANTINED`). | Trust evaluator | M3 Memory models | State transitions obey valid transition rules. |
| **M5** | Build Screen 01 (Overview) and Screen 02 (Agent Registry) UI views. | Overview & Registry views | M1 Agent APIs | Agent table displays real backend agents. |
| **M6** | Add checkpoint snapshot schema and persistence tables. | Checkpoint DDL migration | M3 | Checkpoint tables support aggregate hash. |
| **M7** | Write integration tests for memory ingestion and provenance graph creation. | `tests/test_memory.py` | M3 | Tests pass asserting valid SHA-256 checksums. |

**Exit Gate G3:** Ingested memory generates traceable lineage; Agent Registry displays active runtimes.

---

### Day 4: Protected Tool Gateway (Mandatory Vertical Slice)

| Member | Tasks | Expected Deliverable | Dependencies | Exit Criteria |
|---|---|---|---|---|
| **M1** | Implement `/api/v1/gateway/actions/propose` route with idempotency handling. | `api/gateway.py` | M2, M4 | Duplicate idempotency key returns cached result. |
| **M2** | Wire agent proposal to Gateway; ensure agent cannot directly call adapters. | Proposal controller | M1, M4 | Direct adapter invocation without token fails. |
| **M3** | Connect memory trust check to Gateway: verify memory refs are active and owned. | Trust check connector | M4 Policy engine | Quarantined memory flag detected by Gateway. |
| **M4** | Enforce fail-closed policy logic: block proposals referencing tainted memory. | `security/policy.py` | M2, M3 | Tainted proposal blocked; execution prevented. |
| **M5** | Build live Gateway Activity Stream and Security Alert banner on UI. | Gateway live stream UI | M1 Gateway APIs | Gateway decisions display ALLOW/BLOCK badges. |
| **M6** | Implement atomic transaction wrapping proposal, decision, and tool execution. | Transactional repository | M1, M2 | No tool execution recorded without decision. |
| **M7** | Execute automated gateway bypass security tests; verify zero bypasses. | `tests/test_gateway.py` | M1, M2, M4 | 100% bypass attempts blocked. |

**Exit Gate G4 (MANDATORY VERTICAL SLICE):** Agent submits proposal -> Gateway evaluates memory trust -> Tainted action is BLOCKED before tool execution -> Decision and audit trail committed.

---

### Day 5: Incident Investigation, Quarantine & Recovery Engine

| Member | Tasks | Expected Deliverable | Dependencies | Exit Criteria |
|---|---|---|---|---|
| **M1** | Implement incident creation, evidence attachment, and quarantine REST APIs. | `api/security.py` | M4, M6 | Incident persists tainted memory references. |
| **M2** | Connect tool execution logging to W3C `trace_id` correlation parameters. | Telemetry interceptor | M1 | Execution logs contain valid `trace_id`. |
| **M3** | Build ChroniMem temporal version comparison endpoint (`/chronimem/compare`). | `api/chronimem.py` | M6 Memory tables | Unified diff highlights inserted injection text. |
| **M4** | Implement quarantine workflow: exclude quarantined records from retrieval queries. | Retrieval filter | M3 Memory API | Retrieval queries omit quarantined records. |
| **M5** | Build Screen 04 (Security Center) and Screen 06 (ChroniMem) UI views. | Security & ChroniMem UI | M1, M3, M4 | Inspector drawer triggers one-click quarantine. |
| **M6** | Implement atomic Agent Rewind rollback with pre-recovery state preservation. | `api/recovery.py` | M3, M4 | Pre-recovery snapshot committed before rollback. |
| **M7** | Automated test suite verifying quarantine isolation and rollback accuracy. | `tests/test_recovery.py` | M4, M6 | Rollback restores records to validated checksum. |

**Exit Gate G5:** Analyst investigates incident, quarantines poisoned record, inspects ChroniMem diff, and executes validated recovery.

---

### Day 6: Observability, Dual Trace & Three Core Demonstrations

| Member | Tasks | Expected Deliverable | Dependencies | Exit Criteria |
|---|---|---|---|---|
| **M1** | Implement Dual Trace API endpoint (`/traces/{trace_id}/dual-trace`). | `api/traces.py` | M2, M3 | Returns paired Execution and Memory lanes. |
| **M2** | Finalize External Sandbox Tool Adapter demonstration scenario (Demo 2). | Demo 2 runner script | M1, M4 | Proves unauthorized wire block at Gateway. |
| **M3** | Build Knowledge Graph topological node-edge projection endpoint. | `api/knowledge.py` | M6 Graph tables | Graph returns bounded nodes and provenance edges. |
| **M4** | Implement Drift Monitor observation review and scoring endpoints. | `api/drift.py` | M6 Drift tables | Drift observation review persists analyst status. |
| **M5** | Build Screen 05 (Dual Trace) and Screen 07 (Knowledge Graph) UI views. | Dual Trace & Graph UI | M1, M3 | Clicking execution span highlights memory chunk. |
| **M6** | Verify append-only constraints on audit events table. | Audit verification DDL | M1 | Direct UPDATE/DELETE statements rejected. |
| **M7** | Execute automated Three-Company Tenant Isolation test suite (Demo 3). | `tests/test_isolation.py`| M1, M6 | Zero cross-tenant data bleed verified. |

**Exit Gate G6:** All 11 screens functional; Dual Trace correlates telemetry; all three demonstration flows validated.

---

### Day 7: Integration, Security Validation & Handover

| Member | Tasks | Expected Deliverable | Dependencies | Exit Criteria |
|---|---|---|---|---|
| **M1** | Finalize OpenAPI documentation, audit API error responses, resolve edge cases. | Canonical OpenAPI spec | All leads | Zero unhandled 500 exceptions in test suite. |
| **M2** | Review adapter credential containment; ensure zero credentials exposed. | Adapter security audit | None | Code audit verifies credentials server-side only. |
| **M3** | Validate cryptographic checksum integrity across all memory versions. | Integrity audit script | M6 | 100% memory versions match SHA-256 hash. |
| **M4** | Review fail-closed behavior across simulated infrastructure failures. | Fail-closed test suite | M1, M2 | All simulated outages trigger `BLOCK`. |
| **M5** | Polish responsive UI layouts, verify empty and loading states across 11 screens. | Polished frontend | M1 APIs | Zero UI console errors; all routes functional. |
| **M6** | Verify database migrations from clean database to fully seeded state. | Migration clean test | M7 | Migration runs forward and backward cleanly. |
| **M7** | Run complete automated integration suite; execute full demonstration recording. | Final test report | All leads | 100% test pass rate; demos verified. |

**Exit Gate G7:** Production-ready MVP verified with automated test suite, zero known security bypasses, and complete documentation handover.

---

## 4. Integration Gates Matrix

| Gate Code | Day Target | Mandatory Verification Criteria | Sign-Off Authority |
|---|---|---|---|
| **G1** | Day 1 | Shared contracts agreed, version matrix locked, Docker and local environment boot cleanly. | M1 (Backend) & M7 (QA) |
| **G2** | Day 2 | JWT auth functions, tenant resolution asserts membership, database seed populates 3 tenants. | M1 (Backend) & M6 (Database) |
| **G3** | Day 3 | Ingested memory generates SHA-256 hash and provenance edge; Agent Registry renders in UI. | M3 (Memory) & M5 (Frontend) |
| **G4** | Day 4 | **CRITICAL SLICE:** Gateway blocks unauthorized and untrusted action proposals before execution. | M2 (Adapters) & M4 (Security) |
| **G5** | Day 5 | Quarantined memory excluded from retrieval; rollback preserves pre-recovery state snapshot. | M3 (Memory) & M4 (Security) |
| **G6** | Day 6 | Three-company isolation verified; Dual Trace correlates spans; 11 screens connected. | M5 (Frontend) & M7 (QA) |
| **G7** | Day 7 | 100% test pass rate; zero gateway bypasses; full documentation handover complete. | All 7 Members Unanimous |

---

## 5. Daily Coordination Protocol & Branch Strategy

### 5.1 Standup Protocol (Daily at 09:00 UTC)
Each developer submits a structured 3-point update:
1. **Delivered Yesterday:** Merged PRs, passed tests, closed exit criteria.
2. **Planned Today:** Current branch, target files, interfaces required from teammates.
3. **Blockers & Contract Changes:** Any proposed schema or route modification requiring cross-member approval.

### 5.2 Branching & Pull Request Rules
- Protected Trunk: `main`. Direct commits to `main` are prohibited.
- Standard Branch Naming:
  - `feat/m1-platform-auth`
  - `feat/m2-gateway-adapters`
  - `feat/m3-memory-provenance`
  - `feat/m4-security-policy`
  - `feat/m5-workstation-ui`
  - `feat/m6-schema-governance`
  - `feat/m7-devops-test-harness`
- PR Rules: Minimum one approving review from an affected subsystem lead. CI integration and isolation tests must pass before merge.

---

## 6. Scope Management & Hardening Protocols

If delivery constraints or unforeseen complexities arise during the 7-day sprint, the following scope reduction rules apply:

### Permitted Simplifications (Without Weakening Security):
- Fall back from dynamic vector embedding clusters to relational keyword/string matching in the Drift Monitor.
- Utilize local filesystem or relational storage for documents rather than configuring full AWS S3 integration.
- Utilize single-process ASGI execution rather than multi-worker Celery queues for background tasks.

### Absolute Invariants (CANNOT Be Cut or Compromised):
- **NEVER** bypass the server-side Security Gateway.
- **NEVER** allow an action proposal backed by `SUSPICIOUS` or `QUARANTINED` memory to execute.
- **NEVER** compromise multi-tenant isolation at the database query layer.
- **NEVER** execute a memory rollback without preserving the pre-recovery state snapshot.
- **NEVER** weaken fail-closed defaults simply to allow a failing test to pass.

---

## 7. Sprint Completion Status (Days 1–7 Exit Gate G7)

- **M1 (Platform Backend & API Integration):** Days 1–7 finalized. Ingress security, OpenAPI 3.1 documentation, rate limiting, token revocation, Agent Registry, Protected Gateway, Incident Management, Dual Trace, and Recovery APIs complete.
- **M3 (Knowledge & Memory Systems):** Days 1–7 finalized. PR #7 refactored memory package verified; F-1a (fail closed on unknown trust states) and F-2 (transition matrix enforcement) defects resolved; backward-compatibility shims (`hashing.py`, `service.py`) active.
- **M4 (Security Engine & Incident Response):** Days 1–7 finalized via PR #16. 19-rule `PolicyEngine`, 19-rule `TrustEvaluator`, `ProtectedExecutionGuard`, and `DriftMonitor` active as single-source authorities.
- **M5 (Frontend Workstation):** Days 1–7 finalized via PR #6, #12, #15. Screens 01–11 active with honest fallback and zero mock token forging.
- **M6 (Database Architecture & Governance):** Days 1–7 finalized via PR #8–#14. Migrations 0001–0009, hash-chained audit, composite foreign keys, and app role permissions active.
- **M7 (DevOps & Test Infrastructure):** Existing test suites and CI configurations verified; 1,493 backend unit and security tests passing.



---

## 8. Simulated Company Integration Addendum (DOC-009)

The detailed implementation scope and copy-ready prompts for M1, M3, M4, M5, M6 and M7 are normative in [DOC-009](09-SIMULATED-COMPANY-INTEGRATION-PLAN.md). This addendum resolves older demo wording in this plan:

1. **Primary demo topology:** one fictional company with Head Office, Lahore, Karachi and Islamabad branches, consistent with DOC-001 and README. Branches are not separate tenants.
2. **Three-company wording:** any earlier reference to a three-company demo applies only to dedicated multi-tenant isolation/security tests. It is not the simulated-company business workflow.
3. **M7 seed scope:** seed one fictional company, its branches, synthetic users/roles, agent registrations, policies and company knowledge through the approved seed interfaces. Keep reset restricted to explicitly marked demo data.
4. **M7 isolation tests:** retain separate synthetic tenants/organizations only as adversarial fixtures to prove tenant isolation. Do not display them as the branches of the simulated company.
5. **Runtime integration:** M2 remains owner of the existing agent runtime, proposal protocol, Gateway and protected adapters. DOC-009 assigns no new work to M2; other members integrate through M2's published contracts.
6. **M5 frontend:** integrate the demo into the existing workstation and established React 19/TypeScript/Vite/Tailwind/TanStack Query/Zustand stack. Do not create a second dashboard or replace existing UI foundations.
7. **Cross-member implementation:** use DOC-009's contract order, ownership constraints, demo scenarios, acceptance gates and token-efficient reporting requirements. No member may implement another owner's subsystem without explicit coordination.

Where an older row in the original seven-day schedule conflicts with this addendum, the single-company/multi-branch topology and DOC-009 integration rules take precedence. Existing completed work must be verified and reused rather than re-created.
