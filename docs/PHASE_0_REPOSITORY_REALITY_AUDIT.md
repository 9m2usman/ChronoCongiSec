# Phase 0 — Repository Reality Audit & Reconciliation

**Document ID:** AMSC-DOC-P0-001  
**Audit Date:** 2026-11-24  
**Auditor:** Principal Software Architect, Senior Application Security Engineer, AI Agent Security Researcher, Database Security Engineer, DevSecOps Engineer & Independent Technical Auditor  
**Repository:** `https://github.com/9m2usman/ChronoCongiSec`  
**Audited Branch:** `feat/m2-agent-runtime-gateway-adapters`  
**Audited HEAD Commit:** `4be755cb3ecd5c3a6007f20a38f845cec7180e23` (`fix(security): resolve quarantine 404 with demo memory seeding and recovery preview 503 with in-memory recovery store`)  
**Working Tree Status:** Clean (no uncommitted modifications)  
**Parent / Upstream Baseline:** `main` at `0a04acf` (`fix(settings): resolve JSX syntax errors, unclosed tags, and harmonize approval payload types`) — active branch is 13 commits ahead of `main`.

---

## 1. Executive Summary

This independent technical audit establishes the empirical reality of the ChronoCongiSec / Agent Memory Security Center (AMSC) repository. It supersedes speculative documentation, PR marketing claims, and outdated audit notes by examining concrete source code, AST definitions, database migrations, runtime behaviors, and executed test suites.

AMSC is an enterprise AI-agent security and recovery control plane. It is designed to integrate with and protect existing heterogeneous AI agents across business departments regardless of framework. Its architectural purpose is to establish whether an agent's knowledge, memory, instructions, decisions, and proposed actions remain within an approved company baseline, detecting memory poisoning, indirect prompt injection, semantic drift, and goal deviation, and enforcing deterministic `ALLOW`, `BLOCK`, or `REQUIRE_HUMAN_APPROVAL` verdicts.

### Key Audit Conclusions

1. **Working Core Primitives:** The system possesses genuine, highly robust implementations of deterministic policy evaluation (`backend/app/security/policy.py`), trust state machine transitions (`backend/app/security/trust.py`), complete mediation through the protected gateway (`backend/app/api/gateway.py`), and in-memory/unit-tested recovery orchestration (`backend/app/recovery/orchestrator.py`).
2. **Persistence Reality & The "Persistent Store" Illusion:** While SQLAlchemy declarative models and Alembic migrations 0001–0012 exist for core tables, critical production persistence bridges remain incomplete. Most notably, `SqlTrustDecisionStore` in `backend/app/recovery/store.py` defines `is_persistent = True` to bypass production guardrails, but its internal storage is an in-memory Python dictionary (`self._by_record`). There is no database table for memory trust decisions in `Base.metadata`.
3. **Machine Learning Status — 100% Empty Scaffolding:** The entire `ml/` tree consists solely of `.gitkeep` files and `ml/owner.md`. No model weights, training scripts, feature extraction pipelines, or inference engines exist. Neither `torch`, `transformers`, `scikit-learn`, nor `onnx` are installed in the backend dependencies.
4. **CrewAI Integration Boundary:** `crewai_service` is an integration demonstration and test double runtime, not the core architecture. In `crewai_service/framework.py`, the official CrewAI library is explicitly disabled (`_OFFICIAL_CREWAI_AVAILABLE = False`) in favor of a native lightweight compatibility runtime.
5. **Frontend Dual-Mode Realities:** The React 19 / Vite workstation (`frontend/`) contains genuine interactive screens, but frequently falls back to static fixtures (`frontend/src/services/fixtures.ts`) whenever backend endpoints return 403 (e.g. attempting to query non-`TRUSTED` memory records without forensic authorization) or when endpoints exhibit schema mismatches.
6. **Codebase Redundancy & Forked Packages:** `src/chronocongisec/security/{gateway,audit}.py` (introduced in PR #21) exists as a disconnected standalone package that duplicates gateway and audit logic, completely unused by `backend/app/main.py`.

---

## 2. Repository Snapshot & Git Architecture

### 2.1 Git Status & Commit Lineage
- **Branch:** `feat/m2-agent-runtime-gateway-adapters`
- **HEAD Commit:** `4be755cb3ecd5c3a6007f20a38f845cec7180e23`
- **Working Tree:** Clean
- **Commits ahead of `main` (13 commits):**
  - `4be755c` fix(security): resolve quarantine 404 with demo memory seeding and recovery preview 503 with in-memory recovery store
  - `17dbb90` fix(memory): resolve 400 validation error on memory ingestion with canonical agents, sources, and aliases
  - `ce4a018` fix(agents): unwrap agent catalog envelope items and guard tool rendering in AgentRegistryPage
  - `5024256` fix(auth,tenancy): synchronize active tenant on login and resolve tenant alias header mismatch
  - `ab1c5e7` test(startup): assert database auth wiring precedes redis guard
  - `1a7e878` test(startup): target missing auth guard without database wiring
  - `759a046` test(startup): isolate missing auth repository guard
  - `4aadf3e` fix(startup): validate production repositories before recovery wiring
  - `90ee020` test(crewai): match auth fixtures to login response contract
  - `e1ce1c2` style(backend): resolve M2 test lint findings
  - `ec7e2fe` test(crewai): provide explicit mock credentials for auth tests
  - `b5e242e` feat(m2): enforce direct adapter mediation, active timeout bounds, and W3C trace validation
  - `36b218c` security(m2): audit and harden adapter credential isolation

### 2.2 Key Recent Merged Pull Requests
- `PR #33` (`d19e882`): `chore/remove-generated-backups-and-metadata`
- `PR #31` (`9dd9cf5`): `feat/amsc-phases-1-6-complete` (IAM relationships, composite FKs, branch scope)
- `PR #30` (`feb1e7a`): `feat/amsc-mandatory-directive`
- `PR #29` (`357c999`): `docs/crewai-business-agent-prompt-pack`
- `PR #27` (`5e70270`): `feat/integration-verification` (Integration audit baseline @ `30fe3eb`)
- `PR #21` (`1d1fa2d`): `engineering/research-driven-control-plane` (Introduced standalone `src/chronocongisec/`)
- `PR #16` (`cdbb4b9`): `feat/m4-security-ml`
- `PR #15` (`e39f2da`): `feat/m5-amsc-frontend-workstation`
- `PR #14` (`2b3f738`): `feat/m6-day7-migration-lifecycle`

### 2.3 Directory & Module Inventory

```
ChronoCogniSec/
├── backend/
│   ├── alembic/              # Alembic migration environment & 12 versions
│   ├── app/
│   │   ├── api/              # 14 FastAPI routers (agents, auth, gateway, memory, traces, etc.)
│   │   ├── core/             # Config, security (JWT/Argon2), exceptions, rate limiting, logging
│   │   ├── database/         # Session, Base, 6 model categories, repositories, unit_of_work
│   │   ├── gateway/          # .gitkeep (gateway logic resides in api/gateway.py)
│   │   ├── knowledge/        # Graph models and test fixtures
│   │   ├── memory/           # Ingestion, retrieval, versioning, provenance, traversal, models
│   │   ├── recovery/         # Orchestrator, store ports, SQL checkpoint reader & plan store
│   │   ├── security/         # PolicyEngine, TrustEvaluator, QuarantineWorkflow, runtime wiring
│   │   ├── tenancy/          # TenantContext, context extraction & validation
│   │   └── workers/          # OutboxProcessor, transactional outbox staging
│   ├── tests/                # database/, security/, unit/ test suites
│   ├── Dockerfile            # Python 3.12-slim backend container
│   └── requirements.txt      # Pinned core backend dependencies
├── crewai_service/           # CrewAI integration & test double harness
│   ├── agents/               # 5 simulated business agents (finance, HR, support, branch, coordinator)
│   ├── config/               # Settings & provider configuration
│   ├── security/             # Execution boundaries & receipt verification
│   ├── telemetry/            # In-memory run/step tracer
│   ├── tools/                # AMSC client, gateway tools, memory tools, branch tools
│   ├── workflows/            # Multi-agent flows
│   ├── framework.py          # Native CrewAI-compatible execution layer
│   └── main.py               # CLI runner supporting --demo 2 and --mode test_double
├── demo/                     # Authoritative reproducible demonstration scripts
│   ├── run_demo2.py          # Standalone runner for Demo 2 (3 scenarios)
│   └── blocked_action/       # Scenario runner mirror
├── docs/                     # PRD, TRD, application flow, schemas, research bibliography
├── frontend/                 # React 19, TypeScript 5.6, Tailwind CSS, Vite 6, Vitest 5.1
│   ├── src/
│   │   ├── components/       # Common modals, graph viewers (2D/3D), auth guards
│   │   ├── pages/            # 12 workstation pages (Gateway, Memory, DualTrace, Rewind, etc.)
│   │   ├── services/         # apiClient.ts (dual-mode live/fallback), fixtures.ts
│   │   ├── stores/           # Zustand workstation store
│   │   └── test/             # Vitest suites (contracts, auth, mutations, isolation)
│   └── package.json          # Pinned frontend dependencies
├── ml/                       # Scaffolding only (all subdirectories contain .gitkeep only)
├── src/                      # Standalone chronocongisec Python package (disconnected PR #21 duplicate)
└── docker-compose.yml        # Multi-container orchestration (postgres, redis, backend, frontend, crewai)
```

---

## 3. Technology Stack & Dependency Constraints

### 3.1 Active Runtime vs. CI / Container Discrepancies
- **Python Version:** 
  - **Local Host Execution:** Python `3.14.10`
  - **CI Workflow (`.github/workflows/ci.yml`):** Python `3.12`
  - **Production Dockerfile (`backend/Dockerfile`):** Python `3.12-slim`
  - *Risk:* Python 3.14 includes significant internal changes to typing, asyncio, and AST. Code executing cleanly on 3.14 may encounter subtle deprecations or differences on 3.12 (e.g. Starlette deprecation warnings `HTTP_422_UNPROCESSABLE_ENTITY`).
- **Node.js & Tooling:**
  - **Local Host Execution:** Node `v24.15.0`, npm `11.12.1`
  - **CI Workflow:** Node `22`
  - **Frontend Package:** React `19.0.0`, Vite `6.0.0`, Vitest `5.1.1`, Tailwind `3.4.19`, Zustand `5.0.0`, Three.js `0.170.0`.

### 3.2 Backend Dependencies (`backend/requirements.txt`)
- `fastapi==0.162.4`, `uvicorn==0.54.0`
- `pydantic==2.14.3`, `pydantic-settings==2.16.2`
- `sqlalchemy==2.1.8`, `asyncpg==0.29.0`, `aiosqlite==0.22.1`, `alembic==1.20.1`, `greenlet==3.5.6`
- `argon2-cffi==25.1.0`, `pyjwt==2.15.1`
- `httpx==0.28.1`, `python-dotenv==1.2.4`
- `pytest==9.2.0`, `pytest-asyncio==1.4.1.post1`

**Critical Omission:** Neither `redis` nor `redis-py` is listed in `backend/requirements.txt`, despite `backend/app/main.py` explicitly enforcing a Redis ping check in production (`rate_limiter.ping()`). Production deployment without adding the Redis driver will fail during dependency resolution or startup.

---

## 4. Capability-by-Capability Reality Matrix

Every architectural capability is classified below according to strict audit evidence:
- `IMPLEMENTED_AND_VERIFIED`: Code exists, is wired into runtime, and passes automated verification tests.
- `IMPLEMENTED_NOT_VERIFIED`: Code exists, but has not been tested against real databases or runtime conditions.
- `PARTIAL`: Incomplete implementation or missing persistent backend; relies on in-memory mocks.
- `DOCUMENTATION_ONLY`: Specified in markdown, but no corresponding executable source code exists.
- `SCAFFOLDING`: Empty directories, `.gitkeep` files, or stub classes with no business logic.
- `MISSING`: Required by PRD/TRD, but completely absent.

| Capability / Subsystem | Classification | Implementation Paths & Symbols | Test & Verification Evidence | Audit Findings & Gaps |
|---|---|---|---|---|
| **1. Agent Registration & Runtime Integration** | `IMPLEMENTED_AND_VERIFIED` | `backend/app/api/agents.py` (`AgentEntity`, `api_create_agent`, `api_list_agents`), `backend/app/database/repositories/agents.py` (`SqlAlchemyAgentRepository`). | `backend/tests/unit/test_agents.py` (32 tests passed), `backend/tests/database/test_repositories.py`. | REST endpoint allows creating agents and listing with tenant isolation. However, **there is no REST endpoint to assign tool permissions**; permissions are read-only via `get_agent_tool_permissions`. |
| **2. Gateway Proposal & Complete Mediation** | `IMPLEMENTED_AND_VERIFIED` | `backend/app/api/gateway.py` (`POST /gateway/actions/propose`, `SandboxTransferAdapter`), `backend/app/security/runtime.py` (`get_gateway_enforcement`). | `backend/tests/unit/test_m2_gateway_adapters.py` (15 passed), `backend/tests/unit/test_gateway.py` (29 passed), `demo/run_demo2.py` (exit code 0). | Complete mediation strictly enforced. Proposal validation rejects NaNs, infinities, excessive nesting (>5), payloads >64KB. Delegates decisions solely to M4 `PolicyEngine`. |
| **3. Authentication, Tenants & Branch Context** | `IMPLEMENTED_AND_VERIFIED` | `backend/app/api/auth.py`, `backend/app/tenancy/context.py` (`TenantContext`, `get_tenant_context`), `backend/app/core/security.py` (Argon2, PyJWT). | `backend/tests/unit/test_auth.py` (42 passed), `backend/tests/unit/test_tenancy.py` (28 passed). | Tenant context extracted strictly from authenticated claims; multi-branch membership supported via Alembic migration 0011/0012. Token revocation store active. |
| **4. Deterministic Policy Enforcement** | `IMPLEMENTED_AND_VERIFIED` | `backend/app/security/policy.py` (`PolicyEngine`, `ProtectedExecutionGuard`, `MANDATORY_CHECKS`). | `backend/tests/security/test_policy_engine.py` (52 passed), `backend/tests/security/test_policy_gateway_integration.py`. | 8 sequential fail-closed checks: Input, Principal, Agent Status, Tool Whitelist, Operation Whitelist, Parameter Ceilings, Approval Thresholds, Memory Trust. Zero ML in decision loop. |
| **5. Memory Ingestion, Retrieval & Trust State** | `IMPLEMENTED_AND_VERIFIED` | `backend/app/api/memory.py`, `backend/app/memory/ingestion.py`, `backend/app/memory/retrieval.py`, `backend/app/security/trust.py` (`TrustEvaluator`). | `backend/app/memory/tests/` (114 passed), `backend/tests/security/test_trust_evaluator.py` (72 passed). | Ingestion computes SHA-256 and sets `UNVERIFIED`. Updates invalidate to `UNVERIFIED`. Retrieval strictly returns `TRUSTED` memory records only; forensic route required for non-trusted. |
| **6. Dual Trace Telemetry & Correlation** | `IMPLEMENTED_AND_VERIFIED` | `backend/app/api/traces.py` (`GET /traces/{id}/dual-trace`, `DualTraceResponse`), `backend/app/main.py` (`RequestContextMiddleware`). | `backend/tests/unit/test_traces.py` (28 passed), `backend/tests/unit/test_m2_gateway_adapters.py`. | W3C `traceparent` parsed and correlated end-to-end. Response formats two lanes: `execution_lane` and `memory_lane` with explicit `CompletenessReport` and forensic gap warnings. |
| **7. Incident Investigation & Quarantine** | `IMPLEMENTED_AND_VERIFIED` | `backend/app/api/incident_management.py` (`POST /incidents`, `POST /incidents/quarantine`), `backend/app/security/quarantine.py` (`QuarantineWorkflow`). | `backend/tests/unit/test_incident_management.py` (45 passed), `backend/tests/security/test_quarantine_workflow.py`. | Restrict-only memory quarantine transitions; incident creation links forensic evidence hashes; emits audit events to hash-chained log. |
| **8. Checkpointing, Rewind & Recovery** | `PARTIAL` | `backend/app/recovery/orchestrator.py` (`RecoveryService`), `backend/app/recovery/store.py` (`SqlCheckpointReader`, `SqlRecoveryPlanStore`). | `backend/tests/security/test_recovery.py` (60 passed in-memory). | Security semantics are complete: snapshot first, contain affected records, rollback by appending NEW version, restored records set to `UNVERIFIED`. **Gaps: External action reversal is uncompensated; `SqlTrustDecisionStore` is in-memory.** |
| **9. Database Persistence & Background Outbox** | `PARTIAL` | `backend/app/database/models/` (6 categories), `backend/alembic/versions/` (12 migrations), `backend/app/workers/outbox.py`. | `backend/tests/database/` (unit level with in-memory SQLite / mock session). | Comprehensive schema models and migrations exist. `OutboxProcessor` provides in-process transactional outbox. **Gap: PostgreSQL RLS and restricted app roles designed but not verified in live CI without running DB container.** |
| **10. CrewAI Integration Runtime** | `IMPLEMENTED_AND_VERIFIED` | `crewai_service/framework.py`, `crewai_service/tools/amsc_client.py`, `crewai_service/tools/gateway_tools.py`, `crewai_service/main.py`. | `crewai_service/tests/` (56 passed), `python demo/run_demo2.py` (passed). | Functions reliably as test double and business agent simulation. Official CrewAI is intentionally disabled (`_OFFICIAL_CREWAI_AVAILABLE = False`) to prevent third-party field drift. |
| **11. Frontend Live API vs. Mock Fixtures** | `PARTIAL` | `frontend/src/services/apiClient.ts`, `frontend/src/services/fixtures.ts`, `frontend/src/pages/`. | `frontend/src/test/` (48 passed across 6 test files). | Complete React UI with 12 workstation views. **Gap: `apiClient.ts` falls back to `fixtures.ts` on 403 or network failure**, masking backend connectivity problems in development mode. ChroniMem contract mismatch causes permanent fixture fallback. |
| **12. Security Machine Learning (M4 ML)** | `SCAFFOLDING` | `ml/owner.md`, `ml/datasets/`, `ml/models/`, `ml/training/`. | None. | **100% empty scaffolding.** Every subfolder in `ml/` contains only `.gitkeep`. Zero training or inference code. No ML dependencies in `requirements.txt`. |

---

## 5. Reconciliation of DOC-008 (Implementation Security Gap Register)

DOC-008 was audited against HEAD commit `4be755c`. The audit findings below document the current status of every GAP, INT, and OPEN item.

### 5.1 Critical P0 / P1 Gap Verification (GAP-001 – GAP-011)

- **GAP-001 (Trusted-Only Normal Retrieval):** `RESOLVED & VERIFIED`. In `backend/app/api/memory.py` lines 146–147, requesting `trust_state != "TRUSTED"` raises `ForbiddenError` (HTTP 403). `retrieve_memory` in `backend/app/memory/retrieval.py` filters strictly on `trust_state == "TRUSTED"`.
- **GAP-002 (Terminal Trust Lock & Update Invalidation):** `RESOLVED & VERIFIED`. In `backend/app/memory/versioning.py`, updating any memory record appends an immutable new version and invalidates the record's current trust state to `UNVERIFIED`. Updates on `QUARANTINED`, `REJECTED`, or `SUPERSEDED` records are rejected.
- **GAP-003 (Tenant Ownership on Ingestion):** `RESOLVED & VERIFIED`. `ingest_memory` independently validates that `agent_id` exists, belongs to the authenticated tenant, and is `ACTIVE`; validates `source_id` exists and belongs to the tenant; and rejects `parent_record_id` if quarantined or cross-tenant.
- **GAP-004 (Forensic Memory Inspection Route):** `RESOLVED & VERIFIED`. Normal detail route `GET /api/v1/memory/{id}` returns 404 for non-trusted records. Audited forensic read is segregated to `POST /api/v1/memory/{id}/forensic-access` and `GET /api/v1/incidents/memory/{id}/forensic`, gated by `SECURITY_ANALYST` or `TENANT_ADMIN`.
- **GAP-005 (Global Traversal Budgets):** `RESOLVED & VERIFIED`. `backend/app/memory/traversal.py` enforces global visited node limits (`MAX_PROVENANCE_NODES = 50`), edge limits (`MAX_PROVENANCE_EDGES = 200`), and depth (`MAX_PROVENANCE_DEPTH = 5`). Exhaustion returns explicit incomplete-analysis flags.
- **GAP-006 (Fail-Closed Production Redis Check):** `RESOLVED & VERIFIED`. In `backend/app/main.py` lines 234–259, `lifespan` verifies `APP_ENV == "production"` requires a non-in-memory Redis rate limiter and executes an active `ping()` check, raising `RuntimeError` if unreachable.
- **GAP-007 (Token Revocation & Invalidation):** `RESOLVED & VERIFIED`. `backend/app/core/security.py` issues unique `jti` identifiers, and `revoke_token` writes to `app.state.revocation_store`. Decoded tokens are checked against the revocation store on every authenticated request.
- **GAP-008 (Cross-Tenant Isolation & Transaction Boundaries):** `RESOLVED & VERIFIED`. Alembic migration 0002 added composite foreign keys `(tenant_id, id)` across all child tables. All repositories enforce atomic commit/rollback.
- **GAP-009 (Sensitive Data Redaction):** `RESOLVED & VERIFIED`. In `backend/app/api/traces.py`, `redact_sensitive_dict` scrubs credentials, bearer tokens, private keys, connection strings, and financial identifiers up to depth 5.
- **GAP-010 (Exception Scrubbing):** `RESOLVED & VERIFIED`. `backend/app/core/exceptions.py` installs global exception handlers that scrub stack traces, internal database error strings, and memory payloads before returning standardized JSON error envelopes.
- **GAP-011 (OpenAPI 3.1 Error Envelopes):** `RESOLVED & VERIFIED`. All 14 API routers register standardized `API_ERROR_RESPONSES` in `backend/app/main.py`.

### 5.2 Status of DOC-008 OPEN Items (OPEN-01 – OPEN-09)

| ID | DOC-008 Description | Status on `4be755c` | Code Evidence & Technical Analysis |
|---|---|---|---|
| **OPEN-01** | `create_app` never creates `db_session_factory`; all persistence services return 503 in production. | **RESOLVED IN LIFESPAN, NOT IN FACTORY** | `backend/app/main.py` lines 162–188 initializes `app.state.db_session_factory` inside the async `lifespan` context manager when `DATABASE_URL` is configured. However, calling `create_app()` synchronously does not create the session factory until the ASGI server triggers startup. In production, startup fails closed if the database is unreachable. |
| **OPEN-02** | No durable trust-decision store; M4 refuses in-memory store outside dev/test. | **CRITICAL AUDIT FINDING: PSEUDO-PERSISTENT** | `backend/app/recovery/store.py` line 207 defines `SqlTrustDecisionStore` with attribute `is_persistent = True`. However, inspection of lines 212–222 reveals it stores decisions in `self._by_record: Dict[Tuple[str, str], List[TrustDecision]] = {}`. **It is an in-memory dictionary disguised as a SQL store to bypass the production guard!** No SQL table exists for trust decisions. |
| **OPEN-03** | Agent registry has only `InMemoryAgentRepository`; tool permissions have no writer. | **PARTIALLY RESOLVED** | `backend/app/database/repositories/agents.py` implements `SqlAlchemyAgentRepository` with `create_agent_atomic`, `get_agent_by_id`, `list_agents`, and `get_agent_tool_permissions`. However, **there is still no writer or API endpoint to grant tool permissions**. Tool permissions can only be populated via database seed scripts. |
| **OPEN-04** | ChroniMem contract mismatch: backend `GET /chronimem/timeline?agent_id=` vs frontend `GET /chronimem/timeline?record_id=`. | **STILL OPEN** | `backend/app/api/chronimem.py` lines 33–47 defines `api_get_timeline` filtering by `agent_id` and returning `List[TimelineEvent]`. In contrast, `frontend/src/services/apiClient.ts` line 727 calls `/chronimem/timeline?record_id=${recordId}` and expects `Promise<ChroniMemRecordTimeline>`. The call fails and falls back to `fixtures.ts`. |
| **OPEN-05** | PostgreSQL RLS and restricted app role designed (M6 Day 6) but not enabled. | **STILL OPEN / RE-CLASSIFIED** | Alembic migration `0010_restricted_app_role.py` and `backend/app/database/roles.py` create a restricted `amsc_app` LOGIN role with least-privilege DML permissions. However, empirical inspection confirms **there is zero Row-Level Security (RLS) DDL (`ENABLE ROW LEVEL SECURITY`, `CREATE POLICY`) in migration 0010 or anywhere in the schema**. Tenant isolation is currently enforced solely via application query filters and composite foreign keys `(tenant_id, id)` from migration 0002. True PostgreSQL RLS remains completely missing. |
| **OPEN-06** | Recovery ports missing checkpoint reader, plan store, external action reader (routes return 503). | **RESOLVED IN-MEMORY, PARTIAL IN SQL** | Commit `4be755c` and `backend/app/recovery/store.py` implemented `SqlCheckpointReader`, `SqlRecoveryPlanStore`, `SqlExternalActionReader`, and `create_in_memory_recovery_service`. 60 tests pass in `backend/tests/security/test_recovery.py`. Live PostgreSQL recovery execution remains unverified in CI. |
| **OPEN-07** | No proposal controller/runtime exists; M1 gateway is only proposal path. | **ARCHITECTURALLY RESOLVED** | Verified: The M1/M2 gateway (`POST /api/v1/gateway/actions/propose`) is the intentional, canonical, framework-neutral Policy Enforcement Point. No competing runtime should exist. |
| **OPEN-08** | `src/chronocongisec/security/{gateway,audit}.py` duplicates gateway logic; not imported by backend. | **STILL OPEN (DEAD CODE)** | `src/chronocongisec/` remains in the tree as a disconnected prototype from PR #21. It is not referenced anywhere in `backend/app/` or `crewai_service/`. |
| **OPEN-09** | Local verification used Python 3.14; CI/Docker use 3.12. | **STILL OPEN** | Host machine runs Python 3.14.10; CI runs Python 3.12. Compatibility risk exists for typing and deprecations. |

---

## 6. Disconnected Modules & Duplicate Implementations

1. **Standalone Research Package (`src/chronocongisec/`):**
   - Files: `src/chronocongisec/security/gateway.py`, `src/chronocongisec/security/audit.py`.
   - Issue: Implements a parallel `ToolGovernanceGateway` and `AuditSink` protocol with dataclasses (`AgentPrincipal`, `ToolProposal`, `ToolSpec`).
   - Impact: Causes confusion about where gateway logic lives. The real, active gateway is `backend/app/api/gateway.py`. `src/` is dead code and should be formally retired or marked as legacy reference.
2. **Gateway Repository Scaffolding:**
   - Directory: `backend/app/gateway/` contains only `.gitkeep`.
   - Reality: Gateway repository implementations (`InMemoryGatewayRepository` and `SqlAlchemyGatewayRepository`) are housed inside `backend/app/api/gateway.py` (lines 1200–1450).
3. **Knowledge Graph Subsystem:**
   - Directory: `backend/app/knowledge/` contains `test_knowledge_graph.py` and models, but has no live router wired in `backend/app/main.py`. The route `/api/v1/knowledge` is wired to a placeholder router that returns static graph structures.
4. **Recovery Store Split:**
   - Files: `backend/app/recovery/store.py` and `backend/app/database/rewind.py`.
   - Issue: `RewindCoordinator` in `database/rewind.py` performs atomic version rollbacks, while `RecoveryService` in `recovery/orchestrator.py` wraps it with security policies and containment. Both maintain separate in-memory test doubles.

---

## 7. Prioritized Vulnerability & Risk Register

| Risk ID | Severity | Category | Description | Source Evidence | Remediation Priority |
|---|---|---|---|---|---|
| **VULN-001** | **P0 Critical** | Persistence / Integrity | `SqlTrustDecisionStore` masquerades as persistent (`is_persistent = True`) but stores decisions in an in-memory dictionary. Any container restart wipes all historical trust decisions. | `backend/app/recovery/store.py` lines 207–224. | **Phase 1 Priority 1:** Create `trust_decisions` PostgreSQL table and true SQLAlchemy repository. |
| **VULN-002** | **P1 High** | Dependency / Operability | Production startup strictly mandates Redis rate limiter ping, but `redis` is absent from `backend/requirements.txt`. | `backend/requirements.txt`, `backend/app/main.py` line 248. | **Phase 1 Priority 2:** Add `redis>=5.0.0` to backend requirements. |
| **VULN-003** | **P1 High** | Governance / Authorization | No API endpoint exists to grant or modify agent tool permissions. All runtime tool authorization relies on initial database seeds. | `backend/app/api/agents.py`, `backend/app/database/repositories/agents.py`. | **Phase 1 Priority 3:** Add audited `POST /api/v1/agents/{id}/permissions` endpoint. |
| **VULN-004** | **P2 Medium** | Integration / Usability | Frontend ChroniMem timeline query uses `record_id` parameter, while backend router expects `agent_id`. Frontend permanently renders static mock fixtures. | `frontend/src/services/apiClient.ts` line 727, `backend/app/api/chronimem.py` line 34. | **Phase 1 Priority 4:** Align ChroniMem route to accept optional `record_id` or `agent_id`. |
| **VULN-005** | **P2 Medium** | Recoverability / External State | Recovery engine restores database records to prior checkpoints, but cannot reverse or compensate for external tool side effects (e.g. transfers, external API mutations). | `backend/app/recovery/orchestrator.py` lines 77–81, `backend/app/api/gateway.py`. | **Phase 4:** Implement external action journal and compensating action dispatchers. |
| **VULN-006** | **P3 Low** | Maintainability / Tech Debt | `src/chronocongisec/` duplicates gateway/audit logic without being wired into the application. | `src/chronocongisec/security/gateway.py`. | **Phase 1:** Deprecate or remove unused package. |

---

## 8. Verified Test Execution Evidence

All test executions were run directly against the working tree on branch `feat/m2-agent-runtime-gateway-adapters` @ `4be755c`:

1. **Gateway Adapters & Complete Mediation Suite:**
   - Command: `pytest backend/tests/unit/test_m2_gateway_adapters.py backend/tests/unit/test_gateway.py`
   - Result: **44 passed in 24.26s** (100% pass rate)
   - Verified: Strict Pydantic parameter limits, NaN/Infinity rejection, W3C `traceparent` propagation, fail-closed policy enforcement, parameter ceiling violations, quarantined memory blocking.
2. **Recovery Orchestration Suite:**
   - Command: `pytest backend/tests/security/test_recovery.py`
   - Result: **60 passed in 1.42s** (100% pass rate)
   - Verified: Checkpoint integrity hashing, plan compare-and-set, mandatory pre-recovery containment, version rollback (appending new version), post-condition verification.
3. **Dual Trace Telemetry Suite:**
   - Command: `pytest backend/tests/unit/test_traces.py`
   - Result: **28 passed in 29.85s** (100% pass rate)
   - Verified: Trace retrieval, redaction of secrets/PII, W3C trace ID formatting, dual-lane output formatting (`execution_lane`, `memory_lane`), completeness breakdown.
4. **CrewAI Business Agent Simulation Suite:**
   - Command: `pytest crewai_service/tests`
   - Result: **56 passed in 5.54s** (100% pass rate)
   - Verified: Finance, HR, Support, and Branch agent proposal generation, complete mediation via AMSC Client, test double mode.
5. **Frontend Workstation Vitest Suite:**
   - Command: `npm --prefix frontend test`
   - Result: **6 test files passed, 48 tests passed in 13.91s** (100% pass rate)
   - Verified: API contract parsing, IAM login flow, accessibility attributes, error envelope handling, tenant isolation in stores.
6. **Backend Lint & Static Code Analysis:**
   - CI Configuration: `ruff check backend/` (configured in `.github/workflows/ci.yml`)
   - Local Verification Note: `ruff` is not installed in the local Windows Python environment (`No module named ruff`); in CI workflows, `ruff` is dynamically installed and passes cleanly (0 errors under `E4`, `E7`, `E9`, `F`). It is absent from `backend/requirements.txt` and should be added as a dev dependency.
7. **Database Integration & Schema Invariants Suite:**
   - Command: `pytest backend/tests/database` (585 tests)
   - Local Execution Result: **Blocked locally without Docker** (`CannotConnectNowError` / connection refused on port 5432). Tests require an active PostgreSQL 16 container with superuser credentials for dynamic role creation; unit and security suites pass locally via in-memory and SQLite repository doubles.
