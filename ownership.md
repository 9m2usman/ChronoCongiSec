
# ChronoCongisec — Team File & Folder Ownership


## 1. Purpose

This document defines ownership and editing responsibilities for all seven team members.

Each member is responsible for implementing, testing, documenting, and maintaining their assigned modules.

No member should directly modify another member's core implementation without coordination and approval.

---

## 2. Team Ownership

| Member | Role | Primary Responsibility |

| M1 | Platform Backend & API Integration | FastAPI architecture, authentication, tenant context, API contracts |
| M2 | Agent Runtime & Gateway Adapters | Agent runtime, gateway, protected tool execution |
| M3 | Knowledge & Memory | Memory ingestion, integrity, provenance, versioning, ChroniMem |
| M4 | Security Engine & Incident Response | Security policies, threat detection, trust decisions, quarantine, recovery, ML |
| M5 | Frontend & UX | React frontend, workstation, dashboards, visualization |
| M6 | Database Architect & Governance | PostgreSQL, SQLAlchemy models, Alembic, tenant isolation, audit |
| M7 | DevOps, Testing & QA | Docker, CI/CD, Celery infrastructure, testing, deployment, monitoring |

---

## 3. Root-Level Files

| File | Primary Owner | Contributors |

| README.md | M1 | All members |
| OWNERSHIP.md | M7 | All members |
| .env.example | M1 | M2, M6, M7 |
| .gitignore | M7 | All members |
| docker-compose.yml | M7 | M1, M6 |
| Makefile | M7 | All members |

Root-level infrastructure and configuration changes must be coordinated with M7.

---

## 4. Documentation Ownership

| Directory | Owner | Responsibility |

| docs/architecture/ | M1 | System architecture, components, integration |
| docs/api-contracts/ | M1 | API endpoints, request/response contracts |
| docs/database-design/ | M6 | Database schema, ERD, relationships |
| docs/security-design/ | M4 | Security policies, threat model, trust decisions |
| docs/ml-design/ | M4 | ML models, datasets, evaluation |
| docs/deployment/ | M7 | Docker, CI/CD, environment, deployment |

All members may propose documentation changes relevant to their modules.

---

## 5. Backend Ownership

### backend/app/core/ — M1

M1 owns:
- config.py
- security.py
- dependencies.py
- exceptions.py
- logging.py

Responsibilities:
- Application configuration
- Authentication foundations
- Shared dependencies
- Exception handling
- Application logging

### backend/app/api/ — Coordinated by M1

| File | Owner |

| auth.py | M1 |
| tenants.py | M1 |
| agents.py | M1 |
| gateway.py | M2 |
| memory.py | M3 |
| chronimem.py | M3 |
| security.py | M4 |
| incidents.py | M4 |
| recovery.py | M4 |
| traces.py | M1 (API contract); M2 and M3 (trace integration) |

M1 owns API routing conventions, shared dependencies, and contract consistency.

The assigned subsystem owner implements the business logic behind their routes.

### backend/app/tenancy/ — M1 + M6

| Responsibility | Owner |

| Tenant context and request handling | M1 |
| Tenant database constraints | M6 |
| Tenant-scoped repositories | M6 |
| Tenant authorization integration | M1 |
| Isolation tests | M7, with M1 and M6 |

### backend/app/gateway/ — M2

M2 owns:
- ingress.py
- runtime.py
- adapters/
- credentials.py
- execution.py
- proposal_validation.py

Responsibilities:
- Agent execution interface
- Tool proposal validation
- Protected tool adapters
- Credential isolation
- Gateway-to-security-engine integration

M2 must not bypass M4 security authorization.

### backend/app/memory/ — M3

M3 owns:
- ingestion.py
- integrity.py
- versioning.py
- provenance.py
- checkpoints.py
- retrieval.py
- lineage.py

Responsibilities:
- Memory ingestion
- Content hashing
- Memory versioning
- Provenance tracking
- Checkpoints
- Retrieval and lineage

M3 cannot independently change a memory's security trust state. Trust decisions and quarantine are controlled by M4.

### backend/app/knowledge/ — M3

M3 owns:
- sources.py
- documents.py
- embeddings.py
- indexing.py
- knowledge_graph.py

Responsibilities:
- Knowledge ingestion
- Document processing
- Embeddings
- Indexing
- Knowledge relationships

### backend/app/security/ — M4

M4 owns:
- policy_engine.py
- trust_engine.py
- threat_detection.py
- injection_detection.py
- risk_scoring.py
- quarantine.py
- authorization.py

Responsibilities:
- Security policy evaluation
- Memory trust validation
- Prompt injection detection
- Risk assessment
- Quarantine decisions
- Allow / review / block decisions

Mandatory security checks must not be bypassed by other modules.

### backend/app/recovery/ — M4

M4 owns:
- incident_analysis.py
- blast_radius.py
- rewind.py
- restore.py
- recovery_validation.py

Responsibilities:
- Incident investigation
- Blast-radius analysis
- Memory recovery
- Controlled rewind
- Recovery validation


## 6. Database Ownership

### backend/app/database/ — M6

M6 owns:
- models/
- repositories/
- session.py
- base.py
- constraints.py

Responsibilities:
- SQLAlchemy models
- Database sessions
- Repository patterns
- Tenant isolation constraints
- Database integrity

### backend/alembic/ — M6

M6 has exclusive ownership of:
- Alembic configuration
- Migration environment
- Version migrations
- Schema upgrades

Other members must submit database schema requirements to M6 rather than directly editing migrations.

---

## 7. Celery and Background Workers

### backend/app/workers/ — M7 coordinates infrastructure

| File / Module | Owner |

| celery_app.py | M7 |
| tasks/ingestion.py | M3 |
| tasks/embeddings.py | M3 |
| tasks/provenance.py | M3 |
| tasks/anomaly_detection.py | M4 |
| tasks/incident_analysis.py | M4 |
| tasks/report_generation.py | M4 |
| tasks/maintenance.py | M7 |

M7 owns:
- Celery configuration
- Redis integration
- Worker startup
- Retry policies
- Dead-letter handling
- Worker monitoring

Subsystem owners implement their own business tasks.

Security authorization for protected actions must remain synchronous and must not be deferred to a background worker.

---

## 8. Frontend Ownership — M5

M5 owns the entire frontend directory.

| Directory | Responsibility |

| frontend/src/components/ | Reusable UI components |
| frontend/src/layouts/ | Application layouts |
| frontend/src/pages/ | Main application pages |
| frontend/src/features/dashboard/ | Security dashboard |
| frontend/src/features/agents/ | Agent management |
| frontend/src/features/security/ | Security alerts and decisions |
| frontend/src/features/chronimem/ | Memory history and rewind UI |
| frontend/src/features/knowledge-graph/ | Knowledge and provenance visualization |
| frontend/src/features/dual-trace/ | Execution and memory traces |
| frontend/src/services/ | Backend API clients |
| frontend/src/hooks/ | React hooks |
| frontend/src/stores/ | Frontend state management |
| frontend/src/types/ | TypeScript types |

M5 must follow published backend API contracts.

M5 does not implement security decisions in the frontend. All authorization decisions must come from the backend.

---

## 9. Machine Learning Ownership — M4 Lead

M4 leads the ML directory.

| Directory | Owner | Responsibility |

| ml/datasets/raw/ | M4 | Raw training data |
| ml/datasets/processed/ | M4 | Processed datasets |
| ml/datasets/labels/ | M4 | Labeled security samples |
| ml/preprocessing/ | M4 | Text and feature preprocessing |
| ml/features/ | M4 | Feature engineering |
| ml/models/injection_detector/ | M4 | Injection classification |
| ml/models/anomaly_detector/ | M4 | Anomaly detection |
| ml/models/memory_trust/ | M4 | Memory risk/trust scoring |
| ml/models/embedding/ | M3 + M4 | Embedding model and memory integration |
| ml/training/ | M4 | Model training |
| ml/evaluation/ | M4 | Model evaluation |
| ml/inference/ | M4 | Model inference |
| ml/model_registry/ | M4 | Model versions and registry |

M4 owns model selection, training, evaluation, and security integration.

M3 coordinates embedding requirements with M4.

ML output is a security signal, not an independent authorization decision. Mandatory deterministic controls remain authoritative.

---

## 10. Infrastructure and Testing — M7

M7 owns:
- infrastructure/docker/
- infrastructure/scripts/
- infrastructure/monitoring/
- infrastructure/ci-cd/
- backend/tests/ (test infrastructure and coordination)
- CI workflows
- Docker configuration

All members must write unit tests for their own modules.

| Test Area | Primary Contributor |

| Authentication and API | M1 |
| Gateway and tool execution | M2 |
| Memory and provenance | M3 |
| Security and recovery | M4 |
| Frontend components | M5 |
| Database and tenant isolation | M6 |
| Integration, deployment and CI | M7 |

M7 coordinates test execution, integration testing, coverage, and release validation.

---

## 11. Shared Directory Ownership

| Directory | Coordinator | Contributors |

| shared/schemas/ | M1 | M2, M3, M4, M6 |
| shared/enums/ | M1 | M2, M3, M4, M6 |
| shared/events/ | M1 | M2, M3, M4, M6 |

Changes to shared contracts require approval from affected subsystem owners.

---

## 12. Demo Ownership

| Directory | Owner |

| demo/poisoned_memory/ | M3 + M4 |
| demo/blocked_action/ | M2 + M4 |
| demo/recovery/ | M3 + M4 |

M7 coordinates demo environment and execution.

---

## 13. Branch and Pull Request Rules

Each member must work on their assigned branch:

| Member | Branch |

| M1 | feat/m1-platform-auth |
| M2 | feat/m2-gateway-adapters |
| M3 | feat/m3-memory-provenance |
| M4 | feat/m4-security-ml |
| M5 | feat/m5-workstation-ui |
| M6 | feat/m6-schema-governance |
| M7 | feat/m7-devops-test-harness |

Rules:
1. No direct commits to main.
2. All changes must be submitted through Pull Requests.
3. Each PR must have a clear description.
4. The responsible module owner must review changes.
5. Shared contracts require approval from affected members.
6. M6 must approve all database migrations.
7. M4 must approve changes to mandatory security decision logic.
8. M7 must approve infrastructure and deployment changes.
9. All PRs must pass required tests and CI checks before merging.

---

## 14. Cross-Member Editing Rules

Members may read any project file.

Members may modify their own assigned modules.

Members may propose changes to another member's module, but must coordinate with its owner before merging.

The following boundaries are mandatory:

- M1 owns platform architecture and API conventions.
- M2 cannot bypass the security gateway.
- M3 cannot independently override trust decisions.
- M4 owns security authorization and quarantine.
- M5 cannot make frontend-only authorization decisions.
- M6 exclusively manages database migrations.
- M7 manages deployment and test infrastructure.


---

## 11. Simulated Company Integration Ownership Addendum

The implementation scope, cross-member handoffs and detailed prompts are defined in [docs/09-SIMULATED-COMPANY-INTEGRATION-PLAN.md](docs/09-SIMULATED-COMPANY-INTEGRATION-PLAN.md). That document supplements this ownership map; it does not transfer core ownership.

- **M1:** company/branch request context, authz integration, shared API/OpenAPI and event contracts.
- **M2:** existing runtime, proposal/Gateway and protected adapters remain M2-owned. No new M2 task is assigned by this addendum.
- **M3:** synthetic company knowledge pack, ingestion, branch-aware trusted retrieval, provenance and lineage using existing memory services.
- **M4:** existing policy/trust engine governs company/branch/agent actions and demo threat scenarios.
- **M5:** integrate actual backend data into the existing 11-screen React 19/TypeScript/Vite/Tailwind workstation; preserve current component system and visual language.
- **M6:** minimum required schema/repository/migration support for company/branch-scoped demo data and durable evidence.
- **M7:** deterministic safe seed/reset, local orchestration, demo runner and end-to-end/security verification.

**Boundary:** no member may create a parallel runtime, memory store, policy engine, database schema, event store or frontend. Cross-owner changes require the owning member's review. The product demo is one fictional company with multiple branches; multiple tenants are retained for isolation testing, not as separate demo branches.
