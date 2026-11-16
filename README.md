# Agent Memory Security Center (AMSC)
### Enterprise AI-Agent Memory Security, Governance, Observability & Recovery Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Architecture: High-Assurance Gateway](https://img.shields.io/badge/Architecture-High--Assurance_Gateway-06B6D4.svg)](#)
[![Stage: Documentation & Architecture Preparation](https://img.shields.io/badge/Stage-Documentation_Baseline-amber.svg)](#)

---

## 1. Executive Overview

**Agent Memory Security Center (AMSC)** is an authoritative, multi-tenant security, governance, and recovery platform for autonomous AI agent ecosystems.

In modern enterprise architectures, AI agents autonomously ingest persistent knowledge, synthesize state across operational sessions, and invoke external tool adapters with substantial financial, infrastructure, and data-handling impact. Current industry architectures suffer from a critical structural flaw: **an absolute disconnection between memory integrity and action authorization**.

Existing tool sandboxes evaluate whether an agent has permission to call an API based solely on static credentials or identity, completely blind to whether the memory that prompted the request has been poisoned, spoofed, or drifted. Conversely, traditional vector stores focus exclusively on semantic similarity and retrieval recall, lacking cryptographic source provenance, temporal version checkpoints, quarantine enforcement, or blast-radius dependency tracking.

AMSC bridges this gap by enforcing complete mediation over agent actions and continuous cryptographic verification over agent memory.

---

## 2. Core Problem Solved

AMSC answers five foundational operational questions for every agent interaction:
1. **Can this agent trust the memory or knowledge it is using?**
2. **Can this agent perform the action it is requesting?**
3. **Where did this information come from, and how has it changed over time?**
4. **What other memories, decisions, agents, or downstream actions are contaminated?**
5. **What can safely be quarantined, restored, reversed, or escalated to a human operator?**

---

## 3. Current Project Stage: Clean Documentation Baseline

> [!IMPORTANT]
 > **Current Project Status: Backend foundation and security architecture implementation in progress.**
> The repository contains backend authentication/tenant-context work and memory/provenance services alongside the approved product and technical specifications. The complete seven-member end-to-end product is not yet verified as finished; implementation status must be judged from merged code, tests and integration evidence rather than documentation labels alone.

The documentation is the architecture and requirements baseline. Backend, frontend, database and infrastructure capabilities are delivered incrementally under the M1–M7 ownership plan.

---

## 4. Authoritative Documentation Suite

The complete engineering specification is published in the `docs/` directory. All team members must review the documents in the specified reading order:

| Reading Order | Document Title | File Path | Core Purpose |
|---|---|---|---|
| **01** | **Product Requirements Document (PRD)** | [docs/01-PRD.md](docs/01-PRD.md) | Defines **WHAT** the product must do and **WHY** it is needed. Covers problem statement, personas, functional requirements (`FR-001`..`FR-027`), non-functional requirements, security requirements, and demonstration scenarios. |
| **02** | **Combined TRD & SRS** | [docs/02-TRD-SRS.md](docs/02-TRD-SRS.md) | Defines **HOW** the system is technically structured and **WHAT** technical behavior is required. Details system topology, fail-closed protocols, memory trust models, version freezing, and testing strategy. |
| **03** | **Application Flow & System Workflows** | [docs/03-APPLICATION-FLOW.md](docs/03-APPLICATION-FLOW.md) | Defines **HOW** users and data move through the system. Contains Mermaid state and sequence diagrams for memory ingestion, gateway mediation, quarantine, Dual Trace, and agent rewinding. |
| **04** | **UI/UX Design & Screen Specifications** | [docs/04-UI-UX-DESIGN.md](docs/04-UI-UX-DESIGN.md) | Defines the **WORKSTATION INTERFACE**. Contains complete specifications for all 11 core screens, layout shell, color tokens, contextual inspector drawer, and accessibility rules. |
| **05** | **Backend Database Schema & API Contract** | [docs/05-DATABASE-API-SCHEMA.md](docs/05-DATABASE-API-SCHEMA.md) | Canonical **ENGINEERING CONTRACT**. Defines relational DDL for all 32+ entities, ER diagram, multi-tenant isolation rules, complete REST API route inventory (`/api/v1`), and error envelopes. |
| **06** | **Seven-Person, Seven-Day Implementation Plan** | [docs/06-TEAM-IMPLEMENTATION-PLAN.md](docs/06-TEAM-IMPLEMENTATION-PLAN.md) | Defines the **DEVELOPMENT PLAN**. Assigns exact ownership boundaries (M1-M7), day-by-day deliverables, integration gates (G1-G7), and risk mitigation protocols for future implementation. |
| **07** | **Research-Backed Agent Memory Security & Engineering Standard** | [docs/07-RESEARCH-AND-ENGINEERING-STANDARDS.md](docs/07-RESEARCH-AND-ENGINEERING-STANDARDS.md) | Research foundations, inherited strengths from KnowledgeLine and AgentGuard, non-regression rules, memory poisoning/hallucination/rewind/tool-security research, evaluation methodology and team-wide engineering requirements. |

For full reference to the master prompt that governed this specification, see [MASTER-PROMPT.md](MASTER-PROMPT.md).

---

## 5. UI/UX Design Direction: Technical Security Workstation

AMSC implements a **hybrid technical security operations workstation** engineered for AI developers, researchers, and security analysts:
- **Structural Foundation:** Inspired by the modular component patterns and clean collapsible layouts of `ropean/shadcn-admin-template`.
- **Forensic Interaction Foundation:** Inspired by the synchronized dual-timeline scrubbers and contextual inspector drawers of `as32608/openinspector`.
- **Identity & Density:** Custom AMSC visual identity characterized by dense technical dark navy surfaces (`#0B0F19`, `#111827`), monospace identifier styling, electric blue accents (`#3B82F6`), and unmistakable security status signifiers (Emerald Trusted, Amber Suspicious, Crimson Quarantined).

### Locked Navigation Hierarchy
- **Workspace:** Overview (`/overview`), Agent Registry (`/agents`)
- **Memory:** Memory Explorer (`/memory`), ChroniMem (`/chronimem`), Knowledge Graph (`/knowledge-graph`)
- **Security:** Security Center (`/security`), Dual Trace (`/traces`), Drift Monitor (`/drift`)
- **Recovery:** Agent Rewinding (`/rewind`)
- **Governance:** Audit Center (`/audit`)
- **Administration:** Settings & Governance (`/settings`)

---

## 6. High-Level Technology Architecture

```text
[React 19 / TypeScript / Vite / Tailwind CSS / shadcn/ui]
                     |
                     | HTTPS / JSON (JWT / Scoped API Key)
                     v
  [FastAPI Asynchronous Gateway & Ingress Layer]
   - Tenancy Middleware (Header/JWT Validation)
   - Idempotency & Replay Filter (Redis / DB)
   - Server-Side Policy & Trust Engine (Fail-Closed)
                     |
                     +---------------------------------------+
                     |                                       |
                     v                                       v
   [PostgreSQL 16+ System of Record]       [Server-Side Protected Adapters]
    - Memory Records & Versions (SHA-256)   - Sandbox Financial Wire Adapter
    - Provenance Edges & Lineage Graph      - Cloud Infrastructure Adapter
    - Checkpoints & Pre-Recovery Snapshots   - Proprietary Data Export Adapter
    - Append-Only Forensic Audit Events     (Credentials never sent to agents!)
```

---

## 7. Seven-Person Engineering Team Structure

During future implementation, the engineering team will operate under strict ownership boundaries:

- **M1 — Platform Backend & API Integration Lead:** FastAPI framework, authentication, tenancy middleware, OpenAPI canonical contract ownership.
- **M2 — Agent Runtime & Gateway Adapters Lead:** Agent proposal protocol, sandbox mock tool adapters, adapter credential containment.
- **M3 — Knowledge & Memory Systems Lead:** Ingestion pipelines, SHA-256 content hashing, version tree, provenance graph edge traversals, checkpoint snapshotting.
- **M4 — Security Engine & Incident Lead:** Deterministic policy rule evaluator, memory trust verification, quarantine state machine, rollback blast-radius calculator.
- **M5 — Frontend & UX Engineering Lead:** React 19, TypeScript, Tailwind, AppShell, all 11 core screens, Dual Trace timeline scrubber, React Flow knowledge graph.
- **M6 — Database Architect & Governance Lead:** PostgreSQL relational DDL, Alembic migrations, composite tenant constraints, RBAC mapping, append-only audit persistence.
- **M7 — DevOps, Testing & QA Lead:** Docker Compose orchestration, automated pytest test harness, cross-tenant isolation testing, seed fixtures, demo runner scripts.

---

## 8. One-Week (Seven-Day) MVP Target Schedule

```text
+-------+------------------------------------------------------------------------------------+
| Day   | Milestone / Gate                                                                   |
+-------+------------------------------------------------------------------------------------+
| Day 1 | Architecture, Contracts, Schema DDL & Shared Development Baseline (Gate G1)       |
| Day 2 | Foundation: Auth, Tenancy Context, DB Repositories & UI Shell (Gate G2)            |
| Day 3 | Knowledge Ingestion, Lineage, Agent Registry & Explorer (Gate G3)                  |
| Day 4 | Protected Tool Gateway & Fail-Closed Enforcement Vertical Slice (Gate G4 - P0)     |
| Day 5 | Forensics, Quarantine, ChroniMem Diffing & Rollback Engine (Gate G5)               |
| Day 6 | Observability, Dual Trace, Knowledge Graph & 3 Demos (Gate G6)                     |
| Day 7 | Hardening, Security Validation, End-to-End Test Suite & Handover (Gate G7)         |
+-------+------------------------------------------------------------------------------------+
```

---

## 9. Repository Structure

```text
ChronoCongiSec/
│
├── README.md                          # Primary overview, links, and project guidance
├── MASTER-PROMPT.md                   # Preserved master build prompt and requirements
│
└── docs/
    ├── 01-PRD.md                      # Product Requirements Document
    ├── 02-TRD-SRS.md                  # Combined TRD & SRS
    ├── 03-APPLICATION-FLOW.md         # Application Flow & System Workflows
    ├── 04-UI-UX-DESIGN.md             # UI/UX Design & Screen Specifications
    ├── 05-DATABASE-API-SCHEMA.md      # Backend Database Schema & API Contract
    ├── 06-TEAM-IMPLEMENTATION-PLAN.md # Seven-Person, Seven-Day Implementation Plan
    └── 07-RESEARCH-AND-ENGINEERING-STANDARDS.md # Research-backed security and engineering standard
```

---

## 10. License

This project documentation and architecture baseline is licensed under the [MIT License](LICENSE).
