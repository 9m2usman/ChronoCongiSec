# M5 Contribution Workspace — Frontend & UX Engineering

> **Owner:** Member M5 (Frontend & UX Engineering Lead)  
> **Target Branch:** `feat/m5-workstation-ui`  
> **Repository Target:** [ChronoCongiSec](https://github.com/9m2usman/ChronoCongiSec)  
> **Design Philosophy:** Technical Security Operations Workstation (High-signal, cryptographic signifiers, dual-trace correlation)

---

## 1. Mission & Non-Interference Guarantee

This folder (`m5_contribution`) serves as the dedicated staging and development workspace for **Member M5**. 

Per the team agreements in `ownership.md`:
1. **Isolated Ownership:** M5 exclusively owns the frontend workstation, layouts, visualization components, and all 11 screens.
2. **Zero Overlap:** Work here and in `frontend/` does not modify, disrupt, or conflict with backend (`backend/app/`), database models/migrations (`backend/alembic/`), security policies (`backend/app/security/`), ML models (`ml/`), or infrastructure/DevOps (`infrastructure/`).
3. **Contract Adherence:** M5 consumes published backend API contracts (`docs/05-DATABASE-API-SCHEMA.md`) and does not invent unofficial endpoints or implement client-side authorization decisions.

---

## 2. The 11 Screens Matrix

| # | Screen Name | Route | Description | Backend API Dependencies |
|---|-------------|-------|-------------|--------------------------|
| **01** | **Overview Dashboard** | `/` or `/overview` | System health, active agents, quarantined memories, gateway throughput | `GET /api/v1/overview/stats`, `GET /api/v1/gateway/activity` |
| **02** | **Agent Registry** | `/agents` | Agent lifecycle, assigned trust tiers, permissions, execution history | `GET /api/v1/agents`, `POST /api/v1/agents` |
| **03** | **Memory Explorer** | `/memory` | Ingested memory chunks, SHA-256 hashes, source provenance, trust status | `GET /api/v1/memory/chunks`, `GET /api/v1/memory/{id}` |
| **04** | **Security Center** | `/security` | Real-time threat detection, quarantine drawer, prompt injection alerts | `GET /api/v1/security/alerts`, `POST /api/v1/security/quarantine` |
| **05** | **Dual Trace** | `/traces` | Paired execution & memory scrubber (Agent activity ↔ Memory retrieval) | `GET /api/v1/traces/{trace_id}`, `GET /api/v1/traces/dual` |
| **06** | **ChroniMem** | `/chronimem` | Temporal memory rollback, timeline slider, checkpoint restoration | `GET /api/v1/chronimem/timeline`, `POST /api/v1/chronimem/rewind` |
| **07** | **Knowledge Graph** | `/knowledge-graph` | React Flow visualization of entity relationships, source lineage | `GET /api/v1/knowledge/graph` |
| **08** | **Drift Monitor** | `/drift` | Semantic memory drift, cosine similarity divergence, anomalies | `GET /api/v1/memory/drift` |
| **09** | **Agent Rewinding** | `/rewind` | Blast radius analysis, selective state rollback preview & execution | `POST /api/v1/recovery/blast-radius`, `POST /api/v1/recovery/rollback` |
| **10** | **Audit Center** | `/audit` | Immutable audit log, exportable compliance reports (SOC2/ISO27001) | `GET /api/v1/audit/logs`, `GET /api/v1/audit/export` |
| **11** | **Settings & Governance** | `/settings` | Tenant configuration, RBAC, API keys, gateway policy toggles | `GET /api/v1/tenants/settings`, `PUT /api/v1/tenants/settings` |

---

## 3. Technology Stack & Design System

### Core Libraries
- **Framework:** React 19 + TypeScript (Vite)
- **Styling:** Tailwind CSS + Radix UI / shadcn/ui primitives
- **Routing:** TanStack Router (or React Router v7)
- **Data Fetching & Cache:** TanStack Query (React Query v5)
- **State Management:** Zustand (lightweight client state: active tenant, active trace selection)
- **Graph Visualization:** `@xyflow/react` (React Flow)
- **Forensic Charts:** Recharts
- **Forms & Validation:** React Hook Form + Zod

### Design Tokens (`docs/04-UI-UX-DESIGN.md`)
```css
/* Dark Technical Canvas (Default) */
--bg-deep:        #0B0F19; /* Canvas */
--bg-surface:     #111827; /* Cards & Data grids */
--bg-muted:       #1F2937; /* Headers & Sub-panels */
--border-subtle:  #374151; /* Dividers */
--border-strong:  #4B5563; /* Active borders */

/* Status Tokens */
--status-trusted:     #10B981; /* Emerald: Trusted / Allowed */
--status-warning:     #F59E0B; /* Amber: Suspicious / Drift / Review */
--status-danger:      #EF4444; /* Crimson: Quarantined / Blocked / Threat */
--status-unverified:  #6B7280; /* Slate: Ingested / Pending */
--status-superseded:  #8B5CF6; /* Violet: Restored / Archived */
```

---

## 4. Workstation Directory Layout
All production code developed by M5 lives in `/frontend`, mirrored here for task planning:

```text
frontend/
├── src/
│   ├── components/      # Reusable UI primitives (buttons, badges, modals, drawers)
│   ├── layouts/         # AppShell (collapsible sidebar, tenant dropdown, breadcrumb)
│   ├── pages/           # 11 Screen root route views
│   ├── features/        # High-cohesion domain modules
│   │   ├── dashboard/       # Screen 01: Overview metrics & summary cards
│   │   ├── agents/          # Screen 02: Agent table, trust badges, permissions
│   │   ├── memory/          # Screen 03: Chunk inspector, cryptographic hash displays
│   │   ├── security/        # Screen 04: Alert feeds, quarantine trigger drawer
│   │   ├── dual-trace/      # Screen 05: Synchronized dual-timeline scrubber
│   │   ├── chronimem/       # Screen 06: Temporal memory rewind slider & checkpoints
│   │   ├── knowledge-graph/ # Screen 07: Interactive lineage node graph (React Flow)
│   │   ├── drift/           # Screen 08: Cosine drift charts & distribution
│   │   ├── rewind/          # Screen 09: Blast radius diagram & preview diff
│   │   ├── audit/           # Screen 10: Immutable ledger & filtering
│   │   └── settings/        # Screen 11: Multi-tenant controls & policy toggles
│   ├── services/        # Type-safe Axios/Fetch API clients mapped to backend routes
│   ├── stores/          # Zustand slices (auth tenant context, selected timeline span)
│   ├── hooks/           # Custom React hooks (polling, WebSocket activity, shortcuts)
│   └── types/           # Shared TypeScript interfaces & API response schemas
```

---

## 5. Development Workflow & Git Discipline

1. **Branch:** Always commit to `feat/m5-workstation-ui`.
2. **Never Commit Directly to `main`:** Open a PR targeting `main` when milestones are met.
3. **No Cross-Module Mutation:** Do not edit files outside `frontend/` and `m5_contribution/`.
