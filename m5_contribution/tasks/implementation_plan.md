# M5 Implementation Tasks & Deliverables

Reference: `docs/06-TEAM-IMPLEMENTATION-PLAN.md`  
Branch: `feat/m5-amsc-frontend-workstation`  
Role: Member M5 (Frontend & UX Engineering Lead)

---

### Phase A: Foundation & App Shell [COMPLETED & COMMITTED: `95d000e`]
- [x] Initialized React 19 + TypeScript + Vite + Tailwind CSS 3.4.19.
- [x] Configured PostCSS, Autoprefixer, and design tokens in `index.css` (Dark theme, `#0B0F19`, JetBrains Mono for hashes/UUIDs).
- [x] Built `AppShell` component:
  - Collapsible technical sidebar with all 11 screen routes.
  - Active tenant dropdown switcher (AlphaCorp, BetaShield, GammaAI).
  - DUAL-MODE API status badge (Live Backend vs. Contract Fallback).
  - Top-bar "Simulate Attack Replay" button with 4-stage kill-chain scrubber modal.
  - `Ctrl+K` / `Cmd+K` Forensic Command Palette with screen navigation, simulation triggers, and tenant switching.
  - Global sliding `InspectorDrawer` for deep inspection of records, agents, decisions, incidents, and spans.
- [x] Built hybrid 2D/3D visualization framework:
  - 2D DAG View using `@xyflow/react`.
  - 3D Force-Directed Blast-Radius View using `react-force-graph-3d` and `three` (lazy-loaded inside `ForensicErrorBoundary` with WebGL detection).
  - `HybridGraphViewer` component.
- [x] Configured code-based routing in `src/router.tsx` for all 11 screens.

---

### Phase B: Data Layer & API Resilience [COMPLETED & COMMITTED: `b2c81ad`]
- [x] Read schema contracts in `docs/05-DATABASE-API-SCHEMA.md` and `backend/app/api/`.
- [x] Authored strict TypeScript interfaces in `frontend/src/types/` matching FastAPI Pydantic models field-for-field.
- [x] Created `src/services/fixtures.ts` with tenant-isolated data sets for AlphaCorp, BetaShield, and GammaAI.
- [x] Built resilient `src/services/apiClient.ts`:
  - Network-first architecture with 2500ms `AbortController` timeout.
  - Injects `Authorization: Bearer <token>`, `X-Tenant-ID`, and `X-Trace-ID`.
  - Graceful fallback on 404/502/NetworkError to Document 05 fixtures, updating `DualModeBadge` to `CONTRACT FALLBACK`.
- [x] Implemented tenant-keyed TanStack Query hooks in `src/hooks/useAmscQueries.ts`.
- [x] Configured Vite proxy for `/api` and `/health` to `http://127.0.0.1:8000`.

---

### Phase C: Core Observability (Screens 01–03) [COMPLETED & COMMITTED: `72a08ec`]
- [x] **Screen 01 (OverviewPage.tsx):**
  - 4 live KPI cards (Evaluations 24h, Verified Memories, Blocked Proposals, Quarantined Chunks).
  - Cyera-style Memory Trust Posture Donut Chart (`TRUSTED`, `SUSPICIOUS`, `QUARANTINED`, `SUPERSEDED`) with segment click routing.
  - Live Gateway Decision Stream with latency badges and clickable SHA-256 memory pills opening `InspectorDrawer`.
- [x] **Screen 02 (AgentRegistryPage.tsx):**
  - Reco AI-style Identity-to-Tool Entitlement Matrix.
  - Scoped API key prefixes, active memory count, allowed tool adapters vs. fail-closed blocked tools, search, and trust-tier filter pills.
- [x] **Screen 03 (MemoryExplorerPage.tsx):**
  - Wired to `useMemories()` and `useIngestMemoryMutation()`.
  - Ingest Memory Record modal computing canonical SHA-256 hash.
  - URL query parameter sync (`/memory?status=QUARANTINED`) and one-click `InspectorDrawer` inspection.

---

### Phase D: Security & Forensics (Screens 04–06) [COMPLETED & COMMITTED: `57a46f4`]
- [x] **Screen 04 (SecurityCenterPage.tsx):**
  - Interactive Kill-Chain Alert Triage Board across 4 stages (Ingest Poisoning, Drift Spike, Prompt Injection, Fail-Closed Gate).
  - Click-to-inspect cited memory chunk in `InspectorDrawer`.
  - One-click Emergency Quarantine (`useQuarantineMutation`) and Escalate to Rewind (`/rewind`).
- [x] **Screen 05 (DualTracePage.tsx):**
  - Dual-Track Forensic Scrubber with millisecond playhead (0ms to 1200ms).
  - Track A: Agent Execution Spans with W3C trace IDs and latency bars.
  - Track B: Retrieved Memory Chunks with SHA-256 pills and trust badges.
  - Dynamic animated SVG Bezier correlation beams connecting active spans to retrieved chunks (glowing red on tainted nodes).
- [x] **Screen 06 (ChroniMemPage.tsx):**
  - Horizontal Checkpoint Timeline Scrubber (v1 Ingest, v2 Baseline, v3 Poisoned Mutation, v4 Rewind Target).
  - Side-by-side Cryptographic JSON & SHA-256 Diff Viewer highlighting added/mutated/deleted lines in green/red against baseline authority.

---

### Phase E: Graph & Recovery (Screens 07–11) [COMPLETED & COMMITTED: `0663665`]
- [x] **Screen 07 (KnowledgeGraphPage.tsx):**
  - 2D React Flow DAG with interactive node filtering (Sources, Memories, Agents, Tools) and hop depth expansion (1 to 5).
  - 3D Force-Directed Blast-Radius WebGL view (`react-force-graph-3d` + `three`) with WebGL fallback error boundary.
  - Node selection opening `InspectorDrawer` with SHA-256 and lineage metrics.
- [x] **Screen 08 (DriftMonitorPage.tsx):**
  - Recharts AreaChart visualizer showing cosine divergence trend against the 0.35 Fail-Closed Anomaly Threshold.
  - 4 drift KPI cards (Max Divergence, Policy Threshold, Embedding Vector Space, Flagged Clusters).
  - Cluster comparison table with "Flag & Quarantine", "Accept Baseline", and lineage inspection.
- [x] **Screen 09 (AgentRewindingPage.tsx):**
  - 4-Step Blast-Radius Dependency Recovery Wizard:
    1. Checkpoint/Incident Target Selection.
    2. Blast-Radius Dependency Topology (with 2D/3D Hybrid view).
    3. SEC-007 Pre-Recovery Snapshot Verification.
    4. Atomic Rollback Execution (`useAtomicRewindMutation`) with terminal logs and post-recovery validation.
- [x] **Screen 10 (AuditCenterPage.tsx):**
  - Append-Only immutable cryptographic audit ledger (SEC-010 compliance).
  - Merkle root integrity status banner (zero tampering detected).
  - Multi-category filtering (Action, Actor, Free Search).
  - Real downloadable JSON Forensic Evidence Bundle export.
- [x] **Screen 11 (SettingsPage.tsx):**
  - Multi-tenant partitioning profile (Tenant ID, Namespace, KMS Key ARN).
  - Authoritative SEC policy toggles (SEC-001, SEC-004, SEC-005, SEC-007).
  - Enforcement ceilings & timeout sliders (Gateway timeout, hop depth, drift limit).
  - Scoped tenant API key rotation and clipboard copy.

---

### Phase F: Final Polish & Gate Verification [PASSED: Zero Errors]
- [x] Router aliases added for `/traces`, `/dual-trace`, `/knowledge-graph`, `/graph`.
- [x] TypeScript compiler check: `tsc --noEmit` passed with 0 errors.
- [x] Vite bundler check: `vite build` completed in ~9.4s with 0 errors.
- [x] Repository boundary check: 100% of functional code resides strictly in `frontend/`.
- [x] Preservation check: `frontend/owner.md` is 100% untouched.
