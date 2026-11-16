# M5 Implementation Tasks & Daily Milestones

Reference: `docs/06-TEAM-IMPLEMENTATION-PLAN.md`

---

### Phase 1 (Day 1 - Day 2): Foundation & App Shell
- [ ] Initialize React 19 + TypeScript + Vite in `frontend/`.
- [ ] Install and configure Tailwind CSS, PostCSS, and Autoprefixer.
- [ ] Set up design tokens in `index.css` (Dark theme defaults, `--bg-deep: #0B0F19`, JetBrains Mono for hashes/UUIDs).
- [ ] Build `AppShell` component:
  - Collapsible technical sidebar with navigation links for all 11 screens.
  - Top bar with active tenant dropdown switcher (Company A / B / C isolation indicator).
  - System status pill (Live WebSocket / Gateway heartbeat).
  - User avatar and role indicator (`Security Analyst`).

---

### Phase 2 (Day 3): Primary Observability Screens
- [ ] **Screen 01 (Overview Dashboard):**
  - KPI Stat Cards: Active Agents, Guarded Requests (24h), Blocked Actions, Quarantined Chunks.
  - Live Gateway Activity mini-feed (Allow / Block / Review events).
  - Quick-action shortcuts (Inspect Quarantine, Review Trace).
- [ ] **Screen 02 (Agent Registry):**
  - Dense data table of agents, UUIDs, assigned model, trust tier, status (Active / Suspended).
  - Drawer for agent details and permission policy breakdown.
- [ ] **Screen 03 (Memory Explorer):**
  - Searchable memory catalog with chunk IDs, source document names, SHA-256 hashes.
  - Integrity badge (Verified / Suspect / Quarantined).
  - Inspect drawer showing chunk text, metadata, and provenance chain.

---

### Phase 3 (Day 4 - Day 5): Security Operations & Dual Trace
- [ ] **Screen 04 (Security Center):**
  - Threat detection event stream (Prompt injection, Jailbreak attempts, Memory poisoning alerts).
  - One-click Quarantine action modal/drawer with reason input.
- [ ] **Screen 05 (Dual Trace):**
  - Forensics scrubber (Synchronized Execution Timeline & Memory Retrieval Timeline).
  - Click-to-correlate: Clicking an execution span automatically highlights the memory chunk retrieved during that span.
- [ ] **Screen 06 (ChroniMem):**
  - Temporal memory scrubber with checkpoint markers.
  - Point-in-time diff preview of memory state before and after poisoning.

---

### Phase 4 (Day 5 - Day 6): Advanced Forensics & Governance
- [ ] **Screen 07 (Knowledge Graph):**
  - React Flow interactive node-link graph showing memory sources, derived facts, and dependent agents.
- [ ] **Screen 08 (Drift Monitor):**
  - Vector similarity drift charts (Recharts) and cluster anomaly indicators.
- [ ] **Screen 09 (Agent Rewinding):**
  - Blast-radius calculation visualization (Impacted agents and decisions).
  - Safe rollback confirmation wizard.
- [ ] **Screen 10 (Audit Center):**
  - High-density immutable audit log with tenant-scoped filtering and CSV/JSON export.
- [ ] **Screen 11 (Settings & Governance):**
  - Tenant configuration, API key management, Gateway fail-closed policy toggle.

---

### Phase 5 (Day 7): Polish, Responsiveness & QA
- [ ] Verify zero console warnings/errors.
- [ ] Verify comprehensive empty states and skeleton loading states for all screens.
- [ ] End-to-end integration test with mock or live M1 API endpoints.
