# Agent Memory Security Center (AMSC)
## Document 04: UI/UX Design System & Screen Specifications

**Document Identifier:** `AMSC-DOC-004`  
**Version:** 1.0.0  
**Status:** Approved Design Baseline  
**Design Direction:** Hybrid Technical Security Workstation  
**Author:** Lead UI/UX Architect & Frontend Engineering Council  
**Repository Target:** https://github.com/9m2usman/ChronoCongiSec

---

## 1. Design Direction & Core Philosophy

The Agent Memory Security Center (AMSC) user interface is engineered as an authoritative **technical security operations workstation**. It rejects generic SaaS marketing aesthetics, oversized cards, and decorative gradients in favor of high-signal information density, compact data grids, clear cryptographic status signifiers, and deep forensic correlation tooling.

### 1.1 Architectural Foundations
- **Structural Foundation:** Inspired by the modular component patterns and clean collapsible layouts of `ropean/shadcn-admin-template`.
- **Forensic Interaction Foundation:** Inspired by the synchronized dual-timeline scrubbers and contextual inspector drawers of `as32608/openinspector`.
- **Identity & Aesthetics:** Custom AMSC technical visual system characterized by dark navy/charcoal surfaces, monospace identifier styling, electric blue accenting, and unambiguous status semantics.

---

## 2. Design Tokens & Visual Hierarchy

### 2.1 Color Palette
```text
Dark Theme Surfaces (Default):
  --bg-deep:        #0B0F19 (Dense technical canvas)
  --bg-surface:     #111827 (Card, panel, and table background)
  --bg-muted:       #1F2937 (Headers, sub-panels, secondary containers)
  --border-subtle:  #374151 (Table row dividers, panel borders)
  --border-strong:  #4B5563 (Active input borders, selected card borders)

Light Theme Surfaces (High-Contrast Alternative):
  --bg-deep:        #F9FAFB (Clean neutral background)
  --bg-surface:     #FFFFFF (Card and table canvas)
  --bg-muted:       #F3F4F6 (Secondary containers)
  --border-subtle:  #E5E7EB (Dividers)

Brand & Interactive Accents:
  --accent-blue:    #3B82F6 (Primary action buttons, active navigation)
  --accent-cyan:    #06B6D4 (Interactive graph nodes, trace scrubber)
  --accent-purple:  #8B5CF6 (ChroniMem milestones, rollback markers)

Semantic Status & Security Tokens:
  --status-trusted:     #10B981 (Emerald Green: Trusted, Allowed, Healthy)
  --status-warning:     #F59E0B (Amber: Suspicious, Drift Detected, Approval Required)
  --status-danger:      #EF4444 (Crimson Red: Quarantined, Blocked, Critical Incident)
  --status-unverified:  #6B7280 (Slate Grey: Newly Ingested, Inactive)
  --status-superseded:  #8B5CF6 (Violet: Archived Version, Restored State)
```

### 2.2 Typography
- **Primary Interface Font:** `Inter`, system-ui, sans-serif (Optimized for rapid legibility).
- **Technical & Monospace Font:** `JetBrains Mono`, `Fira Code`, monospace (Mandatory for all UUIDs, SHA-256 hashes, timestamps, JSON payloads, and W3C trace identifiers).
- **Type Scale:**
  - `Display / Page Title`: 24px (1.5rem), semi-bold, letter-spacing -0.02em
  - `Section Header`: 14px (0.875rem), uppercase, font-bold, tracking-wider, text-slate-400
  - `Standard Table Cell`: 13px (0.8125rem), regular, text-slate-200
  - `Code / Hash / Trace`: 12px (0.75rem), font-mono, text-slate-300

---

## 3. Global Application Shell

```
+-------------------------------------------------------------------------------------------------------------+
| [AMSC Logo] | Workspace: [AlphaCorp (Company A) v] | [Global Search (Ctrl+K)] | [Health: NORMAL] | [Sarah (SecOps)] |
+-------------------------------------------------------------------------------------------------------------+
| [Left Sidebar]     | [Main Content Viewport Area]                                    | [Inspector Drawer]   |
|                    | Breadcrumb: Workspace / Memory / Memory Explorer                | (Contextual Details) |
| WORKSPACE          | +-------------------------------------------------------------+ |                      |
| - Overview         | | Search: [                      ] | Trust: [All v] | [Export] | | Record ID:           |
| - Agent Registry   | +-------------------------------------------------------------+ | rec-8812-441a        |
|                    | | Record ID    | Trust State | Content Preview  | Version | Age | |                      |
| MEMORY             | |--------------|-------------|------------------|---------|-----| | SHA-256:             |
| - Memory Explorer  | | rec-8812...  | QUARANTINED | URGENT OVERRIDE: | v2      | 2m  | | 7f83b1657ff1...      |
| - ChroniMem        | | rec-1044...  | TRUSTED     | Official Policy: | v1      | 1d  | |                      |
| - Knowledge Graph  | | rec-9912...  | TRUSTED     | Standard vendor  | v1      | 3d  | | Lineage:             |
|                    | +-------------------------------------------------------------+ | Parent: src-001      |
| SECURITY           |                                                                 |                      |
| - Security Center  |                                                                 | [Quarantine]         |
| - Dual Trace       |                                                                 | [View in ChroniMem]  |
| - Drift Monitor    |                                                                 | [Preview Rewind]     |
|                    |                                                                 |                      |
| RECOVERY           |                                                                 |                      |
| - Agent Rewinding  |                                                                 |                      |
|                    |                                                                 |                      |
| GOVERNANCE         |                                                                 |                      |
| - Audit Center     |                                                                 |                      |
| - Settings & Gov.  |                                                                 |                      |
+-------------------------------------------------------------------------------------------------------------+
```

### 3.1 Locked Navigation Hierarchy
The left sidebar preserves this exact grouping:
- **Workspace**
  - Overview
  - Agent Registry
- **Memory**
  - Memory Explorer
  - ChroniMem
  - Knowledge Graph
- **Security**
  - Security Center
  - Dual Trace
  - Drift Monitor
- **Recovery**
  - Agent Rewinding
- **Governance**
  - Audit Center
- **Administration**
  - Settings & Governance

---

## 4. Screen-by-Screen Detailed Specifications

---

### Screen 01: Overview Dashboard (`/` or `/overview`)

1. **Purpose:** Provide an instant, high-signal situational awareness view of the current tenant's agent activity, memory integrity posture, live security decisions, and open incidents.
2. **Intended Users:** Security Analysts, AI Platform Engineers, Organization Administrators.
3. **Main Layout:** 4-column KPI metric card grid along the top; split 2/3 and 1/3 viewport below containing Live Gateway Stream and System Health/Quarantine Summary.
4. **Components:** MetricCards, LiveGatewayFeed, IncidentAlertBanner, ComponentHealthGrid, QuickActionsPanel.
5. **Data Displayed:**
   - Active Agents count and online status breakdown.
   - Protected Actions: 24h total evaluated by Gateway, breakdown of `ALLOW` vs `BLOCK` vs `REQUIRES_APPROVAL`.
   - Memory Integrity: Percentage of memory records in `TRUSTED` state, total `QUARANTINED` count.
   - Active Security Incidents: Unresolved alerts grouped by severity (`CRITICAL`, `HIGH`).
   - Live Proposal Stream: Real-time table of incoming agent proposals with decision badge, tool name, and trace ID.
6. **User Actions:**
   - Click any KPI card to drill down to the corresponding screen with pre-applied filters.
   - Click any live proposal row to open its details in the Inspector Drawer.
7. **Navigation Behavior:** Clicking an alert jumps directly to Security Center with the incident selected.
8. **API Dependencies:** `GET /api/v1/security/alerts`, `GET /api/v1/gateway/actions`, `GET /api/v1/agents`, `GET /api/v1/memory`.
9. **Loading State:** Skeleton wireframe cards with animated shimmer effect.
10. **Empty State:** "No agent activity recorded in the selected time range. Ingest knowledge or register agents to begin."
11. **Error State:** Banner: "Failed to load dashboard metrics. Retrying connection..." with retry button.
12. **Permission State:** Viewable by all authenticated roles; tenant-filtered.
13. **Responsive Behavior:** 4 metric cards collapse to 2 columns on tablet, 1 column on mobile.
14. **Related Requirements:** `FR-001`, `FR-012`, `FR-019`.
15. **Acceptance Criteria:** Loading time < 500ms; numbers reflect exact database counts for the active tenant.

---

### Screen 02: Agent Registry (`/agents`)

1. **Purpose:** Register, inspect, configure, and monitor autonomous AI agents operating within the tenant.
2. **Intended Users:** AI Platform Engineers, AI Developers, Security Analysts.
3. **Main Layout:** Header with "Register New Agent" button; filterable data table of registered agents; expandable drawer for agent configuration and permissions.
4. **Components:** AgentTable, RegisterAgentModal, ToolPermissionEditor, AgentStatusBadge, SystemPromptViewer.
5. **Data Displayed:**
   - Agent Name, ID, Runtime Framework (`LANGCHAIN`, `CREWAI`, `AUTOGEN`), Model (`gpt-4o`, `claude-3-5-sonnet`).
   - Operational Status (`ACTIVE`, `ISOLATED`, `DEPRECATED`).
   - Configuration Version (`v1.0.0`), System Prompt snippet.
   - Assigned Tool Adapters count and operational limits (e.g., `sandbox_transfer: max $500`).
6. **User Actions:**
   - Click "Register Agent" to input metadata and system prompt.
   - Click "Edit Permissions" to toggle tools and configure numeric parameter ceilings.
   - Click "Isolate Agent" to immediately halt tool proposals for compromised agents.
7. **Navigation Behavior:** Clicking "View Memory" opens Memory Explorer filtered by `agent_id`.
8. **API Dependencies:** `GET /api/v1/agents`, `POST /api/v1/agents`, `PUT /api/v1/agents/{id}/permissions`.
9. **Loading State:** Table skeleton with 5 placeholder rows.
10. **Empty State:** "No agents registered for this tenant. Click 'Register Agent' to add your first runtime."
11. **Error State:** Red alert banner with HTTP error code and message.
12. **Permission State:** Modifying permissions requires `TENANT_ADMIN` or `AI_DEVELOPER` role.
13. **Responsive Behavior:** Table scrolls horizontally on mobile with frozen Agent Name column.
14. **Related Requirements:** `FR-004`, `FR-005`, `FR-006`.
15. **Acceptance Criteria:** Creating an agent persists version 1; updating permissions writes an audit record.

---

### Screen 03: Memory Explorer (`/memory`)

1. **Purpose:** Provide deep forensic inspection of all ingested and derived memory records, their cryptographic content checksums, and provenance trees.
2. **Intended Users:** AI Developers, Security Analysts, Researchers.
3. **Main Layout:** Filter toolbar on top; dense data table in center; contextual Inspector Drawer on right upon row selection.
4. **Components:** MemoryTable, TrustStateBadge, FilterBar, InspectorDrawer, ContentPreviewer, ProvenanceTreeView.
5. **Data Displayed:**
   - Record ID (UUID), Agent ID, Source reference.
   - Trust State (`TRUSTED`, `UNVERIFIED`, `SUSPICIOUS`, `QUARANTINED`, `SUPERSEDED`).
   - Content preview (first 140 characters).
   - Cryptographic SHA-256 Checksum (first 8 hex characters).
   - Version number (`v1`, `v2`), Ingested and Updated timestamps.
   - Drawer details: Complete text payload, parent source document link, downstream derived children.
6. **User Actions:**
   - Filter by agent, record type, or trust state.
   - Toggle "Exclude Quarantined" to preview agent retrieval perspective.
   - Click "Quarantine Record" in Inspector Drawer to immediately isolate a poisoned record.
   - Click "Compare in ChroniMem" to view historical version diffs.
7. **Navigation Behavior:** Clicking parent or child links in Inspector navigates to that memory record.
8. **API Dependencies:** `GET /api/v1/memory`, `POST /api/v1/memory`, `POST /api/v1/memory/{id}/quarantine`.
9. **Loading State:** Table rows render pulsing skeleton cells.
10. **Empty State:** "No memory records found matching filter criteria."
11. **Error State:** "Failed to load memory records. Check network connectivity."
12. **Permission State:** Quarantining records requires `SECURITY_ANALYST` or `TENANT_ADMIN` role.
13. **Responsive Behavior:** Inspector drawer becomes full-screen modal on screens narrower than 768px.
14. **Related Requirements:** `FR-007`, `FR-008`, `FR-009`, `FR-010`, `FR-011`, `FR-018`.
15. **Acceptance Criteria:** Toggling quarantine updates state in < 100ms and excludes item from retrieval queries.

---

### Screen 04: Security Center (`/security`)

1. **Purpose:** Centralized incident response workstation for investigating threats, poisoned memory injections, blocked gateway proposals, and policy breaches.
2. **Intended Users:** Security Analysts, Incident Responders, Organization Administrators.
3. **Main Layout:** Split view: Incident Triage List on left (1/3); Active Forensic Case Workspace on right (2/3).
4. **Components:** IncidentList, CaseHeader, EvidenceViewer, ThreatClassificationBadge, ResponseActionsPanel.
5. **Data Displayed:**
   - Incident ID (`INC-001`), Title, Classification (`PROMPT_INJECTION`, `UNAUTHORIZED_TOOL`, `DATA_LEAK`).
   - Severity Indicator (`CRITICAL`, `HIGH`, `MEDIUM`).
   - Forensic Evidence JSON: Injected prompt text, source URI, triggering proposal payload, matched policy rule.
   - Affected Agent, Affected Memory Record, First Observed timestamp.
6. **User Actions:**
   - Triage alerts and update status (`OPEN`, `INVESTIGATING`, `RESOLVED`).
   - Click "Quarantine Compromised Record" to isolate associated memory.
   - Click "Open Dual Trace" to correlate execution and memory events.
   - Click "Initiate Rewind" to transition directly to the recovery workflow.
7. **Navigation Behavior:** Smooth pivot to Dual Trace or Agent Rewinding with incident context pre-loaded.
8. **API Dependencies:** `GET /api/v1/security/incidents`, `POST /api/v1/security/incidents`, `POST /api/v1/memory/{id}/quarantine`.
9. **Loading State:** Shimmering incident card placeholders.
10. **Empty State:** "All clear. Zero unresolved security incidents detected."
11. **Error State:** Error banner: "Unable to retrieve incident feed."
12. **Permission State:** Read-only for `AI_DEVELOPER`; mitigation actions restricted to `SECURITY_ANALYST`.
13. **Responsive Behavior:** On tablet/mobile, incident list and case detail stack into a master-detail push view.
14. **Related Requirements:** `FR-014`, `FR-018`, `FR-019`, `SEC-002`.
15. **Acceptance Criteria:** Quarantining an incident immediately marks the affected memory record as quarantined.

---

### Screen 05: Dual Trace (`/traces`)

1. **Purpose:** Provide synchronous, paired visualization of an agent's Execution Trace alongside its Memory Trace, correlated by a shared trace identifier.
2. **Intended Users:** Security Analysts, AI Platform Engineers, Researchers.
3. **Main Layout:** Header with Trace ID search and Scrubber Timeline; two coordinated horizontal swimlanes below:
   - **Lane 1 (Execution Lane):** Proposal -> Policy Check -> Approval -> Tool Adapter -> Execution Result.
   - **Lane 2 (Memory Lane):** Vector Retrieval -> Hash Check -> Taint Evaluation -> Trust State Update.
4. **Components:** TraceScrubber, ExecutionLane, MemoryLane, SpanCard, CorrelationLineConnector.
5. **Data Displayed:**
   - Unified `trace_id`, execution duration (ms), total spans.
   - Execution Span details: Tool name, proposed operation, parameter JSON, decision reasons, return code.
   - Memory Span details: Retrieved chunk ID, content checksum, trust state at retrieval, similarity score.
6. **User Actions:**
   - Scrub through time slider to view agent execution step-by-step.
   - Click an Execution Span: immediately highlights all memory records retrieved in that exact context.
   - Click a Memory Span: reveals the raw chunk text and source document link.
7. **Navigation Behavior:** Direct link to ChroniMem to view historical versions of any displayed memory record.
8. **API Dependencies:** `GET /api/v1/traces`, `GET /api/v1/traces/{trace_id}/dual-trace`.
9. **Loading State:** Dual animated pulse bars across both swimlanes.
10. **Empty State:** "Select a trace from the Security Center or Gateway stream to view paired correlation."
11. **Error State:** "Trace ID not found or belongs to another tenant workspace."
12. **Permission State:** Tenant-isolated; viewable by all authorized workspace roles.
13. **Responsive Behavior:** Swimlanes stack vertically on tablet; timeline allows horizontal swipe on mobile.
14. **Related Requirements:** `FR-024`, `NFR-004`.
15. **Acceptance Criteria:** Selecting an execution span highlights linked memory chunks with zero layout jitter.

---

### Screen 06: ChroniMem (`/chronimem`)

1. **Purpose:** Provide interactive temporal navigation, milestone inspection, and visual diffing across memory versions over time.
2. **Intended Users:** Security Analysts, AI Developers, Compliance Auditors.
3. **Main Layout:** Vertical temporal timeline on left; side-by-side Version Comparison Diff View on right.
4. **Components:** TemporalTimeline, MilestoneMarker, UnifiedDiffViewer, VersionSelectorDropdown.
5. **Data Displayed:**
   - Chronological revision stream for selected memory record (`v1`, `v2`, `v3`).
   - Timestamps (UTC ISO 8601), Author/Actor ID, Cryptographic SHA-256 for each version.
   - Side-by-side diff highlighting red strikethroughs for deleted words and green highlights for inserted text.
   - Associated Checkpoint markers highlighted with purple diamond badges.
6. **User Actions:**
   - Select any two versions from the dropdowns (`v_from` vs `v_to`) to generate an instant diff.
   - Inspect source transformation reason.
   - Click "Rollback to this Version" to launch Agent Rewind with this version pre-selected.
7. **Navigation Behavior:** Links back to Memory Explorer and Dual Trace.
8. **API Dependencies:** `GET /api/v1/chronimem/timeline`, `GET /api/v1/chronimem/records/{id}/compare`.
9. **Loading State:** Monospace diff viewer displays skeleton lines.
10. **Empty State:** "Select a memory record to inspect its temporal revision history."
11. **Error State:** "Version comparison failed. One of the selected versions does not exist."
12. **Permission State:** Available to all workspace members.
13. **Responsive Behavior:** Side-by-side diff collapses to unified inline diff view on smaller screens.
14. **Related Requirements:** `FR-008`, `FR-020`, `FR-025`.
15. **Acceptance Criteria:** Diff calculation completes in < 150ms; accurately flags inserted adversarial instructions.

---

### Screen 07: Knowledge Graph (`/knowledge-graph`)

1. **Purpose:** Render an interactive topological canvas displaying knowledge sources, memory chunks, agents, and their directional provenance relationships.
2. **Intended Users:** AI Developers, Security Analysts, Researchers.
3. **Main Layout:** Full-viewport interactive node-edge canvas with floating control dock (Zoom, Pan, Filter, Depth Slider) and right-side Node Inspector panel.
4. **Components:** GraphCanvas (React Flow), NodeFilterToolbar, DepthSlider, NodeDetailInspector.
5. **Data Displayed:**
   - Nodes: Sources (Blue Squares), Memory Records (Circles color-coded by trust state), Agents (Hexagons).
   - Edges: Directed arrows labeled with relationship types (`DERIVED_FROM`, `TRANSFORMED_INTO`, `REFERENCES`).
   - Selected Node Metadata: Full label, SHA-256, version, connected edge count.
6. **User Actions:**
   - Pan, zoom, and drag nodes.
   - Adjust Depth Slider (1 to 5) to restrict graph complexity.
   - Filter by entity type or hide quarantined nodes.
   - Click any node to open its properties in the Node Inspector panel.
7. **Navigation Behavior:** Clicking "View Record" in Node Inspector navigates to Memory Explorer.
8. **API Dependencies:** `GET /api/v1/knowledge/graph?max_depth=...`.
9. **Loading State:** Centered spinner with "Calculating topological projection...".
10. **Empty State:** "No knowledge graph entities found. Ingest knowledge sources to render relationships."
11. **Error State:** Canvas shows error dialog: "Graph layout engine encountered an error."
12. **Permission State:** Tenant-isolated.
13. **Responsive Behavior:** Floating toolbar minimizes to icon menu on mobile; canvas supports touch gestures.
14. **Related Requirements:** `FR-009`, `FR-026`, `NFR-005`.
15. **Acceptance Criteria:** Graph renders within 500ms for up to 150 nodes; depth constraint $\le 5$ enforced.

---

### Screen 08: Drift Monitor (`/drift`)

1. **Purpose:** Track, classify, and review semantic drift, source staleness, and knowledge divergence over time.
2. **Intended Users:** AI Platform Engineers, Security Analysts, Domain Experts.
3. **Main Layout:** KPI metrics for drift trends along top; filterable Drift Observations Table below.
4. **Components:** DriftSummaryCards, ObservationTable, DivergenceScoreMeter, ReviewActionDropdown.
5. **Data Displayed:**
   - Observation ID, Memory Record ID, Ingestion Date.
   - Classification: `LEGITIMATE_UPDATE`, `CONFLICTING_SOURCES`, `OUTDATED`, `POTENTIAL_POISONING`.
   - Divergence Score (Cosine distance / shift metric from 0.00 to 1.00).
   - Evidence Summary: Linguistic and conceptual shift explanation.
   - Reviewer Status (`PENDING`, `APPROVED`, `REJECTED`).
6. **User Actions:**
   - Filter by classification or divergence threshold.
   - Click "Accept Change" to mark drift as legitimate business update.
   - Click "Reject & Quarantine" to treat divergence as potential poisoning.
7. **Navigation Behavior:** Pivot to ChroniMem to view exact textual changes backing the drift observation.
8. **API Dependencies:** `GET /api/v1/drift/observations`, `POST /api/v1/drift/observations/{id}/review`.
9. **Loading State:** Table rows render pulsing placeholders.
10. **Empty State:** "Zero semantic drift anomalies detected. Knowledge baseline is stable."
11. **Error State:** "Failed to load drift observations."
12. **Permission State:** Review actions require `SECURITY_ANALYST` or `TENANT_ADMIN`.
13. **Responsive Behavior:** Table scrolls horizontally on mobile.
14. **Related Requirements:** `FR-010`, `FR-019`.
15. **Acceptance Criteria:** Reviewing drift persists updated status and emits an audit event.

---

### Screen 09: Agent Rewinding (`/rewind`)

1. **Purpose:** Provide a controlled, audited, multi-step memory recovery workstation that previews downstream blast radius and executes atomic rollback with pre-recovery state preservation.
2. **Intended Users:** Security Analysts, AI Platform Engineers, System Administrators.
3. **Main Layout:** 4-step wizard interface:
   - **Step 1:** Checkpoint Selection.
   - **Step 2:** Impact Preview & Blast Radius.
   - **Step 3:** Dual-Authorization Confirmation.
   - **Step 4:** Execution Report & Validation.
4. **Components:** CheckpointSelector, ImpactPreviewCard, PreRecoveryPreservationNotice, RollbackConfirmDialog, RecoveryReport.
5. **Data Displayed:**
   - Available Checkpoints: Name, Snapshot Date, Record Count, Cryptographic Integrity Hash.
   - Impact Analysis: Number of records to be rolled back, derived child records to be quarantined.
   - Irreversible External Tool Warning: Explicitly lists any real-world external tool calls executed during the compromised window that cannot be reversed by database rollback.
   - Pre-Recovery Snapshot ID: Confirms that contaminated state has been committed to permanent storage.
6. **User Actions:**
   - Select validated checkpoint.
   - Click "Generate Impact Preview" to discover affected downstream records.
   - Click "Confirm & Execute Rollback" (requires typing `CONFIRM_ROLLBACK` or analyst dual-confirmation).
7. **Navigation Behavior:** Upon completion, provides direct links to the resulting Audit Event and restored Memory Records.
8. **API Dependencies:** `GET /api/v1/recovery/checkpoints`, `POST /api/v1/recovery/plans/preview`, `POST /api/v1/recovery/plans/execute`.
9. **Loading State:** Modal shows multi-stage progress: "Preserving contaminated snapshot... Restoring checkpoint... Re-indexing graph...".
10. **Empty State:** "No validated checkpoints found. Create a checkpoint from Memory Explorer before attempting rollback."
11. **Error State:** Critical error banner: "Rollback failed integrity check. Checkpoint hash mismatch. Recovery aborted."
12. **Permission State:** Restricted strictly to `SECURITY_ANALYST` and `TENANT_ADMIN`.
13. **Responsive Behavior:** Stepper navigates linearly; warning banners maintain prominent visual priority.
14. **Related Requirements:** `FR-020`, `FR-021`, `FR-022`, `FR-023`, `SEC-007`.
15. **Acceptance Criteria:** Pre-recovery snapshot is committed before rollback; restored records match checkpoint checksum.

---

### Screen 10: Audit Center (`/audit`)

1. **Purpose:** Provide an immutable, searchable, and exportable forensic log of all administrative, security, gateway, and recovery actions.
2. **Intended Users:** Compliance Auditors, Security Analysts, Organization Administrators.
3. **Main Layout:** Header with date range picker and "Export Compliance Package" button; dense tabular event log below; Inspector Drawer on click.
4. **Components:** AuditTable, EventTypeFilter, ExportDropdown, AuditDetailDrawer, NonRepudiationBadge.
5. **Data Displayed:**
   - Timestamp (UTC ISO 8601 with milliseconds).
   - Actor ID (User email, Agent ID, or `GATEWAY_TOOL_ADAPTER`).
   - Event Type (`MEMORY_INGESTED`, `TOOL_POLICY_DECIDED`, `MEMORY_QUARANTINED`, `RECOVERY_EXECUTED`).
   - Resource Target ID, Action, Outcome (`SUCCESS`, `BLOCKED`, `DENIED`, `FAILED`).
   - Trace Correlation ID, Details JSON excerpt.
6. **User Actions:**
   - Filter by actor, event type, or outcome.
   - Click any event row to inspect full JSON details and correlation identifiers.
   - Click "Export as Signed JSON" or "Export CSV" for external regulatory compliance review.
7. **Navigation Behavior:** Selecting a trace ID navigates to Dual Trace.
8. **API Dependencies:** `GET /api/v1/audit/events`.
9. **Loading State:** Table skeleton rows with animated shimmer.
10. **Empty State:** "No audit events recorded for the selected time filter."
11. **Error State:** "Audit service connection error. Logs could not be fetched."
12. **Permission State:** Accessible to `AUDITOR`, `SECURITY_ANALYST`, and `TENANT_ADMIN`.
13. **Responsive Behavior:** Table supports horizontal scroll; timestamps format compactly on small screens.
14. **Related Requirements:** `FR-027`, `SEC-010`.
15. **Acceptance Criteria:** Append-only integrity; audit events cannot be modified or deleted via UI or API.

---

### Screen 11: Settings & Governance (`/settings`)

1. **Purpose:** Manage tenant profile, user memberships, RBAC roles, tool gateway allowlists, and global operational policies.
2. **Intended Users:** Organization Administrators (`TENANT_ADMIN`).
3. **Main Layout:** Vertical tabbed settings layout:
   - *Tab 1:* Tenant Profile & Workspace Settings.
   - *Tab 2:* Users & RBAC Memberships.
   - *Tab 3:* Tool Gateway Allowlists & Parameter Ceilings.
   - *Tab 4:* Memory Governance & Retention Policies.
4. **Components:** SettingsTabNav, MemberManagementTable, ToolCeilingConfigForm, PolicyRuleEditor.
5. **Data Displayed:**
   - Tenant Name, Slug, Unique ID, Status.
   - Member list: Name, Email, Assigned Role (`TENANT_ADMIN`, `SECURITY_ANALYST`, `AI_DEVELOPER`, `AUDITOR`).
   - Registered Tools and global parameter constraints (e.g., maximum disbursement limit).
   - Memory retention days, automated checkpoint schedule.
6. **User Actions:**
   - Invite new users and update role assignments.
   - Configure tool parameter limits and dual-custody approval thresholds.
   - Update tenant profile details.
7. **Navigation Behavior:** Standard tab switching without full-page reloads.
8. **API Dependencies:** `GET /api/v1/tenants/{id}`, `GET /api/v1/agents`, `PUT /api/v1/agents/{id}/permissions`.
9. **Loading State:** Tab content displays skeleton card.
10. **Empty State:** N/A (Always contains tenant settings).
11. **Error State:** Toast notification: "Failed to save governance settings. Check permissions."
12. **Permission State:** Read-only for non-admin users; mutation requires `TENANT_ADMIN` role.
13. **Responsive Behavior:** Tabs switch to horizontal scrollable bar on mobile viewports.
14. **Related Requirements:** `FR-001`, `FR-003`, `FR-005`.
15. **Acceptance Criteria:** Changes to governance rules immediately apply to subsequent gateway proposals.

---

## 5. Accessibility & Interaction Specifications

- **Keyboard Navigation:** 100% of interactive elements (buttons, inputs, table rows, drawers, modal dismissals) accessible via `Tab`, `Shift+Tab`, `Enter`, `Space`, and `Escape`.
- **Visible Focus Indicator:** High-contrast focus ring (`ring-2 ring-blue-500 ring-offset-2 ring-offset-slate-900`) on all focused elements.
- **Color Contrast:** All text tokens meet WCAG 2.1 AA requirements (minimum contrast ratio 4.5:1 against respective surface backgrounds).
- **Redundant Status Signifiers:** Security states are never conveyed by color alone; every badge includes both an explicit text label and a distinctive icon (e.g., Emerald Check for Trusted, Red Octagon/Slash for Quarantined, Amber Triangle for Suspicious).
