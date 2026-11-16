# Agent Memory Security Center (AMSC)
## Document 03: Application Flow & System Workflows

**Document Identifier:** `AMSC-DOC-003`  
**Version:** 1.0.0  
**Status:** Approved System Flow Specification  
**Focus:** User Journeys, Screen Transitions, State Machines & Ingress Sequences  
**Author:** Lead UX Architect & Technical Systems Council  
**Repository Target:** https://github.com/9m2usman/ChronoCongiSec

---

## 1. Global User Journey & System State Machine

The AMSC user journey flows from multi-tenant authentication through real-time observability, alert triage, deep forensic trace investigation, and authorized memory recovery.

```mermaid
stateDiagram-v2
    [*] --> Unauthenticated
    Unauthenticated --> Authenticated : Login (Email/Password or API Key)
    Authenticated --> TenantWorkspace : Select Tenant Context (Company A / B / C)
    
    state TenantWorkspace {
        [*] --> OverviewDashboard
        
        OverviewDashboard --> AgentRegistry : Inspect Agents & Tools
        AgentRegistry --> AgentDetail : View Config Versions & Permissions
        
        OverviewDashboard --> MemoryExplorer : Browse Memory & Provenance
        MemoryExplorer --> MemoryInspector : View Content, SHA256 & Versions
        MemoryInspector --> ChroniMem : Deep Temporal Lineage
        MemoryInspector --> KnowledgeGraph : Topological Node View
        
        OverviewDashboard --> SecurityCenter : Triage Incidents & Alerts
        SecurityCenter --> InvestigationWorkspace : Open Forensic Case
        
        state InvestigationWorkspace {
            [*] --> EvidenceViewer
            EvidenceViewer --> DualTraceView : Correlate Execution & Memory
            EvidenceViewer --> DriftInspector : Compare Semantic Divergence
            EvidenceViewer --> QuarantineAction : Isolate Compromised Record
        }
        
        QuarantineAction --> AgentRewinding : Initiate Recovery Plan
        
        state AgentRewinding {
            [*] --> SelectCheckpoint
            SelectCheckpoint --> DependencyImpactPreview
            DependencyImpactPreview --> PreRecoverySnapshotPreservation
            PreRecoverySnapshotPreservation --> AtomicRollbackExecution
            AtomicRollbackExecution --> PostRecoveryValidation
        }
        
        PostRecoveryValidation --> AuditCenter : Inspect Permanent Audit Trail
        AuditCenter --> OverviewDashboard
    }
```

---

## 2. Authentication & Tenant Workspace Selection

```mermaid
sequenceDiagram
    autonumber
    actor User as Security Analyst / Developer
    participant UI as AMSC Web Frontend
    participant Auth as Auth API (/api/v1/auth)
    participant DB as PostgreSQL

    User->>UI: Enter Email & Password
    UI->>Auth: POST /api/v1/auth/login {email, password, tenant_slug}
    Auth->>DB: Query User & Validate Hashed Password
    alt Invalid Credentials
        Auth-->>UI: 401 Unauthorized (Incorrect email or password)
        UI-->>User: Display Error Banner
    else Credentials Valid
        Auth->>DB: Query Memberships for User
        Auth->>Auth: Generate Signed JWT with user_id, tenant_id, role
        Auth-->>UI: 200 OK {access_token, user_id, active_tenant, role}
        UI->>UI: Store Token in Memory / Session Storage
        UI->>UI: Initialize Workspace Shell for Tenant
        UI-->>User: Navigate to /overview Dashboard
    end
```

---

## 3. Screen-to-Screen Navigation Matrix

| Starting Screen | User Action / Trigger | Destination Screen | Data Context Passed |
|---|---|---|---|
| **Overview** | Click "Active Agents" metric card | Agent Registry (`/agents`) | Filter: `status=ACTIVE` |
| **Overview** | Click "Quarantined Records" counter | Memory Explorer (`/memory`) | Filter: `trust_state=QUARANTINED` |
| **Overview** | Click Critical Alert item | Security Center (`/security`) | Select: `incident_id` |
| **Agent Registry** | Click "Configure Permissions" | Agent Detail Modal | Agent ID, Tool Permissions |
| **Agent Registry** | Click "Inspect Memory" | Memory Explorer (`/memory`) | Filter: `agent_id` |
| **Memory Explorer** | Click Table Row | Contextual Inspector Drawer | Record ID, Versions, Checksum |
| **Memory Explorer** | Click "View Version Diff" in Drawer | ChroniMem (`/chronimem`) | Record ID, `v_from=1`, `v_to=2` |
| **Memory Explorer** | Click "View in Graph" in Drawer | Knowledge Graph (`/knowledge-graph`) | Focus Node: `record_id` |
| **Security Center** | Click "Investigate Incident" | Investigation Workspace | Incident ID, Evidence JSON |
| **Security Center** | Click "Correlate Trace" | Dual Trace (`/traces`) | Trace ID: `trace_id` |
| **Security Center** | Click "Quarantine Record" | Quarantine Confirmation Modal | Record ID, Incident ID |
| **Security Center** | Click "Start Rewind" | Agent Rewinding (`/rewind`) | Target Record ID, Incident ID |
| **Agent Rewinding** | Click "Preview Impact" | Recovery Preview Panel | Checkpoint ID, Affected Children |
| **Agent Rewinding** | Click "Confirm Rollback" | Recovery Result View | Plan ID, Pre-Snapshot ID |
| **Any Screen** | Click Audit Icon on any item | Audit Center (`/audit`) | Filter: `resource_id` |

---

## 4. Critical Ingress Sequence: Memory Ingestion & Hash Verification

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Ingestion Pipeline / Integration
    participant MW as Tenancy Middleware
    participant API as Ingestion API (/api/v1/memory)
    participant MemSvc as Memory Service
    participant DB as PostgreSQL System of Record
    participant Audit as Audit Service

    Caller->>MW: POST /api/v1/memory + Bearer Token + X-Tenant-ID
    MW->>MW: 1. Validate JWT Signature & Expiration
    MW->>MW: 2. Assert Caller Membership in Tenant
    MW->>API: Forward with Injected TenantContext
    API->>MemSvc: IngestKnowledge(tenant_id, content, record_type, source_id, parent_id)
    MemSvc->>MemSvc: Compute Canonical SHA-256 Checksum over normalized content
    MemSvc->>DB: INSERT memory_records (id, tenant_id, trust_state='UNVERIFIED', current_version=1)
    MemSvc->>DB: INSERT memory_versions (record_id, version=1, content, checksum)
    opt Parent Record ID Provided
        MemSvc->>DB: INSERT provenance_edges (from_id=parent_id, to_id=record_id, relation='DERIVED_FROM')
    end
    MemSvc->>Audit: RecordEvent('MEMORY_INGESTED', record_id, checksum)
    Audit->>DB: INSERT audit_events
    MemSvc-->>Caller: 201 Created {id, version: 1, checksum, trust_state: 'UNVERIFIED'}
```

---

## 5. Critical Ingress Sequence: Protected Tool Action & Security Gateway

This represents the non-negotiable security boundary where agents are mediated before executing tools.

```mermaid
sequenceDiagram
    autonumber
    actor Agent as Autonomous AI Agent
    participant GW as AMSC Security Gateway (/api/v1/gateway)
    participant Idemp as Redis / DB Idempotency Filter
    participant Policy as Policy & Trust Engine
    participant Mem as Memory Service
    participant Adapter as Server-Side Tool Adapter (Sandbox)
    participant DB as PostgreSQL
    participant Audit as Audit Center

    Agent->>GW: POST /actions/propose {action_id, agent_id, tool_name, operation, parameters, memory_refs, idempotency_key}
    GW->>Idemp: Check idempotency_key
    alt Duplicate Submission
        Idemp-->>GW: Return Existing Cached Decision
        GW-->>Agent: 200 OK {decision, cached_idempotency: true}
    else First Submission
        GW->>Policy: Validate Agent Registration & Tool Permissions
        alt Agent Not Assigned Tool or Ceiling Exceeded
            Policy-->>GW: Result: BLOCK (Reason: 'CEILING_EXCEEDED' or 'UNAUTHORIZED_TOOL')
            GW->>DB: INSERT policy_decisions (decision='BLOCK', execution_status='NOT_EXECUTED')
            GW->>Audit: RecordEvent('TOOL_POLICY_DECIDED', outcome='BLOCKED')
            GW-->>Agent: 200 OK {decision: 'BLOCK', execution_status: 'NOT_EXECUTED', reasons: [...]}
        else Agent Has Valid Tool Permissions
            GW->>Mem: VerifyTrustState(memory_refs)
            alt Any Referenced Memory is SUSPICIOUS or QUARANTINED
                Mem-->>GW: Memory Trust FAILED (Tainted record detected)
                Policy-->>GW: Result: BLOCK (Reason: 'REFERENCED_UNTRUSTED_MEMORY')
                GW->>DB: INSERT policy_decisions (decision='BLOCK', execution_status='NOT_EXECUTED')
                GW->>Audit: RecordEvent('ACTION_BLOCKED_UNTRUSTED_MEMORY')
                GW-->>Agent: 200 OK {decision: 'BLOCK', reasons: ['Referenced memory is quarantined/suspicious']}
            else All Referenced Memories are TRUSTED and eligible for this action
                Policy-->>GW: Result: ALLOW
                GW->>DB: INSERT policy_decisions (decision='ALLOW')
                GW->>Adapter: ExecuteTool(tool_name, operation, parameters)
                Note over Adapter: Adapter runs with server-side credentials
                Adapter-->>GW: Execution Result {status: 200, result_payload}
                GW->>DB: INSERT tool_executions (status='SUCCESS', duration_ms)
                GW->>Audit: RecordEvent('TOOL_EXECUTED', outcome='SUCCESS')
                GW-->>Agent: 200 OK {decision: 'ALLOW', execution_status: 'EXECUTED', result: {...}}
            end
        end
    end
```

---

## 6. Security Alert Investigation & Quarantine Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant UI as Security Center UI
    participant SecAPI as Security API (/api/v1/security)
    participant MemAPI as Memory API (/api/v1/memory)
    participant DB as PostgreSQL
    participant Audit as Audit Center

    Analyst->>UI: Open Security Center (/security)
    UI->>SecAPI: GET /api/v1/security/incidents
    SecAPI-->>UI: Return Open Incidents (e.g. INC-001: Wire Diversion Injection)
    Analyst->>UI: Select INC-001 & Review Injected Text
    Analyst->>UI: Click [Quarantine Record M-8812]
    UI->>MemAPI: POST /api/v1/memory/M-8812/quarantine {reason: 'Verified Prompt Injection'}
    MemAPI->>DB: UPDATE memory_records SET trust_state='QUARANTINED' WHERE id='M-8812'
    MemAPI->>Audit: RecordEvent('MEMORY_QUARANTINED', record_id='M-8812')
    MemAPI-->>UI: 200 OK {trust_state: 'QUARANTINED'}
    UI-->>Analyst: Show Confirmation Badge: "Record Quarantined and Excluded from Agent Retrieval"
    
    Note over Analyst, DB: Normal agent retrieval returns only eligible TRUSTED records; forensic retrieval is separately authorized
```

---

## 7. Dual Trace Synchronization Workflow

1. **Trigger:** Analyst selects a trace identifier (`trace_id = "tr-forensic-demo-01"`) from the Security Center or Gateway logs.
2. **API Request:** Frontend calls `GET /api/v1/traces/tr-forensic-demo-01/dual-trace`.
3. **Execution Lane Assembly:** The backend aggregates:
   - Action Proposal span (`span-prop-xxxx`).
   - Policy Evaluation span (`span-dec-xxxx`) showing `ALLOW` or `BLOCK` and evaluated reasons.
   - Tool Execution span (`span-exec-xxxx`) showing duration in milliseconds and adapter response.
4. **Memory Lane Assembly:** The backend aggregates:
   - Retrieval events matching `trace_id` (`span-mem-ret-xxxx`).
   - Verified memory trust status spans for all referenced memory IDs (`span-mem-state-xxxx`).
5. **Interactive Scrubbing:** Clicking any span in Lane 1 highlights the linked memory chunks active in agent context at that precise timestamp.

---

## 8. ChroniMem Temporal Version Comparison Workflow

1. **Trigger:** User opens ChroniMem for record `M-8812` to inspect historical modifications.
2. **Timeline View:** System fetches `GET /api/v1/chronimem/timeline?agent_id=...` rendering revision milestones.
3. **Version Comparison:** User selects Version 1 (original trusted policy) and Version 2 (poisoned update).
4. **Diff Generator:** Backend executes `GET /api/v1/chronimem/records/M-8812/compare?v_from=1&v_to=2`.
5. **UI Rendering:** Side-by-side diff view renders red strikethroughs for deleted terms and green highlights for inserted adversarial instructions (e.g., replacement of legitimate account `ACC-VENDOR-VALID` with `ACC-ATTACKER-999`).

---

## 9. Knowledge Graph Progressive Expansion Workflow

1. **Initial Load:** Frontend calls `GET /api/v1/knowledge/graph?max_depth=3`.
2. **Topology Rendering:** React Flow canvas renders nodes color-coded by entity type:
   - *Document Sources:* Navy square nodes.
   - *Memory Chunks:* Circular nodes color-coded by trust state (Green: Trusted, Amber: Suspicious, Red: Quarantined).
   - *Agents:* Hexagonal nodes.
3. **Edge Traversal:** Directed arrows represent:
   - `DERIVED_FROM`: Solid blue line from source to chunk.
   - `TRANSFORMED_INTO`: Dashed cyan line between chunk revisions.
   - `REFERENCES`: Dotted grey line between agents and memories.
4. **Interactive Expansion:** Double-clicking any memory chunk queries downstream descendants up to bounded depth 5, visually revealing the blast radius of contaminated child facts.

---

## 10. Agent Rewinding & Atomic Recovery Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant UI as Agent Rewind UI (/rewind)
    participant RecAPI as Recovery API (/api/v1/recovery)
    participant DB as PostgreSQL
    participant Audit as Audit Center

    Analyst->>UI: Select Validated Checkpoint CP-001 (Baseline Trusted State)
    Analyst->>UI: Select Target Contaminated Record M-8812
    Analyst->>UI: Click [Preview Recovery Impact]
    UI->>RecAPI: POST /api/v1/recovery/plans/preview {checkpoint_id: 'CP-001', target_record_id: 'M-8812'}
    RecAPI->>DB: Traverse Downstream Provenance Edges to find Derived Records
    RecAPI-->>UI: Return Impact Preview {affected_count: 2, irreversible_external_actions: 0}
    UI-->>Analyst: Render Preview Modal showing pre-rollback state and rollback scope
    
    Analyst->>UI: Click [Confirm & Execute Rollback]
    UI->>RecAPI: POST /api/v1/recovery/plans/execute {plan_id}
    RecAPI->>DB: BEGIN TRANSACTION
    RecAPI->>DB: Capture Pre-Recovery State Snapshot into recovery_plans.pre_recovery_snapshot
    RecAPI->>DB: Revert M-8812 to Checkpoint CP-001 Content & Set trust_state='TRUSTED'
    RecAPI->>DB: Quarantine Intermediary Poisoned Versions
    RecAPI->>DB: COMMIT TRANSACTION
    RecAPI->>Audit: RecordEvent('RECOVERY_EXECUTED', plan_id, restored_count)
    RecAPI-->>UI: 200 OK {status: 'COMPLETED', restored_records_count: 2}
    UI-->>Analyst: Display Success Report & Link to Permanent Audit Event
```

---

## 11. Error & Failure Workflows (Fail-Closed Handling)

```mermaid
flowchart TD
    Start[Agent Proposes Tool Action] --> CheckDB{Database Available?}
    CheckDB -->|NO| FailDB[Return 500: System Error / Action Blocked]
    CheckDB -->|YES| CheckAuth{Auth & Tenant Valid?}
    CheckAuth -->|NO| FailAuth[Return 403: Forbidden / Action Blocked]
    CheckAuth -->|YES| CheckPolicy{Policy Engine Online?}
    CheckPolicy -->|NO / Timeout| FailPolicy[Fail-Closed: Return 503 / Action Blocked]
    CheckPolicy -->|YES| CheckMem{Memory Trust Available?}
    CheckMem -->|NO / Error| FailMem[Fail-Closed: Return Blocked / Memory Trust Unavailable]
    CheckMem -->|YES| EvalTrust{Is Memory Quarantined or Suspicious?}
    EvalTrust -->|YES| BlockTaint[Return Blocked: Untrusted Memory Reference]
    EvalTrust -->|NO| CheckCeiling{Parameter Ceilings Obeyed?}
    CheckCeiling -->|NO| BlockCeiling[Return Blocked: Limit Ceiling Exceeded]
    CheckCeiling -->|YES| Execute[Invoke Server-Side Tool Adapter]
```

### Specific Failure Responses:
1. **Database Unreachable:** System logs local critical event. Gateway refuses action proposals. No uncommitted action is executed.
2. **Policy Service Timeout:** If policy rule evaluation exceeds 2000ms, the timer aborts the check and returns `decision: BLOCK` with reason `POLICY_EVALUATION_TIMEOUT`.
3. **Cross-Tenant Access Attempt:** Any attempt by Tenant A to query Tenant B's data halts immediately with `HTTP 403 Forbidden`, emitting a high-priority security incident.
4. **Missing Idempotency Key:** Gateway returns `HTTP 400 Bad Request` with message `Missing required header or parameter: idempotency_key`.
