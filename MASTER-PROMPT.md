# MASTER BUILD PROMPT AND INTEGRATED PROJECT SPECIFICATION
## Agent Memory Security Center (AMSC)

**Document set:** Master Prompt + PRD + Combined TRD/SRS + Application Flow + UI/UX Design Flow + Backend Database/API Schema + Seven-Member, Seven-Day Implementation Plan  
**Product type:** Multi-tenant AI-agent memory security, governance, observability and recovery platform  
**Delivery target:** Seven-day integrated MVP, followed by a clearly defined hardening phase  
**Primary users:** AI developers, AI platform engineers, security analysts, researchers and organization administrators  
**Repository Target:** https://github.com/9m2usman/ChronoCongiSec

---

## 1. Role and Mission

You are the lead product architect, technical lead, security architect, UX lead and delivery coordinator for **Agent Memory Security Center (AMSC)**.

Your task is to design and document AMSC as a coherent, working platform. You are responsible for coordinating seven developers and ensuring that every component integrates through agreed interfaces.

Do not treat this as a generic admin dashboard, a collection of disconnected prototypes, or a simple merge of existing repositories.

Build a unified specification from scratch, using the following repositories as reference material:

1. **Agent Security:** https://github.com/HafizShamaz/agent-security
2. **KnowledgeLine:** https://github.com/9m2usman/KnowledgeLine
3. **Frontend structural reference:** https://github.com/ropean/shadcn-admin-template
4. **Investigation and trace UX reference:** https://github.com/as32608/openinspector

Inspect the repositories before making architecture decisions. Record relevant patterns, components, data models, integration ideas and limitations. Respect each repository's license. Do not copy code without checking its license and compatibility. Do not assume that a repository implements a capability merely because its name suggests it does.

The frontend references are guidance, not the product itself:
- Use the shadcn admin starter as a structural and component-system reference.
- Use OpenInspector as an interaction and visualization reference for investigations and traces.
- Implement a custom AMSC visual identity, navigation, screens and workflows.

---

## 2. Product Definition

AMSC is a security and governance layer for AI agents that protects the knowledge and memory agents rely on, controls the actions they attempt to execute, detects suspicious changes, traces the impact of compromised information and supports safe recovery.

The product must answer five central questions:

1. **Can this agent trust the memory or knowledge it is using?**
2. **Can this agent perform the action it is requesting?**
3. **Where did this information come from, and how has it changed?**
4. **What other memories, decisions, agents or actions may be affected?**
5. **What can safely be quarantined, restored, reversed or escalated to a human?**

AMSC connects memory integrity and agent action security. Protecting memory without controlling the actions that use it is insufficient. Controlling actions without understanding the trustworthiness of the information behind them is also insufficient.

---

## 3. Core Architecture Principles

Treat the following as non-negotiable:

### A. Trusted Knowledge Foundation
Implement:
- Trusted knowledge and source registration.
- Memory ingestion and record management.
- Source provenance and transformation history.
- Version history and checkpoints.
- Integrity validation.
- Memory trust status.
- Knowledge relationship tracking.
- Conflicting-source and outdated-information handling.
- Drift and suspicious-change observations.
- Quarantine and controlled restoration.

A memory record existing in the database does **not** mean it is trustworthy.

### B. Agent Action Security
Every protected tool action must pass through a server-side security gateway before execution.

Required sequence:
1. Agent proposes an action.
2. AMSC authenticates the caller and identifies its tenant and agent.
3. The gateway validates the action schema and permissions.
4. AMSC checks relevant memory trust and provenance.
5. Policy evaluation determines whether the action is allowed, blocked or requires approval.
6. A durable decision record is created.
7. Only an authorized action is passed to the relevant tool adapter.
8. The execution result is recorded and correlated with the decision and trace.

**Agents must never have a direct path to protected tool adapters that bypasses the gateway.** Tool credentials remain server-side.

For sensitive operations, fail closed when authorization or required security checks are unavailable. Do not silently allow an action because a security service timed out.

### C. Memory Contamination and Poisoning Response
AMSC must support an investigation workflow that can:
- Identify suspicious or untrusted memory records.
- Preserve source and transformation evidence.
- Trace records to derived records and dependent decisions.
- Identify affected agents and retrieval events.
- Distinguish malicious, incorrect, outdated and conflicting information.
- Quarantine suspicious records.
- Prevent quarantined information from being used in protected retrieval paths.
- Restore trusted information when a validated checkpoint exists.
- Revalidate related records and relationships.
- Record the investigation and recovery outcome.

Do not label every incorrect record as malicious poisoning. Store the evidence and classification basis.

### D. Semantic Rollback and Agent Rewinding
Implement a controlled recovery process:
1. Select a suspected corruption or incident.
2. Identify affected records and their dependencies.
3. Select a trusted checkpoint or source state.
4. Validate checkpoint integrity and provenance.
5. Preview the proposed recovery scope.
6. Preserve the pre-recovery state.
7. Quarantine affected records where appropriate.
8. Restore the smallest safe scope.
9. Rebuild or revalidate affected relationships.
10. Revalidate retrieval and policy behavior.
11. Check for reinfection or continued propagation.
12. Record the result and unresolved risks.

Do not claim that restoring memory reverses an external action. A payment, message, file transfer or external API operation may be irreversible. Classify outcomes honestly as prevented, quarantined, executed, reversible, compensated, recovered or requiring human intervention.

### E. Multi-Tenant Isolation
The platform must support multiple companies with strict isolation across:
- Authentication and authorization.
- API request handling.
- Database queries.
- Database row-level security where supported.
- Memory retrieval.
- Knowledge graphs.
- Search and caches.
- Background jobs.
- Event streams.
- Tool permissions.
- File and object storage.
- Audit and investigation interfaces.

Every tenant-owned object must have an explicit tenant scope. Never trust a client-supplied tenant ID without validating the authenticated user's membership and permissions.

A user from Company A must never be able to view, retrieve, modify, infer or export Company B's data.

### F. Evidence and Honest Security Status
Distinguish these states:
- Observed event.
- Anomaly.
- Suspected threat.
- Confirmed incident.
- Blocked action.
- Quarantined memory.
- Executed action.
- Recovered state.
- Recovery incomplete.
- Human review required.

Do not present a model-generated suspicion as a confirmed security incident. Show the evidence, detection basis and confidence where available.

---

## 4. Terminology and Research Integrity

- Treat **ChroniMem** as the name of AMSC's temporal memory and history experience unless a verifiable research source establishes a different meaning.
- Treat **Dual Trace** as AMSC's paired observability model:
  - Execution trace: agent activity, tool proposals, policy decisions and tool execution.
  - Memory trace: retrieval, source, transformation, version and provenance events.
- Correlate the two using trace IDs, span IDs, agent IDs, memory IDs, timestamps and operation IDs. Correlation does not automatically prove causation.
- Do not claim that ChroniMem or Dual Trace are established academic methods without verifiable evidence. Separate established techniques from AMSC design choices.

---

## 5. Technology Stack Baseline

### Frontend
- React with TypeScript.
- Vite.
- Tailwind CSS.
- shadcn/ui and Radix-based components.
- TanStack Router.
- TanStack Query.
- TanStack Table.
- Zustand for limited client-side global state.
- React Flow for knowledge graphs.
- Recharts for analytical charts.
- React Hook Form and Zod for forms and validation.

### Backend
- Python.
- FastAPI.
- Pydantic.
- SQLAlchemy.
- Alembic migrations.
- PostgreSQL as the durable system of record.
- Redis for explicitly documented caching, coordination, rate limiting or queue-related purposes.
- Celery only if background task requirements justify it.

---

## 6. The Six Primary Specifications

The authoritative project documentation is organized in `docs/`:

1. `docs/01-PRD.md` — Product Requirements Document
2. `docs/02-TRD-SRS.md` — Combined TRD and SRS
3. `docs/03-APPLICATION-FLOW.md` — Application Flow and System Workflow
4. `docs/04-UI-UX-DESIGN.md` — UI/UX Design and Screen Specification
5. `docs/05-DATABASE-API-SCHEMA.md` — Backend Database Schema and API Contract
6. `docs/06-TEAM-IMPLEMENTATION-PLAN.md` — Seven-Person Implementation Plan: One Week
