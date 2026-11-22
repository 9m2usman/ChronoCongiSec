# ChronoCogniSec CrewAI Business Agents: Implementation Architecture

**Document Identifier:** AMSC-DOC-010  
**Version:** 1.0.0  
**Author:** AI Agent Architecture Council & Security Engineering  
**Status:** Approved & Implemented  
**Date:** November 2026  

---

## 1. Executive Summary

This document specifies the genuine LLM-powered CrewAI business agent system integrated into the ChronoCogniSec simulated enterprise company (`tenant-a-uuid-001`). Rather than relying on mock placeholder classes, toy scripts, or frontend-only fixtures, the implementation provides genuine CrewAI agents, Crews, Tasks, and an event-driven `CrewAI Flow` running within strict enterprise security, authorization, and observability boundaries.

All agent operations are mediated through the ChronoCogniSec Security Gateway (`POST /api/v1/gateway/actions/propose`), validated against deterministic M4 policies, grounded solely in cryptographically verified trusted company memory (`trust_state="TRUSTED"`), and recorded in high-fidelity Dual Trace telemetry.

---

## 2. Architectural Principles & Boundaries

The integration is governed by five non-negotiable architectural mandates:

1. **Deterministic Security Authority:**  
   LLMs are probabilistic reasoning engines, **never** security policy authorities. All sensitive business actions (financial disbursements, system updates, credential access) must be formulated as *action proposals* submitted to the ChronoCogniSec Gateway. The Gateway executes deterministic M4 policies; an LLM cannot self-authorize or bypass policy blocks.
2. **Strict Multi-Tenant Isolation:**  
   The simulated company operates under `tenant-a-uuid-001`. Agents reject any cross-tenant data requests (e.g., Company B `tenant-b-uuid-002` or Company C `tenant-c-uuid-003`) unconditionally with fail-closed exceptions.
3. **Regional Branch Scoping:**  
   The simulated enterprise consists of four branches:
   - **Head Office (`branch-ho-001`):** Core security, policy governance, and enterprise supervisory scope.
   - **Lahore (`branch-lhr-002`):** Regional finance and local operations.
   - **Karachi (`branch-khi-003`):** Regional logistics, shipping, and port operations.
   - **Islamabad (`branch-isb-004`):** Regional corporate affairs and human resources.  
   Regional branch agents are strictly isolated to their assigned branch. Only Head Office agents possess enterprise-wide supervisory aggregation rights.
4. **Memory Trust Verification:**  
   Agents may only retrieve and act upon memory records with `trust_state="TRUSTED"` and non-stale verification timestamps. Any record marked `QUARANTINED`, `UNVERIFIED`, `SUSPICIOUS`, or containing prompt injection signatures is rejected immediately.
5. **Dual Trace Execution Observability:**  
   Every agent run, subtask delegation, tool invocation, Gateway proposal, and policy decision emits structured telemetry records with automatic secret redaction (API keys, authorization bearer tokens, credentials).

---

## 3. Five Genuine Business Agents

The system implements five genuine business agents as defined in `docs/09-SIMULATED-COMPANY-INTEGRATION-PLAN.md`:

```
               ┌────────────────────────────────────────────────────────┐
               │         Enterprise Workflow Coordinator                │
               │         (Head Office - Supervisory Flow)               │
               └──────────────────────────┬─────────────────────────────┘
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            │                             │                             │
┌───────────▼──────────┐      ┌───────────▼──────────┐      ┌───────────▼──────────┐
│   Customer Support   │      │    HR Operations     │      │  Finance Operations  │
│      Specialist      │      │      Specialist      │      │      Specialist      │
│  (Policy Retrieval & │      │  (Leave & Handbook   │      │  (Expense Audits &   │
│   Refund Proposals)  │      │     Guidance)        │      │   Gateway Dual-Cust) │
└──────────────────────┘      └──────────────────────┘      └──────────────────────┘
                                          │
                              ┌───────────▼──────────┐
                              │  Branch Operations   │
                              │      Specialist      │
                              │ (Lahore/Khi/Isb Reg) │
                              └──────────────────────┘
```

### 3.1 Agent 1: Customer Support Specialist
- **Identity & Role:** `agent-crew-support-001` / "Customer Support Specialist"
- **Assigned Branch:** `branch-ho-001` (Head Office)
- **Goal:** Investigate synthetic customer support tickets, retrieve trusted policy knowledge, prepare structured customer responses, and formulate Gateway refund proposals.
- **Backstory:** Senior Customer Support Specialist at ChronoCogniSec Enterprise. Strictly grounds answers in official trusted FAQ memory. Escalates fraud, abusive conduct, or account takeovers to human supervisors.
- **Restricted Tools:**
  - `retrieve_trusted_support_faq`: Query memory store for approved support knowledge.
  - `propose_customer_refund`: Submit refund proposal to Gateway (`POST /api/v1/gateway/actions/propose`).
  - `escalate_to_human_supervisor`: Escalate high-risk tickets to human oversight.
- **Restrictions:** Cannot invent policies, modify memory, access cross-tenant records, or bypass Gateway authorization.

### 3.2 Agent 2: HR Operations Specialist
- **Identity & Role:** `agent-crew-hr-002` / "HR Operations Specialist"
- **Assigned Branch:** `branch-isb-004` (Corporate Affairs & HR, Islamabad)
- **Goal:** Answer employee questions using approved company handbooks, evaluate synthetic leave requests, and escalate sensitive personnel or disciplinary disputes.
- **Backstory:** Authoritative HR Operations Specialist guiding staff through official employment procedures. Never makes consequential employment decisions autonomously (termination, demotion, salary alteration).
- **Restricted Tools:**
  - `retrieve_hr_policy_handbook`: Access trusted HR policies (`AMSC-HR-POL-001`).
  - `escalate_personnel_matter`: Immediately escalate disciplinary, termination, or grievance matters to human HR directors.
- **Restrictions:** Cannot make binding employment decisions, expose confidential employee records, or approve own actions.

### 3.3 Agent 3: Finance Operations Specialist
- **Identity & Role:** `agent-crew-finance-003` / "Finance Operations Specialist"
- **Assigned Branch:** `branch-lhr-002` (Finance & Regional Ops, Lahore)
- **Goal:** Review synthetic expense requests, enforce receipt requirements and spending caps, formulate disbursement proposals to the Security Gateway, and enforce the $300 dual-custody threshold.
- **Backstory:** Experienced Finance Operations Specialist maintaining strict fiduciary hygiene. Validates tax invoices and receipts. Submits action proposals to Gateway; respects Gateway `BLOCK` decisions when threshold exceeds $300.
- **Restricted Tools:**
  - `retrieve_financial_procedure`: Query trusted financial procedural guidelines (`AMSC-FIN-PROC-001`).
  - `propose_expense_disbursement`: Submit disbursement proposal to Security Gateway.
  - `escalate_financial_anomaly`: Escalate missing invoices, suspicious banking details, or anomalies.
- **Restrictions:** No real fund movement, no self-approvals, cannot bypass Gateway M4 policy evaluation.

### 3.4 Agent 4: Branch Operations Specialist
- **Identity & Role:** `agent-crew-branch-004` / "Branch Operations Specialist"
- **Assigned Branch:** Regional parameter (`branch-lhr-002`, `branch-khi-003`, or `branch-isb-004`)
- **Goal:** Review branch facility and operational status, verify local inventory, synchronize reports with Head Office, and escalate issues outside assigned scope.
- **Backstory:** Dedicated Regional Branch Operations Specialist stationed at assigned regional office. Ensures physical facility, server room, and logistics compliance.
- **Restricted Tools:**
  - `retrieve_branch_operational_records`: Query branch-specific memory records.
  - `synchronize_with_head_office`: Transmit regional status updates to Head Office supervisory systems.
  - `escalate_branch_incident`: Escalate security or facility breaches to regional leadership.
- **Restrictions:** Cannot access records belonging to another regional branch; cannot change assigned branch context.

### 3.5 Agent 5: Enterprise Workflow Coordinator
- **Identity & Role:** `agent-crew-coord-005` / "Enterprise Workflow Coordinator"
- **Assigned Branch:** `branch-ho-001` (Head Office)
- **Goal:** Orchestrate cross-functional initiatives spanning Customer Support, HR, Finance, and Branch Operations. Break complex initiatives into bounded subtasks and generate consolidated executive reports.
- **Backstory:** Chief Enterprise Workflow Coordinator stationed at Head Office. Dispatches work to specialist agents, verifies structured results, and ensures all security boundaries remain intact.
- **Restricted Tools:**
  - `delegate_to_support_specialist`: Controlled subtask delegation to Customer Support.
  - `delegate_to_finance_specialist`: Controlled subtask delegation to Finance Operations.
  - `escalate_workflow_anomaly`: Escalate unresolved blocks to executive leadership.
- **Restrictions:** Cannot grant privileges to specialist agents, cannot override Gateway policy blocks, cannot approve proposals.

---

## 4. Framework Architecture: Dual-Mode Engine

To guarantee zero dependency friction across developer workstations, the application implements a dual-mode CrewAI architecture in `crewai_service/framework.py`:

1. **Official CrewAI Release Integration:**  
   If the official `crewai` package is installed in the active Python environment, `crewai_service.framework` directly imports and exposes `Agent`, `Crew`, `Task`, `Process`, `Flow`, `@start`, and `@listen`.
2. **Native CrewAI Compliance Runtime:**  
   If the environment lacks the external `crewai` binary, the runtime activates `NativeAgent`, `NativeCrew`, `NativeTask`, `NativeProcess`, and `NativeFlow`. This native engine implements 100% of the CrewAI programming model:
   - Synchronous and asynchronous task execution.
   - Pydantic v2 structured output enforcement (`output_pydantic`, `output_json`).
   - Context aggregation across predecessor tasks.
   - Event-driven state machine flow orchestration (`@start`, `@listen`).
   - Standard `@tool` decorator wrapping with signature inspection.

This ensures seamless development whether running on Python 3.12, 3.13, or 3.14 without requiring external Git submodules.

---

## 5. Security Gateway & ChronoCogniSec Integration

All business agents interface directly with the existing ChronoCogniSec FastAPI backend via `crewai_service/tools/amsc_client.py`:

```
[CrewAI Agent]
      │
      ▼  (Formulates Action Proposal)
[GatewayToolFactory]
      │
      ▼  (POST /api/v1/gateway/actions/propose)
[ChronoCogniSec Security Gateway]
      │
      ▼  (Deterministic M4 Policy Evaluation)
[Policy Engine] ───► Dual-Custody Check ($300 threshold)
      │
      ▼  (Returns GatewayExecutionReceipt: ALLOW / BLOCK)
[Agent Telemetry & Execution Tracer]
```

### 5.1 Deterministic M4 Policy Rules
- **Rule 1 (Dual Custody):** Any financial disbursement proposal strictly exceeding $300.00 USD receives an unconditional `BLOCK` decision from the Gateway, requiring two distinct human authorizers.
- **Rule 2 (Receipt Requirement):** Any expense lacking attached receipt verification is rejected immediately.
- **Rule 3 (Tenant Context):** Gateway proposals lacking valid `tenant_id="tenant-a-uuid-001"` or containing cross-tenant IDs are rejected with 403 Forbidden.
- **Rule 4 (No Self-Approval):** Agents cannot approve their own submitted proposals.

---

## 6. Observability: Dual Trace Telemetry

Execution telemetry is managed by `crewai_service/telemetry/tracer.py`. Every agent run records:
- `run_id`: Unique execution identifier.
- `workflow_id` & `trace_id`: Distributed correlation identifiers compatible with M5 / M7 trace spans.
- `agent_id` & `agent_role`: Authenticated agent identity.
- `tool_invocations`: Timestamped audit of tool calls, inputs, and outputs.
- `gateway_proposal_ids` & `policy_decisions`: Cryptographic link between agent action and Gateway decision.
- `secret_redaction`: Automatic scrubbing of API keys, Bearer tokens, and sensitive credentials via `redact_sensitive_telemetry`.
