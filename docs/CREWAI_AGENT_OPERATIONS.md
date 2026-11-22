# ChronoCogniSec CrewAI Business Agents: Agent Operations Manual

**Document Identifier:** AMSC-DOC-012  
**Target Audience:** AI Operations Engineers, Enterprise Supervisors, Compliance Officers  
**Version:** 1.0.0  

---

## 1. Overview

This operations manual details the responsibilities, input payloads, output contracts, tool permissions, and escalation pathways for each of the five genuine CrewAI business agents operating within the ChronoCogniSec simulated enterprise (`tenant-a-uuid-001`).

---

## 2. Agent 1: Customer Support Specialist

### 2.1 Role & Scope
- **Agent Identifier:** `agent-crew-support-001`
- **Assigned Branch:** `branch-ho-001` (Head Office)
- **Primary Function:** Ingest customer support inquiries, look up authorized return/refund policies from trusted company memory, evaluate eligibility, prepare structured customer-facing responses, and submit refund proposals to the Security Gateway when warranted.

### 2.2 Input Schema: `SupportTicketInput`
```python
class SupportTicketInput(BaseModel):
    ticket_id: str                   # e.g. "tkt-support-101"
    customer_id: str                 # e.g. "cust-enterprise-500"
    issue_description: str           # Detailed issue narrative
    requested_action: Optional[str]  # e.g. "Return device for refund"
    claim_amount_usd: Optional[float] # e.g. 120.00
    urgency: str                     # "LOW", "MEDIUM", "HIGH", "CRITICAL"
```

### 2.3 Output Schema: `SupportResolutionOutput`
```python
class SupportResolutionOutput(BaseModel):
    ticket_id: str
    classification: str              # "RETURN_REFUND", "BILLING", "HARDWARE", "POLICY"
    priority: str                    # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    resolution_text: str             # Formal customer response text
    action_taken: str                # e.g. "RESOLVED_WITH_POLICY", "ESCALATED_TO_SUPERVISOR"
    gateway_proposal_id: Optional[str]
    escalated: bool
    escalation_reason: Optional[str]
    memory_references: List[str]     # e.g. ["mem-supp-faq-001"]
```

### 2.4 Escalation Conditions
The agent triggers `escalate_to_human_supervisor` whenever:
1. The ticket description contains keywords indicative of fraud, account takeover, or suspicious unauthorized transactions.
2. The customer exhibits abusive behavior.
3. The requested claim exceeds standard support authorization parameters.

---

## 3. Agent 2: HR Operations Specialist

### 3.1 Role & Scope
- **Agent Identifier:** `agent-crew-hr-002`
- **Assigned Branch:** `branch-isb-004` (Corporate Affairs & HR, Islamabad)
- **Primary Function:** Provide authoritative employment handbook guidance, evaluate synthetic leave requests, explain company procedures, and safeguard employee privacy.

### 3.2 Input Schema: `HRRequestInput`
```python
class HRRequestInput(BaseModel):
    request_id: str                  # e.g. "hr-req-202"
    employee_id: str                 # e.g. "emp-lhr-042"
    request_type: str                # "LEAVE_APPLICATION", "BENEFITS_INQUIRY", "DISCIPLINARY_DISPUTE"
    details: str                     # Request narrative
    requested_days: Optional[int]    # e.g. 5
```

### 3.3 Output Schema: `HRResolutionOutput`
```python
class HRResolutionOutput(BaseModel):
    request_id: str
    employee_id: str
    request_type: str
    status: str                      # "ELIGIBLE", "INELIGIBLE", "ESCALATED_FOR_HUMAN_REVIEW"
    policy_reference: str            # e.g. "AMSC-HR-POL-001 (Annual & Medical Leave Guidelines)"
    explanation: str
    escalated: bool
    escalation_reason: Optional[str]
    memory_references: List[str]     # e.g. ["mem-hr-pol-001"]
```

### 3.4 Consequential Decisions Restriction
The agent is strictly prohibited from executing consequential employment decisions autonomously:
- Termination of employment contracts.
- Demotions or disciplinary reprimands.
- Salary or compensation adjustments.
Any request of type `DISCIPLINARY_DISPUTE` or involving contract termination is immediately escalated to a human HR Director.

---

## 4. Agent 3: Finance Operations Specialist

### 4.1 Role & Scope
- **Agent Identifier:** `agent-crew-finance-003`
- **Assigned Branch:** `branch-lhr-002` (Finance & Regional Ops, Lahore)
- **Primary Function:** Audit synthetic expense reimbursement requests, check invoice attachments, enforce procedural spending limits, submit action proposals to the Gateway, and enforce dual-custody rules.

### 4.2 Input Schema: `ExpenseAuditInput`
```python
class ExpenseAuditInput(BaseModel):
    expense_id: str                  # e.g. "exp-audit-303"
    claimant_id: str                 # e.g. "emp-dev-010"
    destination_account: str         # e.g. "acc-vendor-cloud-77"
    amount_usd: float                # e.g. 195.00
    category: str                    # "TRAVEL_ACCOMMODATION", "CLOUD_HOSTING_INFRASTRUCTURE"
    receipt_attached: bool           # True if tax invoice / receipt provided
    memo: Optional[str]
```

### 4.3 Output Schema: `ExpenseAuditOutput`
```python
class ExpenseAuditOutput(BaseModel):
    expense_id: str
    audit_status: str                # "PROPOSAL_SUBMITTED", "REJECTED_MISSING_RECEIPT", "BLOCKED_BY_GATEWAY"
    amount_usd: float
    gateway_proposal_id: Optional[str]
    gateway_decision: str            # "ALLOW" or "BLOCK"
    dual_custody_required: bool      # True if amount > $300.00
    explanation: str
    memory_references: List[str]     # e.g. ["mem-fin-proc-001"]
```

### 4.4 Gateway Dual Custody Policy
- **Threshold:** Exactly $300.00 USD.
- **Amounts <= $300.00:** Gateway evaluates deterministic M4 policy and issues `ALLOW` decision.
- **Amounts > $300.00:** Gateway issues `BLOCK` decision (`DUAL_CUSTODY_REQUIRED`), requiring two authorized financial signatories.
- **Missing Receipts:** Any request with `receipt_attached=False` is rejected immediately prior to disbursement.

---

## 5. Agent 4: Branch Operations Specialist

### 5.1 Role & Scope
- **Agent Identifier:** `agent-crew-branch-004`
- **Assigned Branch:** Regional branch parameter (`branch-lhr-002`, `branch-khi-003`, or `branch-isb-004`)
- **Primary Function:** Manage branch facility status, server room temperature monitoring, physical security compliance, and inventory audits within assigned regional territory.

### 5.2 Input Schema: `BranchRequestInput`
```python
class BranchRequestInput(BaseModel):
    request_id: str                  # e.g. "br-req-404"
    target_branch_id: str            # e.g. "branch-khi-003"
    category: str                    # "FACILITY_STATUS", "LOGISTICS_INVENTORY", "COMPLIANCE_AUDIT"
    details: str
    sync_to_head_office: bool = True
```

### 5.3 Output Schema: `BranchOperationOutput`
```python
class BranchOperationOutput(BaseModel):
    request_id: str
    assigned_branch_id: str
    target_branch_id: str
    status: str                      # "SUCCESS_NORMAL", "BLOCKED_CROSS_BRANCH_BREACH", "ESCALATED"
    operational_summary: str
    head_office_synced: bool
    security_violation_flagged: bool
    memory_references: List[str]
```

### 5.4 Regional Boundary Isolation
If an agent assigned to `branch-lhr-002` (Lahore) attempts an operation targeting `branch-khi-003` (Karachi), the system detects a cross-branch isolation breach:
- The execution is halted immediately.
- `security_violation_flagged` is set to `True`.
- The status returns `BLOCKED_CROSS_BRANCH_BREACH`.
- A security incident record is logged in Dual Trace.

---

## 6. Agent 5: Enterprise Workflow Coordinator

### 6.1 Role & Scope
- **Agent Identifier:** `agent-crew-coord-005`
- **Assigned Branch:** `branch-ho-001` (Head Office)
- **Primary Function:** Coordinate complex business workflows across multiple departments. Deconstruct high-level initiatives into subtasks, dispatch to specialists, collect outputs, and synthesize executive consolidated reports.

### 6.2 Input Schema: `EnterpriseWorkflowInput`
```python
class EnterpriseWorkflowInput(BaseModel):
    workflow_id: str
    initiative_title: str
    description: str
    support_ticket: Optional[SupportTicketInput] = None
    hr_request: Optional[HRRequestInput] = None
    finance_expense: Optional[ExpenseAuditInput] = None
    branch_request: Optional[BranchRequestInput] = None
```

### 6.3 Output Schema: `EnterpriseWorkflowReport`
```python
class EnterpriseWorkflowReport(BaseModel):
    workflow_id: str
    initiative_title: str
    status: str                      # "COMPLETED_CONSOLIDATED", "ESCALATED_ANOMALY", "PARTIAL_BLOCKED"
    specialists_engaged: List[str]   # Names of engaged specialist agents
    support_summary: Optional[str]
    hr_summary: Optional[str]
    finance_summary: Optional[str]
    branch_summary: Optional[str]
    consolidated_assessment: str
    all_security_controls_satisfied: bool
```

### 6.4 Event-Driven Orchestration via CrewAI Flow
The coordinator utilizes an event-driven `EnterpriseLifecycleFlow`:
1. `@start()` initializes workflow state, registers initiative title, and sets start timestamps.
2. `@listen(initialize_enterprise_workflow)` dispatches subtasks across specialists sequentially.
3. Subtask outputs are collected, validated against Pydantic schemas, and checked for security violations.
4. An executive consolidated report is synthesized, certifying that all cross-department controls were satisfied.
