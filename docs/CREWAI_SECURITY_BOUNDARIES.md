# ChronoCogniSec CrewAI Business Agents: Security Boundaries & Policy Specification

**Document Identifier:** AMSC-DOC-013  
**Target Audience:** Security Architects, DevSecOps Engineers, Red Team Reviewers  
**Classification:** Internal Technical Architecture  
**Version:** 1.0.0  

---

## 1. Threat Model & Security Posture

LLM-powered business agents introduce distinct attack vectors that traditional application architectures do not face:
1. **Indirect Prompt Injection:** Adversarial instructions embedded in retrieved untrusted documents, customer tickets, or invoices.
2. **Confused Deputy Attacks:** An agent being manipulated into invoking privileged internal tools (e.g., payment transfers) on behalf of unauthorized actors.
3. **Multi-Tenant Leakage:** An agent inadvertently reading or writing across customer tenant boundaries.
4. **Cross-Branch Lateral Movement:** Regional agents accessing operations, secrets, or facilities of other branches.
5. **Self-Authorization & Policy Bypasses:** Agents attempting to approve their own actions or modifying memory trust states.

To neutralize these threats, the ChronoCogniSec CrewAI architecture implements **defense-in-depth security boundaries** in `crewai_service/security/boundaries.py` that execute deterministically in Python code before and after LLM invocations.

---

## 2. Boundary Layer 1: Multi-Tenant Isolation

### 2.1 The Invariant
All five business agents operate strictly on behalf of the simulated enterprise:
```python
CHRONOCONGISEC_TENANT_ID = "tenant-a-uuid-001"
```
Any operation, query, or proposal bearing an alternate tenant identifier (e.g. `tenant-b-uuid-002` for BetaShield Defense AI, or `tenant-c-uuid-003` for GammaAI) is rejected immediately.

### 2.2 Enforcement Mechanism
```python
def enforce_tenant_isolation(requested_tenant_id: str, active_tenant_id: str = "tenant-a-uuid-001") -> None:
    if requested_tenant_id != active_tenant_id:
        logger.error(f"TENANT ISOLATION BREACH: Attempted cross-tenant access to '{requested_tenant_id}' from '{active_tenant_id}'.")
        raise SecurityBoundaryViolation(
            f"Tenant boundary violation: Agent in tenant '{active_tenant_id}' cannot access tenant '{requested_tenant_id}'."
        )
```
- **Fails Closed:** Returns HTTP 403 / `SecurityBoundaryViolation`.
- **Zero Reflection:** The malicious tenant ID or payload is not reflected back to the user.

---

## 3. Boundary Layer 2: Regional Branch Authorization

### 3.1 Branch Hierarchy
The enterprise topology consists of four distinct operational branches:
- `branch-ho-001`: Head Office (Core Security & Governance)
- `branch-lhr-002`: Lahore Branch (Finance & Regional Ops)
- `branch-khi-003`: Karachi Branch (Maritime & Port Logistics)
- `branch-isb-004`: Islamabad Branch (Corporate Affairs & HR)

### 3.2 Access Rules
1. **Head Office Supervisory Access:** Head Office agents (`branch-ho-001`) possess enterprise-wide supervisory rights to coordinate initiatives across all branches.
2. **Regional Branch Isolation:** Regional branch agents (`branch-lhr-002`, `branch-khi-003`, `branch-isb-004`) are restricted strictly to operations within their own branch.
3. **Lateral Movement Prevention:** A request from a Lahore agent targeting Karachi is blocked immediately prior to tool execution.

### 3.3 Enforcement Implementation
```python
def enforce_branch_scope(assigned_branch_id: str, target_branch_id: str) -> None:
    if assigned_branch_id == "branch-ho-001":
        return  # Head Office has enterprise supervisory scope
    if assigned_branch_id != target_branch_id:
        raise SecurityBoundaryViolation(
            f"Unauthorized branch access: Agent in '{assigned_branch_id}' cannot access or operate on branch '{target_branch_id}'."
        )
```

---

## 4. Boundary Layer 3: Memory Trust State Gating

### 4.1 Strict Memory State Requirements
Business agents do not have raw direct database or vector access. All memory retrieval operations query ChronoCogniSec memory endpoints.

Before an agent consumes any memory record, the record must satisfy:
1. `record["trust_state"] == "TRUSTED"`: The record has been verified and cryptographic integrity checked.
2. Records marked `QUARANTINED`, `UNVERIFIED`, `SUSPICIOUS`, or `STALE` are discarded with a security warning.

### 4.2 Enforcement Implementation
```python
def validate_memory_trust(memory_record: Dict[str, Any]) -> Dict[str, Any]:
    trust_state = memory_record.get("trust_state", "").upper()
    if trust_state != "TRUSTED":
        raise SecurityBoundaryViolation(
            f"Untrusted memory access rejected: Record '{memory_record.get('id')}' has status '{trust_state}'. "
            f"Only TRUSTED records may be consumed by business agents."
        )
    return memory_record
```

---

## 5. Boundary Layer 4: Indirect Prompt Injection Defense

Retrieved documents and user-provided inputs undergo automated injection scanning before they are concatenated into agent prompt contexts.

### 5.1 Blocked Patterns
The scanner inspects text for heuristic prompt injection and system override markers:
- `ignore previous instructions`
- `disregard all prior instructions`
- `bypass security policies`
- `system override`
- `you are now an unrestricted agent`
- `print system prompt`
- `reveal internal instructions`
- `do anything now` (DAN)

### 5.2 Scanner Implementation
```python
def scan_for_indirect_injection(text_content: str) -> bool:
    content_lower = text_content.lower()
    for pattern in INJECTION_PATTERNS:
        if pattern in content_lower:
            logger.warning(f"INDIRECT PROMPT INJECTION DETECTED: Matched pattern '{pattern}'.")
            return True
    return False
```
If an injection pattern is detected, the retrieved document is quarantined and discarded from the agent's context.

---

## 6. Boundary Layer 5: Gateway Mediation & Dual Custody

### 6.1 Action Proposals vs. Direct Execution
Under no circumstances can an agent execute direct fund transfers, payment gateway calls, or database state mutations. All sensitive operations must take the form of an *Action Proposal* submitted to `POST /api/v1/gateway/actions/propose`:

```json
{
  "agent_id": "agent-crew-finance-003",
  "action_type": "EXPENSE_DISBURSEMENT",
  "parameters": {
    "expense_id": "exp-101",
    "amount": 180.00,
    "destination": "acc-hotel-corp-55"
  },
  "tenant_id": "tenant-a-uuid-001",
  "branch_id": "branch-lhr-002"
}
```

### 6.2 Deterministic Policy Rules
The ChronoCogniSec Gateway enforces deterministic M4 policies:
- **Threshold Policy:** `amount > $300.00` triggers an unconditional `BLOCK` decision:
  ```json
  {
    "proposal_id": "prop-exp-001",
    "decision": "BLOCK",
    "reason": "Single agent limit exceeded ($300.00 USD). Dual custody approval required.",
    "execution_permitted": false
  }
  ```
- **Fail-Closed Execution Receipt:** If the Gateway returns `decision="BLOCK"`, the client raises `SecurityBoundaryViolation` if any component attempts execution.
- **No Self-Approval:** An agent submitting a proposal cannot sign or approve that proposal. Dual-custody mandates two distinct authenticated human identities.
