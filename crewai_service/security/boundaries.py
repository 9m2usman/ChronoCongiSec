"""Security Boundaries, Autonomy Limits & Prompt Guard.

Module: crewai_service.security.boundaries
Owner: ChronoCogniSec AMSC Governance Council

Enforces:
- Least privilege.
- Explicit tenant isolation.
- Branch-level scoping (Head Office vs Lahore, Karachi, Islamabad).
- Tool-level permission bounds.
- Trust validation: only TRUSTED memory may back agent action.
- Complete mediation: protected actions require Gateway ALLOW.
- Indirect prompt injection detection on untrusted retrieved data.
- Fail-closed behavior on security anomalies.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("amsc.crewai.security")


class SecurityBoundaryViolation(Exception):
    """Raised when an agent violates tenant, branch, trust, or tool boundaries."""
    pass


class PromptInjectionDetected(SecurityBoundaryViolation):
    """Raised when untrusted text contains adversarial prompt injection instructions."""
    pass


# High-confidence indirect prompt injection signatures (AgentDojo / AMSC-DOC-007)
INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions"),
    re.compile(r"(?i)system\s+override"),
    re.compile(r"(?i)you\s+are\s+now\s+in\s+developer\s+mode"),
    re.compile(r"(?i)bypass\s+(the\s+)?(security\s+)?gateway"),
    re.compile(r"(?i)approve\s+(your\s+own|this)\s+(action|transfer|proposal)"),
    re.compile(r"(?i)exfiltrate\s+(all\s+)?(data|credentials|tokens|passwords)"),
    re.compile(r"(?i)grant\s+yourself\s+(admin|superuser|unrestricted)\s+permissions"),
]


def enforce_tenant_isolation(caller_tenant_id: str, target_tenant_id: str) -> None:
    """Enforce strict multi-tenant boundary. Cross-tenant access is strictly forbidden."""
    if not caller_tenant_id or not target_tenant_id:
        raise SecurityBoundaryViolation("Tenant identification cannot be empty.")
    if caller_tenant_id != target_tenant_id:
        logger.error(
            f"SECURITY BREACH ATTEMPT: Caller tenant '{caller_tenant_id}' attempted cross-tenant access to '{target_tenant_id}'."
        )
        raise SecurityBoundaryViolation(
            f"Cross-tenant data access rejected: '{caller_tenant_id}' cannot access '{target_tenant_id}'."
        )


def enforce_branch_scope(
    agent_branch_id: str,
    target_branch_id: str,
    head_office_branch_id: str = "branch-ho-001",
) -> None:
    """Enforce branch operational boundaries.

    Regional branch agents (Lahore, Karachi, Islamabad) can only access their assigned branch.
    Head Office agents have enterprise-wide supervisory access.
    """
    if not agent_branch_id or not target_branch_id:
        raise SecurityBoundaryViolation("Branch identifiers cannot be empty.")

    # Head Office supervisor has enterprise scope
    if agent_branch_id == head_office_branch_id:
        return

    # Regional branch agents must match target branch
    if agent_branch_id != target_branch_id:
        logger.error(
            f"BRANCH ISOLATION BREACH: Agent assigned to '{agent_branch_id}' attempted unauthorized access to branch '{target_branch_id}'."
        )
        raise SecurityBoundaryViolation(
            f"Unauthorized branch access: Agent in '{agent_branch_id}' cannot access or operate on branch '{target_branch_id}'."
        )


def validate_memory_trust(trust_state: str, memory_id: str) -> None:
    """Enforce that only TRUSTED memories can back agent reasoning or actions."""
    if not trust_state:
        raise SecurityBoundaryViolation(f"Memory '{memory_id}' has missing trust state.")

    clean_state = trust_state.upper().strip()
    if clean_state != "TRUSTED":
        logger.warning(
            f"UNTRUSTED MEMORY ACCESS BLOCKED: Memory '{memory_id}' is in non-trusted state '{clean_state}'."
        )
        raise SecurityBoundaryViolation(
            f"Memory record '{memory_id}' is in state '{clean_state}' and cannot be used for agent operations. Only TRUSTED memory is eligible."
        )


def scan_for_indirect_injection(text: str, context_label: str = "document") -> None:
    """Scan retrieved documents or untrusted inputs for prompt injection attack patterns."""
    if not text:
        return

    for pattern in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            adversarial_phrase = match.group(0)
            logger.critical(
                f"INDIRECT PROMPT INJECTION DETECTED in {context_label}: '{adversarial_phrase}'."
            )
            raise PromptInjectionDetected(
                f"Malicious indirect prompt injection instruction detected in {context_label}: '{adversarial_phrase}'."
            )


def validate_gateway_execution_receipt(decision: str, proposal_id: str) -> None:
    """Enforce that protected actions can ONLY execute when Gateway returns ALLOW."""
    if decision != "ALLOW":
        logger.error(
            f"PROTECTED ACTION BLOCKED: Proposal '{proposal_id}' received Gateway decision '{decision}'."
        )
        raise SecurityBoundaryViolation(
            f"Action execution prohibited: Gateway returned '{decision}' for proposal '{proposal_id}'."
        )


def enforce_no_self_approval(proposer_id: str, approver_id: str) -> None:
    """Enforce strict separation of duties: Agents cannot approve their own action proposals."""
    if not proposer_id or not approver_id:
        raise SecurityBoundaryViolation("Proposer and approver identities cannot be empty.")
    if proposer_id.strip() == approver_id.strip():
        logger.error(
            f"SELF-APPROVAL BREACH ATTEMPT: Agent '{proposer_id}' attempted to approve its own proposal."
        )
        raise SecurityBoundaryViolation(
            f"Self-approval prohibited: Proposer '{proposer_id}' cannot approve its own action proposal. Approval requires independent human manager authorization."
        )


def enforce_tool_authorization(agent_role: str, tool_name: str, allowed_tool_names: Set[str]) -> None:
    """Enforce tool-level permissions: Reject any tool not explicitly granted to the agent."""
    if not tool_name or not tool_name.strip():
        raise SecurityBoundaryViolation("Tool name cannot be empty.")
    if tool_name not in allowed_tool_names:
        logger.error(
            f"UNAUTHORIZED TOOL INVOCATION: Agent '{agent_role}' attempted to execute unauthorized tool '{tool_name}'. Allowed: {sorted(list(allowed_tool_names))}"
        )
        raise SecurityBoundaryViolation(
            f"Unauthorized tool operation: Agent '{agent_role}' attempted to execute unauthorized tool '{tool_name}'. Allowed tools: {sorted(list(allowed_tool_names))}"
        )

