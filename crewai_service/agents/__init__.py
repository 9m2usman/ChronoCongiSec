"""ChronoCogniSec Genuine CrewAI Business Agents Package."""

from crewai_service.agents.customer_support import (
    SupportResolutionOutput,
    SupportTicketInput,
    build_customer_support_agent,
    process_customer_support_ticket,
)
from crewai_service.agents.hr_operations import (
    HRRequestInput,
    HRResolutionOutput,
    build_hr_operations_agent,
    process_hr_request,
)
from crewai_service.agents.finance_operations import (
    ExpenseAuditInput,
    ExpenseAuditOutput,
    audit_and_propose_expense,
    build_finance_operations_agent,
)
from crewai_service.agents.branch_operations import (
    BranchOperationOutput,
    BranchRequestInput,
    build_branch_operations_agent,
    process_branch_request,
)
from crewai_service.agents.workflow_coordinator import (
    EnterpriseWorkflowInput,
    EnterpriseWorkflowReport,
    build_workflow_coordinator_agent,
    execute_enterprise_workflow,
)

__all__ = [
    # Agent 1
    "SupportResolutionOutput",
    "SupportTicketInput",
    "build_customer_support_agent",
    "process_customer_support_ticket",
    # Agent 2
    "HRRequestInput",
    "HRResolutionOutput",
    "build_hr_operations_agent",
    "process_hr_request",
    # Agent 3
    "ExpenseAuditInput",
    "ExpenseAuditOutput",
    "audit_and_propose_expense",
    "build_finance_operations_agent",
    # Agent 4
    "BranchOperationOutput",
    "BranchRequestInput",
    "build_branch_operations_agent",
    "process_branch_request",
    # Agent 5
    "EnterpriseWorkflowInput",
    "EnterpriseWorkflowReport",
    "build_workflow_coordinator_agent",
    "execute_enterprise_workflow",
]
