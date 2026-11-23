"""ChronoCogniSec CrewAI Business Agents Service Entry Point.

Module: crewai_service.main
Owner: ChronoCogniSec AI Engineering Council

Provides CLI runner and orchestration entry point for the five genuine
CrewAI business agents in the simulated enterprise company.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("amsc.crewai.main")

from crewai_service.agents.branch_operations import (
    BranchRequestInput,
    build_branch_operations_agent,
    process_branch_request,
)
from crewai_service.agents.customer_support import (
    SupportTicketInput,
    build_customer_support_agent,
    process_customer_support_ticket,
)
from crewai_service.agents.finance_operations import (
    ExpenseAuditInput,
    audit_and_propose_expense,
    build_finance_operations_agent,
)
from crewai_service.agents.hr_operations import (
    HRRequestInput,
    build_hr_operations_agent,
    process_hr_request,
)
from crewai_service.agents.workflow_coordinator import (
    EnterpriseWorkflowInput,
    build_workflow_coordinator_agent,
    execute_enterprise_workflow,
)
from crewai_service.config.provider import (
    GeminiLLMAdapter,
    TestDoubleLLMAdapter,
    get_llm_adapter,
)
from crewai_service.config.settings import (
    CrewAISettings,
    ExecutionMode,
    SupportedProvider,
    get_crewai_settings,
)
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.tools.amsc_client import ChronoCogniSecClient
from crewai_service.workflows.flows import EnterpriseLifecycleFlow


def run_synthetic_demonstration(
    mode: Optional[str] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> int:
    """Run genuine end-to-end multi-agent demonstration across the simulated enterprise."""
    print("=" * 80)
    print("  ChronoCogniSec: Five Genuine CrewAI Business Agents in Simulated Enterprise")
    print("=" * 80)

    settings = get_crewai_settings()
    if mode is not None:
        settings.EXECUTION_MODE = ExecutionMode(mode)
    if provider is not None:
        settings.LLM_PROVIDER = SupportedProvider(provider)
    if model is not None:
        settings.LLM_MODEL = model

    try:
        settings.validate_provider_configuration()
    except ValueError as e:
        print(f"\n[CONFIGURATION ERROR] {e}")
        print("Tip: To run the offline demonstration without external API keys, execute:")
        print("     python -m crewai_service.main --mode test_double\n")
        return 1

    print(f"Execution Mode: {settings.EXECUTION_MODE.value.upper()}")
    print(f"LLM Provider:   {settings.LLM_PROVIDER.value.upper()} (Model: {settings.LLM_MODEL})")
    print(f"Tenant ID:      {settings.CHRONOCONGISEC_TENANT_ID} (ChronoCogniSec Enterprise)")
    print(f"Branches:       Head Office, Lahore, Karachi, Islamabad")
    print("-" * 80)

    client = ChronoCogniSecClient()
    auth_ok = client.authenticate()
    if auth_ok:
        print(f"Enterprise Auth: Authenticated as {client.auth_email} (Tenant: {client.tenant_id})")
    else:
        print(f"Enterprise Auth: Operating in fallback/fail-closed mode (Tenant: {client.tenant_id})")
    tracer = get_tracer()
    llm = get_llm_adapter(settings=settings)

    print(f"LLM Adapter:    {llm.__class__.__name__} (is_real_execution={llm.is_real_execution})")
    print("-" * 80)

    has_agent_errors = False

    # 1. Agent 1: Customer Support Specialist
    support_res = None
    support_ticket = SupportTicketInput(
        ticket_id="tkt-support-101",
        customer_id="cust-enterprise-500",
        issue_description="Customer requesting standard return and refund within 10 days of purchase with valid receipt.",
        requested_action="Full refund under 14-day policy",
        claim_amount_usd=120.00,
        urgency="HIGH",
    )
    try:
        print("\n[AGENT 1] Customer Support Specialist: Processing Ticket...")
        support_agent = build_customer_support_agent(llm=llm, client=client)
        support_res = process_customer_support_ticket(ticket=support_ticket, agent=support_agent, client=client)
        print(f"  Result: Ticket {support_res.ticket_id} [{support_res.classification}]")
        print(f"  Action: {support_res.action_taken}")
        print(f"  Summary: {support_res.resolution_text[:140]}...")
    except Exception as exc:
        has_agent_errors = True
        print(f"  [AGENT 1 ERROR] Customer Support failed: {exc}")

    # 2. Agent 2: HR Operations Specialist
    hr_res = None
    hr_request = HRRequestInput(
        request_id="hr-req-202",
        employee_id="emp-lhr-042",
        request_type="LEAVE_APPLICATION",
        details="Senior Software Engineer requesting 5 consecutive working days of annual leave.",
        requested_days=5,
    )
    try:
        print("\n[AGENT 2] HR Operations Specialist: Processing Leave Request...")
        hr_agent = build_hr_operations_agent(llm=llm, client=client)
        hr_res = process_hr_request(request_data=hr_request, agent=hr_agent, client=client)
        print(f"  Result: Request {hr_res.request_id} -> Status: {hr_res.status}")
        print(f"  Policy: {hr_res.policy_reference}")
        print(f"  Explanation: {hr_res.explanation[:140]}...")
    except Exception as exc:
        has_agent_errors = True
        print(f"  [AGENT 2 ERROR] HR Operations failed: {exc}")

    # 3. Agent 3: Finance Operations Specialist
    finance_res = None
    expense_item = ExpenseAuditInput(
        expense_id="exp-audit-303",
        claimant_id="emp-dev-010",
        destination_account="acc-vendor-cloud-77",
        amount_usd=195.00,
        category="CLOUD_HOSTING_INFRASTRUCTURE",
        receipt_attached=True,
        memo="Monthly container cluster staging reimbursement",
    )
    try:
        print("\n[AGENT 3] Finance Operations Specialist: Auditing Expense & Proposing Gateway Action...")
        finance_agent = build_finance_operations_agent(llm=llm, client=client)
        finance_res = audit_and_propose_expense(expense=expense_item, agent=finance_agent, client=client)
        print(f"  Result: Expense {finance_res.expense_id} -> Status: {finance_res.audit_status}")
        print(f"  Gateway Proposal ID: {finance_res.gateway_proposal_id}")
        print(f"  Gateway Decision:    {finance_res.gateway_decision}")
        print(f"  Dual Custody Needed: {finance_res.dual_custody_required}")
    except Exception as exc:
        has_agent_errors = True
        print(f"  [AGENT 3 ERROR] Finance Operations failed: {exc}")

    # 4. Agent 4: Branch Operations Specialist
    branch_res = None
    branch_req = BranchRequestInput(
        request_id="br-req-404",
        target_branch_id="branch-khi-003",
        category="FACILITY_STATUS",
        details="Weekly maritime logistics token inventory and vault temperature check.",
    )
    try:
        print("\n[AGENT 4] Branch Operations Specialist: Regional Facility Logistics (Karachi)...")
        branch_agent = build_branch_operations_agent(
            llm=llm, client=client, branch_id="branch-khi-003"
        )
        branch_res = process_branch_request(
            request_data=branch_req, agent=branch_agent, client=client
        )
        print(f"  Result: Branch Request {branch_res.request_id} -> Status: {branch_res.status}")
        print(f"  Head Office Synced:   {branch_res.head_office_synced}")
        print(f"  Security Flagged:     {branch_res.security_violation_flagged}")
    except Exception as exc:
        has_agent_errors = True
        print(f"  [AGENT 4 ERROR] Branch Operations failed: {exc}")

    # 5. Agent 5: Enterprise Workflow Coordinator (CrewAI Flow)
    try:
        print("\n[AGENT 5] Enterprise Workflow Coordinator: Cross-Department Flow Execution...")
        wf_input = EnterpriseWorkflowInput(
            workflow_id="wf-ent-505",
            initiative_title="Q4 Regional Branch Security & Equipment Upgrade Initiative",
            description="Cross-functional initiative auditing branch logistics, staff onboarding, customer support alignment, and equipment expense approval.",
            support_ticket=support_ticket,
            hr_request=hr_request,
            finance_expense=expense_item,
            branch_request=branch_req,
            support_result=support_res,
            hr_result=hr_res,
            finance_result=finance_res,
            branch_result=branch_res,
        )
        flow = EnterpriseLifecycleFlow(workflow_input=wf_input, client=client, llm=llm)
        report = flow.kickoff()
        print(f"\n  Consolidated Report Status: {report.status}")
        print(f"  Specialists Engaged:        {', '.join(report.specialists_engaged)}")
        print(f"  All Security Checks Passed: {report.all_security_controls_satisfied}")
        print(f"  Executive Assessment:       {report.consolidated_assessment[:200]}...")
    except Exception as exc:
        has_agent_errors = True
        print(f"  [AGENT 5 ERROR] Workflow Coordinator failed: {exc}")

    # Dual Trace Telemetry Summary
    runs = tracer.list_runs()
    print("\n" + "=" * 80)
    print(f"  Dual Trace Execution Observability Summary ({len(runs)} Total Runs Recorded)")
    print("=" * 80)
    for r in runs:
        print(f"- Run [{r.run_id}] | Task [{r.task_id}] | Agent: {r.agent_role}")
        print(f"  Status: {r.status} | Model: {r.model_identifier} | Tool Calls: {len(r.tool_invocations)}")
        if r.gateway_proposal_ids:
            print(f"  Gateway Proposals: {', '.join(r.gateway_proposal_ids)} (Decisions: {', '.join(r.policy_decisions)})")

    if has_agent_errors:
        print("\n[PARTIAL EXECUTION] Multi-agent execution completed with errors. See telemetry above.")
        return 1

    print("\n[SUCCESS] Genuine CrewAI Five-Agent Business System successfully executed.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="ChronoCogniSec CrewAI Business Agents Service")
    parser.add_argument("--mode", choices=["live", "test_double"], default=None, help="Execution mode (defaults to .env)")
    parser.add_argument("--provider", choices=["gemini", "openai", "test_double"], default=None, help="LLM Provider (defaults to .env)")
    parser.add_argument("--model", default=None, help="LLM Model identifier (defaults to .env)")
    parser.add_argument("--demo", type=int, choices=[1, 2, 3], default=None, help="Run specific scenario demo (e.g. 2 for Sandbox Adapter Demo)")
    args = parser.parse_args()

    if args.demo == 2:
        from demo.run_demo2 import run_demo2
        exit_code = run_demo2(live=(args.mode == "live"))
        sys.exit(exit_code)

    try:
        exit_code = run_synthetic_demonstration(
            mode=args.mode,
            provider=args.provider,
            model=args.model,
        )
        sys.exit(exit_code)
    except Exception as exc:
        print(f"\n[AGENT EXECUTION ERROR] {exc}\n")
        print("Tip: If using live LLM providers, verify that your API key in crewai_service/.env is valid.")
        print("     To run the complete offline demonstration without any external keys, run:")
        print("     python -m crewai_service.main --mode test_double\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
