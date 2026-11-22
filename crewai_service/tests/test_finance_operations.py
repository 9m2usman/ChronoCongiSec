"""Tests for Agent 3: Finance Operations Specialist.

Module: crewai_service.tests.test_finance_operations
Owner: ChronoCogniSec QA Council
"""

import pytest

from crewai_service.agents.finance_operations import (
    ExpenseAuditInput,
    ExpenseAuditOutput,
    audit_and_propose_expense,
    build_finance_operations_agent,
)
from crewai_service.telemetry.tracer import get_tracer


def test_finance_reviews_expense_and_proposes_approval(test_double_llm, mock_amsc_client):
    """Scenario 3: Finance reviews a synthetic expense request and prepares an approval proposal."""
    agent = build_finance_operations_agent(llm=test_double_llm, client=mock_amsc_client)
    expense = ExpenseAuditInput(
        expense_id="exp-101",
        claimant_id="emp-sales-01",
        destination_account="acc-hotel-corp-55",
        amount_usd=180.00,
        category="TRAVEL_ACCOMMODATION",
        receipt_attached=True,
    )

    result = audit_and_propose_expense(expense=expense, agent=agent, client=mock_amsc_client)

    assert isinstance(result, ExpenseAuditOutput)
    assert result.expense_id == "exp-101"
    assert result.audit_status == "PROPOSAL_SUBMITTED"
    assert result.gateway_decision == "ALLOW"
    assert result.dual_custody_required is False
    assert result.gateway_proposal_id is not None

    # Check Dual Trace records
    tracer = get_tracer()
    runs = tracer.list_runs()
    assert len(runs) >= 1
    assert runs[-1].agent_role == "Finance Operations Specialist"
    assert "prop-test-allowed" in runs[-1].gateway_proposal_ids or "ALLOW" in runs[-1].policy_decisions


def test_finance_blocks_expense_exceeding_dual_custody_threshold(test_double_llm, mock_amsc_client):
    """Scenario 11: Finance proposal exceeding $300 receives a BLOCK decision."""
    agent = build_finance_operations_agent(llm=test_double_llm, client=mock_amsc_client)
    large_expense = ExpenseAuditInput(
        expense_id="exp-large-505",
        claimant_id="emp-exec-02",
        destination_account="acc-luxury-travel-99",
        amount_usd=1200.00,  # Exceeds $300 threshold
        category="CONFERENCE_EXPENSE",
        receipt_attached=True,
    )

    result = audit_and_propose_expense(expense=large_expense, agent=agent, client=mock_amsc_client)

    assert result.audit_status == "BLOCKED_BY_GATEWAY"
    assert result.gateway_decision == "BLOCK"
    assert result.dual_custody_required is True


def test_finance_rejects_expense_without_receipt(test_double_llm, mock_amsc_client):
    """Verify finance specialist rejects expense requests missing receipts."""
    agent = build_finance_operations_agent(llm=test_double_llm, client=mock_amsc_client)
    no_receipt = ExpenseAuditInput(
        expense_id="exp-no-rec-007",
        claimant_id="emp-dev-03",
        destination_account="acc-unverified-44",
        amount_usd=50.00,
        category="MEALS",
        receipt_attached=False,
    )

    result = audit_and_propose_expense(expense=no_receipt, agent=agent, client=mock_amsc_client)
    assert result.audit_status == "REJECTED_MISSING_RECEIPT"
    assert result.gateway_decision == "BLOCK"
