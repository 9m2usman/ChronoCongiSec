"""Tests for Agent 1: Customer Support Specialist.

Module: crewai_service.tests.test_customer_support
Owner: ChronoCogniSec QA Council
"""

import pytest

from crewai_service.agents.customer_support import (
    SupportResolutionOutput,
    SupportTicketInput,
    build_customer_support_agent,
    process_customer_support_ticket,
)
from crewai_service.telemetry.tracer import get_tracer


def test_customer_support_retrieves_knowledge_and_resolves_ticket(test_double_llm, mock_amsc_client):
    """Scenario 1: Customer Support retrieves approved knowledge and prepares a response."""
    agent = build_customer_support_agent(llm=test_double_llm, client=mock_amsc_client)
    ticket = SupportTicketInput(
        ticket_id="tkt-101",
        customer_id="cust-001",
        issue_description="Customer asking if they can return a purchased device within 10 days.",
        requested_action="Return device for refund",
        claim_amount_usd=150.00,
        urgency="NORMAL",
    )

    result = process_customer_support_ticket(ticket=ticket, agent=agent, client=mock_amsc_client)

    assert isinstance(result, SupportResolutionOutput)
    assert result.ticket_id == "tkt-101"
    assert result.escalated is False
    assert len(result.resolution_text) > 0
    assert "mem-supp-faq-001" in result.memory_references

    # Verify Dual Trace telemetry was emitted
    tracer = get_tracer()
    runs = tracer.list_runs()
    assert len(runs) >= 1
    assert runs[-1].agent_role == "Customer Support Specialist"
    assert runs[-1].status == "COMPLETED"


def test_customer_support_escalates_abusive_or_fraudulent_ticket(test_double_llm, mock_amsc_client, monkeypatch):
    """Verify customer support specialist escalates sensitive/fraudulent tickets."""
    agent = build_customer_support_agent(llm=test_double_llm, client=mock_amsc_client)
    
    # Configure mock to simulate an escalated response
    monkeypatch.setattr(
        test_double_llm,
        "complete",
        lambda prompt: '{"ticket_id": "tkt-fraud-999", "classification": "FRAUD_INVESTIGATION", "priority": "CRITICAL", "resolution_text": "Case escalated to Security Supervisor due to suspected account takeover.", "action_taken": "ESCALATED", "escalated": true, "escalation_reason": "Suspected unauthorized account takeover", "memory_references": []}',
    )

    ticket = SupportTicketInput(
        ticket_id="tkt-fraud-999",
        customer_id="cust-suspicious-88",
        issue_description="Urgent account takeover suspected with disputed fraudulent withdrawals.",
        urgency="CRITICAL",
    )

    result = process_customer_support_ticket(ticket=ticket, agent=agent, client=mock_amsc_client)
    assert result.escalated is True
    assert result.priority == "CRITICAL"
    assert "escalated" in result.action_taken.lower()
