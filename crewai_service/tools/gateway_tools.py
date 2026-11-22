"""Protected Gateway Action Proposal Tools.

Module: crewai_service.tools.gateway_tools
Owner: ChronoCogniSec Integration Council

Enforces Complete Mediation:
- No agent has direct access to execution adapters or financial networks.
- Every protected action must submit an Action Proposal to the Gateway.
- Actions execute only when Gateway policy evaluation returns ALLOW.
- Rejection/BLOCK decisions are strictly recorded and fail-closed.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import uuid

from crewai_service.framework import tool
from crewai_service.security.boundaries import validate_gateway_execution_receipt
from crewai_service.telemetry.tracer import get_tracer
from crewai_service.tools.amsc_client import ChronoCogniSecClient

logger = logging.getLogger("amsc.crewai.tools.gateway")


class GatewayToolFactory:
    """Factory creating action proposal tools bound to ChronoCogniSec Gateway."""

    def __init__(self, client: Optional[ChronoCogniSecClient] = None) -> None:
        self.client = client or ChronoCogniSecClient()
        self.tracer = get_tracer()

    def create_expense_proposal_tool(self, agent_id: str) -> Any:
        client = self.client
        tracer = self.tracer

        @tool("propose_expense_disbursement")
        def propose_expense_disbursement(
            destination_account: str = "",
            amount: float = 0.0,
            currency: str = "USD",
            memo: str = "Corporate expense reimbursement",
            memory_refs: Optional[List[str]] = None,
            **kwargs: Any,
        ) -> str:
            """Submit a formal expense disbursement proposal to ChronoCogniSec Security Gateway.

            Returns Gateway authorization receipt. Fails closed if Gateway returns BLOCK.
            """
            import re
            # If destination_account contains serialized JSON or dict, unpack arguments safely
            if isinstance(destination_account, str) and destination_account.strip().startswith("{") and not amount:
                try:
                    import json, ast
                    raw_dict = json.loads(destination_account.strip())
                except Exception:
                    try:
                        raw_dict = ast.literal_eval(destination_account.strip())
                    except Exception:
                        raw_dict = None
                if isinstance(raw_dict, dict):
                    destination_account = raw_dict.get("destination_account") or raw_dict.get("destination") or raw_dict.get("account") or ""
                    amount = raw_dict.get("amount") or raw_dict.get("amount_usd") or 0.0
                    currency = raw_dict.get("currency") or currency
                    memo = raw_dict.get("memo") or memo
                    if not memory_refs and "memory_refs" in raw_dict:
                        memory_refs = raw_dict["memory_refs"]

            dest = destination_account or kwargs.get("destination", "") or kwargs.get("account", "acc-corp-disbursement")
            raw_amt = amount or kwargs.get("amount_usd", 0.0) or kwargs.get("amount", 0.0)
            if isinstance(raw_amt, str):
                cleaned_num = re.sub(r"[^\d.]", "", raw_amt)
                amt = float(cleaned_num) if cleaned_num else 0.0
            else:
                try:
                    amt = float(raw_amt)
                except (ValueError, TypeError):
                    amt = 0.0
            logger.info(
                f"Agent [{agent_id}] submitting expense proposal: ${amt:.2f} {currency} to '{dest}'."
            )
            action_id = f"act-exp-{uuid.uuid4().hex[:8]}"
            idempotency_key = f"idem-exp-{uuid.uuid4().hex[:12]}"
            trace_id = f"trace-exp-{uuid.uuid4().hex[:16]}"
            refs = memory_refs or kwargs.get("memory_references") or []

            parameters = {
                "destination": dest,
                "amount": float(amt),
                "currency": currency,
                "memo": memo,
            }

            # Complete mediation via Gateway API
            response = client.propose_tool_action(
                agent_id=agent_id,
                tool_name="sandbox_transfer",
                operation="transfer_funds",
                parameters=parameters,
                memory_refs=refs,
                action_id=action_id,
                idempotency_key=idempotency_key,
                trace_id=trace_id,
            )

            decision = response.get("decision", "BLOCK")
            proposal_id = response.get("proposal_id", "unknown-proposal")
            reasons = response.get("reasons", [])
            exec_status = response.get("execution_status", "NOT_EXECUTED")
            result_payload = response.get("result", {})

            # Record in Dual Trace telemetry
            run_records = tracer.list_runs()
            active_run_id = run_records[-1].run_id if run_records else f"run-{uuid.uuid4().hex[:8]}"
            tracer.record_tool_invocation(
                run_id=active_run_id,
                tool_name="sandbox_transfer",
                operation="transfer_funds",
                parameters=parameters,
                result=response,
                status="SUCCESS" if decision == "ALLOW" else "BLOCKED",
            )
            tracer.record_gateway_decision(
                run_id=active_run_id,
                proposal_id=proposal_id,
                decision=decision,
            )

            if decision == "ALLOW":
                tx_id = (result_payload or {}).get("transaction_id", f"tx-{uuid.uuid4().hex[:8]}")
                return (
                    f"GATEWAY APPROVAL [ALLOW]: Proposal '{proposal_id}' was authorized. "
                    f"Execution Status: {exec_status}. Transaction ID: {tx_id}. "
                    f"Reasons: {', '.join(reasons)}"
                )
            else:
                return (
                    f"GATEWAY REJECTION [BLOCK]: Proposal '{proposal_id}' was DENIED by policy engine. "
                    f"Execution Status: {exec_status}. "
                    f"Reasons: {', '.join(reasons)}"
                )

        return propose_expense_disbursement

    def create_support_refund_tool(self, agent_id: str) -> Any:
        client = self.client
        tracer = self.tracer

        @tool("propose_customer_refund")
        def propose_customer_refund(
            customer_account: str = "",
            refund_amount: float = 0.0,
            ticket_id: str = "",
            reason: str = "Authorized customer refund",
            memory_refs: Optional[List[str]] = None,
            **kwargs: Any,
        ) -> str:
            """Submit a customer refund proposal to ChronoCogniSec Security Gateway."""
            import re
            # If customer_account contains serialized JSON or dict, unpack arguments safely
            if isinstance(customer_account, str) and customer_account.strip().startswith("{") and not refund_amount:
                try:
                    import json, ast
                    raw_dict = json.loads(customer_account.strip())
                except Exception:
                    try:
                        raw_dict = ast.literal_eval(customer_account.strip())
                    except Exception:
                        raw_dict = None
                if isinstance(raw_dict, dict):
                    customer_account = raw_dict.get("customer_account") or raw_dict.get("destination") or raw_dict.get("account") or ""
                    refund_amount = raw_dict.get("refund_amount") or raw_dict.get("amount") or raw_dict.get("claim_amount_usd") or 0.0
                    ticket_id = raw_dict.get("ticket_id") or raw_dict.get("case_id") or ""
                    reason = raw_dict.get("reason") or reason
                    if not memory_refs and "memory_refs" in raw_dict:
                        memory_refs = raw_dict["memory_refs"]

            dest = customer_account or kwargs.get("destination", "") or kwargs.get("account", "acc-customer")
            raw_amt = refund_amount or kwargs.get("amount", 0.0) or kwargs.get("claim_amount_usd", 0.0)
            if isinstance(raw_amt, str):
                cleaned_num = re.sub(r"[^\d.]", "", raw_amt)
                amt = float(cleaned_num) if cleaned_num else 0.0
            else:
                try:
                    amt = float(raw_amt)
                except (ValueError, TypeError):
                    amt = 0.0
            tkt = ticket_id or kwargs.get("case_id", "tkt-default")
            logger.info(
                f"Agent [{agent_id}] submitting customer refund: ${amt:.2f} for ticket '{tkt}'."
            )
            action_id = f"act-ref-{uuid.uuid4().hex[:8]}"
            idempotency_key = f"idem-ref-{uuid.uuid4().hex[:12]}"
            trace_id = f"trace-ref-{uuid.uuid4().hex[:16]}"
            refs = memory_refs or kwargs.get("memory_references") or []

            parameters = {
                "destination": dest,
                "amount": float(amt),
                "currency": "USD",
                "memo": f"Refund for ticket {tkt}: {reason}",
            }

            response = client.propose_tool_action(
                agent_id=agent_id,
                tool_name="sandbox_transfer",
                operation="transfer_funds",
                parameters=parameters,
                memory_refs=refs,
                action_id=action_id,
                idempotency_key=idempotency_key,
                trace_id=trace_id,
            )

            decision = response.get("decision", "BLOCK")
            proposal_id = response.get("proposal_id", "unknown-proposal")
            reasons = response.get("reasons", [])
            exec_status = response.get("execution_status", "NOT_EXECUTED")

            # Telemetry
            run_records = tracer.list_runs()
            active_run_id = run_records[-1].run_id if run_records else f"run-{uuid.uuid4().hex[:8]}"
            tracer.record_tool_invocation(
                run_id=active_run_id,
                tool_name="sandbox_transfer",
                operation="transfer_funds",
                parameters=parameters,
                result=response,
                status="SUCCESS" if decision == "ALLOW" else "BLOCKED",
            )
            tracer.record_gateway_decision(
                run_id=active_run_id,
                proposal_id=proposal_id,
                decision=decision,
            )

            if decision == "ALLOW":
                return (
                    f"GATEWAY APPROVAL [ALLOW]: Customer refund proposal '{proposal_id}' authorized. "
                    f"Execution Status: {exec_status}. Reasons: {', '.join(reasons)}"
                )
            return (
                f"GATEWAY REJECTION [BLOCK]: Customer refund proposal '{proposal_id}' BLOCKED. "
                f"Reasons: {', '.join(reasons)}"
            )

        return propose_customer_refund
