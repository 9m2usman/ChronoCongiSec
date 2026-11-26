"""Phase 3 company-workspace tools for CrewAI agents.

Module: crewai_service.tools.company_tools

Every tool here submits an ActionProposal for the protected ``company_workspace``
gateway tool. Agents never touch company storage or the database: the gateway,
M4 policy guard and the server-side company adapter decide and execute.

Fail-closed rules:
* Tools never accept tenant, branch, user or role arguments. Scope is derived by
  the server from the authenticated employee session and the agent's governed
  security profile.
* If the client cannot reach a real gateway (``TEST_DOUBLE`` mode without an
  in-process app), the tool refuses instead of using the client's simulated
  decisions, so no fabricated company operation is ever reported.
* Only an ``ALLOW`` decision with ``execution_status == "EXECUTED"`` is reported
  as completed. BLOCK, REQUIRES_APPROVAL, FAILED and UNKNOWN are surfaced as-is.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional

from crewai_service.framework import tool
from crewai_service.tools.amsc_client import ChronoCogniSecClient

logger = logging.getLogger("amsc.crewai.tools.company")

COMPANY_TOOL_NAME = "company_workspace"

# Operations each seeded agent is designed for. The server-side grant is the
# authority; this only limits which tools are offered to the agent.
BRANCH_OPERATIONS_COMPANY_OPERATIONS = (
    "list_workspaces", "list_files", "read_file", "create_file", "update_file",
    "transfer_file", "create_task", "update_task_status", "handoff_task",
    "send_message", "read_inbox",
)
COORDINATOR_COMPANY_OPERATIONS = (
    "list_workspaces", "list_files", "read_file", "create_task",
    "update_task_status", "handoff_task", "send_message", "read_inbox",
)


class GatewayUnavailableError(RuntimeError):
    """Raised when no real gateway is reachable; company tools fail closed."""


class CompanyWorkspaceClient:
    """Runtime-neutral proposal helper shared by CrewAI tools and other adapters."""

    def __init__(self, client: ChronoCogniSecClient, agent_id: str) -> None:
        if not agent_id:
            raise ValueError("agent_id is required.")
        self.client = client
        self.agent_id = agent_id

    def _gateway_reachable(self) -> bool:
        is_double = getattr(self.client, "_is_test_double_mode", lambda: False)()
        return not (is_double and getattr(self.client, "_app", None) is None)

    def propose(
        self,
        operation: str,
        parameters: Dict[str, Any],
        *,
        trace_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._gateway_reachable():
            raise GatewayUnavailableError(
                "No ChronoCongiSec gateway is reachable; company operations fail closed."
            )
        return self.client.propose_tool_action(
            agent_id=self.agent_id,
            tool_name=COMPANY_TOOL_NAME,
            operation=operation,
            parameters=dict(parameters),
            memory_refs=[],
            action_id=f"act-{operation[:24]}-{uuid.uuid4().hex[:12]}",
            idempotency_key=idempotency_key or f"idem-{uuid.uuid4().hex}",
            trace_id=trace_id or f"trace-{uuid.uuid4().hex[:24]}",
        )


def summarize_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]:
    decision = receipt.get("decision", "BLOCK")
    status = receipt.get("execution_status", "NOT_EXECUTED")
    result = receipt.get("result") or {}
    completed = decision == "ALLOW" and status == "EXECUTED"
    summary: Dict[str, Any] = {
        "completed": completed,
        "decision": decision,
        "execution_status": status,
        "proposal_id": receipt.get("proposal_id"),
        "reason_codes": receipt.get("reason_codes", []),
    }
    if completed:
        summary["result"] = result.get("result")
    elif isinstance(result, dict) and result.get("error"):
        summary["error"] = result.get("error")
        summary["error_code"] = result.get("error_code")
    else:
        summary["reasons"] = receipt.get("reasons", [])
    return summary


class CompanyWorkspaceToolFactory:
    """Builds CrewAI tools for the protected company workspace."""

    def __init__(self, client: Optional[ChronoCogniSecClient] = None, agent_id: str = "") -> None:
        self.workspace = CompanyWorkspaceClient(client or ChronoCogniSecClient(), agent_id)

    def _run(self, operation: str, parameters: Dict[str, Any]) -> str:
        try:
            receipt = self.workspace.propose(operation, parameters)
        except GatewayUnavailableError as exc:
            logger.warning("Company operation %s refused: %s", operation, exc)
            return json.dumps({
                "completed": False, "decision": "BLOCK", "execution_status": "NOT_EXECUTED",
                "error": str(exc), "error_code": "GATEWAY_UNAVAILABLE",
            })
        return json.dumps(summarize_receipt(receipt), default=str)

    def create_tools(self, operations: Iterable[str]) -> List[Any]:
        builders: Dict[str, Callable[[], Any]] = {
            "list_workspaces": self._list_workspaces,
            "list_files": self._list_files,
            "read_file": self._read_file,
            "create_file": self._create_file,
            "update_file": self._update_file,
            "transfer_file": self._transfer_file,
            "create_task": self._create_task,
            "update_task_status": self._update_task_status,
            "handoff_task": self._handoff_task,
            "send_message": self._send_message,
            "read_inbox": self._read_inbox,
        }
        unknown = [op for op in operations if op not in builders]
        if unknown:
            raise ValueError(f"Unknown company operations: {unknown}")
        return [builders[op]() for op in operations]

    # Each builder returns one CrewAI tool bound to a single gateway operation.

    def _list_workspaces(self) -> Any:
        @tool("company_list_workspaces")
        def company_list_workspaces() -> str:
            """List company workspaces visible to you in your authorized branch (via the security gateway)."""
            return self._run("list_workspaces", {})
        return company_list_workspaces

    def _list_files(self) -> Any:
        @tool("company_list_files")
        def company_list_files(workspace_id: str) -> str:
            """List active files in a company workspace (via the security gateway)."""
            return self._run("list_files", {"workspace_id": workspace_id})
        return company_list_files

    def _read_file(self) -> Any:
        @tool("company_read_file")
        def company_read_file(file_id: str) -> str:
            """Read the current version of a company file (via the security gateway)."""
            return self._run("read_file", {"file_id": file_id})
        return company_read_file

    def _create_file(self) -> Any:
        @tool("company_create_file")
        def company_create_file(workspace_id: str, name: str, content: str,
                                content_type: str = "text/plain") -> str:
            """Create a new company file in a workspace you own (via the security gateway)."""
            return self._run("create_file", {
                "workspace_id": workspace_id, "name": name, "content": content, "content_type": content_type,
            })
        return company_create_file

    def _update_file(self) -> Any:
        @tool("company_update_file")
        def company_update_file(file_id: str, content: str, name: Optional[str] = None) -> str:
            """Save a new version of a company file you own (via the security gateway)."""
            params: Dict[str, Any] = {"file_id": file_id, "content": content}
            if name:
                params["name"] = name
            return self._run("update_file", params)
        return company_update_file

    def _transfer_file(self) -> Any:
        @tool("company_transfer_file")
        def company_transfer_file(file_id: str, recipient_user_id: str, message: Optional[str] = None) -> str:
            """Offer a company file to a colleague. High impact: requires human approval at the gateway."""
            params: Dict[str, Any] = {"file_id": file_id, "recipient_user_id": recipient_user_id}
            if message:
                params["message"] = message
            return self._run("transfer_file", params)
        return company_transfer_file

    def _create_task(self) -> Any:
        @tool("company_create_task")
        def company_create_task(workspace_id: str, title: str, description: Optional[str] = None,
                                assigned_to_user_id: Optional[str] = None, priority: str = "NORMAL") -> str:
            """Create a company task in a workspace (via the security gateway)."""
            params: Dict[str, Any] = {"workspace_id": workspace_id, "title": title, "priority": priority}
            if description:
                params["description"] = description
            if assigned_to_user_id:
                params["assigned_to_user_id"] = assigned_to_user_id
            return self._run("create_task", params)
        return company_create_task

    def _update_task_status(self) -> Any:
        @tool("company_update_task_status")
        def company_update_task_status(task_id: str, status: str) -> str:
            """Move a company task to OPEN, IN_PROGRESS, BLOCKED, COMPLETED or CANCELLED (via the gateway)."""
            return self._run("update_task_status", {"task_id": task_id, "status": status})
        return company_update_task_status

    def _handoff_task(self) -> Any:
        @tool("company_handoff_task")
        def company_handoff_task(task_id: str, assigned_to_user_id: str) -> str:
            """Hand a company task off to a colleague in the task's branch (via the security gateway)."""
            return self._run("handoff_task", {"task_id": task_id, "assigned_to_user_id": assigned_to_user_id})
        return company_handoff_task

    def _send_message(self) -> Any:
        @tool("company_send_message")
        def company_send_message(recipient_user_id: str, body: str, subject: str = "") -> str:
            """Send an internal company message to a colleague (via the security gateway)."""
            return self._run("send_message", {
                "recipient_user_id": recipient_user_id, "subject": subject, "body": body,
            })
        return company_send_message

    def _read_inbox(self) -> Any:
        @tool("company_read_inbox")
        def company_read_inbox() -> str:
            """Read the internal company inbox of the employee you are acting for (via the gateway)."""
            return self._run("read_inbox", {})
        return company_read_inbox
