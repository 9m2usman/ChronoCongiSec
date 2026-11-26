"""Phase 3 protected company-operations adapter (``company_workspace`` tool).

This adapter is the *only* agent-facing path into the Phase 2 company
application. It is reached exclusively through the ChronoCongiSec Gateway:

    Agent -> ActionProposal -> Gateway (/api/v1/gateway/actions)
          -> M4 PolicyEngine + ProtectedExecutionGuard (ALLOW only)
          -> CompanyOperationsAdapter.execute(...)
          -> Phase 2 company service handlers (one PostgreSQL transaction each)

Security properties (all enforced server side, fail closed):

* The authorization scope comes only from the gateway's authenticated execution
  context (tenant, employee, role, branch). Parameters that try to name a
  tenant, branch, user or role are rejected, never honoured.
* The employee must hold an ACTIVE membership whose branch and role match the
  authenticated context; the tenant must be ACTIVE.
* The agent must be ACTIVE and have an ACTIVE governed ``AgentSecurityProfile``
  whose ``data_scope`` covers the employee's branch and the branch of every
  resource the operation touches (``branch:<branch_id>:*``).
* Business authorization and persistence are delegated unchanged to the
  Phase 2 handlers in ``backend.app.api.company``; this module never writes
  company tables itself and never re-implements Phase 2 rules.
* Any failure returns ``ToolExecutionResult(status="FAILED")`` with an honest
  HTTP status; the gateway records it as FAILED, never as success.
"""
from __future__ import annotations

import logging
import time
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Tuple, Type

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from backend.app.core.exceptions import AMSCException
from backend.app.company.service import CompanyResourceService

from backend.app.database.models.agents import Agent
from backend.app.database.models.baseline import AgentSecurityProfile
from backend.app.database.models.company import CompanyFile, CompanyFileVersion, CompanyMessage, CompanyTask, CompanyWorkspace
from backend.app.database.models.identity import Membership, Tenant
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.gateway.company_adapter")

TOOL_NAME = "company_workspace"

_ID = r"^[A-Za-z0-9_.:-]{1,128}$"

# Keys an agent might use to try to choose its own authorization scope.
FORBIDDEN_SCOPE_KEYS = frozenset({
    "tenant_id", "tenant", "branch_id", "branch", "user_id", "acting_user_id",
    "actor_user_id", "sender_user_id", "owner_user_id", "created_by_user_id",
    "role", "is_admin", "agent_id", "scope", "data_scope",
})

REQUIRED_CONTEXT_KEYS = (
    "tenant_id", "agent_id", "idempotency_key", "trace_id", "proposal_id", "user_id", "role",
)


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


class _ListWorkspaces(_Params):
    pass


class _ListFiles(_Params):
    workspace_id: str = Field(pattern=_ID)


class _ReadFile(_Params):
    file_id: str = Field(pattern=_ID)


class _CreateFile(_Params):
    workspace_id: str = Field(pattern=_ID)
    name: str = Field(min_length=1, max_length=255)
    content: str = Field(max_length=200_000)
    content_type: str = Field(default="text/plain", max_length=128)


class _UpdateFile(_Params):
    file_id: str = Field(pattern=_ID)
    content: str = Field(max_length=200_000)
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)


class _TransferFile(_Params):
    file_id: str = Field(pattern=_ID)
    recipient_user_id: str = Field(pattern=_ID)
    message: Optional[str] = Field(default=None, max_length=500)


class _CreateTask(_Params):
    workspace_id: str = Field(pattern=_ID)
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=4000)
    assigned_to_user_id: Optional[str] = Field(default=None, pattern=_ID)
    priority: str = "NORMAL"


class _UpdateTaskStatus(_Params):
    task_id: str = Field(pattern=_ID)
    status: str


class _HandoffTask(_Params):
    task_id: str = Field(pattern=_ID)
    assigned_to_user_id: str = Field(pattern=_ID)


class _SendMessage(_Params):
    recipient_user_id: str = Field(pattern=_ID)
    subject: str = Field(default="", max_length=255)
    body: str = Field(min_length=1, max_length=20_000)


class _ReadInbox(_Params):
    pass


PARAMETER_SCHEMAS: Dict[str, Type[_Params]] = {
    "list_workspaces": _ListWorkspaces,
    "list_files": _ListFiles,
    "read_file": _ReadFile,
    "create_file": _CreateFile,
    "update_file": _UpdateFile,
    "transfer_file": _TransferFile,
    "create_task": _CreateTask,
    "update_task_status": _UpdateTaskStatus,
    "handoff_task": _HandoffTask,
    "send_message": _SendMessage,
    "read_inbox": _ReadInbox,
}

READ_OPERATIONS = frozenset({"list_workspaces", "list_files", "read_file", "read_inbox"})


class _Denied(Exception):
    def __init__(self, status_code: int, message: str, code: str) -> None:
        super().__init__(message)
        self.status_code, self.message, self.code = status_code, message, code


def _scope_covers(data_scope: Any, branch_id: Optional[str]) -> bool:
    if not branch_id or not isinstance(data_scope, (list, tuple)):
        return False
    return f"branch:{branch_id}:*" in {s for s in data_scope if isinstance(s, str)}


class CompanyOperationsAdapter:
    """Server-side protected adapter for agent-mediated company operations."""

    tool_name: str = TOOL_NAME
    allowed_operations: Tuple[str, ...] = tuple(PARAMETER_SCHEMAS)
    timeout: float = 15.0

    def __init__(self, session_factory: Any, company_service: Optional[CompanyResourceService] = None) -> None:
        if session_factory is None:
            raise ValueError("CompanyOperationsAdapter requires a database session factory.")
        self._session_factory = session_factory
        self._company_service = company_service or CompanyResourceService(session_factory)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _result(status: str, status_code: int, payload: Dict[str, Any], started: float):
        from backend.app.api.gateway import ToolExecutionResult  # lazy: avoid import cycle

        return ToolExecutionResult(
            status=status,
            status_code=status_code,
            result_payload=payload,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _failure(self, status_code: int, message: str, code: str, started: float, operation: str):
        return self._result("FAILED", status_code, {
            "tool": TOOL_NAME, "operation": operation, "error": message, "error_code": code,
        }, started)

    @staticmethod
    def _parse(operation: str, parameters: Any) -> _Params:
        if not isinstance(parameters, dict):
            raise _Denied(400, "Parameters must be an object.", "PARAMETERS_INVALID")
        forged = sorted(k for k in parameters if isinstance(k, str) and k.lower() in FORBIDDEN_SCOPE_KEYS)
        if forged:
            raise _Denied(
                403,
                "Authorization scope is derived from the authenticated context and cannot be supplied "
                f"by the agent (rejected: {', '.join(forged)}).",
                "AGENT_SUPPLIED_SCOPE_REJECTED",
            )
        try:
            return PARAMETER_SCHEMAS[operation].model_validate(parameters)
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in err.get("loc", ())) or "parameters" for err in exc.errors()})
            raise _Denied(400, f"Invalid parameters for {operation}: {', '.join(fields)}.", "PARAMETERS_INVALID")

    async def _authorize(self, context: Dict[str, Any]) -> Tuple[TenantContext, Dict[str, Any]]:
        """Resolve the acting employee and the agent's governed scope from the database."""
        tenant_id, user_id, agent_id = context["tenant_id"], context["user_id"], context["agent_id"]
        async with self._session_factory() as session:
            tenant = await session.scalar(select(Tenant).where(Tenant.id == tenant_id))
            if tenant is None or tenant.status != "ACTIVE":
                raise _Denied(403, "Tenant is not active.", "TENANT_NOT_ACTIVE")
            member = await session.scalar(select(Membership).where(
                Membership.tenant_id == tenant_id,
                Membership.user_id == user_id,
                Membership.status == "ACTIVE",
            ))
            if member is None or not member.branch_id:
                raise _Denied(403, "Acting employee has no active branch membership.", "MEMBERSHIP_REQUIRED")
            ctx_branch = context.get("branch_id")
            if ctx_branch and ctx_branch != member.branch_id:
                raise _Denied(403, "Authenticated branch does not match membership.", "BRANCH_CONTEXT_MISMATCH")
            if member.role != context["role"]:
                raise _Denied(403, "Authenticated role does not match membership.", "ROLE_CONTEXT_MISMATCH")
            agent = await session.scalar(select(Agent).where(Agent.tenant_id == tenant_id, Agent.id == agent_id))
            if agent is None or agent.status != "ACTIVE":
                raise _Denied(403, "Agent is not active in this tenant.", "AGENT_NOT_ACTIVE")
            profile = await session.scalar(select(AgentSecurityProfile).where(
                AgentSecurityProfile.tenant_id == tenant_id,
                AgentSecurityProfile.agent_id == agent_id,
            ))
            if profile is None or profile.status != "ACTIVE":
                raise _Denied(403, "Agent has no active governed security profile.", "AGENT_PROFILE_NOT_ACTIVE")
            scope = list(profile.data_scope_json or [])
            if not _scope_covers(scope, member.branch_id):
                raise _Denied(
                    403,
                    "Agent data scope does not cover the acting employee's branch.",
                    "AGENT_BRANCH_SCOPE_DENIED",
                )
            tenant_ctx = TenantContext(
                tenant_id=tenant_id,
                tenant_slug=tenant.slug,
                tenant_name=tenant.name,
                user_id=user_id,
                role=member.role,
                is_active=True,
                branch_id=member.branch_id,
            )
            return tenant_ctx, {"profile_id": profile.id, "data_scope": scope, "profile_branch_id": profile.branch_id}

    async def _resource_branches(self, ctx: TenantContext, operation: str, params: _Params) -> Iterable[str]:
        """Branches of the resources an operation targets (tenant filtered). Unknown -> none."""
        tid = ctx.tenant_id
        async with self._session_factory() as session:
            if operation in {"list_files", "create_file", "create_task"}:
                branch = await session.scalar(select(CompanyWorkspace.branch_id).where(
                    CompanyWorkspace.tenant_id == tid, CompanyWorkspace.id == params.workspace_id))
                return [branch] if branch else []
            if operation in {"read_file", "update_file", "transfer_file"}:
                branch = await session.scalar(
                    select(CompanyWorkspace.branch_id)
                    .join(CompanyFile, (CompanyFile.workspace_id == CompanyWorkspace.id)
                          & (CompanyFile.tenant_id == CompanyWorkspace.tenant_id))
                    .where(CompanyFile.tenant_id == tid, CompanyFile.id == params.file_id))
                branches = [branch] if branch else []
                if operation == "transfer_file":
                    branches += await self._member_branch(session, tid, params.recipient_user_id)
                return branches
            if operation in {"update_task_status", "handoff_task"}:
                branch = await session.scalar(select(CompanyTask.branch_id).where(
                    CompanyTask.tenant_id == tid, CompanyTask.id == params.task_id))
                branches = [branch] if branch else []
                if operation == "handoff_task":
                    branches += await self._member_branch(session, tid, params.assigned_to_user_id)
                return branches
            if operation == "send_message":
                return await self._member_branch(session, tid, params.recipient_user_id)
        return []

    @staticmethod
    async def _member_branch(session: Any, tenant_id: str, user_id: str) -> list:
        branch = await session.scalar(select(Membership.branch_id).where(
            Membership.tenant_id == tenant_id, Membership.user_id == user_id, Membership.status == "ACTIVE"))
        return [branch] if branch else []

    async def _dispatch(self, ctx: TenantContext, operation: str, p: _Params, context: Dict[str, Any]) -> Any:
        """Execute through the authoritative Phase 2 service with gateway provenance."""
        svc = self._company_service
        agent_id, trace_id = context["agent_id"], context["trace_id"]

        if operation == "list_workspaces":
            async with self._session_factory() as session:
                rows = (await session.execute(select(CompanyWorkspace).where(
                    CompanyWorkspace.tenant_id == ctx.tenant_id,
                    CompanyWorkspace.branch_id == ctx.branch_id,
                ))).scalars().all()
            return [{"id": w.id, "tenant_id": w.tenant_id, "branch_id": w.branch_id,
                     "owner_user_id": w.owner_user_id, "name": w.name,
                     "visibility": w.visibility} for w in rows
                    if not await svc._isolation_adapter.is_resource_isolated(ctx.tenant_id, "WORKSPACE", w.id)]

        if operation == "list_files":
            async with self._session_factory() as session:
                rows = (await session.execute(
                    select(CompanyFile, CompanyWorkspace.branch_id)
                    .join(CompanyWorkspace, (CompanyWorkspace.id == CompanyFile.workspace_id)
                          & (CompanyWorkspace.tenant_id == CompanyFile.tenant_id))
                    .where(CompanyFile.tenant_id == ctx.tenant_id,
                           CompanyFile.workspace_id == p.workspace_id,
                           CompanyWorkspace.branch_id == ctx.branch_id,
                           CompanyFile.status == "ACTIVE")
                )).all()
            result = []
            for file_row, branch_id in rows:
                if await svc._isolation_adapter.is_resource_isolated(ctx.tenant_id, "FILE", file_row.id):
                    continue
                result.append({"id": file_row.id, "tenant_id": file_row.tenant_id,
                               "workspace_id": file_row.workspace_id, "branch_id": branch_id,
                               "owner_user_id": file_row.owner_user_id, "name": file_row.name,
                               "current_version": file_row.current_version, "status": file_row.status})
            return result

        if operation == "read_file":
            result = await svc.read_file(ctx, file_id=p.file_id, agent_id=agent_id, trace_id=trace_id)
            result["version"] = result.get("current_version")
            return result
        if operation == "create_file":
            return await svc.create_file(ctx, workspace_id=p.workspace_id, name=p.name,
                content=p.content, content_type=p.content_type, agent_id=agent_id, trace_id=trace_id)
        if operation == "update_file":
            return await svc.update_file(ctx, file_id=p.file_id, content=p.content,
                agent_id=agent_id, trace_id=trace_id)
        if operation == "transfer_file":
            return await svc.create_file_transfer(ctx, file_id=p.file_id,
                recipient_user_id=p.recipient_user_id, message=p.message,
                agent_id=agent_id, trace_id=trace_id)
        if operation == "create_task":
            return await svc.create_task(ctx, workspace_id=p.workspace_id, title=p.title,
                description=p.description, priority=p.priority, assigned_to_user_id=p.assigned_to_user_id,
                agent_id=agent_id, trace_id=trace_id)
        if operation in {"update_task_status", "handoff_task"}:
            result = await svc.update_task(ctx, task_id=p.task_id,
                status=p.status if operation == "update_task_status" else None,
                assigned_to_user_id=p.assigned_to_user_id if operation == "handoff_task" else None,
                agent_id=agent_id, trace_id=trace_id)
            result["assigned_to_user_id"] = p.assigned_to_user_id if operation == "handoff_task" else None
            return result
        if operation == "send_message":
            return await svc.send_message(ctx, recipient_user_id=p.recipient_user_id,
                subject=p.subject, body=p.body, agent_id=agent_id, trace_id=trace_id)
        if operation == "read_inbox":
            async with self._session_factory() as session:
                rows = (await session.execute(select(CompanyMessage).where(
                    CompanyMessage.tenant_id == ctx.tenant_id,
                    CompanyMessage.recipient_user_id == ctx.user_id,
                    CompanyMessage.status == "SENT",
                ).order_by(CompanyMessage.created_at.desc()))).scalars().all()
            return [{"id": m.id, "tenant_id": m.tenant_id, "sender_user_id": m.sender_user_id,
                     "recipient_user_id": m.recipient_user_id, "subject": m.subject,
                     "body": m.body, "status": m.status} for m in rows
                    if not await svc._isolation_adapter.is_resource_isolated(ctx.tenant_id, "MESSAGE", m.id)]
        raise _Denied(400, f"Unsupported operation '{operation}'.", "OPERATION_UNSUPPORTED")

    # ---------------------------------------------------------------- contract

    async def execute(self, operation: str, parameters: Dict[str, Any], context: Dict[str, Any]):
        started = time.perf_counter()
        if not isinstance(context, dict) or not all(
            isinstance(context.get(k), str) and context.get(k) for k in REQUIRED_CONTEXT_KEYS
        ):
            return self._failure(
                403,
                "Missing authorized gateway execution context; the company adapter cannot be invoked directly.",
                "GATEWAY_CONTEXT_REQUIRED", started, str(operation),
            )
        if operation not in PARAMETER_SCHEMAS:
            return self._failure(400, f"Unsupported operation '{operation}' for {TOOL_NAME}.",
                                 "OPERATION_UNSUPPORTED", started, str(operation))
        try:
            params = self._parse(operation, parameters)
            ctx, governance = await self._authorize(context)
            for branch in await self._resource_branches(ctx, operation, params):
                if not _scope_covers(governance["data_scope"], branch):
                    raise _Denied(403, "Target resource is outside the agent's authorized branch scope.",
                                  "AGENT_RESOURCE_SCOPE_DENIED")
            raw = await self._dispatch(ctx, operation, params, context)
        except _Denied as denied:
            return self._failure(denied.status_code, denied.message, denied.code, started, operation)
        except AMSCException as exc:
            return self._failure(exc.status_code, exc.message, exc.code, started, operation)
        except HTTPException as exc:
            return self._failure(exc.status_code, str(exc.detail), "COMPANY_SERVICE_REJECTED", started, operation)
        except SQLAlchemyError:
            logger.exception("Company persistence failure for %s", operation)
            return self._failure(503, "Company persistence is unavailable.", "COMPANY_PERSISTENCE_UNAVAILABLE",
                                 started, operation)
        except Exception:  # noqa: BLE001 — never report an unexpected error as success
            logger.exception("Unexpected company adapter failure for %s", operation)
            return self._failure(500, "Company operation failed.", "COMPANY_OPERATION_FAILED", started, operation)

        result = jsonable_encoder(raw)
        if operation == "list_workspaces" and isinstance(result, list):
            # Defence in depth: never return workspaces outside the agent's scope.
            result = [w for w in result if _scope_covers(governance["data_scope"], w.get("branch_id"))]
        return self._result("SUCCESS", 200, {
            "tool": TOOL_NAME,
            "operation": operation,
            "mutation": operation not in READ_OPERATIONS,
            "result": result,
            "provenance": {
                "agent_id": context["agent_id"],
                "acting_user_id": ctx.user_id,
                "branch_id": ctx.branch_id,
                "agent_profile_id": governance["profile_id"],
                "proposal_id": context["proposal_id"],
                "trace_id": context["trace_id"],
                "grant_id": context.get("grant_id"),
            },
        }, started)
