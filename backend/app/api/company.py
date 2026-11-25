"""Authoritative Phase 2 Company Application API endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict, Field

from backend.app.company.service import CompanyResourceService
from backend.app.core.dependencies import get_tenant_context
from backend.app.core.exceptions import SecurityDependencyError
from backend.app.tenancy.context import TenantContext

router = APIRouter(prefix="/company", tags=["company"])


def _get_company_service(request: Request) -> CompanyResourceService:
    svc = getattr(request.app.state, "company_resource_service", None)
    if svc is None:
        session_factory = getattr(request.app.state, "db_session_factory", None)
        if session_factory is None:
            raise SecurityDependencyError("Company application persistence is unavailable.")
        obs_repo = getattr(request.app.state, "observation_repo", None)
        iso_adapter = getattr(request.app.state, "company_resource_security_adapter", None)
        svc = CompanyResourceService(
            session_factory,
            isolation_adapter=iso_adapter,
            observation_repo=obs_repo,
        )
        request.app.state.company_resource_service = svc
    return svc


class CreateWorkspaceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: str = Field(default="PRIVATE", pattern=r"^(PRIVATE|BRANCH)$")


class CreateFileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    content: str
    content_type: str = Field(default="text/plain", max_length=128)


class UpdateFileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str


class CreateTransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file_id: str = Field(min_length=1, max_length=64)
    recipient_user_id: str = Field(min_length=1, max_length=64)
    message: Optional[str] = Field(default=None, max_length=500)


class CreateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=4000)
    priority: str = Field(default="NORMAL", pattern=r"^(LOW|NORMAL|HIGH|URGENT)$")
    assigned_to_user_id: Optional[str] = Field(default=None, max_length=64)


class UpdateTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Optional[str] = Field(default=None, pattern=r"^(OPEN|IN_PROGRESS|BLOCKED|COMPLETED|CANCELLED)$")
    assigned_to_user_id: Optional[str] = Field(default=None, max_length=64)


class SendMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient_user_id: str = Field(min_length=1, max_length=64)
    subject: str = Field(default="", max_length=255)
    body: str = Field(min_length=1)


@router.post("/workspaces", status_code=status.HTTP_201_CREATED)
async def create_workspace(
    body: CreateWorkspaceRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.create_workspace(
        context,
        name=body.name,
        description=body.description,
        visibility=body.visibility,
    )


@router.post("/files", status_code=status.HTTP_201_CREATED)
async def create_file(
    body: CreateFileRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.create_file(
        context,
        workspace_id=body.workspace_id,
        name=body.name,
        content=body.content,
        content_type=body.content_type,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/files/{file_id}")
async def read_file(
    file_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.read_file(
        context,
        file_id=file_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.put("/files/{file_id}")
async def update_file(
    file_id: str,
    body: UpdateFileRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.update_file(
        context,
        file_id=file_id,
        content=body.content,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/transfers", status_code=status.HTTP_201_CREATED)
async def create_transfer(
    body: CreateTransferRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.create_file_transfer(
        context,
        file_id=body.file_id,
        recipient_user_id=body.recipient_user_id,
        message=body.message,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/transfers/{transfer_id}/accept")
async def accept_transfer(
    transfer_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.accept_file_transfer(
        context,
        transfer_id=transfer_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/tasks", status_code=status.HTTP_201_CREATED)
async def create_task(
    body: CreateTaskRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.create_task(
        context,
        workspace_id=body.workspace_id,
        title=body.title,
        description=body.description,
        priority=body.priority,
        assigned_to_user_id=body.assigned_to_user_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.patch("/tasks/{task_id}")
async def update_task(
    task_id: str,
    body: UpdateTaskRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.update_task(
        context,
        task_id=task_id,
        status=body.status,
        assigned_to_user_id=body.assigned_to_user_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/messages", status_code=status.HTTP_201_CREATED)
async def send_message(
    body: SendMessageRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.send_message(
        context,
        recipient_user_id=body.recipient_user_id,
        subject=body.subject,
        body=body.body,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/messages/{message_id}")
async def read_message(
    message_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.read_message(
        context,
        message_id=message_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


__all__ = ["router"]
