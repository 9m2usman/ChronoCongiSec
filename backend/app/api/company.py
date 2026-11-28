"""Authoritative Phase 2 Company Application API endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, Query, Request, status
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
        chk_service = getattr(request.app.state, "pre_action_checkpoint_service", None)
        svc = CompanyResourceService(
            session_factory,
            isolation_adapter=iso_adapter,
            observation_repo=obs_repo,
            checkpoint_service=chk_service,
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


class RestoreFileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_version: Optional[int] = Field(default=None, ge=1)


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


@router.get("/workspaces")
async def list_workspaces(
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_workspaces(context)
    return {"items": items, "total": len(items)}


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


@router.get("/files")
async def list_files(
    request: Request,
    workspace_id: Optional[str] = Query(default=None),
    include_deleted: bool = Query(default=False),
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_files(
        context,
        workspace_id=workspace_id,
        include_deleted=include_deleted,
    )
    return {"items": items, "total": len(items)}


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


@router.get("/files/{file_id}/versions/{version_number}")
async def read_file_version(
    file_id: str,
    version_number: int,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.read_file_version(
        context,
        file_id=file_id,
        version_number=version_number,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/tasks/{task_id}")
async def read_task(
    task_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.read_task(context, task_id=task_id)


@router.get("/notifications/{notification_id}")
async def read_notification(
    notification_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.read_notification(context, notification_id=notification_id)


@router.get("/files/{file_id}/versions")
async def list_file_versions(
    file_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_file_versions(context, file_id=file_id)
    return {"items": items, "total": len(items)}


@router.delete("/files/{file_id}")
async def delete_file(
    file_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.delete_file(
        context,
        file_id=file_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/files/{file_id}/restore")
async def restore_file(
    file_id: str,
    request: Request,
    body: Optional[RestoreFileRequest] = Body(default=None),
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.restore_file(
        context,
        file_id=file_id,
        target_version=body.target_version if body else None,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/transfers")
async def list_transfers(
    request: Request,
    direction: str = Query(default="all"),
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_file_transfers(context, direction=direction)
    return {"items": items, "total": len(items)}


@router.post("/transfers/{transfer_id}/reject")
async def reject_transfer(
    transfer_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.reject_file_transfer(
        context,
        transfer_id=transfer_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.post("/transfers/{transfer_id}/cancel")
async def cancel_transfer(
    transfer_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.cancel_file_transfer(
        context,
        transfer_id=transfer_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/tasks")
async def list_tasks(
    request: Request,
    workspace_id: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_tasks(context, workspace_id=workspace_id, status=status_filter)
    return {"items": items, "total": len(items)}


@router.get("/tasks/{task_id}/events")
async def list_task_events(
    task_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_task_events(context, task_id=task_id)
    return {"items": items, "total": len(items)}


@router.get("/messages")
async def list_messages(
    request: Request,
    box: str = Query(default="inbox"),
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_messages(context, box=box)
    return {"items": items, "total": len(items)}


@router.post("/messages/{message_id}/read")
async def mark_message_read(
    message_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.mark_message_read(
        context,
        message_id=message_id,
        trace_id=getattr(request.state, "trace_id", None),
    )


@router.get("/notifications")
async def list_notifications(
    request: Request,
    unread_only: bool = Query(default=False),
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_notifications(context, unread_only=unread_only)
    return {"items": items, "total": len(items)}


@router.post("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    return await svc.mark_notification_read(context, notification_id=notification_id)


@router.get("/activity")
async def list_activity(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    context: TenantContext = Depends(get_tenant_context),
) -> Dict[str, Any]:
    svc = _get_company_service(request)
    items = await svc.list_activity(context, limit=limit)
    return {"items": items, "total": len(items)}


__all__ = ["router"]
