"""Employee-facing persisted company application API (Phase 2).

All tenant/branch scope is derived from the authenticated TenantContext.
Company mutations use one PostgreSQL transaction for the domain row, history,
activity and notification records. Agents must call the service contract, not
access these tables or storage directly.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.dependencies import get_tenant_context
from backend.app.database.models.company import (
    CompanyActivity, CompanyFile, CompanyFileTransfer, CompanyFileVersion,
    CompanyMessage, CompanyNotification, CompanyTask, CompanyTaskEvent,
    CompanyWorkspace,
)
from backend.app.database.models.identity import Branch, Membership
from backend.app.tenancy.context import TenantContext

router = APIRouter(prefix="/company", tags=["Company Application"])


def _id() -> str:
    return str(uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _session_factory(request: Request):
    factory = getattr(request.app.state, "db_session_factory", None)
    if factory is None:
        raise HTTPException(status_code=503, detail="Company persistence is unavailable.")
    return factory


async def _member(session: AsyncSession, ctx: TenantContext) -> Membership:
    member = await session.scalar(select(Membership).where(
        Membership.tenant_id == ctx.tenant_id,
        Membership.user_id == ctx.user_id,
        Membership.status == "ACTIVE",
    ))
    if member is None or (ctx.branch_id and member.branch_id != ctx.branch_id):
        raise HTTPException(status_code=403, detail="Active company membership required.")
    return member


def _admin(ctx: TenantContext) -> bool:
    return ctx.role == "TENANT_ADMIN"


async def _workspace(session: AsyncSession, ctx: TenantContext, workspace_id: str, *, write: bool = False) -> CompanyWorkspace:
    row = await session.scalar(select(CompanyWorkspace).where(
        CompanyWorkspace.id == workspace_id,
        CompanyWorkspace.tenant_id == ctx.tenant_id,
    ))
    if row is None:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    if not _admin(ctx) and row.branch_id != ctx.branch_id:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    if row.visibility == "PRIVATE" and row.owner_user_id != ctx.user_id and not _admin(ctx):
        raise HTTPException(status_code=404, detail="Workspace not found.")
    if write and row.owner_user_id != ctx.user_id and not _admin(ctx):
        raise HTTPException(status_code=403, detail="Workspace owner permission required.")
    return row


async def _activity(session: AsyncSession, ctx: TenantContext, event: str, resource_type: str,
                    resource_id: str, summary: str, details: Optional[dict] = None) -> None:
    session.add(CompanyActivity(
        id=_id(), tenant_id=ctx.tenant_id, branch_id=ctx.branch_id,
        actor_user_id=ctx.user_id, event_type=event, resource_type=resource_type,
        resource_id=resource_id, summary=summary, details=details or {},
    ))


async def _notify(session: AsyncSession, ctx: TenantContext, user_id: str, event: str,
                  title: str, body: str, resource_type: str, resource_id: str) -> None:
    session.add(CompanyNotification(
        id=_id(), tenant_id=ctx.tenant_id, user_id=user_id, event_type=event,
        title=title, body=body, resource_type=resource_type, resource_id=resource_id,
    ))


class WorkspaceCreate(BaseModel):
    branch_id: Optional[str] = None
    name: str = Field(min_length=1, max_length=160)
    description: Optional[str] = Field(default=None, max_length=4000)
    visibility: str = "PRIVATE"


class FileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    content: str
    content_type: str = Field(default="text/plain", max_length=128)


class FileUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    content: str


class TransferCreate(BaseModel):
    recipient_user_id: str
    message: Optional[str] = Field(default=None, max_length=500)


class TransferRespond(BaseModel):
    decision: str


class TaskCreate(BaseModel):
    workspace_id: str
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    assigned_to_user_id: Optional[str] = None
    priority: str = "NORMAL"


class TaskUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to_user_id: Optional[str] = None
    title: Optional[str] = Field(default=None, min_length=1, max_length=255)


class MessageCreate(BaseModel):
    recipient_user_id: str
    subject: str = Field(default="", max_length=255)
    body: str = Field(min_length=1, max_length=20000)


@router.get("/workspaces")
async def list_workspaces(request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        await _member(session, ctx)
        query = select(CompanyWorkspace).where(CompanyWorkspace.tenant_id == ctx.tenant_id)
        if not _admin(ctx):
            query = query.where(CompanyWorkspace.branch_id == ctx.branch_id).where(
                or_(CompanyWorkspace.visibility == "BRANCH", CompanyWorkspace.owner_user_id == ctx.user_id)
            )
        rows = (await session.scalars(query.order_by(CompanyWorkspace.created_at.desc()))).all()
        return [{"id": r.id, "branch_id": r.branch_id, "owner_user_id": r.owner_user_id,
                 "name": r.name, "description": r.description, "visibility": r.visibility,
                 "created_at": r.created_at} for r in rows]


@router.post("/workspaces", status_code=status.HTTP_201_CREATED)
async def create_workspace(payload: WorkspaceCreate, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    if payload.visibility not in {"PRIVATE", "BRANCH"}:
        raise HTTPException(422, "visibility must be PRIVATE or BRANCH")
    target_branch_id = payload.branch_id if _admin(ctx) else ctx.branch_id
    if not target_branch_id or (payload.branch_id and not _admin(ctx)):
        raise HTTPException(403, "A valid authorized branch is required.")
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            branch = await session.scalar(select(Branch).where(
                Branch.id == target_branch_id,
                Branch.tenant_id == ctx.tenant_id,
                Branch.status == "ACTIVE"))
            if branch is None:
                raise HTTPException(404, "Branch not found.")
            row = CompanyWorkspace(id=_id(), tenant_id=ctx.tenant_id, branch_id=target_branch_id,
                owner_user_id=ctx.user_id, name=payload.name.strip(),
                description=payload.description, visibility=payload.visibility)
            session.add(row)
            await _activity(session, ctx, "WORKSPACE_CREATED", "workspace", row.id, f"Created workspace {row.name}")
        return {"id": row.id, "name": row.name, "branch_id": row.branch_id,
                "owner_user_id": row.owner_user_id, "visibility": row.visibility}


@router.get("/workspaces/{workspace_id}/files")
async def list_files(workspace_id: str, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        await _member(session, ctx)
        await _workspace(session, ctx, workspace_id)
        rows = (await session.scalars(select(CompanyFile).where(
            CompanyFile.tenant_id == ctx.tenant_id, CompanyFile.workspace_id == workspace_id,
            CompanyFile.status == "ACTIVE").order_by(CompanyFile.updated_at.desc()))).all()
        return [{"id": r.id, "name": r.name, "content_type": r.content_type,
                 "current_version": r.current_version, "owner_user_id": r.owner_user_id,
                 "updated_at": r.updated_at} for r in rows]


@router.post("/workspaces/{workspace_id}/files", status_code=status.HTTP_201_CREATED)
async def create_file(workspace_id: str, payload: FileCreate, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            await _workspace(session, ctx, workspace_id, write=True)
            file_id = _id()
            checksum = hashlib.sha256(payload.content.encode("utf-8")).hexdigest()
            row = CompanyFile(id=file_id, tenant_id=ctx.tenant_id, workspace_id=workspace_id,
                owner_user_id=ctx.user_id, name=payload.name.strip(), content_type=payload.content_type,
                current_version=1, status="ACTIVE")
            session.add(row)
            session.add(CompanyFileVersion(id=_id(), tenant_id=ctx.tenant_id, file_id=file_id,
                version_number=1, content=payload.content, checksum=checksum, created_by_user_id=ctx.user_id))
            await _activity(session, ctx, "FILE_CREATED", "file", file_id, f"Created file {row.name}",
                            {"version": 1, "checksum": checksum})
        return {"id": file_id, "name": row.name, "version": 1, "checksum": checksum}


@router.get("/files/{file_id}")
async def read_file(file_id: str, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        await _member(session, ctx)
        row = await session.scalar(select(CompanyFile).where(
            CompanyFile.id == file_id, CompanyFile.tenant_id == ctx.tenant_id,
            CompanyFile.status == "ACTIVE"))
        if row is None:
            raise HTTPException(404, "File not found.")
        await _workspace(session, ctx, row.workspace_id)
        version = await session.scalar(select(CompanyFileVersion).where(
            CompanyFileVersion.tenant_id == ctx.tenant_id,
            CompanyFileVersion.file_id == file_id,
            CompanyFileVersion.version_number == row.current_version))
        if version is None:
            raise HTTPException(503, "Current file version is unavailable.")
        return {"id": row.id, "name": row.name, "content_type": row.content_type,
                "version": version.version_number, "content": version.content,
                "checksum": version.checksum, "updated_at": row.updated_at}


@router.put("/files/{file_id}")
async def update_file(file_id: str, payload: FileUpdate, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            row = await session.scalar(select(CompanyFile).where(
                CompanyFile.id == file_id, CompanyFile.tenant_id == ctx.tenant_id,
                CompanyFile.status == "ACTIVE").with_for_update())
            if row is None:
                raise HTTPException(404, "File not found.")
            await _workspace(session, ctx, row.workspace_id, write=True)
            if payload.name is not None:
                row.name = payload.name.strip()
            next_version = row.current_version + 1
            checksum = hashlib.sha256(payload.content.encode("utf-8")).hexdigest()
            session.add(CompanyFileVersion(id=_id(), tenant_id=ctx.tenant_id, file_id=file_id,
                version_number=next_version, content=payload.content, checksum=checksum,
                created_by_user_id=ctx.user_id))
            row.current_version = next_version
            row.updated_at = _now()
            await _activity(session, ctx, "FILE_UPDATED", "file", file_id,
                            f"Updated file {row.name}", {"version": next_version, "checksum": checksum})
        return {"id": file_id, "name": row.name, "version": next_version, "checksum": checksum}


@router.get("/files/{file_id}/versions")
async def file_versions(file_id: str, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        await _member(session, ctx)
        row = await session.scalar(select(CompanyFile).where(
            CompanyFile.id == file_id, CompanyFile.tenant_id == ctx.tenant_id))
        if row is None:
            raise HTTPException(404, "File not found.")
        await _workspace(session, ctx, row.workspace_id)
        versions = (await session.scalars(select(CompanyFileVersion).where(
            CompanyFileVersion.tenant_id == ctx.tenant_id, CompanyFileVersion.file_id == file_id
        ).order_by(CompanyFileVersion.version_number.desc()))).all()
        return [{"version": v.version_number, "checksum": v.checksum,
                 "created_by_user_id": v.created_by_user_id, "created_at": v.created_at} for v in versions]


@router.delete("/files/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file(file_id: str, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            row = await session.scalar(select(CompanyFile).where(
                CompanyFile.id == file_id, CompanyFile.tenant_id == ctx.tenant_id,
                CompanyFile.status == "ACTIVE").with_for_update())
            if row is None:
                raise HTTPException(404, "File not found.")
            await _workspace(session, ctx, row.workspace_id, write=True)
            row.status = "DELETED"
            row.deleted_at = _now()
            await _activity(session, ctx, "FILE_DELETED", "file", file_id, f"Deleted file {row.name}")


@router.post("/files/{file_id}/transfers", status_code=status.HTTP_201_CREATED)
async def create_transfer(file_id: str, payload: TransferCreate, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            row = await session.scalar(select(CompanyFile).where(
                CompanyFile.id == file_id, CompanyFile.tenant_id == ctx.tenant_id,
                CompanyFile.status == "ACTIVE").with_for_update())
            if row is None:
                raise HTTPException(404, "File not found.")
            await _workspace(session, ctx, row.workspace_id, write=True)
            recipient = await session.scalar(select(Membership).where(
                Membership.tenant_id == ctx.tenant_id, Membership.user_id == payload.recipient_user_id,
                Membership.status == "ACTIVE"))
            if recipient is None or recipient.branch_id != ctx.branch_id:
                raise HTTPException(404, "Recipient not found in your branch.")
            transfer = CompanyFileTransfer(id=_id(), tenant_id=ctx.tenant_id, file_id=file_id,
                sender_user_id=ctx.user_id, recipient_user_id=payload.recipient_user_id,
                status="PENDING", message=payload.message)
            session.add(transfer)
            await _notify(session, ctx, payload.recipient_user_id, "FILE_TRANSFER_RECEIVED",
                          "File transfer received", f"{row.name} was shared with you.", "file_transfer", transfer.id)
            await _activity(session, ctx, "FILE_TRANSFER_CREATED", "file_transfer", transfer.id,
                            f"Sent {row.name} for transfer")
        return {"id": transfer.id, "status": transfer.status}


@router.post("/transfers/{transfer_id}/respond")
async def respond_transfer(transfer_id: str, payload: TransferRespond, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    decision = payload.decision.upper()
    if decision not in {"ACCEPTED", "REJECTED"}:
        raise HTTPException(422, "decision must be ACCEPTED or REJECTED")
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            transfer = await session.scalar(select(CompanyFileTransfer).where(
                CompanyFileTransfer.id == transfer_id, CompanyFileTransfer.tenant_id == ctx.tenant_id
            ).with_for_update())
            if transfer is None or transfer.recipient_user_id != ctx.user_id:
                raise HTTPException(404, "Transfer not found.")
            if transfer.status != "PENDING":
                raise HTTPException(409, "Transfer has already been answered.")
            file_row = await session.scalar(select(CompanyFile).where(
                CompanyFile.id == transfer.file_id, CompanyFile.tenant_id == ctx.tenant_id
            ).with_for_update())
            if file_row is None or file_row.status != "ACTIVE":
                raise HTTPException(409, "Transferred file is unavailable.")
            transfer.status = decision
            transfer.responded_at = _now()
            if decision == "ACCEPTED":
                file_row.owner_user_id = ctx.user_id
                file_row.updated_at = _now()
            await _notify(session, ctx, transfer.sender_user_id, "FILE_TRANSFER_RESPONDED",
                          "File transfer updated", f"Transfer was {decision.lower()}.",
                          "file_transfer", transfer.id)
            await _activity(session, ctx, f"FILE_TRANSFER_{decision}", "file_transfer", transfer.id,
                            f"Transfer {decision.lower()}")
        return {"id": transfer.id, "status": transfer.status}


@router.post("/tasks", status_code=status.HTTP_201_CREATED)
async def create_task(payload: TaskCreate, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    if payload.priority not in {"LOW", "NORMAL", "HIGH", "URGENT"}:
        raise HTTPException(422, "Invalid task priority.")
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            workspace = await _workspace(session, ctx, payload.workspace_id)
            assignee_id = payload.assigned_to_user_id
            if assignee_id:
                assignee = await session.scalar(select(Membership).where(
                    Membership.tenant_id == ctx.tenant_id, Membership.user_id == assignee_id,
                    Membership.status == "ACTIVE", Membership.branch_id == workspace.branch_id))
                if assignee is None:
                    raise HTTPException(404, "Assignee not found in workspace branch.")
            task = CompanyTask(id=_id(), tenant_id=ctx.tenant_id, workspace_id=workspace.id,
                branch_id=workspace.branch_id, title=payload.title.strip(), description=payload.description,
                status="OPEN", priority=payload.priority, created_by_user_id=ctx.user_id,
                assigned_to_user_id=assignee_id)
            session.add(task)
            session.add(CompanyTaskEvent(id=_id(), tenant_id=ctx.tenant_id, task_id=task.id,
                actor_user_id=ctx.user_id, event_type="CREATED", details={"status": "OPEN"}))
            if assignee_id:
                await _notify(session, ctx, assignee_id, "TASK_ASSIGNED", "Task assigned",
                              task.title, "task", task.id)
            await _activity(session, ctx, "TASK_CREATED", "task", task.id, f"Created task {task.title}")
        return {"id": task.id, "title": task.title, "status": task.status,
                "assigned_to_user_id": task.assigned_to_user_id}


@router.get("/tasks")
async def list_tasks(request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        await _member(session, ctx)
        query = select(CompanyTask).where(CompanyTask.tenant_id == ctx.tenant_id)
        if not _admin(ctx):
            query = query.where(CompanyTask.branch_id == ctx.branch_id)
        rows = (await session.scalars(query.order_by(CompanyTask.updated_at.desc()))).all()
        return [{"id": r.id, "workspace_id": r.workspace_id, "title": r.title,
                 "description": r.description, "status": r.status, "priority": r.priority,
                 "created_by_user_id": r.created_by_user_id,
                 "assigned_to_user_id": r.assigned_to_user_id, "due_at": r.due_at} for r in rows]


@router.patch("/tasks/{task_id}")
async def update_task(task_id: str, payload: TaskUpdate, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    allowed_status = {"OPEN", "IN_PROGRESS", "BLOCKED", "COMPLETED", "CANCELLED"}
    if payload.status is not None and payload.status not in allowed_status:
        raise HTTPException(422, "Invalid task status.")
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            task = await session.scalar(select(CompanyTask).where(
                CompanyTask.id == task_id, CompanyTask.tenant_id == ctx.tenant_id
            ).with_for_update())
            if task is None or (not _admin(ctx) and task.branch_id != ctx.branch_id):
                raise HTTPException(404, "Task not found.")
            if task.created_by_user_id != ctx.user_id and task.assigned_to_user_id != ctx.user_id and not _admin(ctx):
                raise HTTPException(403, "Task creator, assignee or tenant admin permission required.")
            changes = {}
            if payload.status is not None:
                changes["status"] = {"from": task.status, "to": payload.status}
                task.status = payload.status
            if payload.title is not None:
                task.title = payload.title.strip()
            if payload.assigned_to_user_id is not None:
                assignee = await session.scalar(select(Membership).where(
                    Membership.tenant_id == ctx.tenant_id, Membership.user_id == payload.assigned_to_user_id,
                    Membership.status == "ACTIVE", Membership.branch_id == task.branch_id))
                if assignee is None:
                    raise HTTPException(404, "Assignee not found in task branch.")
                changes["assigned_to_user_id"] = {"from": task.assigned_to_user_id, "to": payload.assigned_to_user_id}
                task.assigned_to_user_id = payload.assigned_to_user_id
                await _notify(session, ctx, payload.assigned_to_user_id, "TASK_ASSIGNED",
                              "Task assigned", task.title, "task", task.id)
            task.updated_at = _now()
            if changes:
                session.add(CompanyTaskEvent(id=_id(), tenant_id=ctx.tenant_id, task_id=task.id,
                    actor_user_id=ctx.user_id, event_type="UPDATED", details=changes))
                await _activity(session, ctx, "TASK_UPDATED", "task", task.id, f"Updated task {task.title}", changes)
        return {"id": task.id, "title": task.title, "status": task.status,
                "assigned_to_user_id": task.assigned_to_user_id}


@router.get("/tasks/{task_id}/events")
async def task_events(task_id: str, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        await _member(session, ctx)
        task = await session.scalar(select(CompanyTask).where(
            CompanyTask.id == task_id, CompanyTask.tenant_id == ctx.tenant_id))
        if task is None or (not _admin(ctx) and task.branch_id != ctx.branch_id):
            raise HTTPException(404, "Task not found.")
        events = (await session.scalars(select(CompanyTaskEvent).where(
            CompanyTaskEvent.tenant_id == ctx.tenant_id, CompanyTaskEvent.task_id == task_id
        ).order_by(CompanyTaskEvent.created_at.asc()))).all()
        return [{"id": e.id, "actor_user_id": e.actor_user_id, "event_type": e.event_type,
                 "details": e.details, "created_at": e.created_at} for e in events]


@router.post("/messages", status_code=status.HTTP_201_CREATED)
async def send_message(payload: MessageCreate, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            member = await _member(session, ctx)
            recipient = await session.scalar(select(Membership).where(
                Membership.tenant_id == ctx.tenant_id, Membership.user_id == payload.recipient_user_id,
                Membership.status == "ACTIVE"))
            if recipient is None or (not _admin(ctx) and recipient.branch_id != member.branch_id):
                raise HTTPException(404, "Recipient not found.")
            message = CompanyMessage(id=_id(), tenant_id=ctx.tenant_id,
                sender_user_id=ctx.user_id, recipient_user_id=payload.recipient_user_id,
                subject=payload.subject, body=payload.body, status="SENT")
            session.add(message)
            await _notify(session, ctx, payload.recipient_user_id, "MESSAGE_RECEIVED",
                          "New company message", payload.subject or "You received a message",
                          "message", message.id)
            await _activity(session, ctx, "MESSAGE_SENT", "message", message.id, "Sent an internal message")
        return {"id": message.id, "status": message.status, "sent_at": message.sent_at}


@router.get("/inbox")
async def inbox(request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        await _member(session, ctx)
        rows = (await session.scalars(select(CompanyMessage).where(
            CompanyMessage.tenant_id == ctx.tenant_id, CompanyMessage.recipient_user_id == ctx.user_id
        ).order_by(CompanyMessage.sent_at.desc()))).all()
        return [{"id": r.id, "sender_user_id": r.sender_user_id, "subject": r.subject,
                 "body": r.body, "status": r.status, "sent_at": r.sent_at, "read_at": r.read_at} for r in rows]


@router.post("/messages/{message_id}/read")
async def mark_message_read(message_id: str, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            row = await session.scalar(select(CompanyMessage).where(
                CompanyMessage.id == message_id, CompanyMessage.tenant_id == ctx.tenant_id,
                CompanyMessage.recipient_user_id == ctx.user_id).with_for_update())
            if row is None:
                raise HTTPException(404, "Message not found.")
            if row.read_at is None:
                row.read_at = _now()
                row.status = "READ"
                await _activity(session, ctx, "MESSAGE_READ", "message", row.id, "Read an internal message")
        return {"id": row.id, "status": row.status, "read_at": row.read_at}


@router.get("/notifications")
async def notifications(request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        await _member(session, ctx)
        rows = (await session.scalars(select(CompanyNotification).where(
            CompanyNotification.tenant_id == ctx.tenant_id,
            CompanyNotification.user_id == ctx.user_id
        ).order_by(CompanyNotification.created_at.desc()).limit(100))).all()
        return [{"id": r.id, "event_type": r.event_type, "title": r.title, "body": r.body,
                 "resource_type": r.resource_type, "resource_id": r.resource_id,
                 "read_at": r.read_at, "created_at": r.created_at} for r in rows]


@router.post("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    factory = _session_factory(request)
    async with factory() as session:
        async with session.begin():
            await _member(session, ctx)
            row = await session.scalar(select(CompanyNotification).where(
                CompanyNotification.id == notification_id, CompanyNotification.tenant_id == ctx.tenant_id,
                CompanyNotification.user_id == ctx.user_id).with_for_update())
            if row is None:
                raise HTTPException(404, "Notification not found.")
            row.read_at = row.read_at or _now()
        return {"id": row.id, "read_at": row.read_at}


@router.get("/activity")
async def activity(request: Request, ctx: TenantContext = Depends(get_tenant_context), limit: int = 50):
    factory = _session_factory(request)
    safe_limit = max(1, min(limit, 100))
    async with factory() as session:
        await _member(session, ctx)
        query = select(CompanyActivity).where(CompanyActivity.tenant_id == ctx.tenant_id)
        if not _admin(ctx):
            query = query.where(CompanyActivity.branch_id == ctx.branch_id)
        rows = (await session.scalars(query.order_by(CompanyActivity.created_at.desc()).limit(safe_limit))).all()
        return [{"id": r.id, "branch_id": r.branch_id, "actor_user_id": r.actor_user_id,
                 "event_type": r.event_type, "resource_type": r.resource_type,
                 "resource_id": r.resource_id, "summary": r.summary,
                 "details": r.details, "created_at": r.created_at} for r in rows]
