"""Authoritative Phase 2 company application services and resource isolation.

Provides real SQLAlchemy-backed persistence and server-enforced access control
for company workspaces, files, file versions, file transfers, tasks, messages,
and notifications.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core.exceptions import (
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.database.models.baseline import ObservationEvent
from backend.app.database.models.company import (
    CompanyFile,
    CompanyFileTransfer,
    CompanyFileVersion,
    CompanyMessage,
    CompanyNotification,
    CompanyTask,
    CompanyTaskEvent,
    CompanyWorkspace,
)
from backend.app.database.models.identity import Membership
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.company.service")

SUPPORTED_RESOURCE_TYPES = frozenset({
    "FILE",
    "FILE_VERSION",
    "FILE_TRANSFER",
    "TASK",
    "WORKSPACE",
    "MESSAGE",
    "NOTIFICATION",
})


def _normalize_resource_type(resource_type: str) -> str:
    norm = (resource_type or "").strip().upper()
    aliases = {
        "COMPANY_FILE": "FILE",
        "COMPANY_FILE_VERSION": "FILE_VERSION",
        "COMPANY_FILE_TRANSFER": "FILE_TRANSFER",
        "TRANSFER": "FILE_TRANSFER",
        "COMPANY_TASK": "TASK",
        "COMPANY_WORKSPACE": "WORKSPACE",
        "COMPANY_MESSAGE": "MESSAGE",
        "COMPANY_NOTIFICATION": "NOTIFICATION",
    }
    norm = aliases.get(norm, norm)
    if norm not in SUPPORTED_RESOURCE_TYPES:
        raise ValidationError(f"Unsupported company resource type: '{resource_type}'.")
    return norm


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class SqlCompanyResourceIsolationAdapter:
    """Durable SQLAlchemy-backed implementation of ``CompanyResourceIsolationAdapter``."""

    is_persistent = True
    is_in_memory = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def is_resource_isolated(
        self,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
    ) -> bool:
        norm_type = _normalize_resource_type(resource_type)
        idemp_key = f"isolate:{tenant_id}:{norm_type}:{resource_id}"
        async with self._session_factory() as session:
            obs = (
                await session.execute(
                    select(ObservationEvent.id).where(
                        ObservationEvent.tenant_id == tenant_id,
                        ObservationEvent.idempotency_key == idemp_key,
                        ObservationEvent.event_type == "COMPANY_RESOURCE_ISOLATED",
                        ObservationEvent.outcome == "ISOLATED",
                    )
                )
            ).scalar_one_or_none()
            if obs is not None:
                return True
            if norm_type == "TASK":
                task_status = (
                    await session.execute(
                        select(CompanyTask.status).where(
                            CompanyTask.tenant_id == tenant_id,
                            CompanyTask.id == resource_id,
                        )
                    )
                ).scalar_one_or_none()
                if task_status == "BLOCKED":
                    return True
        return False

    async def isolate_resource(
        self,
        *,
        tenant_id: str,
        branch_id: Optional[str],
        resource_type: str,
        resource_id: str,
        actor_id: str,
        incident_id: Optional[str],
        reason: str,
    ) -> Mapping[str, Any]:
        norm_type = _normalize_resource_type(resource_type)
        if not tenant_id or not resource_id:
            return {"success": False, "resulting_state": "FAILED", "reason": "MISSING_IDENTIFIER"}

        already_isolated = await self.is_resource_isolated(tenant_id, norm_type, resource_id)
        previous_state = "ISOLATED" if already_isolated else "ACTIVE"
        resolved_branch_id = branch_id

        async with self._session_factory() as session:
            if norm_type == "FILE":
                row = (
                    await session.execute(
                        select(CompanyFile).where(
                            CompanyFile.tenant_id == tenant_id,
                            CompanyFile.id == resource_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return {"success": False, "resulting_state": "NOT_FOUND"}
                ws = (
                    await session.execute(
                        select(CompanyWorkspace).where(
                            CompanyWorkspace.tenant_id == tenant_id,
                            CompanyWorkspace.id == row.workspace_id,
                        )
                    )
                ).scalar_one_or_none()
                if branch_id and ws is not None and ws.branch_id != branch_id:
                    return {"success": False, "resulting_state": "BRANCH_MISMATCH"}
                resolved_branch_id = ws.branch_id if ws is not None else branch_id
                if not already_isolated:
                    previous_state = row.status
                await session.execute(
                    update(CompanyFileTransfer)
                    .where(
                        CompanyFileTransfer.tenant_id == tenant_id,
                        CompanyFileTransfer.file_id == resource_id,
                        CompanyFileTransfer.status == "PENDING",
                    )
                    .values(status="CANCELLED", responded_at=datetime.now(timezone.utc))
                )
            elif norm_type == "FILE_VERSION":
                row = (
                    await session.execute(
                        select(CompanyFileVersion).where(
                            CompanyFileVersion.tenant_id == tenant_id,
                            CompanyFileVersion.id == resource_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return {"success": False, "resulting_state": "NOT_FOUND"}
                parent_file = (
                    await session.execute(
                        select(CompanyFile).where(
                            CompanyFile.tenant_id == tenant_id,
                            CompanyFile.id == row.file_id,
                        )
                    )
                ).scalar_one_or_none()
                if parent_file is not None:
                    ws = (
                        await session.execute(
                            select(CompanyWorkspace).where(
                                CompanyWorkspace.tenant_id == tenant_id,
                                CompanyWorkspace.id == parent_file.workspace_id,
                            )
                        )
                    ).scalar_one_or_none()
                    if branch_id and ws is not None and ws.branch_id != branch_id:
                        return {"success": False, "resulting_state": "BRANCH_MISMATCH"}
                    resolved_branch_id = ws.branch_id if ws is not None else branch_id
            elif norm_type == "FILE_TRANSFER":
                row = (
                    await session.execute(
                        select(CompanyFileTransfer).where(
                            CompanyFileTransfer.tenant_id == tenant_id,
                            CompanyFileTransfer.id == resource_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return {"success": False, "resulting_state": "NOT_FOUND"}
                if not already_isolated:
                    previous_state = row.status
                if row.status == "PENDING":
                    row.status = "CANCELLED"
                    row.responded_at = datetime.now(timezone.utc)
            elif norm_type == "TASK":
                row = (
                    await session.execute(
                        select(CompanyTask).where(
                            CompanyTask.tenant_id == tenant_id,
                            CompanyTask.id == resource_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return {"success": False, "resulting_state": "NOT_FOUND"}
                if branch_id and row.branch_id != branch_id:
                    return {"success": False, "resulting_state": "BRANCH_MISMATCH"}
                resolved_branch_id = row.branch_id
                if not already_isolated:
                    previous_state = row.status
                if row.status != "BLOCKED":
                    row.status = "BLOCKED"
                    row.updated_at = datetime.now(timezone.utc)
                    actor_user = actor_id.split(":", 1)[-1] if ":" in actor_id else actor_id
                    mem_exists = (
                        await session.execute(
                            select(Membership.user_id).where(
                                Membership.tenant_id == tenant_id,
                                Membership.user_id == actor_user,
                            )
                        )
                    ).scalar_one_or_none()
                    session.add(
                        CompanyTaskEvent(
                            id=f"tevt-{uuid.uuid4().hex[:24]}",
                            tenant_id=tenant_id,
                            task_id=row.id,
                            actor_user_id=mem_exists or row.created_by_user_id,
                            event_type="ISOLATED",
                            details={
                                "previous_status": previous_state,
                                "incident_id": incident_id,
                                "reason": reason,
                            },
                        )
                    )
            elif norm_type == "WORKSPACE":
                row = (
                    await session.execute(
                        select(CompanyWorkspace).where(
                            CompanyWorkspace.tenant_id == tenant_id,
                            CompanyWorkspace.id == resource_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return {"success": False, "resulting_state": "NOT_FOUND"}
                if branch_id and row.branch_id != branch_id:
                    return {"success": False, "resulting_state": "BRANCH_MISMATCH"}
                resolved_branch_id = row.branch_id
                await session.execute(
                    update(CompanyTask)
                    .where(
                        CompanyTask.tenant_id == tenant_id,
                        CompanyTask.workspace_id == resource_id,
                        CompanyTask.status.in_(["OPEN", "IN_PROGRESS"]),
                    )
                    .values(status="BLOCKED", updated_at=datetime.now(timezone.utc))
                )
                file_ids_res = await session.execute(
                    select(CompanyFile.id).where(
                        CompanyFile.tenant_id == tenant_id,
                        CompanyFile.workspace_id == resource_id,
                    )
                )
                file_ids = [r[0] for r in file_ids_res.all()]
                if file_ids:
                    await session.execute(
                        update(CompanyFileTransfer)
                        .where(
                            CompanyFileTransfer.tenant_id == tenant_id,
                            CompanyFileTransfer.file_id.in_(file_ids),
                            CompanyFileTransfer.status == "PENDING",
                        )
                        .values(status="CANCELLED", responded_at=datetime.now(timezone.utc))
                    )
            elif norm_type == "MESSAGE":
                row = (
                    await session.execute(
                        select(CompanyMessage).where(
                            CompanyMessage.tenant_id == tenant_id,
                            CompanyMessage.id == resource_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return {"success": False, "resulting_state": "NOT_FOUND"}
                if not already_isolated:
                    previous_state = row.status
            elif norm_type == "NOTIFICATION":
                row = (
                    await session.execute(
                        select(CompanyNotification).where(
                            CompanyNotification.tenant_id == tenant_id,
                            CompanyNotification.id == resource_id,
                        )
                    )
                ).scalar_one_or_none()
                if row is None:
                    return {"success": False, "resulting_state": "NOT_FOUND"}

            idemp_key = f"isolate:{tenant_id}:{norm_type}:{resource_id}"
            existing_obs = (
                await session.execute(
                    select(ObservationEvent).where(
                        ObservationEvent.tenant_id == tenant_id,
                        ObservationEvent.idempotency_key == idemp_key,
                    )
                )
            ).scalar_one_or_none()
            if existing_obs is None:
                session.add(
                    ObservationEvent(
                        id=f"obs-{uuid.uuid4().hex[:24]}",
                        tenant_id=tenant_id,
                        branch_id=resolved_branch_id,
                        event_type="COMPANY_RESOURCE_ISOLATED",
                        event_category="CONTAINMENT",
                        source_component="COMPANY_RESOURCE_ISOLATION",
                        action_id=resource_id,
                        outcome="ISOLATED",
                        idempotency_key=idemp_key,
                        payload_json={
                            "resource_type": norm_type,
                            "resource_id": resource_id,
                            "previous_state": previous_state,
                            "resulting_state": "ISOLATED",
                            "incident_id": incident_id,
                            "actor_id": actor_id,
                            "reason": reason,
                        },
                        occurred_at=datetime.now(timezone.utc),
                    )
                )
            await session.commit()

        verified = await self.is_resource_isolated(tenant_id, norm_type, resource_id)
        if not verified:
            return {"success": False, "resulting_state": "VERIFICATION_FAILED"}
        return {
            "success": True,
            "resource_type": norm_type,
            "resource_id": resource_id,
            "previous_state": previous_state,
            "resulting_state": "ISOLATED",
            "branch_id": resolved_branch_id,
        }


class CompanyResourceService:
    """Authoritative server-side company application service."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        isolation_adapter: Optional[SqlCompanyResourceIsolationAdapter] = None,
        observation_repo: Any = None,
        checkpoint_service: Any = None,
    ) -> None:
        self._session_factory = session_factory
        self._isolation_adapter = isolation_adapter or SqlCompanyResourceIsolationAdapter(session_factory)
        self._observation_repo = observation_repo
        self._checkpoint_service = checkpoint_service

    async def _capture_checkpoint_if_configured(
        self,
        *,
        context: TenantContext,
        operation: str,
        parameters: Mapping[str, Any],
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        if self._checkpoint_service is None:
            return
        capture = getattr(self._checkpoint_service, "capture_pre_action_checkpoint", None)
        if not callable(capture):
            raise SecurityDependencyError("Pre-action checkpoint service is unavailable.")
        res = await capture(
            tenant_id=context.tenant_id,
            branch_id=context.branch_id,
            actor_id=f"user:{context.user_id}",
            agent_id=agent_id or "",
            proposal_id=f"company-prop-{uuid.uuid4().hex[:16]}",
            action_id=f"company-act-{uuid.uuid4().hex[:16]}",
            trace_id=trace_id,
            idempotency_key=f"company-chk-{operation}-{uuid.uuid4().hex[:16]}",
            tool_name="company_service",
            operation=operation,
            parameters=parameters,
            memory_refs=[],
        )
        if not isinstance(res, Mapping) or res.get("committed") is not True:
            raise SecurityDependencyError("Pre-action checkpoint failed to commit.")

    @staticmethod
    def _require_context(context: TenantContext) -> tuple[str, Optional[str], str]:
        if (
            not isinstance(context, TenantContext)
            or not context.is_active
            or not context.tenant_id
            or not context.user_id
        ):
            raise ForbiddenError("Authenticated tenant context is required.")
        return context.tenant_id, context.branch_id, context.user_id

    async def _require_not_isolated(
        self,
        tenant_id: str,
        checks: list[tuple[str, str]],
    ) -> None:
        for rtype, rid in checks:
            if await self._isolation_adapter.is_resource_isolated(tenant_id, rtype, rid):
                raise ForbiddenError(
                    f"Company {rtype.lower()} '{rid}' is isolated under active security containment."
                )

    async def _emit_observation(
        self,
        *,
        context: TenantContext,
        event_type: str,
        event_category: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        payload: Dict[str, Any],
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        mandatory: bool = True,
    ) -> None:
        if self._observation_repo is None:
            if mandatory:
                raise SecurityDependencyError("Mandatory security observation store is unavailable.")
            return
        try:
            await self._observation_repo.record_event({
                "tenant_id": context.tenant_id,
                "branch_id": context.branch_id,
                "event_type": event_type,
                "event_category": event_category,
                "agent_id": agent_id,
                "trace_id": trace_id,
                "source_component": "COMPANY_APPLICATION",
                "action_id": resource_id,
                "outcome": outcome,
                "idempotency_key": f"company-{event_type.lower()}-{context.tenant_id}-{resource_id}-{uuid.uuid4().hex[:12]}",
                "payload_json": {
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "actor_id": context.user_id,
                    "actor_role": context.role,
                    **payload,
                },
            })
        except Exception as exc:
            if mandatory:
                raise SecurityDependencyError("Mandatory company observation persistence failed.") from exc
            logger.warning("Optional company observation failed: %s", exc)

    async def create_workspace(
        self,
        context: TenantContext,
        *,
        name: str,
        description: Optional[str] = None,
        visibility: str = "PRIVATE",
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        if not branch_id:
            raise ValidationError("Branch context is required to create a workspace.")
        ws_id = f"ws-{uuid.uuid4().hex[:24]}"
        async with self._session_factory() as session:
            ws = CompanyWorkspace(
                id=ws_id,
                tenant_id=tenant_id,
                branch_id=branch_id,
                owner_user_id=user_id,
                name=name,
                description=description,
                visibility=visibility,
            )
            session.add(ws)
            await session.commit()
        return {
            "id": ws_id,
            "tenant_id": tenant_id,
            "branch_id": branch_id,
            "owner_user_id": user_id,
            "name": name,
            "visibility": visibility,
        }

    async def create_file(
        self,
        context: TenantContext,
        *,
        workspace_id: str,
        name: str,
        content: str,
        content_type: str = "text/plain",
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        await self._require_not_isolated(tenant_id, [("WORKSPACE", workspace_id)])

        async with self._session_factory() as session:
            ws = (
                await session.execute(
                    select(CompanyWorkspace).where(
                        CompanyWorkspace.tenant_id == tenant_id,
                        CompanyWorkspace.id == workspace_id,
                    )
                )
            ).scalar_one_or_none()
            if ws is None:
                raise NotFoundError("Workspace not found.")
            if branch_id and ws.branch_id != branch_id:
                raise ForbiddenError("Cross-branch workspace access is prohibited.")

            file_id = f"file-{uuid.uuid4().hex[:24]}"
            checksum = _sha256(content)
            await self._emit_observation(
                context=context,
                event_type="COMPANY_FILE_CREATED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="FILE",
                resource_id=file_id,
                outcome="CREATED",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={
                    "workspace_id": workspace_id,
                    "version": 1,
                    "content_sha256": checksum,
                },
                mandatory=True,
            )
            file_row = CompanyFile(
                id=file_id,
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                owner_user_id=user_id,
                name=name,
                content_type=content_type,
                current_version=1,
                status="ACTIVE",
            )
            ver_row = CompanyFileVersion(
                id=f"fver-{uuid.uuid4().hex[:24]}",
                tenant_id=tenant_id,
                file_id=file_id,
                version_number=1,
                content=content,
                checksum=checksum,
                created_by_user_id=user_id,
            )
            session.add(file_row)
            session.add(ver_row)
            await session.commit()

        return {
            "id": file_id,
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "branch_id": ws.branch_id,
            "owner_user_id": user_id,
            "name": name,
            "current_version": 1,
            "checksum": checksum,
            "status": "ACTIVE",
        }

    async def read_file(
        self,
        context: TenantContext,
        *,
        file_id: str,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, _ = self._require_context(context)
        async with self._session_factory() as session:
            file_row = (
                await session.execute(
                    select(CompanyFile).where(
                        CompanyFile.tenant_id == tenant_id,
                        CompanyFile.id == file_id,
                    )
                )
            ).scalar_one_or_none()
            if file_row is None:
                raise NotFoundError("Company file not found.")
            ws = (
                await session.execute(
                    select(CompanyWorkspace).where(
                        CompanyWorkspace.tenant_id == tenant_id,
                        CompanyWorkspace.id == file_row.workspace_id,
                    )
                )
            ).scalar_one_or_none()
            if ws is None or (branch_id and ws.branch_id != branch_id):
                raise ForbiddenError("Cross-branch file access is prohibited.")
            await self._require_not_isolated(
                tenant_id,
                [("FILE", file_id), ("WORKSPACE", file_row.workspace_id)],
            )
            ver = (
                await session.execute(
                    select(CompanyFileVersion).where(
                        CompanyFileVersion.tenant_id == tenant_id,
                        CompanyFileVersion.file_id == file_id,
                        CompanyFileVersion.version_number == file_row.current_version,
                    )
                )
            ).scalar_one_or_none()
            if ver is not None:
                await self._require_not_isolated(tenant_id, [("FILE_VERSION", ver.id)])

        await self._emit_observation(
            context=context,
            event_type="COMPANY_FILE_READ",
            event_category="COMPANY_RESOURCE_ACCESS",
            resource_type="FILE",
            resource_id=file_id,
            outcome="READ",
            agent_id=agent_id,
            trace_id=trace_id,
            payload={
                "workspace_id": file_row.workspace_id,
                "version": file_row.current_version,
                "content_sha256": ver.checksum if ver else None,
            },
            mandatory=False,
        )
        return {
            "id": file_row.id,
            "tenant_id": file_row.tenant_id,
            "workspace_id": file_row.workspace_id,
            "branch_id": ws.branch_id,
            "name": file_row.name,
            "current_version": file_row.current_version,
            "current_version_id": ver.id if ver else None,
            "status": file_row.status,
            "content": ver.content if ver else "",
            "checksum": ver.checksum if ver else None,
        }

    async def update_file(
        self,
        context: TenantContext,
        *,
        file_id: str,
        content: str,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        async with self._session_factory() as session:
            file_row = (
                await session.execute(
                    select(CompanyFile).where(
                        CompanyFile.tenant_id == tenant_id,
                        CompanyFile.id == file_id,
                    )
                )
            ).scalar_one_or_none()
            if file_row is None:
                raise NotFoundError("Company file not found.")
            ws = (
                await session.execute(
                    select(CompanyWorkspace).where(
                        CompanyWorkspace.tenant_id == tenant_id,
                        CompanyWorkspace.id == file_row.workspace_id,
                    )
                )
            ).scalar_one_or_none()
            if ws is None or (branch_id and ws.branch_id != branch_id):
                raise ForbiddenError("Cross-branch file mutation is prohibited.")
            await self._require_not_isolated(
                tenant_id,
                [("FILE", file_id), ("WORKSPACE", file_row.workspace_id)],
            )
            if file_row.status != "ACTIVE":
                raise ForbiddenError("Deleted file cannot be updated.")
            current_ver = (
                await session.execute(
                    select(CompanyFileVersion).where(
                        CompanyFileVersion.tenant_id == tenant_id,
                        CompanyFileVersion.file_id == file_id,
                        CompanyFileVersion.version_number == file_row.current_version,
                    )
                )
            ).scalar_one_or_none()
            if current_ver is not None:
                await self._require_not_isolated(tenant_id, [("FILE_VERSION", current_ver.id)])

            await self._capture_checkpoint_if_configured(
                context=context,
                operation="update_file",
                parameters={"file_id": file_id, "workspace_id": file_row.workspace_id},
                agent_id=agent_id,
                trace_id=trace_id,
            )

            new_version = file_row.current_version + 1
            checksum = _sha256(content)
            await self._emit_observation(
                context=context,
                event_type="COMPANY_FILE_UPDATED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="FILE",
                resource_id=file_id,
                outcome="UPDATED",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={
                    "workspace_id": file_row.workspace_id,
                    "previous_version": file_row.current_version,
                    "new_version": new_version,
                    "content_sha256": checksum,
                },
                mandatory=True,
            )
            file_row.current_version = new_version
            file_row.updated_at = datetime.now(timezone.utc)
            session.add(
                CompanyFileVersion(
                    id=f"fver-{uuid.uuid4().hex[:24]}",
                    tenant_id=tenant_id,
                    file_id=file_id,
                    version_number=new_version,
                    content=content,
                    checksum=checksum,
                    created_by_user_id=user_id,
                )
            )
            await session.commit()

        return {
            "id": file_id,
            "tenant_id": tenant_id,
            "workspace_id": file_row.workspace_id,
            "current_version": new_version,
            "checksum": checksum,
            "status": file_row.status,
        }

    async def create_file_transfer(
        self,
        context: TenantContext,
        *,
        file_id: str,
        recipient_user_id: str,
        message: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        if recipient_user_id == user_id:
            raise ValidationError("Sender and recipient must be different users.")

        async with self._session_factory() as session:
            file_row = (
                await session.execute(
                    select(CompanyFile).where(
                        CompanyFile.tenant_id == tenant_id,
                        CompanyFile.id == file_id,
                    )
                )
            ).scalar_one_or_none()
            if file_row is None:
                raise NotFoundError("Company file not found.")
            ws = (
                await session.execute(
                    select(CompanyWorkspace).where(
                        CompanyWorkspace.tenant_id == tenant_id,
                        CompanyWorkspace.id == file_row.workspace_id,
                    )
                )
            ).scalar_one_or_none()
            if ws is None or (branch_id and ws.branch_id != branch_id):
                raise ForbiddenError("Cross-branch file transfer is prohibited.")
            await self._require_not_isolated(
                tenant_id,
                [("FILE", file_id), ("WORKSPACE", file_row.workspace_id)],
            )
            current_ver = (
                await session.execute(
                    select(CompanyFileVersion).where(
                        CompanyFileVersion.tenant_id == tenant_id,
                        CompanyFileVersion.file_id == file_id,
                        CompanyFileVersion.version_number == file_row.current_version,
                    )
                )
            ).scalar_one_or_none()
            if current_ver is not None:
                await self._require_not_isolated(tenant_id, [("FILE_VERSION", current_ver.id)])

            transfer_id = f"ftr-{uuid.uuid4().hex[:24]}"
            await self._emit_observation(
                context=context,
                event_type="COMPANY_FILE_TRANSFER_CREATED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="FILE_TRANSFER",
                resource_id=transfer_id,
                outcome="PENDING",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={
                    "file_id": file_id,
                    "recipient_user_id": recipient_user_id,
                },
                mandatory=True,
            )
            session.add(
                CompanyFileTransfer(
                    id=transfer_id,
                    tenant_id=tenant_id,
                    file_id=file_id,
                    sender_user_id=user_id,
                    recipient_user_id=recipient_user_id,
                    status="PENDING",
                    message=message,
                )
            )
            await session.commit()

        return {
            "id": transfer_id,
            "tenant_id": tenant_id,
            "file_id": file_id,
            "sender_user_id": user_id,
            "recipient_user_id": recipient_user_id,
            "status": "PENDING",
        }

    async def accept_file_transfer(
        self,
        context: TenantContext,
        *,
        transfer_id: str,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        async with self._session_factory() as session:
            tr = (
                await session.execute(
                    select(CompanyFileTransfer).where(
                        CompanyFileTransfer.tenant_id == tenant_id,
                        CompanyFileTransfer.id == transfer_id,
                    )
                )
            ).scalar_one_or_none()
            if tr is None:
                raise NotFoundError("File transfer not found.")
            if tr.recipient_user_id != user_id:
                raise ForbiddenError("Only the designated recipient may accept a file transfer.")
            file_row = (
                await session.execute(
                    select(CompanyFile).where(
                        CompanyFile.tenant_id == tenant_id,
                        CompanyFile.id == tr.file_id,
                    )
                )
            ).scalar_one_or_none()
            if file_row is None:
                raise NotFoundError("Company file not found.")
            ws = (
                await session.execute(
                    select(CompanyWorkspace).where(
                        CompanyWorkspace.tenant_id == tenant_id,
                        CompanyWorkspace.id == file_row.workspace_id,
                    )
                )
            ).scalar_one_or_none()
            if ws is None or (branch_id and ws.branch_id != branch_id):
                raise ForbiddenError("Cross-branch file transfer acceptance is prohibited.")
            checks = [
                ("FILE_TRANSFER", transfer_id),
                ("FILE", tr.file_id),
                ("WORKSPACE", file_row.workspace_id),
            ]
            current_ver = (
                await session.execute(
                    select(CompanyFileVersion).where(
                        CompanyFileVersion.tenant_id == tenant_id,
                        CompanyFileVersion.file_id == tr.file_id,
                        CompanyFileVersion.version_number == file_row.current_version,
                    )
                )
            ).scalar_one_or_none()
            if current_ver is not None:
                checks.append(("FILE_VERSION", current_ver.id))
            await self._require_not_isolated(tenant_id, checks)
            if tr.status != "PENDING":
                raise ForbiddenError(f"File transfer in status '{tr.status}' cannot be accepted.")

            await self._capture_checkpoint_if_configured(
                context=context,
                operation="accept_file_transfer",
                parameters={"transfer_id": transfer_id, "file_id": tr.file_id},
                agent_id=agent_id,
                trace_id=trace_id,
            )

            await self._emit_observation(
                context=context,
                event_type="COMPANY_FILE_TRANSFER_ACCEPTED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="FILE_TRANSFER",
                resource_id=transfer_id,
                outcome="ACCEPTED",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={"file_id": tr.file_id},
                mandatory=True,
            )
            tr.status = "ACCEPTED"
            tr.responded_at = datetime.now(timezone.utc)
            await session.commit()

        return {"id": tr.id, "file_id": tr.file_id, "status": "ACCEPTED"}

    async def create_task(
        self,
        context: TenantContext,
        *,
        workspace_id: str,
        title: str,
        description: Optional[str] = None,
        priority: str = "NORMAL",
        assigned_to_user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        await self._require_not_isolated(tenant_id, [("WORKSPACE", workspace_id)])

        async with self._session_factory() as session:
            ws = (
                await session.execute(
                    select(CompanyWorkspace).where(
                        CompanyWorkspace.tenant_id == tenant_id,
                        CompanyWorkspace.id == workspace_id,
                    )
                )
            ).scalar_one_or_none()
            if ws is None:
                raise NotFoundError("Workspace not found.")
            if branch_id and ws.branch_id != branch_id:
                raise ForbiddenError("Cross-branch task creation is prohibited.")

            task_id = f"task-{uuid.uuid4().hex[:24]}"
            await self._emit_observation(
                context=context,
                event_type="COMPANY_TASK_CREATED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="TASK",
                resource_id=task_id,
                outcome="OPEN",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={"workspace_id": workspace_id, "priority": priority},
                mandatory=True,
            )
            session.add(
                CompanyTask(
                    id=task_id,
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    branch_id=ws.branch_id,
                    title=title,
                    description=description,
                    status="OPEN",
                    priority=priority,
                    created_by_user_id=user_id,
                    assigned_to_user_id=assigned_to_user_id,
                )
            )
            session.add(
                CompanyTaskEvent(
                    id=f"tevt-{uuid.uuid4().hex[:24]}",
                    tenant_id=tenant_id,
                    task_id=task_id,
                    actor_user_id=user_id,
                    event_type="CREATED",
                    details={"priority": priority},
                )
            )
            await session.commit()

        return {
            "id": task_id,
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "branch_id": ws.branch_id,
            "title": title,
            "status": "OPEN",
        }

    async def update_task(
        self,
        context: TenantContext,
        *,
        task_id: str,
        status: Optional[str] = None,
        assigned_to_user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        async with self._session_factory() as session:
            task = (
                await session.execute(
                    select(CompanyTask).where(
                        CompanyTask.tenant_id == tenant_id,
                        CompanyTask.id == task_id,
                    )
                )
            ).scalar_one_or_none()
            if task is None:
                raise NotFoundError("Company task not found.")
            if branch_id and task.branch_id != branch_id:
                raise ForbiddenError("Cross-branch task mutation is prohibited.")
            await self._require_not_isolated(
                tenant_id,
                [("TASK", task_id), ("WORKSPACE", task.workspace_id)],
            )
            if task.status == "BLOCKED":
                raise ForbiddenError("Blocked task cannot be modified.")

            await self._capture_checkpoint_if_configured(
                context=context,
                operation="update_task",
                parameters={"task_id": task_id, "workspace_id": task.workspace_id},
                agent_id=agent_id,
                trace_id=trace_id,
            )

            new_status = status or task.status
            event_type = "COMPANY_TASK_COMPLETED" if new_status == "COMPLETED" else "COMPANY_TASK_UPDATED"
            await self._emit_observation(
                context=context,
                event_type=event_type,
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="TASK",
                resource_id=task_id,
                outcome=new_status,
                agent_id=agent_id,
                trace_id=trace_id,
                payload={"previous_status": task.status, "new_status": new_status},
                mandatory=True,
            )
            task.status = new_status
            if assigned_to_user_id is not None:
                task.assigned_to_user_id = assigned_to_user_id
            task.updated_at = datetime.now(timezone.utc)
            session.add(
                CompanyTaskEvent(
                    id=f"tevt-{uuid.uuid4().hex[:24]}",
                    tenant_id=tenant_id,
                    task_id=task_id,
                    actor_user_id=user_id,
                    event_type="COMPLETED" if new_status == "COMPLETED" else "UPDATED",
                    details={"status": new_status},
                )
            )
            await session.commit()

        return {"id": task_id, "tenant_id": tenant_id, "status": new_status}

    async def send_message(
        self,
        context: TenantContext,
        *,
        recipient_user_id: str,
        subject: str,
        body: str,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, _, user_id = self._require_context(context)
        if recipient_user_id == user_id:
            raise ValidationError("Sender and recipient must be different users.")

        msg_id = f"msg-{uuid.uuid4().hex[:24]}"
        await self._emit_observation(
            context=context,
            event_type="COMPANY_MESSAGE_SENT",
            event_category="COMPANY_RESOURCE_MUTATION",
            resource_type="MESSAGE",
            resource_id=msg_id,
            outcome="SENT",
            agent_id=agent_id,
            trace_id=trace_id,
            payload={
                "recipient_user_id": recipient_user_id,
                "body_sha256": _sha256(body),
            },
            mandatory=True,
        )
        async with self._session_factory() as session:
            session.add(
                CompanyMessage(
                    id=msg_id,
                    tenant_id=tenant_id,
                    sender_user_id=user_id,
                    recipient_user_id=recipient_user_id,
                    subject=subject,
                    body=body,
                    status="SENT",
                )
            )
            await session.commit()
        return {"id": msg_id, "tenant_id": tenant_id, "status": "SENT"}

    async def read_message(
        self,
        context: TenantContext,
        *,
        message_id: str,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, _, user_id = self._require_context(context)
        await self._require_not_isolated(tenant_id, [("MESSAGE", message_id)])
        async with self._session_factory() as session:
            msg = (
                await session.execute(
                    select(CompanyMessage).where(
                        CompanyMessage.tenant_id == tenant_id,
                        CompanyMessage.id == message_id,
                    )
                )
            ).scalar_one_or_none()
            if msg is None:
                raise NotFoundError("Message not found.")
            if user_id not in (msg.sender_user_id, msg.recipient_user_id):
                raise ForbiddenError("Not authorized to read this message.")
        await self._emit_observation(
            context=context,
            event_type="COMPANY_MESSAGE_READ",
            event_category="COMPANY_RESOURCE_ACCESS",
            resource_type="MESSAGE",
            resource_id=message_id,
            outcome="READ",
            agent_id=agent_id,
            trace_id=trace_id,
            payload={"body_sha256": _sha256(msg.body)},
            mandatory=False,
        )
        return {
            "id": msg.id,
            "tenant_id": msg.tenant_id,
            "subject": msg.subject,
            "body": msg.body,
            "status": msg.status,
        }

    async def create_notification(
        self,
        context: TenantContext,
        *,
        user_id: str,
        event_type: str,
        title: str,
        body: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, _, _ = self._require_context(context)
        notif_id = f"notif-{uuid.uuid4().hex[:24]}"
        await self._emit_observation(
            context=context,
            event_type="COMPANY_NOTIFICATION_CREATED",
            event_category="COMPANY_RESOURCE_MUTATION",
            resource_type="NOTIFICATION",
            resource_id=notif_id,
            outcome="CREATED",
            payload={"target_user_id": user_id, "notification_event_type": event_type},
            mandatory=True,
        )
        async with self._session_factory() as session:
            session.add(
                CompanyNotification(
                    id=notif_id,
                    tenant_id=tenant_id,
                    user_id=user_id,
                    event_type=event_type,
                    title=title,
                    body=body,
                    resource_type=resource_type,
                    resource_id=resource_id,
                )
            )
            await session.commit()
        return {"id": notif_id, "tenant_id": tenant_id, "user_id": user_id}

    async def read_file_version(
        self,
        context: TenantContext,
        *,
        file_id: str,
        version_number: int,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, _ = self._require_context(context)
        async with self._session_factory() as session:
            file_row = (
                await session.execute(
                    select(CompanyFile).where(
                        CompanyFile.tenant_id == tenant_id,
                        CompanyFile.id == file_id,
                    )
                )
            ).scalar_one_or_none()
            if file_row is None:
                raise NotFoundError("Company file not found.")
            ws = (
                await session.execute(
                    select(CompanyWorkspace).where(
                        CompanyWorkspace.tenant_id == tenant_id,
                        CompanyWorkspace.id == file_row.workspace_id,
                    )
                )
            ).scalar_one_or_none()
            if ws is None or (branch_id and ws.branch_id != branch_id):
                raise ForbiddenError("Cross-branch file version access is prohibited.")
            ver = (
                await session.execute(
                    select(CompanyFileVersion).where(
                        CompanyFileVersion.tenant_id == tenant_id,
                        CompanyFileVersion.file_id == file_id,
                        CompanyFileVersion.version_number == version_number,
                    )
                )
            ).scalar_one_or_none()
            if ver is None:
                raise NotFoundError("Company file version not found.")
            await self._require_not_isolated(
                tenant_id,
                [("FILE_VERSION", ver.id), ("FILE", file_id), ("WORKSPACE", file_row.workspace_id)],
            )
        return {
            "id": ver.id,
            "tenant_id": ver.tenant_id,
            "file_id": ver.file_id,
            "version_number": ver.version_number,
            "content": ver.content,
            "checksum": ver.checksum,
        }

    async def read_task(
        self,
        context: TenantContext,
        *,
        task_id: str,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, _ = self._require_context(context)
        async with self._session_factory() as session:
            task = (
                await session.execute(
                    select(CompanyTask).where(
                        CompanyTask.tenant_id == tenant_id,
                        CompanyTask.id == task_id,
                    )
                )
            ).scalar_one_or_none()
            if task is None:
                raise NotFoundError("Company task not found.")
            if branch_id and task.branch_id != branch_id:
                raise ForbiddenError("Cross-branch task access is prohibited.")
            await self._require_not_isolated(
                tenant_id,
                [("TASK", task_id), ("WORKSPACE", task.workspace_id)],
            )
            if task.status == "BLOCKED":
                raise ForbiddenError("Blocked task cannot be accessed.")
        return {
            "id": task.id,
            "tenant_id": task.tenant_id,
            "workspace_id": task.workspace_id,
            "branch_id": task.branch_id,
            "title": task.title,
            "description": task.description,
            "status": task.status,
            "priority": task.priority,
        }

    async def read_notification(
        self,
        context: TenantContext,
        *,
        notification_id: str,
    ) -> Dict[str, Any]:
        tenant_id, _, user_id = self._require_context(context)
        await self._require_not_isolated(tenant_id, [("NOTIFICATION", notification_id)])
        async with self._session_factory() as session:
            notif = (
                await session.execute(
                    select(CompanyNotification).where(
                        CompanyNotification.tenant_id == tenant_id,
                        CompanyNotification.id == notification_id,
                    )
                )
            ).scalar_one_or_none()
            if notif is None:
                raise NotFoundError("Notification not found.")
            if notif.user_id != user_id:
                raise ForbiddenError("Not authorized to read this notification.")
        return {
            "id": notif.id,
            "tenant_id": notif.tenant_id,
            "user_id": notif.user_id,
            "event_type": notif.event_type,
            "title": notif.title,
            "body": notif.body,
        }


__all__ = [
    "CompanyResourceService",
    "SqlCompanyResourceIsolationAdapter",
]
