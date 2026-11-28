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

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core.exceptions import (
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.database.models.baseline import ObservationEvent
from backend.app.database.models.company import (
    CompanyActivity,
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
from backend.app.workers.outbox import publish_outbox_event

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
                await publish_outbox_event(
                    session,
                    tenant_id=tenant_id,
                    event_type="COMPANY_RESOURCE_ISOLATED",
                    payload={
                        "resource_type": norm_type,
                        "resource_id": resource_id,
                        "branch_id": resolved_branch_id,
                        "incident_id": incident_id,
                        "actor_id": actor_id,
                        "reason": reason,
                    },
                    idempotency_key=f"company-isolate-{tenant_id}-{norm_type}-{resource_id}-{incident_id or 'none'}",
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
            session.add(CompanyActivity(
                id=f"cact-{uuid.uuid4().hex[:24]}",
                tenant_id=tenant_id,
                branch_id=branch_id,
                actor_user_id=user_id,
                event_type="WORKSPACE_CREATED",
                resource_type="WORKSPACE",
                resource_id=ws_id,
                summary=f"Created workspace: {name}",
                details={"visibility": visibility},
            ))
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_WORKSPACE_CREATED",
                payload={
                    "workspace_id": ws_id,
                    "branch_id": branch_id,
                    "owner_user_id": user_id,
                    "name": name,
                    "visibility": visibility,
                },
                idempotency_key=f"company-ws-create-{tenant_id}-{ws_id}",
            )
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
            session.add(CompanyActivity(
                id=f"cact-{uuid.uuid4().hex[:24]}",
                tenant_id=tenant_id,
                branch_id=ws.branch_id,
                actor_user_id=user_id,
                event_type="FILE_CREATED",
                resource_type="FILE",
                resource_id=file_id,
                summary=f"Created file: {name}",
                details={"workspace_id": workspace_id, "version": 1, "content_sha256": checksum},
            ))
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_FILE_CREATED",
                payload={
                    "file_id": file_id,
                    "workspace_id": workspace_id,
                    "branch_id": ws.branch_id,
                    "actor_user_id": user_id,
                    "agent_id": agent_id,
                    "version": 1,
                    "content_sha256": checksum,
                },
                idempotency_key=f"company-file-create-{tenant_id}-{file_id}",
            )
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
            session.add(CompanyActivity(
                id=f"cact-{uuid.uuid4().hex[:24]}",
                tenant_id=tenant_id,
                branch_id=ws.branch_id,
                actor_user_id=user_id,
                event_type="FILE_UPDATED",
                resource_type="FILE",
                resource_id=file_id,
                summary=f"Updated file: {file_row.name} (v{new_version})",
                details={"workspace_id": file_row.workspace_id, "version": new_version, "content_sha256": checksum},
            ))
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_FILE_UPDATED",
                payload={
                    "file_id": file_id,
                    "workspace_id": file_row.workspace_id,
                    "branch_id": ws.branch_id,
                    "actor_user_id": user_id,
                    "agent_id": agent_id,
                    "version": new_version,
                    "content_sha256": checksum,
                },
                idempotency_key=f"company-file-update-{tenant_id}-{file_id}-v{new_version}",
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
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_FILE_TRANSFER_CREATED",
                payload={
                    "transfer_id": transfer_id,
                    "file_id": file_id,
                    "branch_id": ws.branch_id,
                    "sender_user_id": user_id,
                    "recipient_user_id": recipient_user_id,
                    "agent_id": agent_id,
                },
                idempotency_key=f"company-transfer-create-{tenant_id}-{transfer_id}",
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
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_FILE_TRANSFER_ACCEPTED",
                payload={
                    "transfer_id": transfer_id,
                    "file_id": tr.file_id,
                    "branch_id": ws.branch_id,
                    "actor_user_id": user_id,
                    "agent_id": agent_id,
                },
                idempotency_key=f"company-transfer-accept-{tenant_id}-{transfer_id}",
            )
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
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_TASK_CREATED",
                payload={
                    "task_id": task_id,
                    "workspace_id": workspace_id,
                    "branch_id": ws.branch_id,
                    "actor_user_id": user_id,
                    "assigned_to_user_id": assigned_to_user_id,
                    "agent_id": agent_id,
                },
                idempotency_key=f"company-task-create-{tenant_id}-{task_id}",
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
            previous_assignee = task.assigned_to_user_id
            if assigned_to_user_id is not None:
                task.assigned_to_user_id = assigned_to_user_id
                if assigned_to_user_id != previous_assignee and assigned_to_user_id != user_id:
                    session.add(CompanyNotification(
                        id=f"cnot-{uuid.uuid4().hex[:24]}",
                        tenant_id=tenant_id,
                        user_id=assigned_to_user_id,
                        event_type="TASK_ASSIGNED",
                        title="Task assigned to you",
                        body=f"Task '{task.title}' was assigned to you.",
                        resource_type="TASK",
                        resource_id=task_id,
                    ))
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
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_TASK_UPDATED",
                payload={
                    "task_id": task_id,
                    "branch_id": task.branch_id,
                    "status": new_status,
                    "actor_user_id": user_id,
                    "assigned_to_user_id": task.assigned_to_user_id,
                    "agent_id": agent_id,
                },
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
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_MESSAGE_SENT",
                payload={
                    "message_id": msg_id,
                    "sender_user_id": user_id,
                    "recipient_user_id": recipient_user_id,
                    "agent_id": agent_id,
                },
                idempotency_key=f"company-msg-send-{tenant_id}-{msg_id}",
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
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_NOTIFICATION_CREATED",
                payload={
                    "notification_id": notif_id,
                    "target_user_id": user_id,
                    "notification_event_type": event_type,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                },
                idempotency_key=f"company-notif-create-{tenant_id}-{notif_id}",
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
            "read_at": notif.read_at.isoformat() if notif.read_at else None,
        }

    async def list_workspaces(self, context: TenantContext) -> list[Dict[str, Any]]:
        tenant_id, branch_id, user_id = self._require_context(context)
        is_admin = context.role in ("TENANT_ADMIN", "BRANCH_ADMIN")
        async with self._session_factory() as session:
            stmt = select(CompanyWorkspace).where(CompanyWorkspace.tenant_id == tenant_id)
            if branch_id:
                stmt = stmt.where(CompanyWorkspace.branch_id == branch_id)
            stmt = stmt.order_by(CompanyWorkspace.created_at.desc())
            rows = (await session.execute(stmt)).scalars().all()

        items: list[Dict[str, Any]] = []
        for w in rows:
            if w.visibility == "PRIVATE" and w.owner_user_id != user_id and not is_admin:
                continue
            if await self._isolation_adapter.is_resource_isolated(tenant_id, "WORKSPACE", w.id):
                continue
            items.append({
                "id": w.id,
                "tenant_id": w.tenant_id,
                "branch_id": w.branch_id,
                "owner_user_id": w.owner_user_id,
                "name": w.name,
                "description": w.description,
                "visibility": w.visibility,
                "created_at": w.created_at.isoformat(),
                "updated_at": w.updated_at.isoformat(),
            })
        return items

    async def list_files(
        self,
        context: TenantContext,
        *,
        workspace_id: Optional[str] = None,
        include_deleted: bool = False,
    ) -> list[Dict[str, Any]]:
        tenant_id, branch_id, user_id = self._require_context(context)
        is_admin = context.role in ("TENANT_ADMIN", "BRANCH_ADMIN")
        async with self._session_factory() as session:
            stmt = (
                select(CompanyFile, CompanyWorkspace)
                .join(
                    CompanyWorkspace,
                    (CompanyWorkspace.id == CompanyFile.workspace_id)
                    & (CompanyWorkspace.tenant_id == CompanyFile.tenant_id),
                )
                .where(CompanyFile.tenant_id == tenant_id)
            )
            if branch_id:
                stmt = stmt.where(CompanyWorkspace.branch_id == branch_id)
            if workspace_id:
                stmt = stmt.where(CompanyFile.workspace_id == workspace_id)
            if not include_deleted:
                stmt = stmt.where(CompanyFile.status == "ACTIVE")
            stmt = stmt.order_by(CompanyFile.updated_at.desc())
            rows = (await session.execute(stmt)).all()

        items: list[Dict[str, Any]] = []
        for f, ws in rows:
            if ws.visibility == "PRIVATE" and ws.owner_user_id != user_id and not is_admin:
                continue
            if await self._isolation_adapter.is_resource_isolated(tenant_id, "WORKSPACE", ws.id):
                continue
            if await self._isolation_adapter.is_resource_isolated(tenant_id, "FILE", f.id):
                continue
            items.append({
                "id": f.id,
                "tenant_id": f.tenant_id,
                "workspace_id": f.workspace_id,
                "branch_id": ws.branch_id,
                "owner_user_id": f.owner_user_id,
                "name": f.name,
                "content_type": f.content_type,
                "current_version": f.current_version,
                "status": f.status,
                "created_at": f.created_at.isoformat(),
                "updated_at": f.updated_at.isoformat(),
                "deleted_at": f.deleted_at.isoformat() if f.deleted_at else None,
            })
        return items

    async def list_file_versions(
        self,
        context: TenantContext,
        *,
        file_id: str,
    ) -> list[Dict[str, Any]]:
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
            await self._require_not_isolated(
                tenant_id,
                [("FILE", file_id), ("WORKSPACE", file_row.workspace_id)],
            )
            versions = (
                await session.execute(
                    select(CompanyFileVersion)
                    .where(
                        CompanyFileVersion.tenant_id == tenant_id,
                        CompanyFileVersion.file_id == file_id,
                    )
                    .order_by(CompanyFileVersion.version_number.desc())
                )
            ).scalars().all()
        return [
            {
                "id": v.id,
                "tenant_id": v.tenant_id,
                "file_id": v.file_id,
                "version_number": v.version_number,
                "checksum": v.checksum,
                "created_by_user_id": v.created_by_user_id,
                "created_at": v.created_at.isoformat(),
            }
            for v in versions
        ]

    async def delete_file(
        self,
        context: TenantContext,
        *,
        file_id: str,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        is_admin = context.role in ("TENANT_ADMIN", "BRANCH_ADMIN")
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
                raise ForbiddenError("Cross-branch file deletion is prohibited.")
            if file_row.owner_user_id != user_id and ws.owner_user_id != user_id and not is_admin:
                raise ForbiddenError("Only the file owner, workspace owner, or admin may delete this file.")
            await self._require_not_isolated(
                tenant_id,
                [("FILE", file_id), ("WORKSPACE", file_row.workspace_id)],
            )
            if file_row.status == "DELETED":
                raise ForbiddenError("File is already deleted.")

            await self._capture_checkpoint_if_configured(
                context=context,
                operation="delete_file",
                parameters={"file_id": file_id, "workspace_id": file_row.workspace_id},
                agent_id=agent_id,
                trace_id=trace_id,
            )

            now = datetime.now(timezone.utc)
            await self._emit_observation(
                context=context,
                event_type="COMPANY_FILE_DELETED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="FILE",
                resource_id=file_id,
                outcome="DELETED",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={"workspace_id": file_row.workspace_id, "current_version": file_row.current_version},
                mandatory=True,
            )
            file_row.status = "DELETED"
            file_row.deleted_at = now
            file_row.updated_at = now
            session.add(CompanyActivity(
                id=f"cact-{uuid.uuid4().hex[:24]}",
                tenant_id=tenant_id,
                branch_id=ws.branch_id,
                actor_user_id=user_id,
                event_type="FILE_DELETED",
                resource_type="FILE",
                resource_id=file_id,
                summary=f"Deleted file: {file_row.name}",
                details={"workspace_id": file_row.workspace_id},
            ))
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_FILE_DELETED",
                payload={
                    "file_id": file_id,
                    "workspace_id": file_row.workspace_id,
                    "branch_id": ws.branch_id,
                    "actor_user_id": user_id,
                    "agent_id": agent_id,
                },
            )
            await session.commit()
        return {"id": file_id, "tenant_id": tenant_id, "status": "DELETED"}

    async def restore_file(
        self,
        context: TenantContext,
        *,
        file_id: str,
        target_version: Optional[int] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tenant_id, branch_id, user_id = self._require_context(context)
        is_admin = context.role in ("TENANT_ADMIN", "BRANCH_ADMIN")
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
                raise ForbiddenError("Cross-branch file restore is prohibited.")
            if file_row.owner_user_id != user_id and ws.owner_user_id != user_id and not is_admin:
                raise ForbiddenError("Only the file owner, workspace owner, or admin may restore this file.")
            await self._require_not_isolated(
                tenant_id,
                [("FILE", file_id), ("WORKSPACE", file_row.workspace_id)],
            )

            if target_version is not None:
                ver = (
                    await session.execute(
                        select(CompanyFileVersion).where(
                            CompanyFileVersion.tenant_id == tenant_id,
                            CompanyFileVersion.file_id == file_id,
                            CompanyFileVersion.version_number == target_version,
                        )
                    )
                ).scalar_one_or_none()
                if ver is None:
                    raise NotFoundError(f"File version {target_version} not found.")
                await self._require_not_isolated(tenant_id, [("FILE_VERSION", ver.id)])
                file_row.current_version = target_version

            now = datetime.now(timezone.utc)
            await self._emit_observation(
                context=context,
                event_type="COMPANY_FILE_RESTORED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="FILE",
                resource_id=file_id,
                outcome="ACTIVE",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={"workspace_id": file_row.workspace_id, "current_version": file_row.current_version},
                mandatory=True,
            )
            file_row.status = "ACTIVE"
            file_row.deleted_at = None
            file_row.updated_at = now
            session.add(CompanyActivity(
                id=f"cact-{uuid.uuid4().hex[:24]}",
                tenant_id=tenant_id,
                branch_id=ws.branch_id,
                actor_user_id=user_id,
                event_type="FILE_RESTORED",
                resource_type="FILE",
                resource_id=file_id,
                summary=f"Restored file: {file_row.name} (v{file_row.current_version})",
                details={"workspace_id": file_row.workspace_id, "current_version": file_row.current_version},
            ))
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_FILE_RESTORED",
                payload={
                    "file_id": file_id,
                    "workspace_id": file_row.workspace_id,
                    "branch_id": ws.branch_id,
                    "actor_user_id": user_id,
                    "current_version": file_row.current_version,
                },
            )
            await session.commit()
        return {
            "id": file_id,
            "tenant_id": tenant_id,
            "status": "ACTIVE",
            "current_version": file_row.current_version,
        }

    async def list_file_transfers(
        self,
        context: TenantContext,
        *,
        direction: str = "all",
    ) -> list[Dict[str, Any]]:
        tenant_id, _, user_id = self._require_context(context)
        if direction not in ("all", "incoming", "outgoing"):
            raise ValidationError("direction must be one of: all, incoming, outgoing.")
        async with self._session_factory() as session:
            stmt = select(CompanyFileTransfer).where(CompanyFileTransfer.tenant_id == tenant_id)
            if direction == "incoming":
                stmt = stmt.where(CompanyFileTransfer.recipient_user_id == user_id)
            elif direction == "outgoing":
                stmt = stmt.where(CompanyFileTransfer.sender_user_id == user_id)
            else:
                stmt = stmt.where(
                    or_(
                        CompanyFileTransfer.sender_user_id == user_id,
                        CompanyFileTransfer.recipient_user_id == user_id,
                    )
                )
            stmt = stmt.order_by(CompanyFileTransfer.created_at.desc())
            rows = (await session.execute(stmt)).scalars().all()

        items: list[Dict[str, Any]] = []
        for tr in rows:
            if await self._isolation_adapter.is_resource_isolated(tenant_id, "FILE_TRANSFER", tr.id):
                continue
            items.append({
                "id": tr.id,
                "tenant_id": tr.tenant_id,
                "file_id": tr.file_id,
                "sender_user_id": tr.sender_user_id,
                "recipient_user_id": tr.recipient_user_id,
                "status": tr.status,
                "message": tr.message,
                "created_at": tr.created_at.isoformat(),
                "responded_at": tr.responded_at.isoformat() if tr.responded_at else None,
            })
        return items

    async def reject_file_transfer(
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
                raise ForbiddenError("Only the designated recipient may reject a file transfer.")
            file_row = (
                await session.execute(
                    select(CompanyFile).where(
                        CompanyFile.tenant_id == tenant_id,
                        CompanyFile.id == tr.file_id,
                    )
                )
            ).scalar_one_or_none()
            ws = None
            if file_row is not None:
                ws = (
                    await session.execute(
                        select(CompanyWorkspace).where(
                            CompanyWorkspace.tenant_id == tenant_id,
                            CompanyWorkspace.id == file_row.workspace_id,
                        )
                    )
                ).scalar_one_or_none()
            if ws is not None and branch_id and ws.branch_id != branch_id:
                raise ForbiddenError("Cross-branch file transfer rejection is prohibited.")
            await self._require_not_isolated(tenant_id, [("FILE_TRANSFER", transfer_id)])
            if tr.status != "PENDING":
                raise ForbiddenError(f"File transfer in status '{tr.status}' cannot be rejected.")

            await self._emit_observation(
                context=context,
                event_type="COMPANY_FILE_TRANSFER_REJECTED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="FILE_TRANSFER",
                resource_id=transfer_id,
                outcome="REJECTED",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={"file_id": tr.file_id},
                mandatory=True,
            )
            tr.status = "REJECTED"
            tr.responded_at = datetime.now(timezone.utc)
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_FILE_TRANSFER_REJECTED",
                payload={
                    "transfer_id": transfer_id,
                    "file_id": tr.file_id,
                    "branch_id": ws.branch_id if ws else branch_id,
                    "actor_user_id": user_id,
                },
                idempotency_key=f"company-transfer-reject-{tenant_id}-{transfer_id}",
            )
            await session.commit()
        return {"id": tr.id, "file_id": tr.file_id, "status": "REJECTED"}

    async def cancel_file_transfer(
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
            if tr.sender_user_id != user_id:
                raise ForbiddenError("Only the sender may cancel a file transfer.")
            await self._require_not_isolated(tenant_id, [("FILE_TRANSFER", transfer_id)])
            if tr.status != "PENDING":
                raise ForbiddenError(f"File transfer in status '{tr.status}' cannot be cancelled.")

            await self._emit_observation(
                context=context,
                event_type="COMPANY_FILE_TRANSFER_CANCELLED",
                event_category="COMPANY_RESOURCE_MUTATION",
                resource_type="FILE_TRANSFER",
                resource_id=transfer_id,
                outcome="CANCELLED",
                agent_id=agent_id,
                trace_id=trace_id,
                payload={"file_id": tr.file_id},
                mandatory=True,
            )
            tr.status = "CANCELLED"
            tr.responded_at = datetime.now(timezone.utc)
            await publish_outbox_event(
                session,
                tenant_id=tenant_id,
                event_type="COMPANY_FILE_TRANSFER_CANCELLED",
                payload={
                    "transfer_id": transfer_id,
                    "file_id": tr.file_id,
                    "branch_id": branch_id,
                    "actor_user_id": user_id,
                },
                idempotency_key=f"company-transfer-cancel-{tenant_id}-{transfer_id}",
            )
            await session.commit()
        return {"id": tr.id, "file_id": tr.file_id, "status": "CANCELLED"}

    async def list_tasks(
        self,
        context: TenantContext,
        *,
        workspace_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[Dict[str, Any]]:
        tenant_id, branch_id, _ = self._require_context(context)
        async with self._session_factory() as session:
            stmt = select(CompanyTask).where(CompanyTask.tenant_id == tenant_id)
            if branch_id:
                stmt = stmt.where(CompanyTask.branch_id == branch_id)
            if workspace_id:
                stmt = stmt.where(CompanyTask.workspace_id == workspace_id)
            if status:
                stmt = stmt.where(CompanyTask.status == status)
            stmt = stmt.order_by(CompanyTask.updated_at.desc())
            rows = (await session.execute(stmt)).scalars().all()

        items: list[Dict[str, Any]] = []
        for t in rows:
            if await self._isolation_adapter.is_resource_isolated(tenant_id, "TASK", t.id):
                continue
            items.append({
                "id": t.id,
                "tenant_id": t.tenant_id,
                "workspace_id": t.workspace_id,
                "branch_id": t.branch_id,
                "title": t.title,
                "description": t.description,
                "status": t.status,
                "priority": t.priority,
                "created_by_user_id": t.created_by_user_id,
                "assigned_to_user_id": t.assigned_to_user_id,
                "created_at": t.created_at.isoformat(),
                "updated_at": t.updated_at.isoformat(),
            })
        return items

    async def list_task_events(
        self,
        context: TenantContext,
        *,
        task_id: str,
    ) -> list[Dict[str, Any]]:
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
                raise ForbiddenError("Cross-branch task event access is prohibited.")
            await self._require_not_isolated(tenant_id, [("TASK", task_id), ("WORKSPACE", task.workspace_id)])
            events = (
                await session.execute(
                    select(CompanyTaskEvent)
                    .where(
                        CompanyTaskEvent.tenant_id == tenant_id,
                        CompanyTaskEvent.task_id == task_id,
                    )
                    .order_by(CompanyTaskEvent.created_at.asc())
                )
            ).scalars().all()
        return [
            {
                "id": e.id,
                "tenant_id": e.tenant_id,
                "task_id": e.task_id,
                "actor_user_id": e.actor_user_id,
                "event_type": e.event_type,
                "details": e.details,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ]

    async def list_messages(
        self,
        context: TenantContext,
        *,
        box: str = "inbox",
    ) -> list[Dict[str, Any]]:
        tenant_id, _, user_id = self._require_context(context)
        if box not in ("inbox", "sent", "all"):
            raise ValidationError("box must be one of: inbox, sent, all.")
        async with self._session_factory() as session:
            stmt = select(CompanyMessage).where(CompanyMessage.tenant_id == tenant_id)
            if box == "inbox":
                stmt = stmt.where(CompanyMessage.recipient_user_id == user_id)
            elif box == "sent":
                stmt = stmt.where(CompanyMessage.sender_user_id == user_id)
            else:
                stmt = stmt.where(
                    or_(
                        CompanyMessage.sender_user_id == user_id,
                        CompanyMessage.recipient_user_id == user_id,
                    )
                )
            stmt = stmt.order_by(CompanyMessage.sent_at.desc())
            rows = (await session.execute(stmt)).scalars().all()

        items: list[Dict[str, Any]] = []
        for m in rows:
            if await self._isolation_adapter.is_resource_isolated(tenant_id, "MESSAGE", m.id):
                continue
            items.append({
                "id": m.id,
                "tenant_id": m.tenant_id,
                "sender_user_id": m.sender_user_id,
                "recipient_user_id": m.recipient_user_id,
                "subject": m.subject,
                "body": m.body,
                "status": m.status,
                "sent_at": m.sent_at.isoformat(),
                "read_at": m.read_at.isoformat() if m.read_at else None,
            })
        return items

    async def mark_message_read(
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
            if msg.recipient_user_id != user_id:
                raise ForbiddenError("Only the recipient may mark this message as read.")
            if msg.status != "READ":
                msg.status = "READ"
                msg.read_at = datetime.now(timezone.utc)
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
                await publish_outbox_event(
                    session,
                    tenant_id=tenant_id,
                    event_type="COMPANY_MESSAGE_READ",
                    payload={"message_id": message_id, "recipient_user_id": user_id},
                    idempotency_key=f"company-msg-read-{tenant_id}-{message_id}",
                )
                await session.commit()
        return {
            "id": msg.id,
            "tenant_id": msg.tenant_id,
            "status": msg.status,
            "read_at": msg.read_at.isoformat() if msg.read_at else None,
        }

    async def list_notifications(
        self,
        context: TenantContext,
        *,
        unread_only: bool = False,
    ) -> list[Dict[str, Any]]:
        tenant_id, _, user_id = self._require_context(context)
        async with self._session_factory() as session:
            stmt = select(CompanyNotification).where(
                CompanyNotification.tenant_id == tenant_id,
                CompanyNotification.user_id == user_id,
            )
            if unread_only:
                stmt = stmt.where(CompanyNotification.read_at.is_(None))
            stmt = stmt.order_by(CompanyNotification.created_at.desc())
            rows = (await session.execute(stmt)).scalars().all()

        items: list[Dict[str, Any]] = []
        for n in rows:
            if await self._isolation_adapter.is_resource_isolated(tenant_id, "NOTIFICATION", n.id):
                continue
            items.append({
                "id": n.id,
                "tenant_id": n.tenant_id,
                "user_id": n.user_id,
                "event_type": n.event_type,
                "title": n.title,
                "body": n.body,
                "resource_type": n.resource_type,
                "resource_id": n.resource_id,
                "read_at": n.read_at.isoformat() if n.read_at else None,
                "created_at": n.created_at.isoformat(),
            })
        return items

    async def mark_notification_read(
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
                raise ForbiddenError("Not authorized to update this notification.")
            if notif.read_at is None:
                notif.read_at = datetime.now(timezone.utc)
                await publish_outbox_event(
                    session,
                    tenant_id=tenant_id,
                    event_type="COMPANY_NOTIFICATION_READ",
                    payload={"notification_id": notification_id, "user_id": user_id},
                    idempotency_key=f"company-notif-read-{tenant_id}-{notification_id}",
                )
                await session.commit()
        return {
            "id": notif.id,
            "tenant_id": notif.tenant_id,
            "read_at": notif.read_at.isoformat() if notif.read_at else None,
        }

    async def list_activity(
        self,
        context: TenantContext,
        *,
        limit: int = 50,
    ) -> list[Dict[str, Any]]:
        tenant_id, branch_id, _ = self._require_context(context)
        safe_limit = max(1, min(limit, 200))
        async with self._session_factory() as session:
            stmt = select(CompanyActivity).where(CompanyActivity.tenant_id == tenant_id)
            if branch_id:
                stmt = stmt.where(CompanyActivity.branch_id == branch_id)
            stmt = stmt.order_by(CompanyActivity.created_at.desc()).limit(safe_limit)
            rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": a.id,
                "tenant_id": a.tenant_id,
                "branch_id": a.branch_id,
                "actor_user_id": a.actor_user_id,
                "event_type": a.event_type,
                "resource_type": a.resource_type,
                "resource_id": a.resource_id,
                "summary": a.summary,
                "details": a.details,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]


__all__ = [
    "CompanyResourceService",
    "SqlCompanyResourceIsolationAdapter",
]
