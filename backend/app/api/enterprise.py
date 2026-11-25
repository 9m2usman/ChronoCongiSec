"""Enterprise-Wide Data Connectivity, Discovery, Synchronization & Knowledge Intelligence API."""

from __future__ import annotations

import logging
from typing import List, Optional
import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from backend.app.api.memory import get_repository as get_memory_repository
from backend.app.core.config import get_settings
from backend.app.core.dependencies import require_roles
from backend.app.core.exceptions import (
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
)
from backend.app.enterprise.discovery import EnterpriseDiscoveryService
from backend.app.enterprise.impact import EnterpriseImpactService
from backend.app.enterprise.intelligence import OrganizationalIntelligenceService
from backend.app.enterprise.models import (
    ConnectorAuditLogDTO,
    ConnectorAuthorizeRequest,
    ConnectorCreateRequest,
    ConnectorStatus,
    ConnectorSyncRequest,
    DiscoveredResourceDTO,
    EnterpriseConnectorDTO,
    EnterpriseMemoryLinkDTO,
    ImpactTraceResponse,
    KnowledgeClaimDTO,
    MemoryExtractRequest,
    ScopedRecoveryPlanRequest,
    ScopedRecoveryPlanResponse,
    SyncJobDTO,
)
from backend.app.enterprise.repository import (
    EnterpriseRepository,
    SqlAlchemyEnterpriseRepository,
    get_default_enterprise_repository,
)
from backend.app.enterprise.sync import EnterpriseSyncService
from backend.app.memory.repository import MemoryRepository
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.enterprise")

router = APIRouter(prefix="/enterprise", tags=["Enterprise Connectivity"])

ADMIN_ROLES = require_roles("TENANT_ADMIN", "SECURITY_ADMIN")
VIEWER_ROLES = require_roles(
    "TENANT_ADMIN",
    "SECURITY_ADMIN",
    "SECURITY_ANALYST",
    "AI_DEVELOPER",
    "AUDITOR",
)


async def get_enterprise_repo(request: Request) -> EnterpriseRepository:
    settings = getattr(request.app.state, "settings", None) or get_settings()
    repo = getattr(request.app.state, "enterprise_repo", None)

    if repo is None:
        session_factory = getattr(request.app.state, "db_session_factory", None)
        if session_factory is not None:
            repo = SqlAlchemyEnterpriseRepository(session_factory)
            request.app.state.enterprise_repo = repo

    if settings.APP_ENV == "production":
        if repo is None or getattr(repo, "is_in_memory", True) or not getattr(repo, "is_persistent", False):
            raise SecurityDependencyError("Production enterprise repository is not configured.")
        return repo

    if repo is not None:
        return repo
    return get_default_enterprise_repository()


@router.post(
    "/connectors",
    response_model=EnterpriseConnectorDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Onboard and configure an enterprise connector",
)
async def create_connector(
    payload: ConnectorCreateRequest,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
    memory_repo: MemoryRepository = Depends(get_memory_repository),
) -> EnterpriseConnectorDTO:
    svc = EnterpriseDiscoveryService(repo, memory_repo)
    return await svc.create_connector(tenant_context.tenant_id, tenant_context.user_id, payload)


@router.get(
    "/connectors",
    response_model=List[EnterpriseConnectorDTO],
    status_code=status.HTTP_200_OK,
    summary="List enterprise connectors for tenant",
)
async def list_connectors(
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> List[EnterpriseConnectorDTO]:
    return await repo.list_connectors(tenant_context.tenant_id)


@router.get(
    "/connectors/{connector_id}",
    response_model=EnterpriseConnectorDTO,
    status_code=status.HTTP_200_OK,
    summary="Get enterprise connector details",
)
async def get_connector(
    connector_id: str,
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> EnterpriseConnectorDTO:
    conn = await repo.get_connector(tenant_context.tenant_id, connector_id)
    if conn is None:
        raise NotFoundError("Enterprise connector not found.")
    return conn


@router.post(
    "/connectors/{connector_id}/authorize",
    response_model=EnterpriseConnectorDTO,
    status_code=status.HTTP_200_OK,
    summary="Explicitly authorize and validate an enterprise connector",
)
async def authorize_connector(
    connector_id: str,
    payload: ConnectorAuthorizeRequest,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
    memory_repo: MemoryRepository = Depends(get_memory_repository),
) -> EnterpriseConnectorDTO:
    svc = EnterpriseDiscoveryService(repo, memory_repo)
    try:
        return await svc.authorize_connector(
            tenant_context.tenant_id,
            connector_id,
            tenant_context.user_id,
            approved_scope=payload.approved_scope,
            justification=payload.justification,
        )
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc


@router.post(
    "/connectors/{connector_id}/pause",
    response_model=EnterpriseConnectorDTO,
    status_code=status.HTTP_200_OK,
    summary="Pause an enterprise connector",
)
async def pause_connector(
    connector_id: str,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> EnterpriseConnectorDTO:
    conn = await repo.get_connector(tenant_context.tenant_id, connector_id)
    if conn is None:
        raise NotFoundError("Enterprise connector not found.")
    conn.status = ConnectorStatus.PAUSED
    updated = await repo.update_connector(conn)
    await repo.append_audit_log(
        ConnectorAuditLogDTO(
            id=str(uuid.uuid4()),
            tenant_id=tenant_context.tenant_id,
            connector_id=connector_id,
            actor_id=tenant_context.user_id,
            action="PAUSE",
            status="SUCCESS",
            details_json={},
        )
    )
    return updated


@router.post(
    "/connectors/{connector_id}/resume",
    response_model=EnterpriseConnectorDTO,
    status_code=status.HTTP_200_OK,
    summary="Resume a paused enterprise connector",
)
async def resume_connector(
    connector_id: str,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> EnterpriseConnectorDTO:
    conn = await repo.get_connector(tenant_context.tenant_id, connector_id)
    if conn is None:
        raise NotFoundError("Enterprise connector not found.")
    if str(conn.status) == ConnectorStatus.REVOKED.value:
        raise ForbiddenError("Revoked connectors cannot be resumed; re-authorization is required.")
    conn.status = ConnectorStatus.AUTHORIZED
    updated = await repo.update_connector(conn)
    await repo.append_audit_log(
        ConnectorAuditLogDTO(
            id=str(uuid.uuid4()),
            tenant_id=tenant_context.tenant_id,
            connector_id=connector_id,
            actor_id=tenant_context.user_id,
            action="RESUME",
            status="SUCCESS",
            details_json={},
        )
    )
    return updated


@router.post(
    "/connectors/{connector_id}/revoke",
    response_model=EnterpriseConnectorDTO,
    status_code=status.HTTP_200_OK,
    summary="Revoke and disconnect an enterprise connector",
)
async def revoke_connector(
    connector_id: str,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
    memory_repo: MemoryRepository = Depends(get_memory_repository),
) -> EnterpriseConnectorDTO:
    intel = OrganizationalIntelligenceService(repo, memory_repo)
    sync_svc = EnterpriseSyncService(repo, intel, memory_repo)
    try:
        return await sync_svc.revoke_connector(
            tenant_context.tenant_id,
            connector_id,
            tenant_context.user_id,
        )
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc


@router.post(
    "/connectors/{connector_id}/discover",
    response_model=List[DiscoveredResourceDTO],
    status_code=status.HTTP_200_OK,
    summary="Discover permitted resources for an authorized connector",
)
async def discover_resources(
    connector_id: str,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
    memory_repo: MemoryRepository = Depends(get_memory_repository),
) -> List[DiscoveredResourceDTO]:
    svc = EnterpriseDiscoveryService(repo, memory_repo)
    try:
        return await svc.discover_resources(
            tenant_context.tenant_id,
            connector_id,
            tenant_context.user_id,
        )
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc
    except PermissionError as exc:
        raise ForbiddenError(str(exc)) from exc


@router.post(
    "/connectors/{connector_id}/sync",
    response_model=SyncJobDTO,
    status_code=status.HTTP_200_OK,
    summary="Run synchronization and change detection for a connector",
)
async def sync_connector(
    connector_id: str,
    payload: ConnectorSyncRequest,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
    memory_repo: MemoryRepository = Depends(get_memory_repository),
) -> SyncJobDTO:
    intel = OrganizationalIntelligenceService(repo, memory_repo)
    sync_svc = EnterpriseSyncService(repo, intel, memory_repo)
    try:
        return await sync_svc.run_sync(
            tenant_context.tenant_id,
            connector_id,
            tenant_context.user_id,
            strategy=payload.strategy,
            target_resource_ids=payload.target_resource_ids or None,
        )
    except KeyError as exc:
        raise NotFoundError(str(exc)) from exc


@router.get(
    "/resources",
    response_model=List[DiscoveredResourceDTO],
    status_code=status.HTTP_200_OK,
    summary="List discovered enterprise resources",
)
async def list_resources(
    connector_id: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
    sync_status: Optional[str] = Query(None),
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> List[DiscoveredResourceDTO]:
    return await repo.list_resources(
        tenant_context.tenant_id,
        connector_id=connector_id,
        resource_type=resource_type,
        classification=classification,
        sync_status=sync_status,
    )


@router.get(
    "/resources/{resource_id}",
    response_model=DiscoveredResourceDTO,
    status_code=status.HTTP_200_OK,
    summary="Get discovered resource details",
)
async def get_resource(
    resource_id: str,
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> DiscoveredResourceDTO:
    res = await repo.get_resource(tenant_context.tenant_id, resource_id)
    if res is None:
        raise NotFoundError("Discovered resource not found.")
    return res


@router.get(
    "/sync-jobs",
    response_model=List[SyncJobDTO],
    status_code=status.HTTP_200_OK,
    summary="List synchronization job history",
)
async def list_sync_jobs(
    connector_id: Optional[str] = Query(None),
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> List[SyncJobDTO]:
    return await repo.list_sync_jobs(tenant_context.tenant_id, connector_id=connector_id)


@router.get(
    "/knowledge/claims",
    response_model=List[KnowledgeClaimDTO],
    status_code=status.HTTP_200_OK,
    summary="List extracted organizational knowledge claims and conflicts",
)
async def list_knowledge_claims(
    resource_id: Optional[str] = Query(None),
    trust_state: Optional[str] = Query(None),
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> List[KnowledgeClaimDTO]:
    return await repo.list_claims(
        tenant_context.tenant_id,
        resource_id=resource_id,
        trust_state=trust_state,
    )


@router.get(
    "/memory/provenance",
    response_model=List[EnterpriseMemoryLinkDTO],
    status_code=status.HTTP_200_OK,
    summary="List enterprise memory provenance and snapshot lineage",
)
async def list_memory_provenance(
    resource_id: Optional[str] = Query(None),
    memory_record_id: Optional[str] = Query(None),
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> List[EnterpriseMemoryLinkDTO]:
    return await repo.list_memory_links(
        tenant_context.tenant_id,
        resource_id=resource_id,
        memory_record_id=memory_record_id,
    )


@router.post(
    "/memory/extract",
    response_model=EnterpriseMemoryLinkDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Perform controlled memory extraction from an authorized enterprise resource",
)
async def extract_memory_from_resource(
    payload: MemoryExtractRequest,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
    memory_repo: MemoryRepository = Depends(get_memory_repository),
) -> EnterpriseMemoryLinkDTO:
    res = await repo.get_resource(tenant_context.tenant_id, payload.resource_id)
    if res is None:
        raise NotFoundError("Discovered resource not found.")
    claims = await repo.list_claims(tenant_context.tenant_id, resource_id=res.id)
    summary_text = "\n".join(f"{c.subject} | {c.predicate}: {c.object_value}" for c in claims[:10])
    if not summary_text:
        summary_text = f"Enterprise resource {res.name} ({res.external_id}) version={res.source_version}"

    intel = OrganizationalIntelligenceService(repo, memory_repo)
    _, _, link = await intel.extract_controlled_memory(
        tenant_context.tenant_id,
        res,
        content=summary_text,
        agent_id=payload.agent_id,
        purpose=payload.purpose,
    )
    return link


@router.get(
    "/impact/{target_id}",
    response_model=ImpactTraceResponse,
    status_code=status.HTTP_200_OK,
    summary="Trace enterprise-wide incident impact for a resource, claim, or memory record",
)
async def trace_impact(
    target_id: str,
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> ImpactTraceResponse:
    svc = EnterpriseImpactService(repo)
    return await svc.trace_impact(tenant_context.tenant_id, target_id)


@router.post(
    "/recovery/plan",
    response_model=ScopedRecoveryPlanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a scoped, evidence-based recovery plan for affected enterprise resources",
)
async def create_scoped_recovery_plan(
    payload: ScopedRecoveryPlanRequest,
    tenant_context: TenantContext = Depends(ADMIN_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> ScopedRecoveryPlanResponse:
    svc = EnterpriseImpactService(repo)
    return await svc.build_scoped_recovery_plan(
        tenant_context.tenant_id,
        tenant_context.user_id,
        payload.target_id,
        payload.reason,
        require_human_approval=payload.require_human_approval,
    )


@router.get(
    "/audit",
    response_model=List[ConnectorAuditLogDTO],
    status_code=status.HTTP_200_OK,
    summary="List enterprise connector integration audit history",
)
async def list_connector_audit_logs(
    connector_id: Optional[str] = Query(None),
    tenant_context: TenantContext = Depends(VIEWER_ROLES),
    repo: EnterpriseRepository = Depends(get_enterprise_repo),
) -> List[ConnectorAuditLogDTO]:
    return await repo.list_audit_logs(tenant_context.tenant_id, connector_id=connector_id)
