"""Repository layer for Enterprise Connectivity, Discovery, Sync & Knowledge Intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Protocol, runtime_checkable
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models.enterprise import (
    ConnectorAuditLog,
    DiscoveredResource,
    EnterpriseConnector,
    EnterpriseMemoryLink,
    KnowledgeClaim,
    SyncJob,
)
from backend.app.enterprise.models import (
    ConnectorAuditLogDTO,
    DiscoveredResourceDTO,
    EnterpriseConnectorDTO,
    EnterpriseMemoryLinkDTO,
    KnowledgeClaimDTO,
    SyncJobDTO,
)


@runtime_checkable
class EnterpriseRepository(Protocol):
    is_in_memory: bool
    is_persistent: bool

    async def create_connector(self, dto: EnterpriseConnectorDTO) -> EnterpriseConnectorDTO: ...
    async def get_connector(self, tenant_id: str, connector_id: str) -> Optional[EnterpriseConnectorDTO]: ...
    async def list_connectors(self, tenant_id: str) -> List[EnterpriseConnectorDTO]: ...
    async def update_connector(self, dto: EnterpriseConnectorDTO) -> EnterpriseConnectorDTO: ...

    async def upsert_resource(self, dto: DiscoveredResourceDTO) -> DiscoveredResourceDTO: ...
    async def get_resource(self, tenant_id: str, resource_id: str) -> Optional[DiscoveredResourceDTO]: ...
    async def list_resources(
        self,
        tenant_id: str,
        connector_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        classification: Optional[str] = None,
        sync_status: Optional[str] = None,
    ) -> List[DiscoveredResourceDTO]: ...

    async def create_sync_job(self, dto: SyncJobDTO) -> SyncJobDTO: ...
    async def update_sync_job(self, dto: SyncJobDTO) -> SyncJobDTO: ...
    async def list_sync_jobs(self, tenant_id: str, connector_id: Optional[str] = None) -> List[SyncJobDTO]: ...

    async def create_claim(self, dto: KnowledgeClaimDTO) -> KnowledgeClaimDTO: ...
    async def update_claim(self, dto: KnowledgeClaimDTO) -> KnowledgeClaimDTO: ...
    async def list_claims(
        self,
        tenant_id: str,
        resource_id: Optional[str] = None,
        trust_state: Optional[str] = None,
    ) -> List[KnowledgeClaimDTO]: ...

    async def create_memory_link(self, dto: EnterpriseMemoryLinkDTO) -> EnterpriseMemoryLinkDTO: ...
    async def update_memory_link(self, dto: EnterpriseMemoryLinkDTO) -> EnterpriseMemoryLinkDTO: ...
    async def list_memory_links(
        self,
        tenant_id: str,
        resource_id: Optional[str] = None,
        memory_record_id: Optional[str] = None,
    ) -> List[EnterpriseMemoryLinkDTO]: ...

    async def append_audit_log(self, dto: ConnectorAuditLogDTO) -> ConnectorAuditLogDTO: ...
    async def list_audit_logs(self, tenant_id: str, connector_id: Optional[str] = None) -> List[ConnectorAuditLogDTO]: ...


class InMemoryEnterpriseRepository:
    """Thread-safe in-memory repository for dev and unit/integration tests."""

    is_in_memory = True
    is_persistent = False

    def __init__(self) -> None:
        self._connectors: Dict[str, EnterpriseConnectorDTO] = {}
        self._resources: Dict[str, DiscoveredResourceDTO] = {}
        self._sync_jobs: Dict[str, SyncJobDTO] = {}
        self._claims: Dict[str, KnowledgeClaimDTO] = {}
        self._memory_links: Dict[str, EnterpriseMemoryLinkDTO] = {}
        self._audit_logs: List[ConnectorAuditLogDTO] = []

    async def create_connector(self, dto: EnterpriseConnectorDTO) -> EnterpriseConnectorDTO:
        self._connectors[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def get_connector(self, tenant_id: str, connector_id: str) -> Optional[EnterpriseConnectorDTO]:
        c = self._connectors.get(connector_id)
        if c and c.tenant_id == tenant_id:
            return c.model_copy(deep=True)
        return None

    async def list_connectors(self, tenant_id: str) -> List[EnterpriseConnectorDTO]:
        return [
            c.model_copy(deep=True)
            for c in self._connectors.values()
            if c.tenant_id == tenant_id
        ]

    async def update_connector(self, dto: EnterpriseConnectorDTO) -> EnterpriseConnectorDTO:
        dto.updated_at = datetime.now(timezone.utc)
        self._connectors[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def upsert_resource(self, dto: DiscoveredResourceDTO) -> DiscoveredResourceDTO:
        # Check uniqueness on (tenant_id, connector_id, external_id)
        for existing_id, existing in self._resources.items():
            if (
                existing.tenant_id == dto.tenant_id
                and existing.connector_id == dto.connector_id
                and existing.external_id == dto.external_id
            ):
                updated = dto.model_copy(deep=True)
                updated.id = existing_id
                updated.created_at = existing.created_at
                updated.updated_at = datetime.now(timezone.utc)
                self._resources[existing_id] = updated
                return updated.model_copy(deep=True)
        self._resources[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def get_resource(self, tenant_id: str, resource_id: str) -> Optional[DiscoveredResourceDTO]:
        r = self._resources.get(resource_id)
        if r and r.tenant_id == tenant_id:
            return r.model_copy(deep=True)
        return None

    async def list_resources(
        self,
        tenant_id: str,
        connector_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        classification: Optional[str] = None,
        sync_status: Optional[str] = None,
    ) -> List[DiscoveredResourceDTO]:
        results = []
        for r in self._resources.values():
            if r.tenant_id != tenant_id:
                continue
            if connector_id and r.connector_id != connector_id:
                continue
            if resource_type and str(r.resource_type) != resource_type:
                continue
            if classification and str(r.classification) != classification:
                continue
            if sync_status and str(r.sync_status) != sync_status:
                continue
            results.append(r.model_copy(deep=True))
        return sorted(results, key=lambda x: x.created_at, reverse=True)

    async def create_sync_job(self, dto: SyncJobDTO) -> SyncJobDTO:
        self._sync_jobs[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def update_sync_job(self, dto: SyncJobDTO) -> SyncJobDTO:
        self._sync_jobs[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def list_sync_jobs(self, tenant_id: str, connector_id: Optional[str] = None) -> List[SyncJobDTO]:
        res = [
            j.model_copy(deep=True)
            for j in self._sync_jobs.values()
            if j.tenant_id == tenant_id and (connector_id is None or j.connector_id == connector_id)
        ]
        return sorted(res, key=lambda x: x.started_at, reverse=True)

    async def create_claim(self, dto: KnowledgeClaimDTO) -> KnowledgeClaimDTO:
        self._claims[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def update_claim(self, dto: KnowledgeClaimDTO) -> KnowledgeClaimDTO:
        dto.updated_at = datetime.now(timezone.utc)
        self._claims[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def list_claims(
        self,
        tenant_id: str,
        resource_id: Optional[str] = None,
        trust_state: Optional[str] = None,
    ) -> List[KnowledgeClaimDTO]:
        res = []
        for c in self._claims.values():
            if c.tenant_id != tenant_id:
                continue
            if resource_id and c.resource_id != resource_id:
                continue
            if trust_state and str(c.trust_state) != trust_state:
                continue
            res.append(c.model_copy(deep=True))
        return sorted(res, key=lambda x: x.created_at, reverse=True)

    async def create_memory_link(self, dto: EnterpriseMemoryLinkDTO) -> EnterpriseMemoryLinkDTO:
        self._memory_links[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def update_memory_link(self, dto: EnterpriseMemoryLinkDTO) -> EnterpriseMemoryLinkDTO:
        dto.updated_at = datetime.now(timezone.utc)
        self._memory_links[dto.id] = dto.model_copy(deep=True)
        return dto.model_copy(deep=True)

    async def list_memory_links(
        self,
        tenant_id: str,
        resource_id: Optional[str] = None,
        memory_record_id: Optional[str] = None,
    ) -> List[EnterpriseMemoryLinkDTO]:
        res = []
        for m in self._memory_links.values():
            if m.tenant_id != tenant_id:
                continue
            if resource_id and m.resource_id != resource_id:
                continue
            if memory_record_id and m.memory_record_id != memory_record_id:
                continue
            res.append(m.model_copy(deep=True))
        return sorted(res, key=lambda x: x.retrieved_at, reverse=True)

    async def append_audit_log(self, dto: ConnectorAuditLogDTO) -> ConnectorAuditLogDTO:
        self._audit_logs.append(dto.model_copy(deep=True))
        return dto.model_copy(deep=True)

    async def list_audit_logs(
        self, tenant_id: str, connector_id: Optional[str] = None
    ) -> List[ConnectorAuditLogDTO]:
        res = [
            a.model_copy(deep=True)
            for a in self._audit_logs
            if a.tenant_id == tenant_id and (connector_id is None or a.connector_id == connector_id)
        ]
        return sorted(res, key=lambda x: x.created_at, reverse=True)


class SqlAlchemyEnterpriseRepository:
    """Persistent PostgreSQL repository for enterprise connectivity."""

    is_in_memory = False
    is_persistent = True

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create_connector(self, dto: EnterpriseConnectorDTO) -> EnterpriseConnectorDTO:
        async with self._session_factory() as session:
            row = EnterpriseConnector(
                id=dto.id,
                tenant_id=dto.tenant_id,
                name=dto.name,
                connector_type=str(dto.connector_type),
                status=str(dto.status),
                auth_mode=str(dto.auth_mode),
                config_json=dto.config_json,
                secret_ref=dto.secret_ref,
                scope_json=dto.scope_json,
                monitoring_coverage_json=dto.monitoring_coverage_json,
                last_sync_at=dto.last_sync_at,
                last_sync_status=dto.last_sync_status,
                last_error=dto.last_error,
                created_by=dto.created_by,
                created_at=dto.created_at,
                updated_at=dto.updated_at,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return EnterpriseConnectorDTO.model_validate(row)

    async def get_connector(self, tenant_id: str, connector_id: str) -> Optional[EnterpriseConnectorDTO]:
        async with self._session_factory() as session:
            stmt = select(EnterpriseConnector).where(
                EnterpriseConnector.tenant_id == tenant_id,
                EnterpriseConnector.id == connector_id,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            return EnterpriseConnectorDTO.model_validate(row) if row else None

    async def list_connectors(self, tenant_id: str) -> List[EnterpriseConnectorDTO]:
        async with self._session_factory() as session:
            stmt = (
                select(EnterpriseConnector)
                .where(EnterpriseConnector.tenant_id == tenant_id)
                .order_by(EnterpriseConnector.created_at.desc())
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [EnterpriseConnectorDTO.model_validate(r) for r in rows]

    async def update_connector(self, dto: EnterpriseConnectorDTO) -> EnterpriseConnectorDTO:
        async with self._session_factory() as session:
            stmt = select(EnterpriseConnector).where(
                EnterpriseConnector.tenant_id == dto.tenant_id,
                EnterpriseConnector.id == dto.id,
            )
            row = (await session.execute(stmt)).scalar_one()
            row.status = str(dto.status)
            row.config_json = dto.config_json
            row.secret_ref = dto.secret_ref
            row.scope_json = dto.scope_json
            row.monitoring_coverage_json = dto.monitoring_coverage_json
            row.last_sync_at = dto.last_sync_at
            row.last_sync_status = dto.last_sync_status
            row.last_error = dto.last_error
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(row)
            return EnterpriseConnectorDTO.model_validate(row)

    async def upsert_resource(self, dto: DiscoveredResourceDTO) -> DiscoveredResourceDTO:
        async with self._session_factory() as session:
            stmt = select(DiscoveredResource).where(
                DiscoveredResource.tenant_id == dto.tenant_id,
                DiscoveredResource.connector_id == dto.connector_id,
                DiscoveredResource.external_id == dto.external_id,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if row is None:
                row = DiscoveredResource(
                    id=dto.id or str(uuid.uuid4()),
                    tenant_id=dto.tenant_id,
                    connector_id=dto.connector_id,
                    source_id=dto.source_id,
                    resource_type=str(dto.resource_type),
                    external_id=dto.external_id,
                    name=dto.name,
                    parent_resource_id=dto.parent_resource_id,
                    owner=dto.owner,
                    access_scope=dto.access_scope,
                    classification=str(dto.classification),
                    sync_status=str(dto.sync_status),
                    source_version=dto.source_version,
                    content_checksum=dto.content_checksum,
                    metadata_json=dto.metadata_json,
                    retention_policy=dto.retention_policy,
                    last_synced_at=dto.last_synced_at,
                    created_at=dto.created_at,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.source_id = dto.source_id or row.source_id
                row.resource_type = str(dto.resource_type)
                row.name = dto.name
                row.owner = dto.owner
                row.access_scope = dto.access_scope
                row.classification = str(dto.classification)
                row.sync_status = str(dto.sync_status)
                row.source_version = dto.source_version
                row.content_checksum = dto.content_checksum
                row.metadata_json = dto.metadata_json
                row.last_synced_at = dto.last_synced_at
                row.updated_at = now
            await session.commit()
            await session.refresh(row)
            return DiscoveredResourceDTO.model_validate(row)

    async def get_resource(self, tenant_id: str, resource_id: str) -> Optional[DiscoveredResourceDTO]:
        async with self._session_factory() as session:
            stmt = select(DiscoveredResource).where(
                DiscoveredResource.tenant_id == tenant_id,
                DiscoveredResource.id == resource_id,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            return DiscoveredResourceDTO.model_validate(row) if row else None

    async def list_resources(
        self,
        tenant_id: str,
        connector_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        classification: Optional[str] = None,
        sync_status: Optional[str] = None,
    ) -> List[DiscoveredResourceDTO]:
        async with self._session_factory() as session:
            stmt = select(DiscoveredResource).where(DiscoveredResource.tenant_id == tenant_id)
            if connector_id:
                stmt = stmt.where(DiscoveredResource.connector_id == connector_id)
            if resource_type:
                stmt = stmt.where(DiscoveredResource.resource_type == resource_type)
            if classification:
                stmt = stmt.where(DiscoveredResource.classification == classification)
            if sync_status:
                stmt = stmt.where(DiscoveredResource.sync_status == sync_status)
            stmt = stmt.order_by(DiscoveredResource.created_at.desc())
            rows = (await session.execute(stmt)).scalars().all()
            return [DiscoveredResourceDTO.model_validate(r) for r in rows]

    async def create_sync_job(self, dto: SyncJobDTO) -> SyncJobDTO:
        async with self._session_factory() as session:
            row = SyncJob(
                id=dto.id,
                tenant_id=dto.tenant_id,
                connector_id=dto.connector_id,
                strategy=str(dto.strategy),
                status=str(dto.status),
                resources_discovered=dto.resources_discovered,
                resources_synced=dto.resources_synced,
                resources_changed=dto.resources_changed,
                resources_deleted=dto.resources_deleted,
                resources_failed=dto.resources_failed,
                checkpoint_json=dto.checkpoint_json,
                error_message=dto.error_message,
                started_at=dto.started_at,
                completed_at=dto.completed_at,
                created_at=dto.created_at,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return SyncJobDTO.model_validate(row)

    async def update_sync_job(self, dto: SyncJobDTO) -> SyncJobDTO:
        async with self._session_factory() as session:
            stmt = select(SyncJob).where(SyncJob.tenant_id == dto.tenant_id, SyncJob.id == dto.id)
            row = (await session.execute(stmt)).scalar_one()
            row.status = str(dto.status)
            row.resources_discovered = dto.resources_discovered
            row.resources_synced = dto.resources_synced
            row.resources_changed = dto.resources_changed
            row.resources_deleted = dto.resources_deleted
            row.resources_failed = dto.resources_failed
            row.checkpoint_json = dto.checkpoint_json
            row.error_message = dto.error_message
            row.completed_at = dto.completed_at
            await session.commit()
            await session.refresh(row)
            return SyncJobDTO.model_validate(row)

    async def list_sync_jobs(self, tenant_id: str, connector_id: Optional[str] = None) -> List[SyncJobDTO]:
        async with self._session_factory() as session:
            stmt = select(SyncJob).where(SyncJob.tenant_id == tenant_id)
            if connector_id:
                stmt = stmt.where(SyncJob.connector_id == connector_id)
            stmt = stmt.order_by(SyncJob.started_at.desc())
            rows = (await session.execute(stmt)).scalars().all()
            return [SyncJobDTO.model_validate(r) for r in rows]

    async def create_claim(self, dto: KnowledgeClaimDTO) -> KnowledgeClaimDTO:
        async with self._session_factory() as session:
            row = KnowledgeClaim(
                id=dto.id,
                tenant_id=dto.tenant_id,
                resource_id=dto.resource_id,
                source_id=dto.source_id,
                claim_type=str(dto.claim_type),
                subject=dto.subject,
                predicate=dto.predicate,
                object_value=dto.object_value,
                department=dto.department,
                branch_id=dto.branch_id,
                provenance_json=dto.provenance_json,
                trust_state=str(dto.trust_state),
                confidence=dto.confidence,
                conflict_group_id=dto.conflict_group_id,
                superseded_by_id=dto.superseded_by_id,
                created_at=dto.created_at,
                updated_at=dto.updated_at,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return KnowledgeClaimDTO.model_validate(row)

    async def update_claim(self, dto: KnowledgeClaimDTO) -> KnowledgeClaimDTO:
        async with self._session_factory() as session:
            stmt = select(KnowledgeClaim).where(
                KnowledgeClaim.tenant_id == dto.tenant_id,
                KnowledgeClaim.id == dto.id,
            )
            row = (await session.execute(stmt)).scalar_one()
            row.trust_state = str(dto.trust_state)
            row.confidence = dto.confidence
            row.conflict_group_id = dto.conflict_group_id
            row.superseded_by_id = dto.superseded_by_id
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(row)
            return KnowledgeClaimDTO.model_validate(row)

    async def list_claims(
        self,
        tenant_id: str,
        resource_id: Optional[str] = None,
        trust_state: Optional[str] = None,
    ) -> List[KnowledgeClaimDTO]:
        async with self._session_factory() as session:
            stmt = select(KnowledgeClaim).where(KnowledgeClaim.tenant_id == tenant_id)
            if resource_id:
                stmt = stmt.where(KnowledgeClaim.resource_id == resource_id)
            if trust_state:
                stmt = stmt.where(KnowledgeClaim.trust_state == trust_state)
            stmt = stmt.order_by(KnowledgeClaim.created_at.desc())
            rows = (await session.execute(stmt)).scalars().all()
            return [KnowledgeClaimDTO.model_validate(r) for r in rows]

    async def create_memory_link(self, dto: EnterpriseMemoryLinkDTO) -> EnterpriseMemoryLinkDTO:
        async with self._session_factory() as session:
            row = EnterpriseMemoryLink(
                id=dto.id,
                tenant_id=dto.tenant_id,
                memory_record_id=dto.memory_record_id,
                memory_version=dto.memory_version,
                resource_id=dto.resource_id,
                source_version=dto.source_version,
                agent_id=dto.agent_id,
                extraction_purpose=dto.extraction_purpose,
                confidence=dto.confidence,
                freshness_status=str(dto.freshness_status),
                snapshot_checksum=dto.snapshot_checksum,
                snapshot_json=dto.snapshot_json,
                retrieved_at=dto.retrieved_at,
                created_at=dto.created_at,
                updated_at=dto.updated_at,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return EnterpriseMemoryLinkDTO.model_validate(row)

    async def update_memory_link(self, dto: EnterpriseMemoryLinkDTO) -> EnterpriseMemoryLinkDTO:
        async with self._session_factory() as session:
            stmt = select(EnterpriseMemoryLink).where(
                EnterpriseMemoryLink.tenant_id == dto.tenant_id,
                EnterpriseMemoryLink.id == dto.id,
            )
            row = (await session.execute(stmt)).scalar_one()
            row.freshness_status = str(dto.freshness_status)
            row.source_version = dto.source_version
            row.snapshot_json = dto.snapshot_json
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(row)
            return EnterpriseMemoryLinkDTO.model_validate(row)

    async def list_memory_links(
        self,
        tenant_id: str,
        resource_id: Optional[str] = None,
        memory_record_id: Optional[str] = None,
    ) -> List[EnterpriseMemoryLinkDTO]:
        async with self._session_factory() as session:
            stmt = select(EnterpriseMemoryLink).where(EnterpriseMemoryLink.tenant_id == tenant_id)
            if resource_id:
                stmt = stmt.where(EnterpriseMemoryLink.resource_id == resource_id)
            if memory_record_id:
                stmt = stmt.where(EnterpriseMemoryLink.memory_record_id == memory_record_id)
            stmt = stmt.order_by(EnterpriseMemoryLink.retrieved_at.desc())
            rows = (await session.execute(stmt)).scalars().all()
            return [EnterpriseMemoryLinkDTO.model_validate(r) for r in rows]

    async def append_audit_log(self, dto: ConnectorAuditLogDTO) -> ConnectorAuditLogDTO:
        async with self._session_factory() as session:
            row = ConnectorAuditLog(
                id=dto.id,
                tenant_id=dto.tenant_id,
                connector_id=dto.connector_id,
                actor_id=dto.actor_id,
                action=dto.action,
                status=dto.status,
                details_json=dto.details_json,
                created_at=dto.created_at,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return ConnectorAuditLogDTO.model_validate(row)

    async def list_audit_logs(
        self, tenant_id: str, connector_id: Optional[str] = None
    ) -> List[ConnectorAuditLogDTO]:
        async with self._session_factory() as session:
            stmt = select(ConnectorAuditLog).where(ConnectorAuditLog.tenant_id == tenant_id)
            if connector_id:
                stmt = stmt.where(ConnectorAuditLog.connector_id == connector_id)
            stmt = stmt.order_by(ConnectorAuditLog.created_at.desc())
            rows = (await session.execute(stmt)).scalars().all()
            return [ConnectorAuditLogDTO.model_validate(r) for r in rows]


_default_enterprise_repo = InMemoryEnterpriseRepository()


def get_default_enterprise_repository() -> InMemoryEnterpriseRepository:
    return _default_enterprise_repo
