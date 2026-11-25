"""Enterprise Onboarding, Authorization & Automatic Data Discovery Service."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
import uuid

from backend.app.enterprise.connectors import DiscoveredItem, get_connector_implementation
from backend.app.enterprise.models import (
    ConnectorAuditLogDTO,
    ConnectorCreateRequest,
    ConnectorStatus,
    DataClassification,
    DiscoveredResourceDTO,
    EnterpriseConnectorDTO,
    SyncStatus,
)
from backend.app.enterprise.repository import EnterpriseRepository
from backend.app.memory.models import SourceRecord
from backend.app.memory.repository import MemoryRepository


CLASSIFICATION_RANK = {
    DataClassification.PUBLIC.value: 0,
    DataClassification.INTERNAL.value: 1,
    DataClassification.CONFIDENTIAL.value: 2,
    DataClassification.RESTRICTED.value: 3,
}


def _mask_secret(secret_value: Optional[str]) -> Optional[str]:
    if not secret_value:
        return None
    digest = hashlib.sha256(secret_value.encode("utf-8")).hexdigest()[:12]
    return f"sec_sha256_{digest}"


class EnterpriseDiscoveryService:
    """Handles enterprise connector onboarding, explicit authorization, and resource discovery."""

    def __init__(
        self,
        enterprise_repo: EnterpriseRepository,
        memory_repo: Optional[MemoryRepository] = None,
    ) -> None:
        self._repo = enterprise_repo
        self._memory_repo = memory_repo

    async def create_connector(
        self,
        tenant_id: str,
        actor_id: str,
        req: ConnectorCreateRequest,
    ) -> EnterpriseConnectorDTO:
        now = datetime.now(timezone.utc)
        dto = EnterpriseConnectorDTO(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=req.name,
            connector_type=req.connector_type,
            status=ConnectorStatus.PENDING_AUTH,
            auth_mode=req.auth_mode,
            config_json=dict(req.config),
            secret_ref=_mask_secret(req.secret_value),
            scope_json=dict(req.scope),
            monitoring_coverage_json={
                "observed_events": [],
                "inferred_events": [],
                "unsupported_events": ["NOT_YET_AUTHORIZED"],
            },
            created_by=actor_id,
            created_at=now,
            updated_at=now,
        )
        created = await self._repo.create_connector(dto)
        await self._repo.append_audit_log(
            ConnectorAuditLogDTO(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                connector_id=created.id,
                actor_id=actor_id,
                action="CREATE",
                status="SUCCESS",
                details_json={"connector_type": str(req.connector_type), "name": req.name},
            )
        )
        return created

    async def authorize_connector(
        self,
        tenant_id: str,
        connector_id: str,
        actor_id: str,
        approved_scope: Optional[Dict[str, Any]] = None,
        justification: Optional[str] = None,
    ) -> EnterpriseConnectorDTO:
        connector = await self._repo.get_connector(tenant_id, connector_id)
        if connector is None:
            raise KeyError(f"Connector '{connector_id}' not found for tenant.")

        if approved_scope:
            connector.scope_json = {**connector.scope_json, **approved_scope}

        impl = get_connector_implementation(connector)
        ok, message, coverage = impl.validate_connection(connector)
        connector.monitoring_coverage_json = coverage

        if ok:
            connector.status = ConnectorStatus.AUTHORIZED
            connector.last_error = None
        else:
            # Never fake connection if adapter is unavailable or validation fails
            connector.status = (
                ConnectorStatus.UNAVAILABLE
                if "unavailable" in message.lower()
                else ConnectorStatus.ERROR
            )
            connector.last_error = message

        updated = await self._repo.update_connector(connector)
        await self._repo.append_audit_log(
            ConnectorAuditLogDTO(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                connector_id=connector_id,
                actor_id=actor_id,
                action="AUTHORIZE",
                status="SUCCESS" if ok else "FAILED",
                details_json={"message": message, "justification": justification, "status": str(updated.status)},
            )
        )
        return updated

    async def discover_resources(
        self,
        tenant_id: str,
        connector_id: str,
        actor_id: str,
    ) -> List[DiscoveredResourceDTO]:
        connector = await self._repo.get_connector(tenant_id, connector_id)
        if connector is None:
            raise KeyError(f"Connector '{connector_id}' not found for tenant.")
        if str(connector.status) != ConnectorStatus.AUTHORIZED.value:
            raise PermissionError(
                f"Connector '{connector.name}' is '{connector.status}'; must be AUTHORIZED before discovery."
            )

        impl = get_connector_implementation(connector)
        items: List[DiscoveredItem] = impl.discover_and_read(connector, include_content=False)

        max_class = str(connector.scope_json.get("max_classification", DataClassification.CONFIDENTIAL.value))
        max_rank = CLASSIFICATION_RANK.get(max_class, 2)

        discovered: List[DiscoveredResourceDTO] = []
        now = datetime.now(timezone.utc)

        for item in items:
            item_rank = CLASSIFICATION_RANK.get(str(item.classification), 1)
            if item_rank > max_rank:
                # Least-privilege ceiling: record as INACCESSIBLE / out of scope without reading content
                sync_status = SyncStatus.INACCESSIBLE
            else:
                sync_status = SyncStatus.DISCOVERED

            source_id = await self._ensure_source_record(tenant_id, connector, item)
            dto = DiscoveredResourceDTO(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                connector_id=connector_id,
                source_id=source_id,
                resource_type=item.resource_type,
                external_id=item.external_id,
                name=item.name,
                owner=item.owner,
                access_scope=item.access_scope,
                classification=item.classification,
                sync_status=sync_status,
                source_version=item.source_version,
                content_checksum=item.content_checksum,
                metadata_json=item.metadata,
                created_at=now,
                updated_at=now,
            )
            saved = await self._repo.upsert_resource(dto)
            discovered.append(saved)

        await self._repo.append_audit_log(
            ConnectorAuditLogDTO(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                connector_id=connector_id,
                actor_id=actor_id,
                action="DISCOVER",
                status="SUCCESS",
                details_json={"discovered_count": len(discovered)},
            )
        )
        return discovered

    async def _ensure_source_record(
        self,
        tenant_id: str,
        connector: EnterpriseConnectorDTO,
        item: DiscoveredItem,
    ) -> Optional[str]:
        if self._memory_repo is None:
            return None
        source_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_id}:{connector.id}:{item.external_id}"))
        existing = await self._memory_repo.get_source(source_id, tenant_id)
        if existing is None:
            src = SourceRecord(
                id=source_id,
                tenant_id=tenant_id,
                name=f"{connector.name}:{item.name}",
                source_type=str(connector.connector_type),
                uri=item.external_id,
                trust_state="UNVERIFIED",
                status="ACTIVE",
            )
            await self._memory_repo.create_source(src)
        return source_id
