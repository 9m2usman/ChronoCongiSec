"""Continuous Synchronization & Change Detection Service."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
import uuid

from backend.app.enterprise.connectors import DiscoveredItem, get_connector_implementation
from backend.app.enterprise.discovery import CLASSIFICATION_RANK
from backend.app.enterprise.intelligence import OrganizationalIntelligenceService, screen_untrusted_content
from backend.app.enterprise.models import (
    ClaimTrustState,
    ConnectorAuditLogDTO,
    ConnectorStatus,
    DataClassification,
    DiscoveredResourceDTO,
    EnterpriseConnectorDTO,
    FreshnessStatus,
    SyncJobDTO,
    SyncJobStatus,
    SyncStatus,
    SyncStrategy,
)
from backend.app.enterprise.repository import EnterpriseRepository
from backend.app.memory.models import SourceRecord
from backend.app.memory.repository import MemoryRepository


class EnterpriseSyncService:
    """Executes authorized synchronization, detects source changes/deletions/revocations, and updates lineage."""

    def __init__(
        self,
        enterprise_repo: EnterpriseRepository,
        intelligence: OrganizationalIntelligenceService,
        memory_repo: Optional[MemoryRepository] = None,
    ) -> None:
        self._repo = enterprise_repo
        self._intelligence = intelligence
        self._memory_repo = memory_repo

    async def run_sync(
        self,
        tenant_id: str,
        connector_id: str,
        actor_id: str,
        *,
        strategy: SyncStrategy = SyncStrategy.INCREMENTAL,
        target_resource_ids: Optional[List[str]] = None,
    ) -> SyncJobDTO:
        connector = await self._repo.get_connector(tenant_id, connector_id)
        if connector is None:
            raise KeyError(f"Connector '{connector_id}' not found.")

        now = datetime.now(timezone.utc)
        job = SyncJobDTO(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            connector_id=connector_id,
            strategy=strategy,
            status=SyncJobStatus.RUNNING,
            started_at=now,
            created_at=now,
        )
        await self._repo.create_sync_job(job)

        if str(connector.status) != ConnectorStatus.AUTHORIZED.value:
            job.status = SyncJobStatus.FAILED
            job.error_message = f"Connector is '{connector.status}'; synchronization requires AUTHORIZED status."
            job.completed_at = datetime.now(timezone.utc)
            await self._repo.update_sync_job(job)
            await self._repo.append_audit_log(
                ConnectorAuditLogDTO(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    connector_id=connector_id,
                    actor_id=actor_id,
                    action="SYNC",
                    status="FAILED",
                    details_json={"reason": job.error_message, "strategy": str(strategy)},
                )
            )
            return job

        try:
            impl = get_connector_implementation(connector)
            ok, msg, coverage = impl.validate_connection(connector)
            if not ok:
                # Do not treat an inaccessible source as proof that previous content remains current
                existing = await self._repo.list_resources(tenant_id, connector_id=connector_id)
                for res in existing:
                    res.sync_status = SyncStatus.INACCESSIBLE
                    await self._repo.upsert_resource(res)
                    await self._invalidate_dependents(tenant_id, res.id, FreshnessStatus.STALE, ClaimTrustState.OUTDATED)
                connector.status = ConnectorStatus.ERROR
                connector.last_error = msg
                connector.last_sync_status = SyncJobStatus.FAILED.value
                await self._repo.update_connector(connector)

                job.status = SyncJobStatus.FAILED
                job.error_message = msg
                job.completed_at = datetime.now(timezone.utc)
                return await self._repo.update_sync_job(job)

            existing_resources = await self._repo.list_resources(tenant_id, connector_id=connector_id)
            existing_by_ext = {r.external_id: r for r in existing_resources}

            target_ext_ids: Optional[List[str]] = None
            if target_resource_ids:
                target_ext_ids = [
                    r.external_id for r in existing_resources if r.id in set(target_resource_ids)
                ]

            items: List[DiscoveredItem] = impl.discover_and_read(
                connector,
                include_content=True,
                target_external_ids=target_ext_ids,
            )
            seen_ext_ids = {it.external_id for it in items}

            max_class = str(connector.scope_json.get("max_classification", DataClassification.CONFIDENTIAL.value))
            max_rank = CLASSIFICATION_RANK.get(max_class, 2)

            for item in items:
                job.resources_discovered += 1
                prev = existing_by_ext.get(item.external_id)
                item_rank = CLASSIFICATION_RANK.get(str(item.classification), 1)
                if item_rank > max_rank:
                    # Out of authorized scope
                    dto = DiscoveredResourceDTO(
                        id=prev.id if prev else str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        connector_id=connector_id,
                        source_id=prev.source_id if prev else None,
                        resource_type=item.resource_type,
                        external_id=item.external_id,
                        name=item.name,
                        owner=item.owner,
                        access_scope=item.access_scope,
                        classification=item.classification,
                        sync_status=SyncStatus.INACCESSIBLE,
                        source_version=item.source_version,
                        content_checksum=item.content_checksum,
                        metadata_json=item.metadata,
                        last_synced_at=now,
                    )
                    await self._repo.upsert_resource(dto)
                    continue

                changed = prev is None or prev.last_synced_at is None or prev.content_checksum != item.content_checksum
                if changed and prev is not None and prev.last_synced_at is not None:
                    job.resources_changed += 1

                # Screen content for prompt injection / poisoning indicators
                combined_text = item.extracted_text or (
                    str(item.structured_records) if item.structured_records else ""
                )
                flagged, hits = screen_untrusted_content(combined_text)

                source_id = prev.source_id if prev else None
                if source_id is None and self._memory_repo is not None:
                    candidate_sid = str(
                        uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_id}:{connector.id}:{item.external_id}")
                    )
                    if await self._memory_repo.get_source(candidate_sid, tenant_id) is None:
                        await self._memory_repo.create_source(
                            SourceRecord(
                                id=candidate_sid,
                                tenant_id=tenant_id,
                                name=f"{connector.name}:{item.name}",
                                source_type=str(connector.connector_type),
                                uri=item.external_id,
                                trust_state="UNVERIFIED",
                                status="ACTIVE",
                            )
                        )
                    source_id = candidate_sid

                saved_res = await self._repo.upsert_resource(
                    DiscoveredResourceDTO(
                        id=prev.id if prev else str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        connector_id=connector_id,
                        source_id=source_id,
                        resource_type=item.resource_type,
                        external_id=item.external_id,
                        name=item.name,
                        owner=item.owner,
                        access_scope=item.access_scope,
                        classification=item.classification,
                        sync_status=SyncStatus.CHANGED if (changed and prev is not None and prev.last_synced_at is not None) else SyncStatus.SYNCED,
                        source_version=item.source_version,
                        content_checksum=item.content_checksum,
                        metadata_json={
                            **item.metadata,
                            "injection_screened": True,
                            "injection_flagged": flagged,
                            "injection_hits": hits,
                        },
                        last_synced_at=now,
                    )
                )
                job.resources_synced += 1

                if flagged:
                    await self._repo.append_audit_log(
                        ConnectorAuditLogDTO(
                            id=str(uuid.uuid4()),
                            tenant_id=tenant_id,
                            connector_id=connector_id,
                            actor_id=actor_id,
                            action="SECURITY_ALERT",
                            status="CRITICAL",
                            details_json={
                                "alert_type": "PROMPT_INJECTION_DETECTED",
                                "resource_id": saved_res.id,
                                "external_id": saved_res.external_id,
                                "hits": hits,
                            },
                        )
                    )

                if changed:
                    # Reprocess knowledge claims & mark dependent memories as SOURCE_CHANGED
                    await self._intelligence.extract_claims_from_resource(
                        tenant_id,
                        saved_res,
                        text_content=item.extracted_text,
                        structured_records=item.structured_records,
                    )
                    if prev is not None and prev.last_synced_at is not None:
                        await self._invalidate_dependents(
                            tenant_id,
                            saved_res.id,
                            FreshnessStatus.QUARANTINED if flagged else FreshnessStatus.SOURCE_CHANGED,
                            ClaimTrustState.OUTDATED if not flagged else ClaimTrustState.UNCERTAIN,
                        )

            # Detect deleted resources (only on full/incremental/reconciliation scans, not targeted single-resource refresh)
            if not target_resource_ids:
                for ext_id, prev in existing_by_ext.items():
                    if ext_id not in seen_ext_ids and str(prev.sync_status) not in {
                        SyncStatus.DELETED.value,
                        SyncStatus.REVOKED.value,
                    }:
                        prev.sync_status = SyncStatus.DELETED
                        await self._repo.upsert_resource(prev)
                        await self._invalidate_dependents(
                            tenant_id,
                            prev.id,
                            FreshnessStatus.SOURCE_DELETED,
                            ClaimTrustState.REVOKED,
                        )
                        job.resources_deleted += 1

            job.status = SyncJobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            job.checkpoint_json = {
                "last_sync_at": job.completed_at.isoformat(),
                "strategy": str(strategy),
                "seen_resources": len(seen_ext_ids),
            }
            await self._repo.update_sync_job(job)

            connector.last_sync_at = job.completed_at
            connector.last_sync_status = SyncJobStatus.COMPLETED.value
            connector.monitoring_coverage_json = coverage
            connector.last_error = None
            await self._repo.update_connector(connector)

            await self._repo.append_audit_log(
                ConnectorAuditLogDTO(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    connector_id=connector_id,
                    actor_id=actor_id,
                    action="SYNC",
                    status="SUCCESS",
                    details_json={
                        "job_id": job.id,
                        "strategy": str(strategy),
                        "synced": job.resources_synced,
                        "changed": job.resources_changed,
                        "deleted": job.resources_deleted,
                    },
                )
            )
            return job

        except Exception as exc:
            job.status = SyncJobStatus.FAILED
            job.error_message = str(exc)
            job.completed_at = datetime.now(timezone.utc)
            await self._repo.update_sync_job(job)

            connector.last_sync_status = SyncJobStatus.FAILED.value
            connector.last_error = str(exc)
            await self._repo.update_connector(connector)

            await self._repo.append_audit_log(
                ConnectorAuditLogDTO(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    connector_id=connector_id,
                    actor_id=actor_id,
                    action="SYNC",
                    status="FAILED",
                    details_json={"job_id": job.id, "error": str(exc)},
                )
            )
            return job

    async def revoke_connector(
        self,
        tenant_id: str,
        connector_id: str,
        actor_id: str,
    ) -> EnterpriseConnectorDTO:
        connector = await self._repo.get_connector(tenant_id, connector_id)
        if connector is None:
            raise KeyError(f"Connector '{connector_id}' not found.")

        connector.status = ConnectorStatus.REVOKED
        updated = await self._repo.update_connector(connector)

        resources = await self._repo.list_resources(tenant_id, connector_id=connector_id)
        for res in resources:
            res.sync_status = SyncStatus.REVOKED
            await self._repo.upsert_resource(res)
            await self._invalidate_dependents(
                tenant_id,
                res.id,
                FreshnessStatus.SOURCE_REVOKED,
                ClaimTrustState.REVOKED,
            )

        await self._repo.append_audit_log(
            ConnectorAuditLogDTO(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                connector_id=connector_id,
                actor_id=actor_id,
                action="REVOKE",
                status="SUCCESS",
                details_json={"revoked_resources": len(resources)},
            )
        )
        return updated

    async def _invalidate_dependents(
        self,
        tenant_id: str,
        resource_id: str,
        freshness: FreshnessStatus,
        claim_trust: ClaimTrustState,
    ) -> None:
        links = await self._repo.list_memory_links(tenant_id, resource_id=resource_id)
        for lnk in links:
            lnk.freshness_status = freshness
            await self._repo.update_memory_link(lnk)

        claims = await self._repo.list_claims(tenant_id, resource_id=resource_id)
        for cl in claims:
            if str(cl.trust_state) != ClaimTrustState.SUPERSEDED.value:
                cl.trust_state = claim_trust
                await self._repo.update_claim(cl)
