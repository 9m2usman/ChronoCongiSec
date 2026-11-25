"""FastAPI router for Memory & Provenance endpoints.

Module: backend.app.api.memory
Owner: M3 — Knowledge & Memory Systems Lead

Implements Document 05 Section 5.1 Route Catalog:
- GET  /api/v1/memory      (Query memory records with pagination & strict quarantine exclusion)
- POST /api/v1/memory      (Ingest knowledge chunk & hash)
- GET  /api/v1/memory/{id} (Get memory detail, versions & provenance)

Security & Governance:
- Authenticated Tenant Context: Verified via M1's `get_tenant_context` dependency.
- Mandatory Quarantine Exclusion: Standard agent retrieval strictly excludes QUARANTINED and REJECTED states.
- Bound Pagination: TRD §22 pagination limits enforced (default 50, maximum 100).
- Production Safety: Rejects in-memory repository fallbacks in production.
- Cryptographic Integrity: SHA-256 verified on retrieval and detail endpoints.
"""

import inspect
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.config import get_settings
from backend.app.core.dependencies import get_tenant_context
from backend.app.core.exceptions import ForbiddenError, SecurityDependencyError
from backend.app.memory.models import (
    MemoryDetailResponse,
    MemoryIngestRequest,
    MemoryRecordResponse,
)
from backend.app.memory.ingestion import ingest_memory
from backend.app.memory.repository import MemoryRepository, get_default_repository
from backend.app.memory.retrieval import (
    get_memory_detail,
    retrieve_memory,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.memory")


# --- Dependencies ---

async def get_memory_tenant_id(
    context: TenantContext = Depends(get_tenant_context),
) -> str:
    """Extract verified tenant_id from M1's authenticated TenantContext.

    Guarantees client-provided X-Tenant-ID headers are never trusted in isolation,
    and request body cannot spoof tenant ownership.
    """
    return context.tenant_id


async def get_repository(request: Request) -> MemoryRepository:
    """Dependency provider for MemoryRepository."""
    settings = getattr(request.app.state, "settings", None) or get_settings()
    repo = getattr(request.app.state, "memory_repo", None)

    if repo is None:
        session_factory = getattr(request.app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.memory.adapters import DatabaseMemoryRepository
            repo = DatabaseMemoryRepository(session_factory)
            request.app.state.memory_repo = repo

    if settings.APP_ENV == "production":
        if repo is None or getattr(repo, "is_in_memory", True) or not getattr(repo, "is_persistent", False):
            raise SecurityDependencyError("Production database memory repository is not configured.")
        return repo

    if repo is not None:
        return repo
    return get_default_repository()


router = APIRouter(prefix="/memory", tags=["memory"])


async def _persist_memory_detection_incidents(
    request: Request,
    context: TenantContext,
    record: Any,
    findings: List[Any],
    content_checksum: str,
) -> List[str]:
    """Idempotently correlate confirmed ingestion findings with the incident ledger."""
    from hashlib import sha256
    from uuid import UUID

    from backend.app.api.incident_management import (
        AuditEventEntity,
        IncidentEntity,
        IncidentEvidenceEntity,
        get_default_incident_repository,
    )

    qualifying = [
        finding for finding in findings
        if getattr(finding.recommended_outcome, "value", finding.recommended_outcome) == "BLOCK"
        and getattr(finding.classification_type, "value", finding.classification_type)
        in {"CONFIRMED_SECURITY_INCIDENT", "CONFIRMED_POLICY_VIOLATION"}
    ]
    if not qualifying:
        return []

    settings = getattr(request.app.state, "settings", None) or get_settings()
    incident_repo = getattr(request.app.state, "incident_repo", None)
    if incident_repo is None:
        if settings.APP_ENV == "production":
            raise SecurityDependencyError("Durable incident repository is not configured.")
        incident_repo = get_default_incident_repository(settings)
    if not all(
        callable(getattr(incident_repo, method, None))
        for method in ("get_incident", "create_incident_atomic", "attach_evidence_atomic")
    ):
        raise SecurityDependencyError("Incident repository does not satisfy the required contract.")

    category_map = {
        "PROMPT_INJECTION": "PROMPT_INJECTION",
        "MEMORY_INTEGRITY": "UNTRUSTED_MEMORY_ACTION",
        "SEMANTIC_INTEGRITY": "DRIFT_DIVERGENCE",
        "BEHAVIORAL_DEVIATION": "UNAUTHORIZED_TOOL",
        "TOOL_THREAT": "UNAUTHORIZED_TOOL",
    }
    incident_ids: List[str] = []
    for finding in qualifying:
        category = getattr(finding.detection_category, "value", finding.detection_category)
        classification = getattr(finding.classification_type, "value", finding.classification_type)
        severity = getattr(finding.severity, "value", finding.severity)
        reason_code = str((finding.details or {}).get("reason_code") or category)
        digest = sha256(
            f"{context.tenant_id}:{record.id}:{category}:{reason_code}".encode("utf-8")
        ).hexdigest()
        incident_id = f"inc-{digest[:32]}"
        evidence_id = f"evi-{sha256(f'{incident_id}:{finding.id}'.encode('utf-8')).hexdigest()[:32]}"
        metadata = {
            "detection_id": finding.id,
            "detection_category": str(category),
            "classification_type": str(classification),
            "severity": str(severity),
            "confidence_score": finding.confidence_score,
            "uncertainty_state": getattr(
                finding.uncertainty_state, "value", finding.uncertainty_state
            ),
            "reason_code": reason_code,
            "content_sha256": content_checksum,
            "branch_id": context.branch_id,
            "trace_id": finding.trace_id,
        }
        evidence = IncidentEvidenceEntity(
            id=evidence_id,
            tenant_id=context.tenant_id,
            incident_id=incident_id,
            evidence_type="MEMORY_RECORD",
            resource_id=record.id,
            metadata_json=metadata,
        )
        audit_digest = sha256(f"{incident_id}:{finding.id}".encode("utf-8")).hexdigest()[:32]
        audit = AuditEventEntity(
            id=str(UUID(audit_digest)),
            tenant_id=context.tenant_id,
            actor_id=context.user_id,
            event_type="MEMORY_SECURITY_INCIDENT_CORRELATED",
            resource_id=incident_id,
            action="CORRELATE_DETECTION",
            outcome="SUCCESS",
            trace_id=finding.trace_id,
            details_json={
                "memory_record_id": record.id,
                "detection_id": finding.id,
                "detection_category": str(category),
                "reason_code": reason_code,
                "content_sha256": content_checksum,
            },
        )
        existing = await incident_repo.get_incident(context.tenant_id, incident_id)
        if existing is not None:
            await incident_repo.attach_evidence_atomic(
                context.tenant_id, incident_id, [evidence], audit_event=audit
            )
        else:
            incident = IncidentEntity(
                id=incident_id,
                tenant_id=context.tenant_id,
                title=str(finding.title)[:255],
                classification=category_map.get(str(category), "UNTRUSTED_MEMORY_ACTION"),
                severity=str(severity),
                status="OPEN",
                affected_record_id=record.id,
                agent_id=finding.agent_id,
                evidence_json={
                    "summary": "Automatically correlated high-confidence memory ingestion detection",
                    "total_count": 1,
                    "detection_ids": [finding.id],
                    "content_sha256": content_checksum,
                },
            )
            try:
                await incident_repo.create_incident_atomic(
                    incident, [evidence], audit_event=audit
                )
            except Exception:
                # Resolve a concurrent idempotent create; propagate genuine persistence failures.
                existing = await incident_repo.get_incident(context.tenant_id, incident_id)
                if existing is None:
                    raise
                await incident_repo.attach_evidence_atomic(
                    context.tenant_id, incident_id, [evidence], audit_event=audit
                )
        incident_ids.append(incident_id)
    return list(dict.fromkeys(incident_ids))


@router.post(
    "",
    response_model=MemoryRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest knowledge chunk & hash",
)
async def api_ingest_memory(
    payload: MemoryIngestRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> MemoryRecordResponse:
    """Ingest a new knowledge chunk, assign version 1, and compute SHA-256 hash.

    Matches Document 05 Section 5.1 Route Catalog.
    Tenant ID is strictly derived from verified authentication context.
    """
    res = ingest_memory(
        tenant_id=tenant_id,
        content=payload.content,
        agent_id=payload.agent_id,
        record_type=payload.record_type,
        source_id=payload.source_id,
        parent_record_id=payload.parent_record_id,
        repository=repo,
    )
    if inspect.isawaitable(res):
        record, version = await res
    else:
        record, version = res

    # Phase 4: every newly ingested memory is inspected before it can become eligible
    # for normal retrieval. New records remain UNVERIFIED regardless of detector output.
    settings = getattr(request.app.state, "settings", None) or get_settings()
    detection_engine = getattr(request.app.state, "detection_engine", None)
    detection_repo = getattr(request.app.state, "detection_repo", None)
    if detection_engine is None or detection_repo is None:
        if settings.APP_ENV == "production":
            raise SecurityDependencyError("Durable memory detection is not configured.")
        from backend.app.security.detection import get_default_detection_engine
        detection_engine = detection_engine or get_default_detection_engine()
        detection_repo = detection_repo or getattr(detection_engine, "detection_repo", None)
    if detection_engine is None or detection_repo is None:
        raise SecurityDependencyError("Memory detection persistence is unavailable.")

    try:
        findings = await detection_engine.detect_memory_integrity(
            tenant_id=tenant_id,
            content=payload.content,
            record=record,
            record_id=record.id,
            expected_checksum=version.checksum,
            source_type=payload.record_type,
            agent_id=payload.agent_id,
            branch_id=getattr(context, "branch_id", None),
            parent_record_id=payload.parent_record_id,
            memory_repo=repo,
            trace_id=getattr(request.state, "trace_id", None),
            actor_role=getattr(context, "role", None),
        )
        persisted_findings = []
        for finding in findings:
            persisted = await detection_repo.record_detection(finding.to_dict())
            persisted_findings.append(persisted)
        incident_ids = await _persist_memory_detection_incidents(
            request, context, record, findings, version.checksum
        )

        observation_repo = getattr(request.app.state, "observation_repo", None)
        if observation_repo is None:
            if settings.APP_ENV == "production":
                raise SecurityDependencyError("Durable memory observation is not configured.")
            from backend.app.api.observation import get_default_observation_repository
            observation_repo = get_default_observation_repository()
        await observation_repo.record_event({
            "tenant_id": tenant_id,
            "branch_id": getattr(context, "branch_id", None),
            "event_type": "MEMORY_INGESTION_EVALUATED",
            "event_category": "MEMORY_WRITE_AND_TRANSFORMATION",
            "agent_id": payload.agent_id,
            "trace_id": getattr(request.state, "trace_id", None),
            "source_component": "MEMORY_INGESTION",
            "related_memory_id": record.id,
            "related_memory_version": record.current_version,
            "outcome": "DETECTED" if persisted_findings else "STORED_UNVERIFIED",
            "idempotency_key": f"memory-ingestion-{record.id}-{record.current_version}",
            "payload_json": {
                "source_id": record.source_id,
                "record_type": record.record_type,
                "content_sha256": version.checksum,
                "actor_id": context.user_id,
                "actor_role": context.role,
                "detection_ids": [item.get("id") for item in persisted_findings],
                "incident_ids": incident_ids,
                "detection_categories": sorted({
                    str(item.get("detection_category")) for item in persisted_findings
                }),
            },
        })
    except SecurityDependencyError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("Memory security evaluation or evidence persistence failed.")
        raise SecurityDependencyError(
            "Memory was stored as UNVERIFIED but its security evaluation could not be completed."
        ) from exc

    return MemoryRecordResponse(
        id=record.id,
        tenant_id=record.tenant_id,
        agent_id=record.agent_id,
        source_id=record.source_id,
        record_type=record.record_type,
        trust_state=record.trust_state,
        current_version=record.current_version,
        checksum=version.checksum,
        content=version.content,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get(
    "",
    response_model=List[MemoryRecordResponse],
    status_code=status.HTTP_200_OK,
    summary="Query memory records",
)
async def api_query_memory(
    agent_id: Optional[str] = Query(None, description="Filter by agent identifier"),
    trust_state: Optional[str] = Query(None, description="Filter by trust state"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return (1-100, default 50)"),
    offset: int = Query(0, ge=0, description="Number of records to skip (default 0)"),
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> List[MemoryRecordResponse]:
    """Query memory records with mandatory quarantine filtering and bounded pagination.

    Matches Document 05 Section 5.1 Route Catalog and TRD §22 pagination rules.
    Normal agent retrieval is strictly restricted to TRUSTED memory records.
    UNVERIFIED, SUSPICIOUS, QUARANTINED, REJECTED, and SUPERSEDED records are unconditionally excluded.
    """
    if trust_state and trust_state.upper() != "TRUSTED":
        raise ForbiddenError("Normal agent retrieval is strictly restricted to TRUSTED memory records.")

    records = retrieve_memory(
        tenant_id=tenant_id,
        agent_id=agent_id,
        trust_state="TRUSTED",
        for_forensic=False,
        limit=limit,
        offset=offset,
        repository=repo,
    )
    if inspect.isawaitable(records):
        records = await records

    responses: List[MemoryRecordResponse] = []
    for rec in records:
        latest_ver = repo.get_latest_version(rec.id, tenant_id)
        if inspect.isawaitable(latest_ver):
            latest_ver = await latest_ver
        responses.append(
            MemoryRecordResponse(
                id=rec.id,
                tenant_id=rec.tenant_id,
                agent_id=rec.agent_id,
                source_id=rec.source_id,
                record_type=rec.record_type,
                trust_state=rec.trust_state,
                current_version=rec.current_version,
                checksum=latest_ver.checksum if latest_ver else None,
                content=latest_ver.content if latest_ver else None,
                created_at=rec.created_at,
                updated_at=rec.updated_at,
            )
        )
    return responses


@router.get(
    "/{id}",
    response_model=MemoryDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get memory detail, versions & provenance",
)
async def api_get_memory_detail(
    id: str,
    tenant_id: str = Depends(get_memory_tenant_id),
    repo: MemoryRepository = Depends(get_repository),
) -> MemoryDetailResponse:
    """Fetch complete memory detail including full revision history and provenance lineage.

    Normal agent access is strictly restricted to TRUSTED records (returns 404 for non-trusted).
    Forensic access is reserved for authorized M4 investigation workflows.
    """
    res = get_memory_detail(
        tenant_id=tenant_id,
        record_id=id,
        for_forensic=False,
        repository=repo,
    )
    if inspect.isawaitable(res):
        record, versions, provenance = await res
    else:
        record, versions, provenance = res

    return MemoryDetailResponse(
        record=record,
        versions=versions,
        provenance=provenance,
    )


class ForensicAccessRequest(BaseModel):
    """Justification for audited forensic access (GAP-012: no forensic flag on normal routes)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str = Field(min_length=5, max_length=500)
    incident_id: Optional[str] = Field(default=None, min_length=1, max_length=128,
                                       pattern=r"^[A-Za-z0-9_.:\-]{1,128}$")


@router.post(
    "/{id}/forensic-access",
    response_model=MemoryDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Audited forensic read of a memory record (analyst/admin)",
)
async def api_forensic_memory_access(
    id: str,
    payload: ForensicAccessRequest,
    request: Request,
    context: TenantContext = Depends(get_tenant_context),
    repo: MemoryRepository = Depends(get_repository),
) -> MemoryDetailResponse:
    """Separate, authorized, audited path for non-TRUSTED records (TRD §17, GAP-012).

    Served only by M4's ``ForensicAccess``: SECURITY_ANALYST or TENANT_ADMIN from the verified
    tenant context, an investigation reason, and a durable audit event written BEFORE the read.
    The result is non-actionable (never agent context). Any failure refuses access. The normal
    detail route never accepts a forensic flag.
    """
    from backend.app.security.runtime import get_audit_sink, get_forensic_access

    view = await get_forensic_access(request.app.state, repo).read(
        context, id, payload.reason, persist_audit=get_audit_sink(request.app.state),
        incident_id=payload.incident_id, trace_id=getattr(request.state, "trace_id", None),
    )
    return MemoryDetailResponse(record=view.record, versions=list(view.versions), provenance=list(view.provenance))
