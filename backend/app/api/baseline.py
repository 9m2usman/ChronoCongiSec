"""Enterprise Security Baseline API Endpoints (Phase 1 §2).

Provides independently governed lifecycle management for authoritative
enterprise knowledge, security policies, and organizational baselines:
- Separation from mutable agent memory
- Controlled lifecycle: Create -> Review -> Approve -> Activate -> Supersede -> Revoke -> Archive
- Multi-branch and tenant isolation (HO, LHR, KHI, ISB)
- Full cryptographic digest (SHA-256) and audit logging
- Strict role-based access: agents cannot approve or elevate their own baselines
"""

from copy import deepcopy
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from backend.app.api.audit import record_audit_event
from backend.app.core.dependencies import (
    CurrentUserDep,
    SettingsDep,
    TenantContextDep,
    require_roles,
)
from backend.app.core.exceptions import (
    ForbiddenError,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.database.repositories.baseline import (
    BaselineRepositoryProtocol,
    InMemoryBaselineRepository,
    seed_demo_baselines,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.baseline")
router = APIRouter(prefix="/baseline", tags=["Enterprise Baseline"])

SAFE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

# In-memory default repo singleton for dev/test
_default_baseline_repo: Optional[BaselineRepositoryProtocol] = None


def get_default_baseline_repository() -> BaselineRepositoryProtocol:
    global _default_baseline_repo
    if _default_baseline_repo is None:
        repo = InMemoryBaselineRepository()
        seed_demo_baselines(repo)
        _default_baseline_repo = repo
    return _default_baseline_repo


async def get_baseline_repo(
    request: Request,
    settings: SettingsDep,
) -> BaselineRepositoryProtocol:
    """Dependency injection for baseline repository."""
    repo = getattr(request.app.state, "baseline_repo", None)
    if repo is None:
        session_factory = getattr(request.app.state, "db_session_factory", None)
        if session_factory is not None:
            from backend.app.database.repositories.baseline import SqlAlchemyBaselineRepository
            repo = SqlAlchemyBaselineRepository(session_factory)
            request.app.state.baseline_repo = repo

    if repo is not None:
        if settings.APP_ENV == "production":
            if getattr(repo, "is_in_memory", True) or not getattr(repo, "is_persistent", False):
                raise SecurityDependencyError("Production database baseline repository is not configured.")
        return repo

    if settings.APP_ENV == "production":
        raise SecurityDependencyError("Production database baseline repository is not configured.")

    return get_default_baseline_repository()


BaselineRepoDep = Depends(get_baseline_repo)


# ============================================================================
# DTOs
# ============================================================================

class BaselineCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=255, description="Baseline title or policy name")
    category: str = Field(default="POLICY", description="POLICY, PROCEDURE, APPROVED_KNOWLEDGE, SECURITY_DIRECTIVE")
    source_type: str = Field(default="EXECUTIVE_DIRECTIVE", description="Source type or authority")
    provenance: str = Field(..., min_length=1, max_length=65535, description="Documented provenance and authority")
    classification: str = Field(default="ENTERPRISE_CONFIDENTIAL", description="Security classification")
    access_scope: str = Field(default="ALL_BRANCHES", description="Target departmental or branch access scope")
    content: str = Field(..., min_length=1, max_length=500000, description="Authoritative baseline content")
    change_summary: str = Field(default="Initial version creation", description="Reason for change")
    branch_id: Optional[str] = Field(None, max_length=64, description="Optional branch assignment (HO, LHR, KHI, ISB)")
    source_uri: Optional[str] = Field(None, max_length=1024, description="Authoritative document storage URI")
    effective_from: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class BaselineVersionAppendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(..., min_length=1, max_length=500000, description="New baseline version content")
    change_summary: str = Field(..., min_length=1, max_length=1024, description="Summary of changes")


class BaselineTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1, max_length=1024, description="Documented justification for transition")
    superseded_by_id: Optional[str] = Field(None, max_length=64, description="Target baseline ID if superseding")


class BaselineRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    branch_id: Optional[str] = None
    title: str
    category: str
    source_uri: Optional[str] = None
    source_type: str
    provenance: str
    classification: str
    access_scope: str
    current_version: int
    content_digest: Optional[str] = None
    lifecycle_status: str
    superseded_by_id: Optional[str] = None
    effective_from: Optional[str] = None
    expires_at: Optional[str] = None
    created_by_user_id: str
    reviewed_by_user_id: Optional[str] = None
    approved_by_user_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class BaselineVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    baseline_id: str
    version: int
    version_number: int = Field(validation_alias=AliasChoices("version_number", "version"))
    content: str
    content_sha256: str
    content_digest: str = Field(validation_alias=AliasChoices("content_digest", "content_sha256"))
    change_summary: str
    created_by_user_id: str
    created_at: Optional[str] = None


class BaselineGovernanceLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    baseline_id: str
    version: int
    operation: str
    actor_id: str
    actor_role: str
    reason: str
    occurred_at: Optional[str] = None


class BaselineListEnvelope(BaseModel):
    items: List[BaselineRecordResponse]
    limit: int
    offset: int
    has_more: bool


# ============================================================================
# Endpoints
# ============================================================================

@router.post(
    "",
    response_model=BaselineRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Enterprise Baseline Record",
    description="Establish an authoritative enterprise policy or knowledge baseline. Starts in DRAFT status. Restricted to administrators and analysts.",
)
async def create_baseline_record(
    payload: BaselineCreateRequest,
    request: Request,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("TENANT_ADMIN", "SECURITY_ANALYST")),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineRecordResponse:
    """Create new baseline record with atomic initial version snapshot and SHA-256 digest."""
    # Branch isolation: inherit caller's branch if user is branch-scoped
    effective_branch: Optional[str] = getattr(tenant_context, "branch_id", None) or payload.branch_id

    try:
        record = await repo.create_baseline_record(
            tenant_id=tenant_context.tenant_id,
            title=payload.title,
            category=payload.category,
            source_type=payload.source_type,
            provenance=payload.provenance,
            classification=payload.classification,
            access_scope=payload.access_scope,
            content=payload.content,
            change_summary=payload.change_summary,
            user_id=current_user.id,
            branch_id=effective_branch,
            source_uri=payload.source_uri,
            effective_from=payload.effective_from,
            expires_at=payload.expires_at,
        )
    except Exception as exc:
        logger.error("Failed to create baseline record: %s", exc)
        raise SecurityDependencyError("Failed to create enterprise baseline record.") from exc

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=current_user.id,
        event_type="BASELINE_GOVERNANCE",
        action="CREATE_BASELINE",
        resource_id=record["id"],
        outcome="SUCCESS",
        details={"title": payload.title, "category": payload.category, "branch_id": effective_branch},
    )

    return BaselineRecordResponse(**record)


@router.get(
    "",
    response_model=BaselineListEnvelope,
    status_code=status.HTTP_200_OK,
    summary="List Enterprise Baseline Records",
    description="Query authoritative policies and knowledge records scoped strictly to the authenticated tenant and optional branch.",
)
async def list_baseline_records(
    tenant_context: TenantContextDep,
    category: Optional[str] = Query(None, description="Filter by category (POLICY, PROCEDURE, APPROVED_KNOWLEDGE)"),
    lifecycle_status: Optional[str] = Query(None, description="Filter by lifecycle status (ACTIVE, APPROVED, DRAFT)"),
    branch_id: Optional[str] = Query(None, description="Filter by branch identifier"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineListEnvelope:
    """List baseline records with tenant and branch isolation."""
    # User branch scope restriction
    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)
    effective_branch = user_branch or branch_id

    items, has_more = await repo.list_baseline_records(
        tenant_id=tenant_context.tenant_id,
        category=category,
        lifecycle_status=lifecycle_status,
        branch_id=effective_branch,
        limit=limit,
        offset=offset,
    )

    return BaselineListEnvelope(
        items=[BaselineRecordResponse(**r) for r in items],
        limit=limit,
        offset=offset,
        has_more=has_more,
    )


@router.get(
    "/{baseline_id}",
    response_model=BaselineRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Baseline Record Detail",
    description="Retrieve authoritative baseline record metadata and current version.",
)
async def get_baseline_detail(
    baseline_id: str,
    tenant_context: TenantContextDep,
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineRecordResponse:
    if not baseline_id or not SAFE_ID_REGEX.match(baseline_id.strip()):
        raise NotFoundError("Baseline record not found.")
    clean_id = baseline_id.strip()

    record = await repo.get_baseline_record(tenant_context.tenant_id, clean_id)
    if record is None:
        raise NotFoundError("Baseline record not found.")

    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)
    if user_branch and record.get("branch_id") and record["branch_id"] != user_branch:
        raise NotFoundError("Baseline record not found.")

    return BaselineRecordResponse(**record)


@router.get(
    "/{baseline_id}/versions",
    response_model=List[BaselineVersionResponse],
    status_code=status.HTTP_200_OK,
    summary="List Historical Baseline Versions",
    description="Retrieve immutable, auditable version history with SHA-256 integrity digests.",
)
async def get_baseline_versions(
    baseline_id: str,
    tenant_context: TenantContextDep,
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> List[BaselineVersionResponse]:
    if not baseline_id or not SAFE_ID_REGEX.match(baseline_id.strip()):
        raise NotFoundError("Baseline record not found.")
    clean_id = baseline_id.strip()

    record = await repo.get_baseline_record(tenant_context.tenant_id, clean_id)
    if record is None:
        raise NotFoundError("Baseline record not found.")

    versions = await repo.get_baseline_versions(tenant_context.tenant_id, clean_id)
    return [BaselineVersionResponse(**v) for v in versions]


@router.post(
    "/{baseline_id}/versions",
    response_model=BaselineVersionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Append New Baseline Version",
    description="Append a new version snapshot. Resets lifecycle to DRAFT for mandatory administrative review.",
)
async def append_baseline_version(
    baseline_id: str,
    payload: BaselineVersionAppendRequest,
    request: Request,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("TENANT_ADMIN", "SECURITY_ANALYST")),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineVersionResponse:
    if not baseline_id or not SAFE_ID_REGEX.match(baseline_id.strip()):
        raise NotFoundError("Baseline record not found.")
    clean_id = baseline_id.strip()

    version = await repo.append_baseline_version(
        tenant_id=tenant_context.tenant_id,
        baseline_id=clean_id,
        content=payload.content,
        change_summary=payload.change_summary,
        user_id=current_user.id,
    )

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=current_user.id,
        event_type="BASELINE_GOVERNANCE",
        action="APPEND_VERSION",
        resource_id=clean_id,
        outcome="SUCCESS",
        details={"version": version["version"], "change_summary": payload.change_summary},
    )

    return BaselineVersionResponse(**version)


@router.post(
    "/{baseline_id}/review",
    response_model=BaselineRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit Baseline for Review",
    description="Transition baseline status from DRAFT to IN_REVIEW.",
)
async def review_baseline(
    baseline_id: str,
    payload: BaselineTransitionRequest,
    request: Request,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("TENANT_ADMIN", "SECURITY_ANALYST")),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineRecordResponse:
    clean_id = baseline_id.strip()
    updated = await repo.transition_lifecycle(
        tenant_id=tenant_context.tenant_id,
        baseline_id=clean_id,
        target_status="IN_REVIEW",
        actor_id=current_user.id,
        actor_role=tenant_context.role,
        reason=payload.reason,
    )

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=current_user.id,
        event_type="BASELINE_GOVERNANCE",
        action="SUBMIT_REVIEW",
        resource_id=clean_id,
        outcome="SUCCESS",
        details={"reason": payload.reason},
    )
    return BaselineRecordResponse(**updated)


@router.post(
    "/{baseline_id}/approve",
    response_model=BaselineRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve Enterprise Baseline",
    description="Formally approve a baseline record in review. Restricted to TENANT_ADMIN. Agents cannot self-approve.",
)
async def approve_baseline(
    baseline_id: str,
    payload: BaselineTransitionRequest,
    request: Request,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("TENANT_ADMIN")),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineRecordResponse:
    clean_id = baseline_id.strip()

    # Self-approval guard: Agent identities cannot approve baselines
    if tenant_context.role == "AGENT" or current_user.id.startswith("agent-"):
        raise ForbiddenError("AI agents are strictly prohibited from approving enterprise baselines.")

    updated = await repo.transition_lifecycle(
        tenant_id=tenant_context.tenant_id,
        baseline_id=clean_id,
        target_status="APPROVED",
        actor_id=current_user.id,
        actor_role=tenant_context.role,
        reason=payload.reason,
    )

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=current_user.id,
        event_type="BASELINE_GOVERNANCE",
        action="APPROVE_BASELINE",
        resource_id=clean_id,
        outcome="SUCCESS",
        details={"reason": payload.reason},
    )
    return BaselineRecordResponse(**updated)


@router.post(
    "/{baseline_id}/activate",
    response_model=BaselineRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Activate Enterprise Baseline",
    description="Activate an approved baseline record. Makes it effective for enterprise agents and compliance checks. Restricted to TENANT_ADMIN.",
)
async def activate_baseline(
    baseline_id: str,
    payload: BaselineTransitionRequest,
    request: Request,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("TENANT_ADMIN")),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineRecordResponse:
    clean_id = baseline_id.strip()

    if tenant_context.role == "AGENT" or current_user.id.startswith("agent-"):
        raise ForbiddenError("AI agents are strictly prohibited from mutating enterprise baseline lifecycle.")

    updated = await repo.transition_lifecycle(
        tenant_id=tenant_context.tenant_id,
        baseline_id=clean_id,
        target_status="ACTIVE",
        actor_id=current_user.id,
        actor_role=tenant_context.role,
        reason=payload.reason,
    )

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=current_user.id,
        event_type="BASELINE_GOVERNANCE",
        action="ACTIVATE_BASELINE",
        resource_id=clean_id,
        outcome="SUCCESS",
        details={"reason": payload.reason},
    )
    return BaselineRecordResponse(**updated)


@router.post(
    "/{baseline_id}/supersede",
    response_model=BaselineRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Supersede Enterprise Baseline",
    description="Mark an active baseline as superseded by a newer baseline record. Restricted to TENANT_ADMIN.",
)
async def supersede_baseline(
    baseline_id: str,
    payload: BaselineTransitionRequest,
    request: Request,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("TENANT_ADMIN")),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineRecordResponse:
    clean_id = baseline_id.strip()
    if not payload.superseded_by_id:
        raise ValidationError("superseded_by_id is required when superseding a baseline.")

    if tenant_context.role == "AGENT" or current_user.id.startswith("agent-"):
        raise ForbiddenError("AI agents are strictly prohibited from mutating enterprise baseline lifecycle.")

    updated = await repo.transition_lifecycle(
        tenant_id=tenant_context.tenant_id,
        baseline_id=clean_id,
        target_status="SUPERSEDED",
        actor_id=current_user.id,
        actor_role=tenant_context.role,
        reason=payload.reason,
        superseded_by_id=payload.superseded_by_id,
    )

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=current_user.id,
        event_type="BASELINE_GOVERNANCE",
        action="SUPERSEDE_BASELINE",
        resource_id=clean_id,
        outcome="SUCCESS",
        details={"reason": payload.reason, "superseded_by": payload.superseded_by_id},
    )
    return BaselineRecordResponse(**updated)


@router.post(
    "/{baseline_id}/revoke",
    response_model=BaselineRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke Enterprise Baseline",
    description="Immediately revoke an active or approved baseline policy. Restricted to TENANT_ADMIN.",
)
async def revoke_baseline(
    baseline_id: str,
    payload: BaselineTransitionRequest,
    request: Request,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("TENANT_ADMIN")),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineRecordResponse:
    clean_id = baseline_id.strip()

    if tenant_context.role == "AGENT" or current_user.id.startswith("agent-"):
        raise ForbiddenError("AI agents are strictly prohibited from mutating enterprise baseline lifecycle.")

    updated = await repo.transition_lifecycle(
        tenant_id=tenant_context.tenant_id,
        baseline_id=clean_id,
        target_status="REVOKED",
        actor_id=current_user.id,
        actor_role=tenant_context.role,
        reason=payload.reason,
    )

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=current_user.id,
        event_type="BASELINE_GOVERNANCE",
        action="REVOKE_BASELINE",
        resource_id=clean_id,
        outcome="SUCCESS",
        details={"reason": payload.reason},
    )
    return BaselineRecordResponse(**updated)


@router.post(
    "/{baseline_id}/archive",
    response_model=BaselineRecordResponse,
    status_code=status.HTTP_200_OK,
    summary="Archive Enterprise Baseline",
    description="Archive a superseded or revoked baseline record. Restricted to TENANT_ADMIN.",
)
async def archive_baseline(
    baseline_id: str,
    payload: BaselineTransitionRequest,
    request: Request,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("TENANT_ADMIN")),
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> BaselineRecordResponse:
    clean_id = baseline_id.strip()

    if tenant_context.role == "AGENT" or current_user.id.startswith("agent-"):
        raise ForbiddenError("AI agents are strictly prohibited from mutating enterprise baseline lifecycle.")

    updated = await repo.transition_lifecycle(
        tenant_id=tenant_context.tenant_id,
        baseline_id=clean_id,
        target_status="ARCHIVED",
        actor_id=current_user.id,
        actor_role=tenant_context.role,
        reason=payload.reason,
    )

    await record_audit_event(
        request=request,
        tenant_id=tenant_context.tenant_id,
        actor_id=current_user.id,
        event_type="BASELINE_GOVERNANCE",
        action="ARCHIVE_BASELINE",
        resource_id=clean_id,
        outcome="SUCCESS",
        details={"reason": payload.reason},
    )
    return BaselineRecordResponse(**updated)


@router.get(
    "/{baseline_id}/governance-logs",
    response_model=List[BaselineGovernanceLogResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Baseline Governance Audit Trail",
    description="Retrieve immutable lifecycle operation log (who, when, why, version).",
)
async def get_baseline_governance_logs(
    baseline_id: str,
    tenant_context: TenantContextDep,
    repo: BaselineRepositoryProtocol = BaselineRepoDep,
) -> List[BaselineGovernanceLogResponse]:
    if not baseline_id or not SAFE_ID_REGEX.match(baseline_id.strip()):
        raise NotFoundError("Baseline record not found.")
    clean_id = baseline_id.strip()

    record = await repo.get_baseline_record(tenant_context.tenant_id, clean_id)
    if record is None:
        raise NotFoundError("Baseline record not found.")

    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)
    if user_branch and record.get("branch_id") and record["branch_id"] != user_branch:
        raise NotFoundError("Baseline record not found.")

    logs = await repo.list_governance_logs(tenant_context.tenant_id, clean_id)
    return [BaselineGovernanceLogResponse(**l) for l in logs]
