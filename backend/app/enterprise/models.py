"""Pydantic models and domain enums for Enterprise Data Connectivity."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class _StrEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class ConnectorType(_StrEnum):
    DATABASE = "DATABASE"
    FILESYSTEM = "FILESYSTEM"
    DOCUMENT_REPO = "DOCUMENT_REPO"
    CLOUD_STORAGE = "CLOUD_STORAGE"
    INTERNAL_API = "INTERNAL_API"
    KNOWLEDGE_BASE = "KNOWLEDGE_BASE"
    AGENT_FRAMEWORK = "AGENT_FRAMEWORK"
    ENTERPRISE_APP = "ENTERPRISE_APP"


class ConnectorStatus(_StrEnum):
    PENDING_AUTH = "PENDING_AUTH"
    AUTHORIZED = "AUTHORIZED"
    PAUSED = "PAUSED"
    REVOKED = "REVOKED"
    DISCONNECTED = "DISCONNECTED"
    ERROR = "ERROR"
    UNAVAILABLE = "UNAVAILABLE"


class AuthMode(_StrEnum):
    LOCAL_SCOPED = "LOCAL_SCOPED"
    API_KEY = "API_KEY"
    OAUTH2 = "OAUTH2"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    CONNECTION_STRING = "CONNECTION_STRING"


class ResourceType(_StrEnum):
    DATABASE_SCHEMA = "DATABASE_SCHEMA"
    DATABASE_TABLE = "DATABASE_TABLE"
    DATABASE_VIEW = "DATABASE_VIEW"
    DIRECTORY = "DIRECTORY"
    DOCUMENT_PDF = "DOCUMENT_PDF"
    DOCUMENT_DOCX = "DOCUMENT_DOCX"
    DOCUMENT_TEXT = "DOCUMENT_TEXT"
    SPREADSHEET = "SPREADSHEET"
    POLICY_DOC = "POLICY_DOC"
    KNOWLEDGE_ARTICLE = "KNOWLEDGE_ARTICLE"
    AGENT_REGISTRATION = "AGENT_REGISTRATION"
    AGENT_MEMORY_STORE = "AGENT_MEMORY_STORE"
    API_ENDPOINT = "API_ENDPOINT"


class DataClassification(_StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class SyncStatus(_StrEnum):
    DISCOVERED = "DISCOVERED"
    SYNCED = "SYNCED"
    CHANGED = "CHANGED"
    DELETED = "DELETED"
    INACCESSIBLE = "INACCESSIBLE"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"
    FAILED = "FAILED"


class SyncStrategy(_StrEnum):
    INITIAL = "INITIAL"
    INCREMENTAL = "INCREMENTAL"
    SCHEDULED = "SCHEDULED"
    EVENT_DRIVEN = "EVENT_DRIVEN"
    ON_DEMAND = "ON_DEMAND"
    TARGETED_REFRESH = "TARGETED_REFRESH"
    RECONCILIATION = "RECONCILIATION"


class SyncJobStatus(_StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ClaimType(_StrEnum):
    FACT = "FACT"
    ENTITY = "ENTITY"
    RELATIONSHIP = "RELATIONSHIP"
    POLICY = "POLICY"
    PROCEDURE = "PROCEDURE"
    RESPONSIBILITY = "RESPONSIBILITY"
    CONSTRAINT = "CONSTRAINT"
    BUSINESS_RULE = "BUSINESS_RULE"
    DEPENDENCY = "DEPENDENCY"
    CONFLICT = "CONFLICT"


class ClaimTrustState(_StrEnum):
    UNVERIFIED = "UNVERIFIED"
    TRUSTED = "TRUSTED"
    CONFLICTING = "CONFLICTING"
    UNCERTAIN = "UNCERTAIN"
    OUTDATED = "OUTDATED"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"


class FreshnessStatus(_StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    SOURCE_REVOKED = "SOURCE_REVOKED"
    SOURCE_DELETED = "SOURCE_DELETED"
    QUARANTINED = "QUARANTINED"


class ConnectorCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    connector_type: ConnectorType
    auth_mode: AuthMode = AuthMode.LOCAL_SCOPED
    config: Dict[str, Any] = Field(default_factory=dict)
    secret_value: Optional[str] = Field(default=None, description="Secret/credential; stored masked/referenced")
    scope: Dict[str, Any] = Field(
        default_factory=lambda: {
            "allowed_operations": ["READ", "DISCOVER"],
            "max_classification": "CONFIDENTIAL",
            "allowed_paths": [],
            "allowed_tables": [],
        }
    )


class ConnectorAuthorizeRequest(BaseModel):
    approved_scope: Optional[Dict[str, Any]] = None
    justification: Optional[str] = Field(default=None, max_length=512)


class ConnectorSyncRequest(BaseModel):
    strategy: SyncStrategy = SyncStrategy.INCREMENTAL
    target_resource_ids: List[str] = Field(default_factory=list)


class EnterpriseConnectorDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    tenant_id: str
    name: str
    connector_type: ConnectorType
    status: ConnectorStatus
    auth_mode: AuthMode
    config_json: Dict[str, Any] = Field(default_factory=dict)
    secret_ref: Optional[str] = None
    scope_json: Dict[str, Any] = Field(default_factory=dict)
    monitoring_coverage_json: Dict[str, Any] = Field(default_factory=dict)
    last_sync_at: Optional[datetime] = None
    last_sync_status: Optional[str] = None
    last_error: Optional[str] = None
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DiscoveredResourceDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    tenant_id: str
    connector_id: str
    source_id: Optional[str] = None
    resource_type: ResourceType
    external_id: str
    name: str
    parent_resource_id: Optional[str] = None
    owner: Optional[str] = None
    access_scope: str = "TENANT_SCOPED"
    classification: DataClassification = DataClassification.INTERNAL
    sync_status: SyncStatus = SyncStatus.DISCOVERED
    source_version: Optional[str] = None
    content_checksum: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    retention_policy: str = "STANDARD_90D"
    last_synced_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SyncJobDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    tenant_id: str
    connector_id: str
    strategy: SyncStrategy
    status: SyncJobStatus
    resources_discovered: int = 0
    resources_synced: int = 0
    resources_changed: int = 0
    resources_deleted: int = 0
    resources_failed: int = 0
    checkpoint_json: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class KnowledgeClaimDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    tenant_id: str
    resource_id: str
    source_id: Optional[str] = None
    claim_type: ClaimType
    subject: str
    predicate: str
    object_value: str
    department: Optional[str] = None
    branch_id: Optional[str] = None
    provenance_json: Dict[str, Any] = Field(default_factory=dict)
    trust_state: ClaimTrustState = ClaimTrustState.UNVERIFIED
    confidence: float = 0.5
    conflict_group_id: Optional[str] = None
    superseded_by_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EnterpriseMemoryLinkDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    id: str
    tenant_id: str
    memory_record_id: str
    memory_version: int = 1
    resource_id: str
    source_version: Optional[str] = None
    agent_id: Optional[str] = None
    extraction_purpose: str
    confidence: float = 0.8
    freshness_status: FreshnessStatus = FreshnessStatus.CURRENT
    snapshot_checksum: str
    snapshot_json: Dict[str, Any] = Field(default_factory=dict)
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ConnectorAuditLogDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    connector_id: Optional[str] = None
    actor_id: str
    action: str
    status: str
    details_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MemoryExtractRequest(BaseModel):
    resource_id: str
    agent_id: Optional[str] = None
    purpose: str = Field(default="ENTERPRISE_KNOWLEDGE_EXTRACTION", max_length=255)


class ImpactTraceResponse(BaseModel):
    target_id: str
    tenant_id: str
    source_resources: List[DiscoveredResourceDTO] = Field(default_factory=list)
    affected_claims: List[KnowledgeClaimDTO] = Field(default_factory=list)
    dependent_memories: List[EnterpriseMemoryLinkDTO] = Field(default_factory=list)
    affected_agent_ids: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)


class ScopedRecoveryPlanRequest(BaseModel):
    target_id: str
    reason: str = Field(..., min_length=3, max_length=512)
    require_human_approval: bool = True


class ScopedRecoveryPlanResponse(BaseModel):
    plan_id: str
    tenant_id: str
    target_id: str
    requires_human_approval: bool
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    compensating_actions: List[Dict[str, Any]] = Field(default_factory=list)
    preserved_evidence_ids: List[str] = Field(default_factory=list)
    status: str = "PENDING_APPROVAL"
