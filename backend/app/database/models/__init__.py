"""SQLAlchemy declarative models for every AMSC table."""
from backend.app.database.models.agents import Agent, AgentToolPermission, AgentVersion, ToolRegistration
from backend.app.database.models.baseline import AgentSecurityProfile, BaselineGovernanceLog, EnterpriseBaselineRecord, EnterpriseBaselineVersion, ObservationEvent, TrustDecisionModel
from backend.app.database.models.company import (
    CompanyActivity, CompanyFile, CompanyFileTransfer, CompanyFileVersion,
    CompanyMessage, CompanyNotification, CompanyTask, CompanyTaskEvent,
    CompanyWorkspace,
)
from backend.app.database.models.detection import DetectionResultModel
from backend.app.database.models.enterprise import ConnectorAuditLog, DiscoveredResource, EnterpriseConnector, EnterpriseMemoryLink, KnowledgeClaim, SyncJob
from backend.app.database.models.gateway import Approval, PolicyDecision, ToolExecution, ToolProposal
from backend.app.database.models.identity import Branch, Membership, Permission, RegistrationRequest, Role, RolePermission, Tenant, User
from backend.app.database.models.memory import Document, MemoryRecord, MemoryVersion, ProvenanceEdge, RetrievalEvent, Source, Transformation
from backend.app.database.models.observability import AuditEvent, DriftObservation, KnowledgeEntity, KnowledgeRelation, OutboxEvent, Trace, TraceSpan
from backend.app.database.models.recovery import Checkpoint, CheckpointItem, Incident, IncidentEvidence, Quarantine, RecoveryAction, RecoveryPlan

GLOBAL_TABLES = frozenset({"tenants", "users", "permissions", "role_permissions"})
NULLABLE_TENANT_TABLES = frozenset({"roles"})

__all__ = [
    "GLOBAL_TABLES", "NULLABLE_TENANT_TABLES", "Agent", "AgentSecurityProfile",
    "AgentToolPermission", "AgentVersion", "Approval", "AuditEvent",
    "BaselineGovernanceLog", "Branch", "Checkpoint", "CheckpointItem",
    "CompanyActivity", "CompanyFile", "CompanyFileTransfer", "CompanyFileVersion",
    "CompanyMessage", "CompanyNotification", "CompanyTask", "CompanyTaskEvent",
    "CompanyWorkspace", "ConnectorAuditLog", "DetectionResultModel",
    "DiscoveredResource", "Document", "DriftObservation", "EnterpriseBaselineRecord",
    "EnterpriseBaselineVersion", "EnterpriseConnector", "EnterpriseMemoryLink",
    "Incident", "IncidentEvidence", "KnowledgeClaim", "KnowledgeEntity",
    "KnowledgeRelation", "Membership", "MemoryRecord", "MemoryVersion",
    "ObservationEvent", "OutboxEvent", "Permission", "PolicyDecision",
    "ProvenanceEdge", "Quarantine", "RecoveryAction", "RecoveryPlan",
    "RegistrationRequest", "RetrievalEvent", "Role", "RolePermission", "Source",
    "SyncJob", "Tenant", "ToolExecution", "ToolProposal", "ToolRegistration",
    "Trace", "TraceSpan", "Transformation", "TrustDecisionModel", "User",
]
