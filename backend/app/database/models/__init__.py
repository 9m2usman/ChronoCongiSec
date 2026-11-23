"""SQLAlchemy declarative models for every AMSC table (AMSC-DOC-005 Section 3).

Importing this package registers all tables on ``Base.metadata`` (used by
Alembic and by schema tests).
"""

from backend.app.database.models.agents import (
    Agent,
    AgentToolPermission,
    AgentVersion,
    ToolRegistration,
)
from backend.app.database.models.gateway import (
    Approval,
    PolicyDecision,
    ToolExecution,
    ToolProposal,
)
from backend.app.database.models.identity import (
    Branch,
    Membership,
    Permission,
    RegistrationRequest,
    Role,
    RolePermission,
    Tenant,
    User,
)
from backend.app.database.models.memory import (
    Document,
    MemoryRecord,
    MemoryVersion,
    ProvenanceEdge,
    RetrievalEvent,
    Source,
    Transformation,
)
from backend.app.database.models.observability import (
    AuditEvent,
    DriftObservation,
    KnowledgeEntity,
    KnowledgeRelation,
    OutboxEvent,
    Trace,
    TraceSpan,
)
from backend.app.database.models.recovery import (
    Checkpoint,
    CheckpointItem,
    Incident,
    IncidentEvidence,
    Quarantine,
    RecoveryAction,
    RecoveryPlan,
)

# Tables that are intentionally NOT tenant-owned (no tenant_id column).
# Every other table must carry a NOT NULL tenant_id FK to tenants.id,
# except roles, whose tenant_id may be NULL for platform-global roles.
GLOBAL_TABLES = frozenset({"tenants", "users", "permissions", "role_permissions"})
NULLABLE_TENANT_TABLES = frozenset({"roles"})

__all__ = [
    "GLOBAL_TABLES",
    "NULLABLE_TENANT_TABLES",
    "Agent",
    "AgentToolPermission",
    "AgentVersion",
    "Approval",
    "AuditEvent",
    "Branch",
    "Checkpoint",
    "CheckpointItem",
    "Document",
    "DriftObservation",
    "Incident",
    "IncidentEvidence",
    "KnowledgeEntity",
    "KnowledgeRelation",
    "Membership",
    "MemoryRecord",
    "MemoryVersion",
    "OutboxEvent",
    "Permission",
    "PolicyDecision",
    "ProvenanceEdge",
    "Quarantine",
    "RecoveryAction",
    "RecoveryPlan",
    "RegistrationRequest",
    "RetrievalEvent",
    "Role",
    "RolePermission",
    "Source",
    "Tenant",
    "ToolExecution",
    "ToolProposal",
    "ToolRegistration",
    "Trace",
    "TraceSpan",
    "Transformation",
    "User",
]
