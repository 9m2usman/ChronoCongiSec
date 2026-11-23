"""Tenant-scoped repositories (M6)."""

from backend.app.database.repositories.base import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    TenantScopedRepository,
    TenantScopeError,
    check_page,
)
from backend.app.database.repositories.gateway import (
    AppendOnlyError,
    ApprovalRepository,
    AuditEventRepository,
    PolicyDecisionRepository,
    ToolExecutionRepository,
    ToolProposalRepository,
)
from backend.app.database.repositories.agents import SqlAlchemyAgentRepository
from backend.app.database.repositories.auth import DatabaseAuthRepository
from backend.app.database.repositories.memberships import MembershipRepository
from backend.app.database.repositories.memory import (
    EdgePage,
    MemoryVersionRepository,
    ProvenanceEdgeRepository,
)

__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "AppendOnlyError",
    "ApprovalRepository",
    "AuditEventRepository",
    "DatabaseAuthRepository",
    "EdgePage",
    "MembershipRepository",
    "MemoryVersionRepository",
    "PolicyDecisionRepository",
    "ProvenanceEdgeRepository",
    "SqlAlchemyAgentRepository",
    "TenantScopeError",
    "TenantScopedRepository",
    "ToolExecutionRepository",
    "ToolProposalRepository",
    "check_page",
]
