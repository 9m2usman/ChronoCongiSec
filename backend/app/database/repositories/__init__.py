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
    "EdgePage",
    "MembershipRepository",
    "MemoryVersionRepository",
    "PolicyDecisionRepository",
    "ProvenanceEdgeRepository",
    "TenantScopeError",
    "TenantScopedRepository",
    "ToolExecutionRepository",
    "ToolProposalRepository",
    "check_page",
]
