"""Agent Registry API Endpoints & Contract.

Module: backend.app.api.agents
Owner: M1 — Platform Backend & API Integration Lead

Follows:
- AMSC-DOC-002 (TRD/SRS) Section 5: Security Architecture & Credential Isolation
- AMSC-DOC-005 (Database & API Schema) Section 3.2: Agent Registry & Tool Permissions
- AMSC-DOC-005 Section 5.1: Route Catalog (GET /agents, POST /agents, GET /agents/{id})
- AMSC-DOC-006 (Team Implementation Plan) Day 3: M1 Agent Registry Deliverable
- AMSC-DOC-008: GAP-010 (Confidentiality & Redaction of Sensitive System Prompts)
"""

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
import re
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.core.dependencies import (
    CurrentUserDep,
    SettingsDep,
    TenantContextDep,
    require_roles,
)
from backend.app.core.exceptions import (
    AMSCException,
    NotFoundError,
    SecurityDependencyError,
    ValidationError,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.api.agents")

# Safe UUID/ID validation pattern
SAFE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


# ============================================================================
# 1. Enums and Domain Entities
# ============================================================================

class AgentRuntime(str, Enum):
    """Documented runtime execution engines per AMSC-DOC-005 Table 5."""
    LANGCHAIN = "LANGCHAIN"
    CREWAI = "CREWAI"
    AUTOGEN = "AUTOGEN"
    RAW_HTTP = "RAW_HTTP"


class AgentStatus(str, Enum):
    """Documented agent lifecycle status values per AMSC-DOC-005 Table 5."""
    ACTIVE = "ACTIVE"
    ISOLATED = "ISOLATED"
    DEPRECATED = "DEPRECATED"


@dataclass
class AgentEntity:
    """Agent domain entity contract for database and service layers."""
    id: str
    tenant_id: str
    name: str
    runtime: str
    model: str
    status: str
    config_version: str
    system_prompt: str
    branch_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AgentVersionEntity:
    """Agent version historical configuration snapshot per AMSC-DOC-005 Table 6."""
    id: str
    tenant_id: str
    agent_id: str
    version: str
    config_payload: Dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# 2. Repository Protocol & Default Store (M6 Boundary)
# ============================================================================

@runtime_checkable
class AgentRepositoryProtocol(Protocol):
    """Protocol defining the repository contract between M1 (Platform) and M6 (Database)."""

    is_persistent: bool
    is_in_memory: bool

    async def create_agent_atomic(
        self,
        agent: AgentEntity,
        version: AgentVersionEntity,
    ) -> AgentEntity:
        """Atomically persist an agent and its initial configuration version snapshot."""
        ...

    async def get_agent_by_id(
        self,
        agent_id: str,
        tenant_id: str,
    ) -> Optional[AgentEntity]:
        """Fetch agent strictly asserting tenant isolation."""
        ...

    async def list_agents(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AgentEntity], bool]:
        """Query agents strictly scoped to tenant and optional branch, returning (items, has_more)."""
        ...

    async def get_agent_version(
        self,
        agent_id: str,
        version: str,
        tenant_id: str,
    ) -> Optional[AgentVersionEntity]:
        """Retrieve historical configuration snapshot."""
        ...

    async def get_agent_tool_permissions(
        self,
        agent_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Retrieve read-only tool permissions for agent (owned by M2/M6)."""
        ...


class InMemoryAgentRepository:
    """Thread-safe test and development repository baseline.

    Follows the same architectural contract pattern established in M1 Day 2 and M3.
    Strictly forbidden in production environments.
    """

    is_persistent: bool = False
    is_in_memory: bool = True

    def __init__(self) -> None:
        self._agents: Dict[str, AgentEntity] = {}
        # key: (agent_id, version) -> AgentVersionEntity
        self._versions: Dict[Tuple[str, str], AgentVersionEntity] = {}
        # key: agent_id -> list of permissions
        self._tool_permissions: Dict[str, List[Dict[str, Any]]] = {}
        # Injection hook for testing rollback behavior on transaction failure
        self.fail_version_insert: bool = False

    async def create_agent_atomic(
        self,
        agent: AgentEntity,
        version: AgentVersionEntity,
    ) -> AgentEntity:
        """Atomically persist agent and initial version; rolls back on failure."""
        if agent.id in self._agents:
            raise ValidationError(f"Agent with ID '{agent.id}' already exists.")

        # Simulate transactional atomicity
        # Step 1: Stage agent
        staged_agent = deepcopy(agent)
        staged_version = deepcopy(version)

        if self.fail_version_insert:
            # Simulate failure during version insertion (e.g. DB constraint or network error)
            logger.warning("Simulated transaction failure during agent version snapshot insertion.")
            raise AMSCException(
                message="Transaction aborted: failed to persist configuration version snapshot.",
                code="TRANSACTION_ROLLBACK",
                status_code=500,
            )

        # Step 2: Atomic commit of both entities
        self._agents[agent.id] = staged_agent
        self._versions[(version.agent_id, version.version)] = staged_version
        return deepcopy(staged_agent)

    async def get_agent_by_id(
        self,
        agent_id: str,
        tenant_id: str,
    ) -> Optional[AgentEntity]:
        agent = self._agents.get(agent_id)
        if agent is None:
            return None
        # Strict tenant boundary assertion: never return cross-tenant records
        if agent.tenant_id != tenant_id:
            return None
        return deepcopy(agent)

    async def list_agents(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AgentEntity], bool]:
        # Filter by tenant
        matched = [
            a for a in self._agents.values()
            if a.tenant_id == tenant_id
        ]

        # Filter by status if specified
        if status:
            matched = [a for a in matched if a.status == status]

        # Filter by branch if specified
        if branch_id:
            matched = [a for a in matched if a.branch_id == branch_id]

        # Deterministic ordering: created_at descending, then id
        matched.sort(key=lambda a: (a.created_at, a.id), reverse=True)

        total_matched = len(matched)
        page = matched[offset : offset + limit]
        has_more = (offset + limit) < total_matched

        return [deepcopy(a) for a in page], has_more

    async def get_agent_version(
        self,
        agent_id: str,
        version: str,
        tenant_id: str,
    ) -> Optional[AgentVersionEntity]:
        agent = await self.get_agent_by_id(agent_id, tenant_id)
        if agent is None:
            return None
        v = self._versions.get((agent_id, version))
        if v is None or v.tenant_id != tenant_id:
            return None
        return deepcopy(v)

    async def get_agent_tool_permissions(
        self,
        agent_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        agent = await self.get_agent_by_id(agent_id, tenant_id)
        if agent is None:
            return []
        return deepcopy(self._tool_permissions.get(agent_id, []))


_default_agent_repo: Optional[AgentRepositoryProtocol] = None


def get_default_agent_repository() -> AgentRepositoryProtocol:
    """Factory returning singleton in-memory repository for dev/test."""
    global _default_agent_repo
    if _default_agent_repo is None:
        _default_agent_repo = InMemoryAgentRepository()
    return _default_agent_repo


# ============================================================================
# 3. Pydantic DTOs & Strict Validation
# ============================================================================

class AgentRegisterRequest(BaseModel):
    """Agent registration payload per AMSC-DOC-005 Section 5.1.

    Extra fields are strictly forbidden to reject client-controlled tenant_id,
    id, status, config_version, created_at, or updated_at.
    """
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Agent display name")
    runtime: AgentRuntime = Field(default=AgentRuntime.LANGCHAIN, description="Agent execution runtime")
    model: str = Field(..., min_length=1, max_length=64, description="LLM model identifier")
    system_prompt: str = Field(..., min_length=1, max_length=65535, description="Agent system prompt instructions")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Agent name cannot be empty or whitespace only.")
        return trimmed

    @field_validator("model")
    @classmethod
    def validate_model(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Model identifier cannot be empty or whitespace only.")
        return trimmed

    @field_validator("system_prompt")
    @classmethod
    def validate_system_prompt(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("System prompt cannot be empty or whitespace only.")
        return trimmed


class AgentSummaryResponse(BaseModel):
    """Summary representation of an agent for list views.

    CRITICAL SECURITY REQUIREMENT:
    System prompt and internal JSON configuration are strictly excluded to preserve
    business logic confidentiality and prevent prompt leakage.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Agent unique identifier (UUIDv4)")
    tenant_id: str = Field(description="Authorized tenant identifier")
    name: str = Field(description="Agent display name")
    runtime: str = Field(description="Execution runtime engine")
    model: str = Field(description="LLM model identifier")
    status: str = Field(description="Agent lifecycle status")
    config_version: str = Field(description="Active configuration version")
    created_at: datetime = Field(description="UTC timestamp of creation")
    updated_at: datetime = Field(description="UTC timestamp of last update")


class AgentDetailResponse(BaseModel):
    """Detailed representation of an agent including tool permissions.

    CRITICAL SECURITY REQUIREMENT:
    system_prompt is strictly excluded from ordinary detail responses to members.
    Tool permissions are read-only (managed by M2).
    """
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Agent unique identifier (UUIDv4)")
    tenant_id: str = Field(description="Authorized tenant identifier")
    name: str = Field(description="Agent display name")
    runtime: str = Field(description="Execution runtime engine")
    model: str = Field(description="LLM model identifier")
    status: str = Field(description="Agent lifecycle status")
    config_version: str = Field(description="Active configuration version")
    tool_permissions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Assigned tool permissions and execution ceilings (M2)",
    )
    created_at: datetime = Field(description="UTC timestamp of creation")
    updated_at: datetime = Field(description="UTC timestamp of last update")


class AgentListEnvelope(BaseModel):
    """Bounded pagination envelope for agent catalog per TRD §22."""
    items: List[AgentSummaryResponse]
    limit: int = Field(description="Requested page size limit")
    offset: int = Field(description="Requested page offset")
    has_more: bool = Field(description="Whether additional records exist beyond current page")


# ============================================================================
# 4. Dependency Injection
# ============================================================================

async def get_agent_repo(
    request: Request,
    settings: SettingsDep,
) -> AgentRepositoryProtocol:
    """Dependency providing the Agent repository interface.

    In production, strictly requires a real database repository; in-memory fallback
    is strictly forbidden and fails closed with SecurityDependencyError.
    """
    repo = getattr(request.app.state, "agent_repo", None)
    if repo is not None:
        if settings.APP_ENV == "production":
            if getattr(repo, "is_in_memory", True) or not getattr(repo, "is_persistent", False):
                raise SecurityDependencyError("Production database agent repository is not configured.")
        return repo

    if settings.APP_ENV == "production":
        raise SecurityDependencyError("Production database agent repository is not configured.")

    return get_default_agent_repository()


AgentRepoDep = Depends(get_agent_repo)


# ============================================================================
# 5. API Routes
# ============================================================================

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.get(
    "",
    response_model=AgentListEnvelope,
    status_code=status.HTTP_200_OK,
    summary="List Agents in Workspace",
    description=(
        "Returns agents visible to the authenticated caller within their authorized "
        "tenant and branch scope. Bounded pagination and deterministic ordering applied."
    ),
)
async def list_agents(
    tenant_context: TenantContextDep,
    repo: AgentRepositoryProtocol = AgentRepoDep,
    status_filter: Optional[str] = Query(
        None,
        alias="status",
        description="Filter agents by lifecycle status (ACTIVE, ISOLATED, DEPRECATED)",
    ),
    limit: int = Query(50, ge=1, le=100, description="Page limit (1-100)"),
    offset: int = Query(0, ge=0, le=10000, description="Page offset (0-10000)"),
) -> AgentListEnvelope:
    """List agents in the authorized tenant workspace."""
    # Strict validation of status filter if provided
    validated_status: Optional[str] = None
    if status_filter is not None:
        clean_status = status_filter.strip().upper()
        allowed_statuses = {s.value for s in AgentStatus}
        if clean_status not in allowed_statuses:
            raise ValidationError(
                f"Invalid status filter '{status_filter}'. Allowed: {sorted(list(allowed_statuses))}"
            )
        validated_status = clean_status

    # Branch authorization scope: if context contains branch_id, restrict scope
    branch_id: Optional[str] = getattr(tenant_context, "branch_id", None)

    try:
        agents, has_more = await repo.list_agents(
            tenant_id=tenant_context.tenant_id,
            status=validated_status,
            branch_id=branch_id,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.error(
            "Database error while listing agents",
            extra={"tenant_id": tenant_context.tenant_id, "error_type": type(exc).__name__},
        )
        raise SecurityDependencyError("Agent registry persistence service unavailable.") from exc

    return AgentListEnvelope(
        items=[
            AgentSummaryResponse(
                id=a.id,
                tenant_id=a.tenant_id,
                name=a.name,
                runtime=a.runtime,
                model=a.model,
                status=a.status,
                config_version=a.config_version,
                created_at=a.created_at,
                updated_at=a.updated_at,
            )
            for a in agents
        ],
        limit=limit,
        offset=offset,
        has_more=has_more,
    )


@router.post(
    "",
    response_model=AgentSummaryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register New Agent",
    description=(
        "Registers a new agent within the caller's tenant workspace and atomically creates "
        "its initial configuration version snapshot (v1.0.0). Restricted to AI_DEVELOPER."
    ),
)
async def register_agent(
    payload: AgentRegisterRequest,
    current_user: CurrentUserDep,
    tenant_context: TenantContext = Depends(require_roles("AI_DEVELOPER")),
    repo: AgentRepositoryProtocol = AgentRepoDep,
) -> AgentSummaryResponse:
    """Register a new agent with atomic configuration versioning."""
    now = datetime.now(timezone.utc)
    agent_id = str(uuid.uuid4())
    initial_version = "v1.0.0"

    # Branch scoping: inherit caller's branch if present
    branch_id: Optional[str] = getattr(tenant_context, "branch_id", None)

    # 1. Create Agent Entity (tenant_id derived exclusively from trusted TenantContext)
    agent_entity = AgentEntity(
        id=agent_id,
        tenant_id=tenant_context.tenant_id,
        name=payload.name,
        runtime=payload.runtime.value,
        model=payload.model,
        status=AgentStatus.ACTIVE.value,
        config_version=initial_version,
        system_prompt=payload.system_prompt,
        branch_id=branch_id,
        created_at=now,
        updated_at=now,
    )

    # 2. Create Initial Version Snapshot preserving registration parameters
    version_entity = AgentVersionEntity(
        id=str(uuid.uuid4()),
        tenant_id=tenant_context.tenant_id,
        agent_id=agent_id,
        version=initial_version,
        config_payload={
            "name": payload.name,
            "runtime": payload.runtime.value,
            "model": payload.model,
            "system_prompt": payload.system_prompt,
            "version": initial_version,
            "registered_by": current_user.id,
        },
        created_at=now,
    )

    # 3. Atomically persist both Agent and initial AgentVersion
    try:
        created_agent = await repo.create_agent_atomic(
            agent=agent_entity,
            version=version_entity,
        )
    except AMSCException:
        raise
    except Exception as exc:
        # Sensitive data filter: NEVER log system_prompt
        logger.error(
            "Failed to register agent due to database error",
            extra={
                "tenant_id": tenant_context.tenant_id,
                "actor_id": current_user.id,
                "error_type": type(exc).__name__,
            },
        )
        raise SecurityDependencyError("Failed to register agent. Transaction rolled back.") from exc

    # Structured audit logging: Record administrative security event without sensitive prompt
    logger.info(
        "Agent registered successfully",
        extra={
            "event_type": "AGENT_REGISTERED",
            "agent_id": created_agent.id,
            "tenant_id": created_agent.tenant_id,
            "actor_id": current_user.id,
            "runtime": created_agent.runtime,
            "model": created_agent.model,
            "config_version": created_agent.config_version,
        },
    )

    return AgentSummaryResponse(
        id=created_agent.id,
        tenant_id=created_agent.tenant_id,
        name=created_agent.name,
        runtime=created_agent.runtime,
        model=created_agent.model,
        status=created_agent.status,
        config_version=created_agent.config_version,
        created_at=created_agent.created_at,
        updated_at=created_agent.updated_at,
    )


@router.get(
    "/{agent_id}",
    response_model=AgentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Agent Details & Tool Permissions",
    description=(
        "Retrieves detailed metadata and read-only tool permissions for a specific agent. "
        "Enforces strict tenant scoping and rejects cross-tenant lookups with 404."
    ),
)
async def get_agent_details(
    agent_id: str,
    tenant_context: TenantContextDep,
    repo: AgentRepositoryProtocol = AgentRepoDep,
) -> AgentDetailResponse:
    """Retrieve details and tool permissions for a specific agent."""
    # Sanitize and validate agent_id parameter
    if not agent_id or not SAFE_ID_REGEX.match(agent_id.strip()):
        raise NotFoundError("Agent not found.")

    clean_agent_id = agent_id.strip()

    try:
        agent = await repo.get_agent_by_id(
            agent_id=clean_agent_id,
            tenant_id=tenant_context.tenant_id,
        )
    except Exception as exc:
        logger.error(
            "Database error retrieving agent detail",
            extra={"agent_id": clean_agent_id, "tenant_id": tenant_context.tenant_id},
        )
        raise SecurityDependencyError("Agent registry persistence service unavailable.") from exc

    # Defense-in-depth: if agent does not exist or belongs to another tenant, return 404
    # Never return 403 or disclose existence of cross-tenant resource
    if agent is None:
        raise NotFoundError("Agent not found.")

    # Branch authorization check: if user is branch-scoped, reject cross-branch agent
    user_branch: Optional[str] = getattr(tenant_context, "branch_id", None)
    if user_branch and agent.branch_id and agent.branch_id != user_branch:
        raise NotFoundError("Agent not found.")

    # Retrieve read-only tool permissions (managed by M2)
    tool_permissions: List[Dict[str, Any]] = []
    try:
        tool_permissions = await repo.get_agent_tool_permissions(
            agent_id=clean_agent_id,
            tenant_id=tenant_context.tenant_id,
        )
    except Exception:
        # Graceful degradation for tool permissions contract
        logger.warning(
            "Could not fetch tool permissions; falling back to empty list",
            extra={"agent_id": clean_agent_id},
        )

    return AgentDetailResponse(
        id=agent.id,
        tenant_id=agent.tenant_id,
        name=agent.name,
        runtime=agent.runtime,
        model=agent.model,
        status=agent.status,
        config_version=agent.config_version,
        tool_permissions=tool_permissions,
        created_at=agent.created_at,
        updated_at=agent.updated_at,
    )
