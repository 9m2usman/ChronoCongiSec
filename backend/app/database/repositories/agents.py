"""SQLAlchemy PostgreSQL repository for Agent Registry and Tool Permissions.

Module: backend.app.database.repositories.agents
Owner: M6 (Database Architect & Governance) + M1 (Platform & API)
Spec: AMSC-DOC-005 Section 3.2, PRD FR-004, FR-005
"""

from copy import deepcopy
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.api.agents import AgentEntity, AgentRepositoryProtocol, AgentVersionEntity
from backend.app.core.exceptions import NotFoundError, ValidationError
from backend.app.database.models.agents import (
    Agent as OrmAgent,
    AgentToolPermission as OrmAgentToolPermission,
    AgentVersion as OrmAgentVersion,
    ToolRegistration as OrmToolRegistration,
)
from backend.app.database.models.baseline import AgentSecurityProfile as OrmAgentSecurityProfile


class SqlAlchemyAgentRepository(AgentRepositoryProtocol):
    """Production database repository for Agent Registry and version snapshots."""

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def create_agent_atomic(
        self,
        agent: AgentEntity,
        version: AgentVersionEntity,
    ) -> AgentEntity:
        """Atomically persist agent and initial configuration version snapshot."""
        async with self.session_factory() as session:
            async with session.begin():
                # Check for existing agent
                stmt = select(OrmAgent).where(OrmAgent.id == agent.id)
                existing = (await session.execute(stmt)).scalar_one_or_none()
                if existing:
                    raise ValidationError(f"Agent with ID '{agent.id}' already exists.")

                orm_agent = OrmAgent(
                    id=agent.id,
                    tenant_id=agent.tenant_id,
                    name=agent.name,
                    runtime=agent.runtime,
                    model=agent.model,
                    status=agent.status,
                    config_version=agent.config_version,
                    system_prompt=agent.system_prompt,
                    created_at=agent.created_at,
                    updated_at=agent.updated_at,
                )
                session.add(orm_agent)

                orm_version = OrmAgentVersion(
                    id=version.id,
                    tenant_id=version.tenant_id,
                    agent_id=version.agent_id,
                    version=version.version,
                    config_payload=version.config_payload,
                    created_at=version.created_at,
                )
                session.add(orm_version)

                # Every registered agent receives an explicit governed security profile
                # in the same transaction as its registry row and initial version.
                registered_by = str(version.config_payload.get("registered_by") or "system")
                profile = OrmAgentSecurityProfile(
                    id=f"prof-{uuid.uuid4().hex[:12]}",
                    tenant_id=agent.tenant_id,
                    agent_id=agent.id,
                    owner_department="Enterprise Operations",
                    approved_purpose=f"Approved business task execution for {agent.name}",
                    approved_goals_json=[
                        "Execute approved business operations within assigned tenant and branch scope"
                    ],
                    branch_id=agent.branch_id,
                    data_scope_json=["general:*"],
                    operational_restrictions_json={
                        "max_parameter_depth": 5,
                        "require_complete_mediation": True,
                    },
                    approval_requirements_json={
                        "threshold_exceeded": "REQUIRE_HUMAN_APPROVAL"
                    },
                    profile_version=agent.config_version,
                    status="ACTIVE",
                    governed_by_user_id=registered_by,
                    created_at=agent.created_at,
                    updated_at=agent.updated_at,
                )
                session.add(profile)

        return deepcopy(agent)

    async def get_agent_by_id(
        self,
        agent_id: str,
        tenant_id: str,
    ) -> Optional[AgentEntity]:
        """Fetch agent strictly asserting tenant isolation."""
        async with self.session_factory() as session:
            stmt = (
                select(OrmAgent, OrmAgentSecurityProfile.branch_id)
                .outerjoin(
                    OrmAgentSecurityProfile,
                    (OrmAgentSecurityProfile.agent_id == OrmAgent.id)
                    & (OrmAgentSecurityProfile.tenant_id == OrmAgent.tenant_id),
                )
                .where(
                    OrmAgent.id == agent_id,
                    OrmAgent.tenant_id == tenant_id,
                )
            )
            result = (await session.execute(stmt)).one_or_none()
            if result is None:
                return None
            row, profile_branch_id = result

            return AgentEntity(
                id=row.id,
                tenant_id=row.tenant_id,
                name=row.name,
                runtime=row.runtime,
                model=row.model,
                status=row.status,
                config_version=row.config_version,
                system_prompt=row.system_prompt,
                branch_id=profile_branch_id,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def list_agents(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AgentEntity], bool]:
        """Query agents strictly scoped to tenant, returning (items, has_more)."""
        async with self.session_factory() as session:
            stmt = (
                select(OrmAgent, OrmAgentSecurityProfile.branch_id)
                .outerjoin(
                    OrmAgentSecurityProfile,
                    (OrmAgentSecurityProfile.agent_id == OrmAgent.id)
                    & (OrmAgentSecurityProfile.tenant_id == OrmAgent.tenant_id),
                )
                .where(OrmAgent.tenant_id == tenant_id)
            )
            if status:
                stmt = stmt.where(OrmAgent.status == status)
            if branch_id:
                # The governed profile is the single source of truth for branch scope.
                stmt = stmt.where(OrmAgentSecurityProfile.branch_id == branch_id)

            stmt = stmt.order_by(OrmAgent.created_at.desc()).limit(limit + 1).offset(offset)
            rows = list((await session.execute(stmt)).all())

            has_more = len(rows) > limit
            page_rows = rows[:limit]

            entities = [
                AgentEntity(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    name=row.name,
                    runtime=row.runtime,
                    model=row.model,
                    status=row.status,
                    config_version=row.config_version,
                    system_prompt=row.system_prompt,
                    branch_id=profile_branch_id,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
                for row, profile_branch_id in page_rows
            ]
            return entities, has_more

    async def get_agent_version(
        self,
        agent_id: str,
        version: str,
        tenant_id: str,
    ) -> Optional[AgentVersionEntity]:
        """Retrieve historical configuration snapshot."""
        async with self.session_factory() as session:
            stmt = select(OrmAgentVersion).where(
                OrmAgentVersion.agent_id == agent_id,
                OrmAgentVersion.version == version,
                OrmAgentVersion.tenant_id == tenant_id,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None

            return AgentVersionEntity(
                id=row.id,
                tenant_id=row.tenant_id,
                agent_id=row.agent_id,
                version=row.version,
                config_payload=row.config_payload,
                created_at=row.created_at,
            )

    async def get_agent_tool_permissions(
        self,
        agent_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Retrieve tool permissions for agent joined with tool registrations."""
        async with self.session_factory() as session:
            stmt = (
                select(OrmAgentToolPermission, OrmToolRegistration)
                .join(
                    OrmToolRegistration,
                    (OrmToolRegistration.id == OrmAgentToolPermission.tool_id)
                    & (OrmToolRegistration.tenant_id == OrmAgentToolPermission.tenant_id),
                )
                .where(
                    OrmAgentToolPermission.agent_id == agent_id,
                    OrmAgentToolPermission.tenant_id == tenant_id,
                )
            )
            results = (await session.execute(stmt)).all()

            permissions = []
            for perm, tool in results:
                allowed_ops = perm.allowed_operations
                if isinstance(allowed_ops, str):
                    ops = [o.strip() for o in allowed_ops.split(",") if o.strip()]
                elif isinstance(allowed_ops, (list, tuple)):
                    ops = list(allowed_ops)
                else:
                    ops = []
                permissions.append({
                    "tool_id": perm.tool_id,
                    "tool_name": tool.name,
                    "adapter_type": tool.adapter_type,
                    "allowed_operations": ops,
                    "constraints": perm.constraints_json or {},
                    "is_protected": tool.is_protected,
                })
            return permissions

    async def grant_tool_permission(
        self,
        tenant_id: str,
        agent_id: str,
        tool_id: str,
        allowed_operations: str = "*",
        constraints: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Grant or update tool permission for an agent."""
        async with self.session_factory() as session:
            async with session.begin():
                # Verify agent exists
                stmt_agent = select(OrmAgent).where(
                    OrmAgent.id == agent_id,
                    OrmAgent.tenant_id == tenant_id,
                )
                agent = (await session.execute(stmt_agent)).scalar_one_or_none()
                if not agent:
                    raise NotFoundError(f"Agent '{agent_id}' not found.")

                # Verify tool exists
                stmt_tool = select(OrmToolRegistration).where(
                    OrmToolRegistration.id == tool_id,
                    OrmToolRegistration.tenant_id == tenant_id,
                )
                tool = (await session.execute(stmt_tool)).scalar_one_or_none()
                if not tool:
                    # Also try looking up tool by name
                    stmt_tool_name = select(OrmToolRegistration).where(
                        OrmToolRegistration.name == tool_id,
                        OrmToolRegistration.tenant_id == tenant_id,
                    )
                    tool = (await session.execute(stmt_tool_name)).scalar_one_or_none()
                    if not tool:
                        raise NotFoundError(f"Tool registration '{tool_id}' not found.")
                    tool_id = tool.id

                # Upsert permission
                stmt_perm = select(OrmAgentToolPermission).where(
                    OrmAgentToolPermission.agent_id == agent_id,
                    OrmAgentToolPermission.tool_id == tool_id,
                    OrmAgentToolPermission.tenant_id == tenant_id,
                )
                perm = (await session.execute(stmt_perm)).scalar_one_or_none()
                if perm is None:
                    perm = OrmAgentToolPermission(
                        id=f"perm-{uuid.uuid4().hex[:12]}",
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        tool_id=tool_id,
                        allowed_operations=allowed_operations,
                        constraints_json=constraints or {},
                    )
                    session.add(perm)
                else:
                    perm.allowed_operations = allowed_operations
                    perm.constraints_json = constraints or {}

                return {
                    "tool_id": tool.id,
                    "tool_name": tool.name,
                    "adapter_type": tool.adapter_type,
                    "allowed_operations": allowed_operations.split(",") if isinstance(allowed_operations, str) else list(allowed_operations),
                    "constraints": constraints or {},
                    "is_protected": tool.is_protected,
                }

    async def revoke_tool_permission(
        self,
        tenant_id: str,
        agent_id: str,
        tool_id: str,
    ) -> bool:
        """Revoke tool permission from an agent by tool ID or tool name."""
        async with self.session_factory() as session:
            async with session.begin():
                target_tool_ids = [tool_id]
                stmt_tool = select(OrmToolRegistration.id).where(
                    OrmToolRegistration.name == tool_id,
                    OrmToolRegistration.tenant_id == tenant_id,
                )
                resolved_id = (await session.execute(stmt_tool)).scalar_one_or_none()
                if resolved_id:
                    target_tool_ids.append(resolved_id)

                stmt = delete(OrmAgentToolPermission).where(
                    OrmAgentToolPermission.tenant_id == tenant_id,
                    OrmAgentToolPermission.agent_id == agent_id,
                    OrmAgentToolPermission.tool_id.in_(target_tool_ids),
                )
                result = await session.execute(stmt)
                return result.rowcount > 0

    async def get_agent_profile(
        self,
        agent_id: str,
        tenant_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch authoritative agent security profile."""
        async with self.session_factory() as session:
            stmt = select(OrmAgentSecurityProfile).where(
                OrmAgentSecurityProfile.tenant_id == tenant_id,
                OrmAgentSecurityProfile.agent_id == agent_id,
            )
            profile = (await session.execute(stmt)).scalar_one_or_none()
            if profile is not None:
                return {
                    "id": profile.id,
                    "tenant_id": profile.tenant_id,
                    "agent_id": profile.agent_id,
                    "owner_department": profile.owner_department,
                    "approved_purpose": profile.approved_purpose,
                    "approved_goals": profile.approved_goals_json or [],
                    "branch_id": profile.branch_id,
                    "data_scope": profile.data_scope_json or [],
                    "operational_restrictions": profile.operational_restrictions_json or {},
                    "approval_requirements": profile.approval_requirements_json or {},
                    "profile_version": profile.profile_version,
                    "status": profile.status,
                    "governed_by_user_id": profile.governed_by_user_id,
                    "created_at": profile.created_at.isoformat() if profile.created_at else None,
                    "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
                }

            # Missing governed profiles are a security failure, not a reason to
            # synthesize permissions from agent metadata.
            return None

    async def update_agent_profile(
        self,
        agent_id: str,
        tenant_id: str,
        profile_data: Dict[str, Any],
        user_id: str,
    ) -> Dict[str, Any]:
        """Update or create authoritative agent security profile under independent governance."""
        async with self.session_factory() as session:
            async with session.begin():
                agent = await self.get_agent_by_id(agent_id, tenant_id)
                if agent is None:
                    raise NotFoundError(f"Agent '{agent_id}' not found.")

                stmt = select(OrmAgentSecurityProfile).where(
                    OrmAgentSecurityProfile.tenant_id == tenant_id,
                    OrmAgentSecurityProfile.agent_id == agent_id,
                )
                profile = (await session.execute(stmt)).scalar_one_or_none()
                now = datetime.now(timezone.utc)
                if profile is None:
                    profile = OrmAgentSecurityProfile(
                        id=f"prof-{uuid.uuid4().hex[:12]}",
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        owner_department=profile_data.get("owner_department", "Enterprise Operations"),
                        approved_purpose=profile_data.get("approved_purpose", ""),
                        approved_goals_json=profile_data.get("approved_goals", []),
                        branch_id=profile_data.get("branch_id", agent.branch_id),
                        data_scope_json=profile_data.get("data_scope", []),
                        operational_restrictions_json=profile_data.get("operational_restrictions", {}),
                        approval_requirements_json=profile_data.get("approval_requirements", {}),
                        profile_version=profile_data.get("profile_version", "v1.0.0"),
                        status=profile_data.get("status", "ACTIVE"),
                        governed_by_user_id=user_id,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(profile)
                else:
                    profile.owner_department = profile_data.get("owner_department", profile.owner_department)
                    profile.approved_purpose = profile_data.get("approved_purpose", profile.approved_purpose)
                    profile.approved_goals_json = profile_data.get("approved_goals", profile.approved_goals_json)
                    profile.branch_id = profile_data.get("branch_id", profile.branch_id)
                    profile.data_scope_json = profile_data.get("data_scope", profile.data_scope_json)
                    profile.operational_restrictions_json = profile_data.get("operational_restrictions", profile.operational_restrictions_json)
                    profile.approval_requirements_json = profile_data.get("approval_requirements", profile.approval_requirements_json)
                    profile.profile_version = profile_data.get("profile_version", profile.profile_version)
                    profile.status = profile_data.get("status", profile.status)
                    profile.governed_by_user_id = user_id
                    profile.updated_at = now

                return {
                    "id": profile.id,
                    "tenant_id": profile.tenant_id,
                    "agent_id": profile.agent_id,
                    "owner_department": profile.owner_department,
                    "approved_purpose": profile.approved_purpose,
                    "approved_goals": profile.approved_goals_json,
                    "branch_id": profile.branch_id,
                    "data_scope": profile.data_scope_json,
                    "operational_restrictions": profile.operational_restrictions_json,
                    "approval_requirements": profile.approval_requirements_json,
                    "profile_version": profile.profile_version,
                    "status": profile.status,
                    "governed_by_user_id": profile.governed_by_user_id,
                    "created_at": profile.created_at.isoformat() if profile.created_at else None,
                    "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
                }

