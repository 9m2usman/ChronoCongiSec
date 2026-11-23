"""SQLAlchemy PostgreSQL repository for Agent Registry and Tool Permissions.

Module: backend.app.database.repositories.agents
Owner: M6 (Database Architect & Governance) + M1 (Platform & API)
Spec: AMSC-DOC-005 Section 3.2, PRD FR-004, FR-005
"""

from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.api.agents import AgentEntity, AgentRepositoryProtocol, AgentVersionEntity
from backend.app.core.exceptions import AMSCException, ValidationError
from backend.app.database.models.agents import (
    Agent as OrmAgent,
    AgentToolPermission as OrmAgentToolPermission,
    AgentVersion as OrmAgentVersion,
    ToolRegistration as OrmToolRegistration,
)


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

        return deepcopy(agent)

    async def get_agent_by_id(
        self,
        agent_id: str,
        tenant_id: str,
    ) -> Optional[AgentEntity]:
        """Fetch agent strictly asserting tenant isolation."""
        async with self.session_factory() as session:
            stmt = select(OrmAgent).where(
                OrmAgent.id == agent_id,
                OrmAgent.tenant_id == tenant_id,
            )
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None:
                return None

            return AgentEntity(
                id=row.id,
                tenant_id=row.tenant_id,
                name=row.name,
                runtime=row.runtime,
                model=row.model,
                status=row.status,
                config_version=row.config_version,
                system_prompt=row.system_prompt,
                branch_id=getattr(row, "branch_id", None),
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
            stmt = select(OrmAgent).where(OrmAgent.tenant_id == tenant_id)
            if status:
                stmt = stmt.where(OrmAgent.status == status)
            if branch_id and hasattr(OrmAgent, "branch_id"):
                stmt = stmt.where(OrmAgent.branch_id == branch_id)

            stmt = stmt.order_by(OrmAgent.created_at.desc()).limit(limit + 1).offset(offset)
            rows = list((await session.execute(stmt)).scalars().all())

            has_more = len(rows) > limit
            page_rows = rows[:limit]

            entities = [
                AgentEntity(
                    id=r.id,
                    tenant_id=r.tenant_id,
                    name=r.name,
                    runtime=r.runtime,
                    model=r.model,
                    status=r.status,
                    config_version=r.config_version,
                    system_prompt=r.system_prompt,
                    branch_id=getattr(r, "branch_id", None),
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                )
                for r in page_rows
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
