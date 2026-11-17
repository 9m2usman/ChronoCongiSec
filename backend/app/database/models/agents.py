"""Agent Registry & Tool Permissions (AMSC-DOC-005 Section 3.2).

Tables: agents, agent_versions, tool_registrations, agent_tool_permissions.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Index, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import (
    ID_LENGTH,
    NOW,
    Base,
    created_at_column,
    id_column,
    jsonb_object_column,
    tenant_fk,
    tenant_id_column,
    tenant_parent_key,
)


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    runtime: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'LANGCHAIN'"))
    model: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'gpt-4o'"))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'ACTIVE'"))
    config_version: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'v1.0.0'"))
    system_prompt: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)

    __table_args__ = (Index("idx_agents_tenant", "tenant_id"), tenant_parent_key())


class AgentVersion(Base):
    __tablename__ = "agent_versions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    config_payload: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("agent_id", "version", name="uq_agent_version"),
        *tenant_fk("agent_versions", "agent_id", "agents", "CASCADE"),
    )


class ToolRegistration(Base):
    __tablename__ = "tool_registrations"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    adapter_type: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'SANDBOX_REST'")
    )
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_protected: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    schema_definition: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_tenant_tool_name"),
        tenant_parent_key(),
    )


class AgentToolPermission(Base):
    __tablename__ = "agent_tool_permissions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    allowed_operations: Mapped[str] = mapped_column(String(255), nullable=False, server_default=text("'*'"))
    constraints_json: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("agent_id", "tool_id", name="uq_agent_tool_perm"),
        *tenant_fk("agent_tool_permissions", "agent_id", "agents", "CASCADE"),
        *tenant_fk("agent_tool_permissions", "tool_id", "tool_registrations", "CASCADE"),
    )
