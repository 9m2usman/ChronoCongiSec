"""Tool Proposals, Gateway Decisions & Executions (AMSC-DOC-005 Section 3.4).

Tables: tool_proposals, policy_decisions, approvals, tool_executions.

Decision/status values are stored as plain strings exactly as in DOC-005; this
layer does not interpret them (decision semantics belong to M4).
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import (
    ID_LENGTH,
    NOW,
    Base,
    created_at_column,
    id_column,
    jsonb_array_column,
    jsonb_object_column,
    tenant_fk,
    tenant_id_column,
    tenant_parent_key,
)


class ToolProposal(Base):
    __tablename__ = "tool_proposals"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    agent_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    action_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    operation: Mapped[str] = mapped_column(String(128), nullable=False)
    parameters_json: Mapped[dict[str, Any]] = jsonb_object_column()
    memory_refs_json: Mapped[list[Any]] = jsonb_array_column()
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_tenant_idemp_key"),
        Index("idx_tool_proposals_trace", "tenant_id", "trace_id"),
        tenant_parent_key(),
        *tenant_fk("tool_proposals", "agent_id", "agents", "CASCADE"),
    )


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    proposal_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False, unique=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    memory_trust: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_result: Mapped[str] = mapped_column(String(32), nullable=False)
    reasons_json: Mapped[list[Any]] = jsonb_array_column()
    # DOC-005 leaves incident_id unconstrained; M6 adds a tenant-consistent FK so a
    # decision can never cite another tenant's incident.
    incident_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    execution_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'NOT_EXECUTED'")
    )
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        tenant_parent_key(),
        # proposal_id is already UNIQUE, which covers FK lookups.
        *tenant_fk("policy_decisions", "proposal_id", "tool_proposals", "CASCADE", index=False),
        *tenant_fk("policy_decisions", "incident_id", "incidents", "SET NULL"),
    )


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    decision_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    # users is a global table, so this stays a plain FK (see open questions in the M6 log).
    approver_user_id: Mapped[Optional[str]] = mapped_column(
        String(ID_LENGTH), ForeignKey("users.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'PENDING'"))
    comments: Mapped[Optional[str]] = mapped_column(Text)
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    __table_args__ = (*tenant_fk("approvals", "decision_id", "policy_decisions", "CASCADE"),)


class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column()
    proposal_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False, unique=True)
    decision_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'SUCCESS'"))
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("200"))
    result_payload_json: Mapped[dict[str, Any]] = jsonb_object_column()
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)

    __table_args__ = (
        *tenant_fk("tool_executions", "proposal_id", "tool_proposals", "CASCADE", index=False),
        *tenant_fk("tool_executions", "decision_id", "policy_decisions", "CASCADE"),
    )
