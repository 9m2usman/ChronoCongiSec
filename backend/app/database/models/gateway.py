"""Tool Proposals, Gateway Decisions & Executions (AMSC-DOC-005 Section 3.4).

Tables: tool_proposals, policy_decisions, approvals, tool_executions.

Decision/status values are stored as plain strings exactly as in DOC-005; this
layer does not interpret them (decision semantics belong to M4). Their allowed
values are deliberately NOT constrained yet: see OPEN-DEPENDENCIES in
docs/database-design/M6-PROGRESS-LOG.md.

Day 4 (migration 0007): the whole proposal -> decision -> approval/execution chain
is ON DELETE RESTRICT, and an execution's decision must belong to its proposal.

Day 6 (migration 0009, TRD section 8 "Append-Only Immutability"): a committed policy
decision is permanent. A trigger rejects any DELETE and any UPDATE of its content; only
``execution_status`` may still change, because the gateway records the execution outcome
there (see OD-25).

Forensic history (migration 0003): every table here uses ``tenant_id ... ON DELETE
RESTRICT``, and ``tool_proposals.agent_id`` is RESTRICT, so deleting a tenant or an
agent can never silently erase proposals, decisions, approvals or executions.
Agents are isolated (status), not deleted.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKeyConstraint, Index, Integer, String, Text, UniqueConstraint, text
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
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
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
        *tenant_fk("tool_proposals", "agent_id", "agents", "RESTRICT"),
    )


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
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
        # Parent key for tool_executions' "decision belongs to the same proposal" FK (0007).
        UniqueConstraint("tenant_id", "proposal_id", "id"),
        # proposal_id is already UNIQUE, which covers FK lookups.
        # RESTRICT (0007): a proposal with a decision cannot be deleted (forensic history).
        *tenant_fk("policy_decisions", "proposal_id", "tool_proposals", "RESTRICT", index=False),
        *tenant_fk("policy_decisions", "incident_id", "incidents", "SET NULL"),
    )


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    decision_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    # NULL = not yet assigned. When set, the approver must hold a membership in the
    # SAME tenant: (tenant_id, approver_user_id) -> memberships (tenant_id, user_id).
    # RESTRICT keeps "who approved" as evidence: revoke the membership via status.
    approver_user_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'PENDING'"))
    comments: Mapped[Optional[str]] = mapped_column(Text)
    responded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        # RESTRICT (0007): a decision with approvals cannot be deleted.
        *tenant_fk("approvals", "decision_id", "policy_decisions", "RESTRICT"),
        ForeignKeyConstraint(
            ["tenant_id", "approver_user_id"],
            ["memberships.tenant_id", "memberships.user_id"],
            name="fk_approvals_approver_user_id_tenant",
            ondelete="RESTRICT",
        ),
        Index("ix_approvals_tenant_id_approver_user_id", "tenant_id", "approver_user_id"),
    )


class ToolExecution(Base):
    __tablename__ = "tool_executions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    proposal_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False, unique=True)
    decision_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'SUCCESS'"))
    status_code: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("200"))
    result_payload_json: Mapped[dict[str, Any]] = jsonb_object_column()
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=NOW)

    __table_args__ = (
        # RESTRICT (0007): executions are evidence; their proposal/decision cannot be deleted.
        *tenant_fk("tool_executions", "proposal_id", "tool_proposals", "RESTRICT", index=False),
        *tenant_fk("tool_executions", "decision_id", "policy_decisions", "RESTRICT"),
        # 0007: the decision must belong to THIS execution's proposal, not only to the same
        # tenant ("no tool execution recorded without its decision", DOC-006 Day 4).
        # Lookups are covered by the UNIQUE index on proposal_id, so no extra index.
        ForeignKeyConstraint(
            ["tenant_id", "proposal_id", "decision_id"],
            ["policy_decisions.tenant_id", "policy_decisions.proposal_id", "policy_decisions.id"],
            name="fk_tool_executions_decision_matches_proposal",
            ondelete="RESTRICT",
        ),
    )
