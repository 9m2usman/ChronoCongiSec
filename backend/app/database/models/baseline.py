"""Enterprise Baseline, Agent Profiles, Trust Decisions & Observation (Phase 1).

Tables:
- trust_decisions: durable storage for memory trust evaluations (replaces in-memory store)
- enterprise_baseline_records: independently governed authoritative enterprise knowledge & policies
- enterprise_baseline_versions: immutable, versioned baseline content snapshots with SHA-256 digests
- baseline_governance_logs: auditable governance operations (create, review, approve, activate, supersede, revoke, archive)
- agent_security_profiles: authoritative agent security profiles with purpose, goals, branch, data scope, and restrictions
- observation_events: structured observation & telemetry foundation with idempotent deduplication
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
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

BASELINE_LIFECYCLE_STATUSES = (
    "DRAFT",
    "IN_REVIEW",
    "APPROVED",
    "ACTIVE",
    "SUPERSEDED",
    "REVOKED",
    "ARCHIVED",
)

BASELINE_OPERATIONS = (
    "CREATE",
    "REVIEW",
    "APPROVE",
    "ACTIVATE",
    "SUPERSEDE",
    "REVOKE",
    "ARCHIVE",
    "APPEND_VERSION",
)

OBSERVATION_CATEGORIES = (
    "AGENT_REGISTRATION_AND_PROFILE",
    "AGENT_EXECUTION_LIFECYCLE",
    "TASK_AND_CONTEXT_TRANSITION",
    "MEMORY_READ_AND_RETRIEVAL",
    "MEMORY_WRITE_AND_TRANSFORMATION",
    "TOOL_ACTION_PROPOSAL",
    "POLICY_DECISION",
    "TOOL_EXECUTION_RECEIPT",
    "EXTERNAL_ACTION_OUTCOME",
    "BASELINE_GOVERNANCE_CHANGE",
)


class TrustDecisionModel(Base):
    """Durable PostgreSQL storage for memory trust decisions (VULN-001 / OPEN-02)."""

    __tablename__ = "trust_decisions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    record_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_json: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        Index("idx_trust_decisions_tenant_record", "tenant_id", "record_id"),
        Index("idx_trust_decisions_tenant_created", "tenant_id", "created_at"),
        *tenant_fk("trust_decisions", "record_id", "memory_records", "CASCADE"),
    )


class EnterpriseBaselineRecord(Base):
    """Authoritative enterprise knowledge & security policy baseline.

    Independently governed by human administrators; immutable to agent memory influence.
    Separated from ordinary agent memory records (Phase 1 §2.C).
    """

    __tablename__ = "enterprise_baseline_records"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    branch_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'POLICY'")
    )  # POLICY, PROCEDURE, APPROVED_KNOWLEDGE, SECURITY_DIRECTIVE
    source_uri: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    source_type: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'EXECUTIVE_DIRECTIVE'")
    )
    provenance: Mapped[str] = mapped_column(Text, nullable=False)
    classification: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'ENTERPRISE_CONFIDENTIAL'")
    )
    access_scope: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'ALL_BRANCHES'")
    )
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    lifecycle_status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'DRAFT'")
    )
    superseded_by_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    effective_from: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    reviewed_by_user_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    approved_by_user_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        tenant_parent_key(),
        ForeignKeyConstraint(
            ["tenant_id", "branch_id"],
            ["branches.tenant_id", "branches.id"],
            name="fk_baseline_records_branch_tenant",
            ondelete="RESTRICT",
        ),
        Index("idx_baseline_tenant_status", "tenant_id", "lifecycle_status"),
        Index("idx_baseline_tenant_branch", "tenant_id", "branch_id"),
        CheckConstraint(
            "lifecycle_status IN ("
            + ", ".join(f"'{s}'" for s in BASELINE_LIFECYCLE_STATUSES)
            + ")",
            name="ck_baseline_lifecycle_status",
        ),
    )


class EnterpriseBaselineVersion(Base):
    """Immutable versioned content snapshot of an enterprise baseline record."""

    __tablename__ = "enterprise_baseline_versions"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    baseline_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    created_at: Mapped[datetime] = created_at_column()

    __table_args__ = (
        UniqueConstraint("baseline_id", "version", name="uq_baseline_version"),
        ForeignKeyConstraint(
            ["tenant_id", "baseline_id"],
            ["enterprise_baseline_records.tenant_id", "enterprise_baseline_records.id"],
            name="fk_baseline_versions_record_tenant",
            ondelete="CASCADE",
        ),
        Index("idx_baseline_versions_hash", "content_sha256"),
    )


class BaselineGovernanceLog(Base):
    """Auditable lifecycle transitions and operations on enterprise baseline records."""

    __tablename__ = "baseline_governance_logs"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    baseline_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "baseline_id"],
            ["enterprise_baseline_records.tenant_id", "enterprise_baseline_records.id"],
            name="fk_baseline_governance_record_tenant",
            ondelete="CASCADE",
        ),
        Index("idx_baseline_gov_occurred", "tenant_id", "baseline_id", "occurred_at"),
    )


class AgentSecurityProfile(Base):
    """Authoritative security profile for registered AI agents.

    Governed independently by administrators. Agents cannot grant themselves permissions
    or rewrite approved goals/restrictions (Phase 1 §2.B).
    """

    __tablename__ = "agent_security_profiles"

    id: Mapped[str] = id_column()
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    agent_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False, unique=True)
    owner_department: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_purpose: Mapped[str] = mapped_column(Text, nullable=False)
    approved_goals_json: Mapped[list[Any]] = jsonb_array_column("approved_goals")
    branch_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    data_scope_json: Mapped[list[Any]] = jsonb_array_column("data_scope")
    operational_restrictions_json: Mapped[dict[str, Any]] = jsonb_object_column(
        "operational_restrictions"
    )
    approval_requirements_json: Mapped[dict[str, Any]] = jsonb_object_column(
        "approval_requirements"
    )
    profile_version: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'v1.0.0'")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'ACTIVE'"))
    governed_by_user_id: Mapped[str] = mapped_column(String(ID_LENGTH), nullable=False)
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        tenant_parent_key(),
        ForeignKeyConstraint(
            ["tenant_id", "agent_id"],
            ["agents.tenant_id", "agents.id"],
            name="fk_agent_profiles_agent_tenant",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "branch_id"],
            ["branches.tenant_id", "branches.id"],
            name="fk_agent_profiles_branch_tenant",
            ondelete="RESTRICT",
        ),
        Index("idx_agent_profiles_tenant_agent", "tenant_id", "agent_id"),
        Index("idx_agent_profiles_branch", "tenant_id", "branch_id"),
    )


class ObservationEvent(Base):
    """Structured, durable observation event supporting cross-system correlation.

    Captures the 10 Phase 1 observation categories with idempotency deduplication
    and strict parameter sanitization (Phase 1 §3 & §4).
    """

    __tablename__ = "observation_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    branch_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_category: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_runtime: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    execution_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    trace_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    parent_span_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source_component: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("'GATEWAY'")
    )
    related_memory_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    related_memory_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    tool_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    action_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    policy_decision_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    execution_receipt_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    baseline_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    payload_json: Mapped[dict[str, Any]] = jsonb_object_column()
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        Index("idx_obs_tenant_occurred", "tenant_id", "occurred_at"),
        Index("idx_obs_tenant_trace", "tenant_id", "trace_id"),
        Index("idx_obs_tenant_agent", "tenant_id", "agent_id"),
        Index("idx_obs_tenant_category", "tenant_id", "event_category"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_obs_tenant_idemp"),
    )
