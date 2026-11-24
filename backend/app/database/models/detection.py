"""Detection Result Models (Phase 2 Detection & Action Security).

Tables:
- detection_results: durable, auditable record of security detections, classification,
  evidence items, and recommended outcomes.
"""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import (
    ID_LENGTH,
    NOW,
    Base,
    created_at_column,
    jsonb_array_column,
    jsonb_object_column,
    tenant_id_column,
    tenant_parent_key,
)

DETECTION_CATEGORIES = (
    "MEMORY_INTEGRITY",
    "PROMPT_INJECTION",
    "PROVENANCE_INTEGRITY",
    "KNOWLEDGE_INTEGRITY",
    "SEMANTIC_INTEGRITY",
    "BEHAVIORAL_DEVIATION",
    "TOOL_EXECUTION_THREAT",
)

CLASSIFICATION_TYPES = (
    "OBSERVATION",
    "SUSPICIOUS_INDICATOR",
    "CONFIRMED_POLICY_VIOLATION",
    "CONFIRMED_SECURITY_INCIDENT",
)

DETECTION_METHODS = (
    "DETERMINISTIC_RULE",
    "CRYPTOGRAPHIC_HASH",
    "POLICY_VERIFICATION",
    "HEURISTIC_PATTERN",
    "STATISTICAL_FREQUENCY",
    "SEMANTIC_GROUNDING",
)

UNCERTAINTY_STATES = (
    "DEFINITIVE",
    "HIGH_CONFIDENCE",
    "PROBABILISTIC_INDICATOR",
    "INDETERMINATE",
)

SEVERITY_LEVELS = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",
)

RECOMMENDED_OUTCOMES = (
    "ALLOW",
    "BLOCK",
    "REQUIRE_HUMAN_APPROVAL",
    "QUARANTINE_RECORD",
    "ALERT_ONLY",
)

DETECTION_STATUSES = (
    "DETECTED",
    "EVALUATED",
    "CONFIRMED_VIOLATION",
    "CONFIRMED_INCIDENT",
    "DISMISSED_FALSE_POSITIVE",
    "RESOLVED",
)


class DetectionResultModel(Base):
    """Authoritative detection outcome with evidence references and uncertainty states."""

    __tablename__ = "detection_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = tenant_id_column(ondelete="RESTRICT")
    branch_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    detection_category: Mapped[str] = mapped_column(String(64), nullable=False)
    classification_type: Mapped[str] = mapped_column(String(32), nullable=False)
    agent_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    profile_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    execution_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    task_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    trace_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    action_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    detection_method: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("1.0"))
    uncertainty_state: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    recommended_outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_decision_id: Mapped[Optional[str]] = mapped_column(String(ID_LENGTH), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'DETECTED'"))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    memory_refs_json: Mapped[list[Any]] = jsonb_array_column()
    baseline_refs_json: Mapped[list[Any]] = jsonb_array_column()
    evidence_items_json: Mapped[list[Any]] = jsonb_array_column()
    details_json: Mapped[dict[str, Any]] = jsonb_object_column()
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=NOW
    )

    __table_args__ = (
        tenant_parent_key(),
        ForeignKeyConstraint(
            ["tenant_id", "branch_id"],
            ["branches.tenant_id", "branches.id"],
            name="fk_detection_results_branch_tenant",
            ondelete="RESTRICT",
        ),
        Index("idx_det_tenant_created", "tenant_id", "created_at"),
        Index("idx_det_tenant_category", "tenant_id", "detection_category"),
        Index("idx_det_tenant_agent", "tenant_id", "agent_id"),
        Index("idx_det_tenant_trace", "tenant_id", "trace_id"),
        Index("idx_det_tenant_status", "tenant_id", "status"),
        Index("idx_det_tenant_classification", "tenant_id", "classification_type"),
        CheckConstraint(
            "detection_category IN ("
            + ", ".join(f"'{c}'" for c in DETECTION_CATEGORIES)
            + ")",
            name="ck_detection_category",
        ),
        CheckConstraint(
            "classification_type IN ("
            + ", ".join(f"'{c}'" for c in CLASSIFICATION_TYPES)
            + ")",
            name="ck_detection_classification_type",
        ),
        CheckConstraint(
            "severity IN ("
            + ", ".join(f"'{s}'" for s in SEVERITY_LEVELS)
            + ")",
            name="ck_detection_severity",
        ),
        CheckConstraint(
            "recommended_outcome IN ("
            + ", ".join(f"'{r}'" for r in RECOMMENDED_OUTCOMES)
            + ")",
            name="ck_detection_recommended_outcome",
        ),
        CheckConstraint(
            "status IN ("
            + ", ".join(f"'{s}'" for s in DETECTION_STATUSES)
            + ")",
            name="ck_detection_status",
        ),
    )
