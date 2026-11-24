"""Repository layer for Phase 2 Detection & Action Security results.

Provides both thread-safe development/test persistence (InMemoryDetectionRepository)
and PostgreSQL durable persistence (SqlAlchemyDetectionRepository).
"""

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
import uuid

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core.exceptions import NotFoundError, ValidationError
from backend.app.database.models.detection import (
    DETECTION_STATUSES,
    DetectionResultModel as OrmDetectionResult,
)


@runtime_checkable
class DetectionRepositoryProtocol(Protocol):
    """Protocol defining the repository contract for Security Detections."""

    is_persistent: bool
    is_in_memory: bool

    async def record_detection(
        self,
        detection_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        ...

    async def get_detection(
        self,
        detection_id: str,
        tenant_id: str,
        branch_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        ...

    async def list_detections(
        self,
        tenant_id: str,
        branch_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        classification_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        ...

    async def update_detection_status(
        self,
        detection_id: str,
        tenant_id: str,
        new_status: str,
        reviewer_user_id: str,
        notes: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        ...


class InMemoryDetectionRepository:
    """Thread-safe, non-durable repository for testing and local development."""

    def __init__(self) -> None:
        self.is_persistent: bool = False
        self.is_in_memory: bool = True
        # Key: (tenant_id, detection_id) -> dict
        self._detections: Dict[tuple[str, str], Dict[str, Any]] = {}

    async def record_detection(
        self,
        detection_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        tenant_id = detection_data["tenant_id"]
        det_id = detection_data.get("id") or f"det-{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        record = deepcopy(detection_data)
        record["id"] = det_id
        record["tenant_id"] = tenant_id
        record.setdefault("status", "DETECTED")
        record.setdefault("created_at", now)
        record.setdefault("updated_at", now)
        record.setdefault("memory_refs", [])
        record.setdefault("baseline_refs", [])
        record.setdefault("evidence_items", [])
        record.setdefault("details", {})
        record.setdefault("audit_history", [])
        record.setdefault("confidence_score", 1.0)

        # Normalize datetime objects to ISO strings if needed
        if isinstance(record.get("created_at"), datetime):
            record["created_at_dt"] = record["created_at"]
        else:
            record["created_at_dt"] = now

        self._detections[(tenant_id, det_id)] = record
        return deepcopy(record)

    async def get_detection(
        self,
        detection_id: str,
        tenant_id: str,
        branch_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        record = self._detections.get((tenant_id, detection_id))
        if record is None:
            return None

        # Branch isolation check: if branch_id is set, records scoped to other branches are inaccessible
        if branch_id is not None and record.get("branch_id") is not None:
            if record["branch_id"] != branch_id:
                return None

        return deepcopy(record)

    async def list_detections(
        self,
        tenant_id: str,
        branch_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        classification_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        for (t_id, _), rec in self._detections.items():
            if t_id != tenant_id:
                continue

            # Branch filtering
            if branch_id is not None and rec.get("branch_id") is not None:
                if rec["branch_id"] != branch_id:
                    continue

            if category is not None and rec.get("detection_category") != category:
                continue

            if severity is not None and rec.get("severity") != severity:
                continue

            if status is not None and rec.get("status") != status:
                continue

            if classification_type is not None and rec.get("classification_type") != classification_type:
                continue

            if agent_id is not None and rec.get("agent_id") != agent_id:
                continue

            if trace_id is not None and rec.get("trace_id") != trace_id:
                continue

            results.append(rec)

        # Sort descending by created_at_dt
        results.sort(
            key=lambda x: x.get("created_at_dt") or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        safe_limit = max(1, min(limit, 200))
        safe_offset = max(0, offset)
        sliced = results[safe_offset : safe_offset + safe_limit]
        return [deepcopy(r) for r in sliced]

    async def update_detection_status(
        self,
        detection_id: str,
        tenant_id: str,
        new_status: str,
        reviewer_user_id: str,
        notes: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if new_status not in DETECTION_STATUSES:
            raise ValidationError(f"Invalid detection status: '{new_status}'")

        key = (tenant_id, detection_id)
        record = self._detections.get(key)
        if record is None:
            raise NotFoundError(f"Detection {detection_id} not found in tenant {tenant_id}")

        now = datetime.now(timezone.utc)
        record["status"] = new_status
        record["updated_at"] = now
        record.setdefault("audit_history", [])
        record["audit_history"].append({
            "status": new_status,
            "reviewer_user_id": reviewer_user_id,
            "reviewed_at": now.isoformat(),
            "notes": notes or "",
        })
        return deepcopy(record)


class SqlAlchemyDetectionRepository:
    """PostgreSQL-backed durable repository with atomic transactions and branch scoping."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory
        self.is_persistent: bool = True
        self.is_in_memory: bool = False

    def _to_dict(self, model: OrmDetectionResult) -> Dict[str, Any]:
        return {
            "id": model.id,
            "tenant_id": model.tenant_id,
            "branch_id": model.branch_id,
            "detection_category": model.detection_category,
            "classification_type": model.classification_type,
            "agent_id": model.agent_id,
            "profile_version": model.profile_version,
            "execution_id": model.execution_id,
            "task_id": model.task_id,
            "trace_id": model.trace_id,
            "action_id": model.action_id,
            "detection_method": model.detection_method,
            "confidence_score": model.confidence_score,
            "uncertainty_state": model.uncertainty_state,
            "severity": model.severity,
            "recommended_outcome": model.recommended_outcome,
            "policy_decision_id": model.policy_decision_id,
            "status": model.status,
            "title": model.title,
            "description": model.description,
            "memory_refs": model.memory_refs_json or [],
            "baseline_refs": model.baseline_refs_json or [],
            "evidence_items": model.evidence_items_json or [],
            "details": model.details_json or {},
            "audit_history": (model.details_json or {}).get("audit_history", []),
            "created_at": model.created_at.isoformat() if model.created_at else None,
            "updated_at": model.updated_at.isoformat() if model.updated_at else None,
        }

    async def record_detection(
        self,
        detection_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        tenant_id = detection_data["tenant_id"]
        det_id = detection_data.get("id") or f"det-{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        raw_created = detection_data.get("created_at")
        if isinstance(raw_created, datetime):
            created_at = raw_created
        elif isinstance(raw_created, str):
            created_at = datetime.fromisoformat(raw_created)
        else:
            created_at = now

        orm_item = OrmDetectionResult(
            id=det_id,
            tenant_id=tenant_id,
            branch_id=detection_data.get("branch_id"),
            detection_category=detection_data["detection_category"],
            classification_type=detection_data["classification_type"],
            agent_id=detection_data.get("agent_id"),
            profile_version=detection_data.get("profile_version"),
            execution_id=detection_data.get("execution_id"),
            task_id=detection_data.get("task_id"),
            trace_id=detection_data.get("trace_id"),
            action_id=detection_data.get("action_id"),
            detection_method=detection_data["detection_method"],
            confidence_score=float(detection_data.get("confidence_score", 1.0)),
            uncertainty_state=detection_data["uncertainty_state"],
            severity=detection_data["severity"],
            recommended_outcome=detection_data["recommended_outcome"],
            policy_decision_id=detection_data.get("policy_decision_id"),
            status=detection_data.get("status", "DETECTED"),
            title=detection_data["title"],
            description=detection_data["description"],
            memory_refs_json=detection_data.get("memory_refs") or [],
            baseline_refs_json=detection_data.get("baseline_refs") or [],
            evidence_items_json=detection_data.get("evidence_items") or [],
            details_json=detection_data.get("details") or {},
            created_at=created_at,
            updated_at=now,
        )

        async with self.session_factory() as session:
            async with session.begin():
                session.add(orm_item)
            return self._to_dict(orm_item)

    async def get_detection(
        self,
        detection_id: str,
        tenant_id: str,
        branch_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        async with self.session_factory() as session:
            stmt = select(OrmDetectionResult).where(
                OrmDetectionResult.tenant_id == tenant_id,
                OrmDetectionResult.id == detection_id,
            )
            model = (await session.execute(stmt)).scalar_one_or_none()
            if model is None:
                return None

            if branch_id is not None and model.branch_id is not None:
                if model.branch_id != branch_id:
                    return None

            return self._to_dict(model)

    async def list_detections(
        self,
        tenant_id: str,
        branch_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        classification_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        async with self.session_factory() as session:
            stmt = select(OrmDetectionResult).where(OrmDetectionResult.tenant_id == tenant_id)

            if branch_id is not None:
                stmt = stmt.where(
                    (OrmDetectionResult.branch_id == branch_id)
                    | (OrmDetectionResult.branch_id.is_(None))
                )

            if category is not None:
                stmt = stmt.where(OrmDetectionResult.detection_category == category)

            if severity is not None:
                stmt = stmt.where(OrmDetectionResult.severity == severity)

            if status is not None:
                stmt = stmt.where(OrmDetectionResult.status == status)

            if classification_type is not None:
                stmt = stmt.where(OrmDetectionResult.classification_type == classification_type)

            if agent_id is not None:
                stmt = stmt.where(OrmDetectionResult.agent_id == agent_id)

            if trace_id is not None:
                stmt = stmt.where(OrmDetectionResult.trace_id == trace_id)

            safe_limit = max(1, min(limit, 200))
            safe_offset = max(0, offset)
            stmt = (
                stmt.order_by(desc(OrmDetectionResult.created_at), desc(OrmDetectionResult.id))
                .limit(safe_limit)
                .offset(safe_offset)
            )

            models = (await session.execute(stmt)).scalars().all()
            return [self._to_dict(m) for m in models]

    async def update_detection_status(
        self,
        detection_id: str,
        tenant_id: str,
        new_status: str,
        reviewer_user_id: str,
        notes: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if new_status not in DETECTION_STATUSES:
            raise ValidationError(f"Invalid detection status: '{new_status}'")

        now = datetime.now(timezone.utc)
        async with self.session_factory() as session:
            async with session.begin():
                stmt = select(OrmDetectionResult).where(
                    OrmDetectionResult.tenant_id == tenant_id,
                    OrmDetectionResult.id == detection_id,
                )
                model = (await session.execute(stmt)).scalar_one_or_none()
                if model is None:
                    raise NotFoundError(f"Detection {detection_id} not found in tenant {tenant_id}")

                model.status = new_status
                model.updated_at = now

                details = dict(model.details_json or {})
                audit_history = list(details.get("audit_history") or [])
                audit_history.append({
                    "status": new_status,
                    "reviewer_user_id": reviewer_user_id,
                    "reviewed_at": now.isoformat(),
                    "notes": notes or "",
                })
                details["audit_history"] = audit_history
                model.details_json = details

            return self._to_dict(model)


_default_repo: Optional[InMemoryDetectionRepository] = None


def get_default_detection_repository() -> InMemoryDetectionRepository:
    global _default_repo
    if _default_repo is None:
        _default_repo = InMemoryDetectionRepository()
    return _default_repo
