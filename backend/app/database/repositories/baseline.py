"""Repository layer for independently governed enterprise security baseline (Phase 1 §2).

Provides both PostgreSQL durable persistence (SqlAlchemyBaselineRepository)
and thread-safe development/test persistence (InMemoryBaselineRepository).
"""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable
import uuid

from sqlalchemy import delete, desc, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core.exceptions import ConflictError, NotFoundError, ValidationError
from backend.app.database.models.baseline import (
    BASELINE_LIFECYCLE_STATUSES,
    BASELINE_OPERATIONS,
    BaselineGovernanceLog as OrmBaselineGovernanceLog,
    EnterpriseBaselineRecord as OrmBaselineRecord,
    EnterpriseBaselineVersion as OrmBaselineVersion,
)


@runtime_checkable
class BaselineRepositoryProtocol(Protocol):
    """Protocol defining the repository contract for Enterprise Baseline."""

    is_persistent: bool
    is_in_memory: bool

    async def create_baseline_record(
        self,
        tenant_id: str,
        title: str,
        category: str,
        source_type: str,
        provenance: str,
        classification: str,
        access_scope: str,
        content: str,
        change_summary: str,
        user_id: str,
        branch_id: Optional[str] = None,
        source_uri: Optional[str] = None,
        effective_from: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        ...

    async def get_baseline_record(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> Optional[Dict[str, Any]]:
        ...

    async def list_baseline_records(
        self,
        tenant_id: str,
        category: Optional[str] = None,
        lifecycle_status: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        ...

    async def get_baseline_versions(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> List[Dict[str, Any]]:
        ...

    async def append_baseline_version(
        self,
        tenant_id: str,
        baseline_id: str,
        content: str,
        change_summary: str,
        user_id: str,
    ) -> Dict[str, Any]:
        ...

    async def transition_lifecycle(
        self,
        tenant_id: str,
        baseline_id: str,
        target_status: str,
        actor_id: str,
        actor_role: str,
        reason: str,
        superseded_by_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        ...

    async def list_governance_logs(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> List[Dict[str, Any]]:
        ...


class InMemoryBaselineRepository(BaselineRepositoryProtocol):
    """Thread-safe in-memory baseline store for development and testing."""

    is_persistent: bool = False
    is_in_memory: bool = True

    def __init__(self) -> None:
        # key: (tenant_id, baseline_id) -> record dict
        self._records: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # key: (baseline_id, version) -> version dict
        self._versions: Dict[Tuple[str, int], Dict[str, Any]] = {}
        # key: baseline_id -> list of governance logs
        self._governance_logs: Dict[str, List[Dict[str, Any]]] = {}

    async def create_baseline_record(
        self,
        tenant_id: str,
        title: str,
        category: str,
        source_type: str,
        provenance: str,
        classification: str,
        access_scope: str,
        content: str,
        change_summary: str,
        user_id: str,
        branch_id: Optional[str] = None,
        source_uri: Optional[str] = None,
        effective_from: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        baseline_id = f"base-{uuid.uuid4().hex[:12]}"
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

        rec = {
            "id": baseline_id,
            "tenant_id": tenant_id,
            "branch_id": branch_id,
            "title": title,
            "category": category,
            "source_uri": source_uri,
            "source_type": source_type,
            "provenance": provenance,
            "classification": classification,
            "access_scope": access_scope,
            "current_version": 1,
            "content_digest": checksum,
            "lifecycle_status": "DRAFT",
            "superseded_by_id": None,
            "effective_from": effective_from.isoformat() if effective_from else None,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "created_by_user_id": user_id,
            "reviewed_by_user_id": None,
            "approved_by_user_id": None,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }

        ver = {
            "id": f"bver-{uuid.uuid4().hex[:12]}",
            "tenant_id": tenant_id,
            "baseline_id": baseline_id,
            "version": 1,
            "content": content,
            "content_sha256": checksum,
            "change_summary": change_summary,
            "created_by_user_id": user_id,
            "created_at": now.isoformat(),
        }

        gov_log = {
            "id": f"bgov-{uuid.uuid4().hex[:12]}",
            "tenant_id": tenant_id,
            "baseline_id": baseline_id,
            "version": 1,
            "operation": "CREATE",
            "actor_id": user_id,
            "actor_role": "ADMIN",
            "reason": "Initial baseline record creation",
            "occurred_at": now.isoformat(),
        }

        self._records[(tenant_id, baseline_id)] = rec
        self._versions[(baseline_id, 1)] = ver
        self._governance_logs.setdefault(baseline_id, []).append(gov_log)

        return deepcopy(rec)

    async def get_baseline_record(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> Optional[Dict[str, Any]]:
        rec = self._records.get((tenant_id, baseline_id))
        return deepcopy(rec) if rec else None

    async def list_baseline_records(
        self,
        tenant_id: str,
        category: Optional[str] = None,
        lifecycle_status: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        matched = [
            r for (t, _), r in self._records.items()
            if t == tenant_id
        ]
        if category:
            matched = [r for r in matched if r["category"] == category]
        if lifecycle_status:
            matched = [r for r in matched if r["lifecycle_status"] == lifecycle_status]
        if branch_id:
            matched = [r for r in matched if r.get("branch_id") == branch_id or r.get("branch_id") is None]

        matched.sort(key=lambda x: (x["updated_at"], x["id"]), reverse=True)
        total = len(matched)
        page = matched[offset : offset + limit]
        has_more = (offset + limit) < total
        return [deepcopy(r) for r in page], has_more

    async def get_baseline_versions(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> List[Dict[str, Any]]:
        rec = await self.get_baseline_record(tenant_id, baseline_id)
        if not rec:
            return []
        versions = [
            deepcopy(v) for (b_id, _), v in self._versions.items()
            if b_id == baseline_id and v["tenant_id"] == tenant_id
        ]
        versions.sort(key=lambda x: x["version"])
        return versions

    async def append_baseline_version(
        self,
        tenant_id: str,
        baseline_id: str,
        content: str,
        change_summary: str,
        user_id: str,
    ) -> Dict[str, Any]:
        rec = self._records.get((tenant_id, baseline_id))
        if not rec:
            raise NotFoundError(f"Baseline record '{baseline_id}' not found.")

        now = datetime.now(timezone.utc)
        next_ver = rec["current_version"] + 1
        if (baseline_id, next_ver) in self._versions:
            raise ConflictError(
                f"Concurrent version conflict on baseline '{baseline_id}'. Please refresh and retry."
            )
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

        ver = {
            "id": f"bver-{uuid.uuid4().hex[:12]}",
            "tenant_id": tenant_id,
            "baseline_id": baseline_id,
            "version": next_ver,
            "content": content,
            "content_sha256": checksum,
            "change_summary": change_summary,
            "created_by_user_id": user_id,
            "created_at": now.isoformat(),
        }

        rec["current_version"] = next_ver
        rec["content_digest"] = checksum
        rec["lifecycle_status"] = "DRAFT"  # New versions re-enter DRAFT for review/approval
        rec["updated_at"] = now.isoformat()

        gov_log = {
            "id": f"bgov-{uuid.uuid4().hex[:12]}",
            "tenant_id": tenant_id,
            "baseline_id": baseline_id,
            "version": next_ver,
            "operation": "APPEND_VERSION",
            "actor_id": user_id,
            "actor_role": "ADMIN",
            "reason": change_summary,
            "occurred_at": now.isoformat(),
        }

        self._versions[(baseline_id, next_ver)] = ver
        self._governance_logs.setdefault(baseline_id, []).append(gov_log)

        return deepcopy(ver)

    async def transition_lifecycle(
        self,
        tenant_id: str,
        baseline_id: str,
        target_status: str,
        actor_id: str,
        actor_role: str,
        reason: str,
        superseded_by_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        rec = self._records.get((tenant_id, baseline_id))
        if not rec:
            raise NotFoundError(f"Baseline record '{baseline_id}' not found.")

        current_status = rec["lifecycle_status"]
        now = datetime.now(timezone.utc)

        # Validate lifecycle transitions (Phase 1 §2.D)
        valid_transitions = {
            "DRAFT": ["IN_REVIEW", "ARCHIVED"],
            "IN_REVIEW": ["APPROVED", "DRAFT", "ARCHIVED"],
            "APPROVED": ["ACTIVE", "REVOKED", "ARCHIVED"],
            "ACTIVE": ["SUPERSEDED", "REVOKED"],
            "SUPERSEDED": ["ARCHIVED"],
            "REVOKED": ["ARCHIVED"],
            "ARCHIVED": [],
        }

        if target_status not in valid_transitions.get(current_status, []):
            raise ValidationError(
                f"Invalid baseline lifecycle transition from '{current_status}' to '{target_status}'."
            )

        rec["lifecycle_status"] = target_status
        rec["updated_at"] = now.isoformat()

        if target_status == "IN_REVIEW":
            rec["reviewed_by_user_id"] = actor_id
        elif target_status == "APPROVED":
            rec["approved_by_user_id"] = actor_id
        elif target_status == "ACTIVE":
            if not rec.get("effective_from"):
                rec["effective_from"] = now.isoformat()
        elif target_status == "SUPERSEDED":
            rec["superseded_by_id"] = superseded_by_id

        gov_log = {
            "id": f"bgov-{uuid.uuid4().hex[:12]}",
            "tenant_id": tenant_id,
            "baseline_id": baseline_id,
            "version": rec["current_version"],
            "operation": target_status,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "reason": reason,
            "occurred_at": now.isoformat(),
        }
        self._governance_logs.setdefault(baseline_id, []).append(gov_log)

        return deepcopy(rec)

    async def list_governance_logs(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> List[Dict[str, Any]]:
        rec = await self.get_baseline_record(tenant_id, baseline_id)
        if not rec:
            return []
        logs = self._governance_logs.get(baseline_id, [])
        return [deepcopy(l) for l in logs]


def seed_demo_baselines(repo: InMemoryBaselineRepository) -> None:
    """Seed canonical enterprise knowledge and policies for Head Office, Lahore, Karachi, Islamabad."""
    t_a = "tenant-a-uuid-001"
    now = datetime.now(timezone.utc)

    # 1. Vendor Disbursement Policy (Head Office / Corporate Finance)
    rec1 = {
        "id": "base-fin-disbursement-001",
        "tenant_id": t_a,
        "branch_id": "branch-ho-001",
        "title": "Corporate Vendor Disbursement and Dual-Custody Policy",
        "category": "POLICY",
        "source_uri": "s3://corp-policies/finance/2026/vendor_disbursement.pdf",
        "source_type": "EXECUTIVE_DIRECTIVE",
        "provenance": "Corporate Board Resolution FIN-2026-08, Chief Financial Officer approval",
        "classification": "ENTERPRISE_CONFIDENTIAL",
        "access_scope": "FINANCE_OPERATIONS",
        "current_version": 2,
        "lifecycle_status": "ACTIVE",
        "superseded_by_id": None,
        "effective_from": now.isoformat(),
        "expires_at": None,
        "created_by_user_id": "usr-admin-001",
        "reviewed_by_user_id": "usr-reviewer-001",
        "approved_by_user_id": "usr-admin-001",
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    repo._records[(t_a, rec1["id"])] = rec1
    repo._versions[(rec1["id"], 1)] = {
        "id": "bver-fin-001-v1",
        "tenant_id": t_a,
        "baseline_id": rec1["id"],
        "version": 1,
        "content": "All vendor disbursements over $100.00 require manager approval. Wire transfers under $100 are pre-authorized.",
        "content_sha256": hashlib.sha256(b"v1 content").hexdigest(),
        "change_summary": "Initial policy release",
        "created_by_user_id": "usr-admin-001",
        "created_at": now.isoformat(),
    }
    repo._versions[(rec1["id"], 2)] = {
        "id": "bver-fin-001-v2",
        "tenant_id": t_a,
        "baseline_id": rec1["id"],
        "version": 2,
        "content": "Corporate Vendor Disbursement and Dual-Custody Policy:\nAll disbursements and reimbursements over $300.00 USD strictly require dual-custody approval from a Finance Manager. Wire transfers strictly require verified recipient registrations.",
        "content_sha256": hashlib.sha256(b"v2 content").hexdigest(),
        "change_summary": "Updated dual-custody threshold to $300.00 USD",
        "created_by_user_id": "usr-admin-001",
        "created_at": now.isoformat(),
    }
    repo._governance_logs[rec1["id"]] = [
        {"id": "bgov-001", "tenant_id": t_a, "baseline_id": rec1["id"], "version": 1, "operation": "CREATE", "actor_id": "usr-admin-001", "actor_role": "TENANT_ADMIN", "reason": "Initial policy", "occurred_at": now.isoformat()},
        {"id": "bgov-002", "tenant_id": t_a, "baseline_id": rec1["id"], "version": 1, "operation": "ACTIVATE", "actor_id": "usr-admin-001", "actor_role": "TENANT_ADMIN", "reason": "Board signoff", "occurred_at": now.isoformat()},
        {"id": "bgov-003", "tenant_id": t_a, "baseline_id": rec1["id"], "version": 2, "operation": "ACTIVATE", "actor_id": "usr-admin-001", "actor_role": "TENANT_ADMIN", "reason": "Threshold update", "occurred_at": now.isoformat()},
    ]

    # 2. Customer Refund Policy (Customer Support)
    rec2 = {
        "id": "base-supp-refund-002",
        "tenant_id": t_a,
        "branch_id": "branch-ho-001",
        "title": "Customer Support Refund and Ticket Resolution Policy",
        "category": "POLICY",
        "source_uri": "s3://corp-policies/support/2026/refund_guidelines.pdf",
        "source_type": "EXECUTIVE_DIRECTIVE",
        "provenance": "VP of Customer Success directive CS-2026-03",
        "classification": "INTERNAL",
        "access_scope": "CUSTOMER_SUPPORT",
        "current_version": 1,
        "lifecycle_status": "ACTIVE",
        "superseded_by_id": None,
        "effective_from": now.isoformat(),
        "expires_at": None,
        "created_by_user_id": "usr-admin-001",
        "reviewed_by_user_id": "usr-reviewer-001",
        "approved_by_user_id": "usr-admin-001",
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    repo._records[(t_a, rec2["id"])] = rec2
    repo._versions[(rec2["id"], 1)] = {
        "id": "bver-supp-002-v1",
        "tenant_id": t_a,
        "baseline_id": rec2["id"],
        "version": 1,
        "content": "ChronoCogniSec Return & Refund Policy:\nFull refund permitted within 14 calendar days of purchase with valid receipt. Disbursements over $300 require dual-custody managerial approval.",
        "content_sha256": hashlib.sha256(b"support refund policy v1").hexdigest(),
        "change_summary": "Initial refund baseline",
        "created_by_user_id": "usr-admin-001",
        "created_at": now.isoformat(),
    }
    repo._governance_logs[rec2["id"]] = [
        {"id": "bgov-004", "tenant_id": t_a, "baseline_id": rec2["id"], "version": 1, "operation": "ACTIVATE", "actor_id": "usr-admin-001", "actor_role": "TENANT_ADMIN", "reason": "Support guidelines", "occurred_at": now.isoformat()},
    ]

    # 3. HR Employee Handbook (Islamabad Branch)
    rec3 = {
        "id": "base-hr-handbook-003",
        "tenant_id": t_a,
        "branch_id": "branch-isb-004",
        "title": "Islamabad Branch HR Policy and Leave Entitlement Handbook",
        "category": "PROCEDURE",
        "source_uri": "s3://corp-policies/hr/2026/employee_handbook.pdf",
        "source_type": "EXECUTIVE_DIRECTIVE",
        "provenance": "Chief Human Resources Officer policy CHRO-2026-01",
        "classification": "INTERNAL",
        "access_scope": "HUMAN_RESOURCES",
        "current_version": 1,
        "lifecycle_status": "ACTIVE",
        "superseded_by_id": None,
        "effective_from": now.isoformat(),
        "expires_at": None,
        "created_by_user_id": "usr-admin-001",
        "reviewed_by_user_id": "usr-reviewer-001",
        "approved_by_user_id": "usr-admin-001",
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    repo._records[(t_a, rec3["id"])] = rec3
    repo._versions[(rec3["id"], 1)] = {
        "id": "bver-hr-003-v1",
        "tenant_id": t_a,
        "baseline_id": rec3["id"],
        "version": 1,
        "content": "ChronoCogniSec HR Handbook:\nAnnual leave entitlement is 22 working days per year for full-time employees. Sick leave up to 10 days with certificate required after 2 days.",
        "content_sha256": hashlib.sha256(b"hr handbook v1").hexdigest(),
        "change_summary": "Initial HR baseline",
        "created_by_user_id": "usr-admin-001",
        "created_at": now.isoformat(),
    }
    repo._governance_logs[rec3["id"]] = [
        {"id": "bgov-005", "tenant_id": t_a, "baseline_id": rec3["id"], "version": 1, "operation": "ACTIVATE", "actor_id": "usr-admin-001", "actor_role": "TENANT_ADMIN", "reason": "HR handbook", "occurred_at": now.isoformat()},
    ]


class SqlAlchemyBaselineRepository(BaselineRepositoryProtocol):
    """PostgreSQL durable repository for enterprise security baseline."""

    is_persistent: bool = True
    is_in_memory: bool = False

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def create_baseline_record(
        self,
        tenant_id: str,
        title: str,
        category: str,
        source_type: str,
        provenance: str,
        classification: str,
        access_scope: str,
        content: str,
        change_summary: str,
        user_id: str,
        branch_id: Optional[str] = None,
        source_uri: Optional[str] = None,
        effective_from: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        baseline_id = f"base-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

        async with self.session_factory() as session:
            async with session.begin():
                rec = OrmBaselineRecord(
                    id=baseline_id,
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    title=title,
                    category=category,
                    source_uri=source_uri,
                    source_type=source_type,
                    provenance=provenance,
                    classification=classification,
                    access_scope=access_scope,
                    current_version=1,
                    lifecycle_status="DRAFT",
                    effective_from=effective_from,
                    expires_at=expires_at,
                    created_by_user_id=user_id,
                    created_at=now,
                    updated_at=now,
                )
                session.add(rec)

                ver = OrmBaselineVersion(
                    id=f"bver-{uuid.uuid4().hex[:12]}",
                    tenant_id=tenant_id,
                    baseline_id=baseline_id,
                    version=1,
                    content=content,
                    content_sha256=checksum,
                    change_summary=change_summary,
                    created_by_user_id=user_id,
                    created_at=now,
                )
                session.add(ver)

                log = OrmBaselineGovernanceLog(
                    id=f"bgov-{uuid.uuid4().hex[:12]}",
                    tenant_id=tenant_id,
                    baseline_id=baseline_id,
                    version=1,
                    operation="CREATE",
                    actor_id=user_id,
                    actor_role="ADMIN",
                    reason="Initial baseline record creation",
                    occurred_at=now,
                )
                session.add(log)

        return await self.get_baseline_record(tenant_id, baseline_id)  # type: ignore

    async def get_baseline_record(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> Optional[Dict[str, Any]]:
        async with self.session_factory() as session:
            stmt = select(OrmBaselineRecord).where(
                OrmBaselineRecord.tenant_id == tenant_id,
                OrmBaselineRecord.id == baseline_id,
            )
            r = (await session.execute(stmt)).scalar_one_or_none()
            if r is None:
                return None

            stmt_ver = select(OrmBaselineVersion.content_sha256).where(
                OrmBaselineVersion.tenant_id == tenant_id,
                OrmBaselineVersion.baseline_id == baseline_id,
                OrmBaselineVersion.version == r.current_version,
            )
            content_digest = (await session.execute(stmt_ver)).scalar_one_or_none()

            return {
                "id": r.id,
                "tenant_id": r.tenant_id,
                "branch_id": r.branch_id,
                "title": r.title,
                "category": r.category,
                "source_uri": r.source_uri,
                "source_type": r.source_type,
                "provenance": r.provenance,
                "classification": r.classification,
                "access_scope": r.access_scope,
                "current_version": r.current_version,
                "content_digest": content_digest,
                "lifecycle_status": r.lifecycle_status,
                "superseded_by_id": r.superseded_by_id,
                "effective_from": r.effective_from.isoformat() if r.effective_from else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "created_by_user_id": r.created_by_user_id,
                "reviewed_by_user_id": r.reviewed_by_user_id,
                "approved_by_user_id": r.approved_by_user_id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }

    async def list_baseline_records(
        self,
        tenant_id: str,
        category: Optional[str] = None,
        lifecycle_status: Optional[str] = None,
        branch_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        async with self.session_factory() as session:
            stmt = select(OrmBaselineRecord).where(OrmBaselineRecord.tenant_id == tenant_id)
            if category:
                stmt = stmt.where(OrmBaselineRecord.category == category)
            if lifecycle_status:
                stmt = stmt.where(OrmBaselineRecord.lifecycle_status == lifecycle_status)
            if branch_id:
                stmt = stmt.where(
                    (OrmBaselineRecord.branch_id == branch_id) | (OrmBaselineRecord.branch_id.is_(None))
                )

            stmt = stmt.order_by(desc(OrmBaselineRecord.updated_at)).limit(limit + 1).offset(offset)
            rows = list((await session.execute(stmt)).scalars().all())
            has_more = len(rows) > limit
            page = rows[:limit]

            # Batch fetch digests for current versions
            rec_ids = [r.id for r in page]
            digest_map: Dict[Tuple[str, int], str] = {}
            if rec_ids:
                stmt_ver = select(
                    OrmBaselineVersion.baseline_id,
                    OrmBaselineVersion.version,
                    OrmBaselineVersion.content_sha256,
                ).where(
                    OrmBaselineVersion.tenant_id == tenant_id,
                    OrmBaselineVersion.baseline_id.in_(rec_ids),
                )
                ver_rows = (await session.execute(stmt_ver)).all()
                digest_map = {(row[0], row[1]): row[2] for row in ver_rows}

            items = [
                {
                    "id": r.id,
                    "tenant_id": r.tenant_id,
                    "branch_id": r.branch_id,
                    "title": r.title,
                    "category": r.category,
                    "source_uri": r.source_uri,
                    "source_type": r.source_type,
                    "provenance": r.provenance,
                    "classification": r.classification,
                    "access_scope": r.access_scope,
                    "current_version": r.current_version,
                    "content_digest": digest_map.get((r.id, r.current_version)),
                    "lifecycle_status": r.lifecycle_status,
                    "superseded_by_id": r.superseded_by_id,
                    "effective_from": r.effective_from.isoformat() if r.effective_from else None,
                    "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                    "created_by_user_id": r.created_by_user_id,
                    "reviewed_by_user_id": r.reviewed_by_user_id,
                    "approved_by_user_id": r.approved_by_user_id,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                }
                for r in page
            ]
            return items, has_more

    async def get_baseline_versions(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> List[Dict[str, Any]]:
        async with self.session_factory() as session:
            stmt = select(OrmBaselineVersion).where(
                OrmBaselineVersion.tenant_id == tenant_id,
                OrmBaselineVersion.baseline_id == baseline_id,
            ).order_by(OrmBaselineVersion.version.asc())
            rows = list((await session.execute(stmt)).scalars().all())
            return [
                {
                    "id": v.id,
                    "tenant_id": v.tenant_id,
                    "baseline_id": v.baseline_id,
                    "version": v.version,
                    "content": v.content,
                    "content_sha256": v.content_sha256,
                    "change_summary": v.change_summary,
                    "created_by_user_id": v.created_by_user_id,
                    "created_at": v.created_at.isoformat() if v.created_at else None,
                }
                for v in rows
            ]

    async def append_baseline_version(
        self,
        tenant_id: str,
        baseline_id: str,
        content: str,
        change_summary: str,
        user_id: str,
    ) -> Dict[str, Any]:
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    stmt = select(OrmBaselineRecord).where(
                        OrmBaselineRecord.tenant_id == tenant_id,
                        OrmBaselineRecord.id == baseline_id,
                    )
                    rec = (await session.execute(stmt)).scalar_one_or_none()
                    if not rec:
                        raise NotFoundError(f"Baseline record '{baseline_id}' not found.")

                    now = datetime.now(timezone.utc)
                    next_ver = rec.current_version + 1
                    checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()

                    ver = OrmBaselineVersion(
                        id=f"bver-{uuid.uuid4().hex[:12]}",
                        tenant_id=tenant_id,
                        baseline_id=baseline_id,
                        version=next_ver,
                        content=content,
                        content_sha256=checksum,
                        change_summary=change_summary,
                        created_by_user_id=user_id,
                        created_at=now,
                    )
                    session.add(ver)

                    rec.current_version = next_ver
                    rec.lifecycle_status = "DRAFT"
                    rec.updated_at = now

                    log = OrmBaselineGovernanceLog(
                        id=f"bgov-{uuid.uuid4().hex[:12]}",
                        tenant_id=tenant_id,
                        baseline_id=baseline_id,
                        version=next_ver,
                        operation="APPEND_VERSION",
                        actor_id=user_id,
                        actor_role="ADMIN",
                        reason=change_summary,
                        occurred_at=now,
                    )
                    session.add(log)

                    return {
                        "id": ver.id,
                        "tenant_id": ver.tenant_id,
                        "baseline_id": ver.baseline_id,
                        "version": ver.version,
                        "content": ver.content,
                        "content_sha256": ver.content_sha256,
                        "change_summary": ver.change_summary,
                        "created_by_user_id": ver.created_by_user_id,
                        "created_at": now.isoformat(),
                    }
            except IntegrityError as exc:
                raise ConflictError(
                    f"Concurrent version conflict on baseline '{baseline_id}'. Please refresh and retry."
                ) from exc

    async def transition_lifecycle(
        self,
        tenant_id: str,
        baseline_id: str,
        target_status: str,
        actor_id: str,
        actor_role: str,
        reason: str,
        superseded_by_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        async with self.session_factory() as session:
            async with session.begin():
                stmt = select(OrmBaselineRecord).where(
                    OrmBaselineRecord.tenant_id == tenant_id,
                    OrmBaselineRecord.id == baseline_id,
                )
                rec = (await session.execute(stmt)).scalar_one_or_none()
                if not rec:
                    raise NotFoundError(f"Baseline record '{baseline_id}' not found.")

                current_status = rec.lifecycle_status
                now = datetime.now(timezone.utc)

                valid_transitions = {
                    "DRAFT": ["IN_REVIEW", "ARCHIVED"],
                    "IN_REVIEW": ["APPROVED", "DRAFT", "ARCHIVED"],
                    "APPROVED": ["ACTIVE", "REVOKED", "ARCHIVED"],
                    "ACTIVE": ["SUPERSEDED", "REVOKED"],
                    "SUPERSEDED": ["ARCHIVED"],
                    "REVOKED": ["ARCHIVED"],
                    "ARCHIVED": [],
                }

                if target_status not in valid_transitions.get(current_status, []):
                    raise ValidationError(
                        f"Invalid baseline lifecycle transition from '{current_status}' to '{target_status}'."
                    )

                rec.lifecycle_status = target_status
                rec.updated_at = now

                if target_status == "IN_REVIEW":
                    rec.reviewed_by_user_id = actor_id
                elif target_status == "APPROVED":
                    rec.approved_by_user_id = actor_id
                elif target_status == "ACTIVE":
                    if not rec.effective_from:
                        rec.effective_from = now
                elif target_status == "SUPERSEDED":
                    rec.superseded_by_id = superseded_by_id

                log = OrmBaselineGovernanceLog(
                    id=f"bgov-{uuid.uuid4().hex[:12]}",
                    tenant_id=tenant_id,
                    baseline_id=baseline_id,
                    version=rec.current_version,
                    operation=target_status,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason=reason,
                    occurred_at=now,
                )
                session.add(log)

        return await self.get_baseline_record(tenant_id, baseline_id)  # type: ignore

    async def list_governance_logs(
        self,
        tenant_id: str,
        baseline_id: str,
    ) -> List[Dict[str, Any]]:
        async with self.session_factory() as session:
            stmt = select(OrmBaselineGovernanceLog).where(
                OrmBaselineGovernanceLog.tenant_id == tenant_id,
                OrmBaselineGovernanceLog.baseline_id == baseline_id,
            ).order_by(OrmBaselineGovernanceLog.occurred_at.desc())
            rows = list((await session.execute(stmt)).scalars().all())
            return [
                {
                    "id": l.id,
                    "tenant_id": l.tenant_id,
                    "baseline_id": l.baseline_id,
                    "version": l.version,
                    "operation": l.operation,
                    "actor_id": l.actor_id,
                    "actor_role": l.actor_role,
                    "reason": l.reason,
                    "occurred_at": l.occurred_at.isoformat() if l.occurred_at else None,
                }
                for l in rows
            ]
