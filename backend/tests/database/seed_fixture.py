"""Test-only seeded dataset for migration lifecycle tests (Day 7).

ILLUSTRATIVE TEST DATA, NOT DECISIONS.
Owner: M6

This is NOT the product seed. The product seed (``core/seed.py``, DOC-006 Day 2) belongs to
M7 and does not exist yet (OD-27). Values such as decisions, statuses or roles are taken
from the examples documented in AMSC-DOC-005 only to make the data look realistic; they do
not choose any vocabulary. The database does not constrain those columns (OPEN-DEPENDENCIES).

Shape (TRD section 12.1: one company with branches; OD-28 covers the "3 tenants" question):
- tenant A "ChronoCongiSec Enterprise" with branches Head Office, Lahore, Karachi, Islamabad;
- tenant B "Isolation Check Co", only so that cross-tenant isolation can be observed.

Every one of the 37 tables gets at least one row. The gateway chain is written through
``UnitOfWork``, the rewind through ``RewindCoordinator`` and audit events through
``AuditEventRepository``, so the real M6 code paths are exercised while seeding.
"""

import uuid
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.database.models import (
    Agent,
    AgentSecurityProfile,
    AgentToolPermission,
    AgentVersion,
    Approval,
    AuditEvent,
    BaselineGovernanceLog,
    Branch,
    Checkpoint,
    CheckpointItem,
    ConnectorAuditLog,
    CompanyActivity,
    CompanyFile,
    CompanyFileTransfer,
    CompanyFileVersion,
    CompanyMessage,
    CompanyNotification,
    CompanyTask,
    CompanyTaskEvent,
    CompanyWorkspace,
    DetectionResultModel,
    DiscoveredResource,
    Document,
    DriftObservation,
    EnterpriseBaselineRecord,
    EnterpriseBaselineVersion,
    EnterpriseConnector,
    EnterpriseMemoryLink,
    Incident,
    IncidentEvidence,
    KnowledgeClaim,
    KnowledgeEntity,
    KnowledgeRelation,
    Membership,
    MemoryRecord,
    MemoryVersion,
    ObservationEvent,
    OutboxEvent,
    Permission,
    PolicyDecision,
    ProvenanceEdge,
    Quarantine,
    RecoveryPlan,
    RetrievalEvent,
    RegistrationRequest,
    Role,
    RolePermission,
    Source,
    SyncJob,
    Tenant,
    ToolExecution,
    ToolProposal,
    ToolRegistration,
    Trace,
    TraceSpan,
    Transformation,
    TrustDecisionModel,
    User,
)
from backend.app.database.rewind import RewindCoordinator
from backend.app.database.unit_of_work import UnitOfWork

ILLUSTRATIVE = "illustrative test data, not decisions"
BRANCHES = (("Head Office", "HO"), ("Branch Lahore", "LHR"), ("Branch Karachi", "KHI"), ("Branch Islamabad", "ISB"))


def _id() -> str:
    return str(uuid.uuid4())


@dataclass
class SeedResult:
    tenant_a: str
    tenant_b: str
    ids: dict[str, str] = field(default_factory=dict)


async def seed_dataset(session_factory: async_sessionmaker[AsyncSession]) -> SeedResult:
    """Populate a freshly migrated (head) database. Returns the important ids."""
    ids: dict[str, str] = {k: _id() for k in (
        "tenant_a", "tenant_b", "u_admin", "u_analyst", "u_auditor", "role", "permission",
        "agent", "agent_isolated", "agent_b", "tool", "source", "source_old",
        "rec1", "rec2", "rec3", "rec_b", "r1v1", "r1v2", "r1v3", "r2v1", "r3v1", "rbv1",
        "incident", "checkpoint", "plan", "entity1", "entity2", "trace",
    )}
    a, b = ids["tenant_a"], ids["tenant_b"]

    # 1. Global catalog, tenants, branches, identities and the memory graph (one transaction).
    async with session_factory() as session, session.begin():
        session.add_all([
            Tenant(id=a, name="ChronoCongiSec Enterprise", slug="chronocongisec-enterprise"),
            Tenant(id=b, name="Isolation Check Co", slug="isolation-check-co"),
        ])
        session.add_all([
            User(id=ids["u_admin"], email="admin@example.test", hashed_password="x", full_name="Admin"),
            User(id=ids["u_analyst"], email="analyst@example.test", hashed_password="x", full_name="Analyst"),
            User(id=ids["u_auditor"], email="auditor@example.test", hashed_password="x", full_name="Auditor"),
        ])
        session.add(Role(id=ids["role"], tenant_id=None, name="SECURITY_ANALYST", description=ILLUSTRATIVE))
        session.add(Permission(id=ids["permission"], key="memory:quarantine", description=ILLUSTRATIVE))
        await session.flush()
        session.add(RolePermission(role_id=ids["role"], permission_id=ids["permission"]))
        branch_ids = [_id() for _ in BRANCHES]
        ids["branches"] = branch_ids
        session.add_all([Branch(id=bid, tenant_id=a, name=n, code=c) for bid, (n, c) in zip(branch_ids, BRANCHES)])
        session.add(Branch(id=_id(), tenant_id=b, name="Head Office", code="HO"))
        session.add_all([
            Membership(id=_id(), tenant_id=a, user_id=ids["u_admin"], role="TENANT_ADMIN", status="ACTIVE"),
            Membership(id=_id(), tenant_id=a, user_id=ids["u_analyst"], role="SECURITY_ANALYST", status="ACTIVE"),
            Membership(id=_id(), tenant_id=a, user_id=ids["u_auditor"], role="AUDITOR", status="SUSPENDED"),
            Membership(id=_id(), tenant_id=b, user_id=ids["u_analyst"], role="SECURITY_ANALYST", status="ACTIVE"),
        ])
        session.add(RegistrationRequest(
            id=_id(),
            tenant_id=a,
            full_name="Pending Employee",
            email="pending.employee@example.test",
            hashed_password="x",
            requested_branch_code="HO",
            status="PENDING",
        ))
        session.add_all([
            Agent(id=ids["agent"], tenant_id=a, name="Treasury Bot"),
            Agent(id=ids["agent_isolated"], tenant_id=a, name="Old Bot", status="ISOLATED"),
            Agent(id=ids["agent_b"], tenant_id=b, name="Other Bot"),
            ToolRegistration(id=ids["tool"], tenant_id=a, name="sandbox_transfer"),
            Source(id=ids["source"], tenant_id=a, name="Policy Feed", status="ACTIVE"),
            Source(id=ids["source_old"], tenant_id=a, name="Old Feed", status="INACTIVE"),
        ])
        await session.flush()
        session.add_all([
            AgentVersion(id=_id(), tenant_id=a, agent_id=ids["agent"], version="v1.0.0"),
            AgentToolPermission(id=_id(), tenant_id=a, agent_id=ids["agent"], tool_id=ids["tool"]),
            Document(id=_id(), tenant_id=a, source_id=ids["source"], title="Treasury policy"),
            MemoryRecord(id=ids["rec1"], tenant_id=a, agent_id=ids["agent"], source_id=ids["source"], current_version=3),
            MemoryRecord(id=ids["rec2"], tenant_id=a, source_id=ids["source"]),
            MemoryRecord(id=ids["rec3"], tenant_id=a),
            MemoryRecord(id=ids["rec_b"], tenant_id=b),
        ])
        await session.flush()
        session.add_all([
            MemoryVersion(id=ids["r1v1"], tenant_id=a, record_id=ids["rec1"], version=1, content="limit 1000", checksum="c1"),
            MemoryVersion(id=ids["r1v2"], tenant_id=a, record_id=ids["rec1"], version=2, content="limit 5000", checksum="c2"),
            MemoryVersion(id=ids["r1v3"], tenant_id=a, record_id=ids["rec1"], version=3, content="limit 999999", checksum="c3"),
            MemoryVersion(id=ids["r2v1"], tenant_id=a, record_id=ids["rec2"], version=1, content="summary", checksum="c4"),
            MemoryVersion(id=ids["r3v1"], tenant_id=a, record_id=ids["rec3"], version=1, content="derived", checksum="c5"),
            MemoryVersion(id=ids["rbv1"], tenant_id=b, record_id=ids["rec_b"], version=1, content="other", checksum="c6"),
            Transformation(id=_id(), tenant_id=a, input_record_id=ids["rec1"], output_record_id=ids["rec2"],
                           operation="SUMMARIZE"),
            ProvenanceEdge(id=_id(), tenant_id=a, from_record_id=ids["rec2"], to_record_id=ids["rec1"]),
            ProvenanceEdge(id=_id(), tenant_id=a, from_record_id=ids["rec1"], to_record_id=ids["rec3"],
                           relation_type="TRANSFORMED_INTO"),
            RetrievalEvent(id=_id(), tenant_id=a, agent_id=ids["agent"], record_id=ids["rec1"], trace_id="trace-1"),
            DriftObservation(id=_id(), tenant_id=a, record_id=ids["rec2"], evidence_summary=ILLUSTRATIVE),
            KnowledgeEntity(id=ids["entity1"], tenant_id=a, label="Treasury"),
            KnowledgeEntity(id=ids["entity2"], tenant_id=a, label="Transfer limit"),
            Trace(id=ids["trace"], tenant_id=a, agent_id=ids["agent"]),
            OutboxEvent(id=_id(), tenant_id=a, event_type="MEMORY_INGESTED", payload={"note": ILLUSTRATIVE}),
            Incident(id=ids["incident"], tenant_id=a, title="Poisoned limit", classification="PROMPT_INJECTION",
                     affected_record_id=ids["rec1"], agent_id=ids["agent"]),
            Checkpoint(id=ids["checkpoint"], tenant_id=a, agent_id=ids["agent"], name="CP-001", integrity_hash="h",
                       record_count=2),
        ])
        await session.flush()
        session.add_all([
            KnowledgeRelation(id=_id(), tenant_id=a, source_entity_id=ids["entity1"], target_entity_id=ids["entity2"]),
            TraceSpan(id=_id(), tenant_id=a, trace_id=ids["trace"], operation="tool.call"),
            IncidentEvidence(id=_id(), tenant_id=a, incident_id=ids["incident"], evidence_type="MEMORY_RECORD",
                             resource_id=ids["rec1"]),
            Quarantine(id=_id(), tenant_id=a, record_id=ids["rec1"], incident_id=ids["incident"],
                       reason=ILLUSTRATIVE, quarantined_by=ids["u_analyst"]),
            CheckpointItem(id=_id(), tenant_id=a, checkpoint_id=ids["checkpoint"], record_id=ids["rec1"],
                           version_id=ids["r1v1"], checksum="c1"),
            CheckpointItem(id=_id(), tenant_id=a, checkpoint_id=ids["checkpoint"], record_id=ids["rec2"],
                           version_id=ids["r2v1"], checksum="c4"),
            RecoveryPlan(id=ids["plan"], tenant_id=a, incident_id=ids["incident"], checkpoint_id=ids["checkpoint"],
                         target_record_id=ids["rec1"]),
        ])
        base_id = _id()
        session.add_all([
            TrustDecisionModel(
                id=_id(), tenant_id=a, record_id=ids["rec1"], from_state="PROPOSED", to_state="TRUSTED",
                operation="INGEST", actor_id=ids["u_admin"], reason_code="VERIFIED", evidence_json={"note": ILLUSTRATIVE},
            ),
            EnterpriseBaselineRecord(
                id=base_id, tenant_id=a, branch_id=ids["branches"][0], title="Enterprise Baseline",
                category="POLICY", provenance=ILLUSTRATIVE, created_by_user_id=ids["u_admin"],
            ),
            AgentSecurityProfile(
                id=_id(), tenant_id=a, agent_id=ids["agent"], owner_department="Finance",
                approved_purpose=ILLUSTRATIVE, branch_id=ids["branches"][0], governed_by_user_id=ids["u_admin"],
            ),
            ObservationEvent(
                id=_id(), tenant_id=a, event_type="OBSERVATION_RECORDED", event_category="AGENT_EXECUTION_LIFECYCLE",
                outcome="SUCCESS", payload_json={"note": ILLUSTRATIVE},
            ),
            DetectionResultModel(
                id=_id(), tenant_id=a, branch_id=ids["branches"][0], detection_category="MEMORY_INTEGRITY",
                classification_type="OBSERVATION", detection_method="DETERMINISTIC_RULE", uncertainty_state="DEFINITIVE",
                severity="LOW", recommended_outcome="ALLOW", title="Clean Memory", description=ILLUSTRATIVE,
            ),
        ])
        await session.flush()
        session.add_all([
            EnterpriseBaselineVersion(
                id=_id(), tenant_id=a, baseline_id=base_id, version=1, content=ILLUSTRATIVE,
                content_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                change_summary="Initial", created_by_user_id=ids["u_admin"],
            ),
            BaselineGovernanceLog(
                id=_id(), tenant_id=a, baseline_id=base_id, version=1, operation="CREATE",
                actor_id=ids["u_admin"], actor_role="ADMIN", reason=ILLUSTRATIVE,
            ),
        ])
        connector_id = _id()
        resource_id = _id()
        session.add(
            EnterpriseConnector(
                id=connector_id,
                tenant_id=a,
                name="SharePoint Policy Store",
                connector_type="SHAREPOINT",
                created_by=ids["u_admin"],
            )
        )
        await session.flush()
        session.add_all([
            DiscoveredResource(
                id=resource_id,
                tenant_id=a,
                connector_id=connector_id,
                source_id=ids["source"],
                resource_type="DOCUMENT",
                external_id="sp-doc-001",
                name="Treasury Policy.pdf",
            ),
            SyncJob(
                id=_id(),
                tenant_id=a,
                connector_id=connector_id,
                strategy="FULL",
                status="COMPLETED",
                resources_discovered=1,
                resources_synced=1,
            ),
            ConnectorAuditLog(
                id=_id(),
                tenant_id=a,
                connector_id=connector_id,
                actor_id=ids["u_admin"],
                action="CONNECTOR_CREATED",
                status="SUCCESS",
            ),
        ])
        await session.flush()
        session.add_all([
            KnowledgeClaim(
                id=_id(),
                tenant_id=a,
                resource_id=resource_id,
                source_id=ids["source"],
                claim_type="POLICY_RULE",
                subject="Treasury",
                predicate="MAX_TRANSFER",
                object_value="1000",
            ),
            EnterpriseMemoryLink(
                id=_id(),
                tenant_id=a,
                memory_record_id=ids["rec1"],
                resource_id=resource_id,
                extraction_purpose="POLICY_GROUNDING",
                snapshot_checksum="c1",
            ),
        ])

    # 2. Employee company application records (all nine Phase 2 tables).
    workspace_id = _id()
    file_id = _id()
    task_id = _id()
    async with session_factory() as session, session.begin():
        session.add(CompanyWorkspace(
            id=workspace_id, tenant_id=a, branch_id=ids["branches"][0],
            owner_user_id=ids["u_admin"], name="Finance Workspace",
            description=ILLUSTRATIVE, visibility="BRANCH",
        ))
        await session.flush()
        session.add(CompanyFile(
            id=file_id, tenant_id=a, workspace_id=workspace_id,
            owner_user_id=ids["u_admin"], name="transfer-policy.txt",
            content_type="text/plain", current_version=1, status="ACTIVE",
        ))
        session.add(CompanyTask(
            id=task_id, tenant_id=a, workspace_id=workspace_id,
            branch_id=ids["branches"][0], title="Review transfer policy",
            description=ILLUSTRATIVE, status="OPEN", priority="NORMAL",
            created_by_user_id=ids["u_admin"], assigned_to_user_id=ids["u_analyst"],
        ))
        await session.flush()
        session.add_all([
            CompanyFileVersion(
                id=_id(), tenant_id=a, file_id=file_id, version_number=1,
                content="Maximum transfer: 1000", checksum="a" * 64,
                created_by_user_id=ids["u_admin"],
            ),
            CompanyFileTransfer(
                id=_id(), tenant_id=a, file_id=file_id,
                sender_user_id=ids["u_admin"], recipient_user_id=ids["u_analyst"],
                status="PENDING", message=ILLUSTRATIVE,
            ),
            CompanyTaskEvent(
                id=_id(), tenant_id=a, task_id=task_id,
                actor_user_id=ids["u_admin"], event_type="CREATED",
                details={"note": ILLUSTRATIVE},
            ),
            CompanyMessage(
                id=_id(), tenant_id=a, sender_user_id=ids["u_admin"],
                recipient_user_id=ids["u_analyst"], subject="Policy review",
                body=ILLUSTRATIVE, status="SENT",
            ),
            CompanyNotification(
                id=_id(), tenant_id=a, user_id=ids["u_analyst"],
                event_type="TASK_ASSIGNED", title="New task",
                body="Review transfer policy", resource_type="TASK",
                resource_id=task_id,
            ),
            CompanyActivity(
                id=_id(), tenant_id=a, branch_id=ids["branches"][0],
                actor_user_id=ids["u_admin"], event_type="TASK_CREATED",
                resource_type="TASK", resource_id=task_id,
                summary="Created a policy review task",
                details={"note": ILLUSTRATIVE},
            ),
        ])

    # 3. Gateway chain and audit trail through the unit of work (one transaction per action).
    uow = UnitOfWork(session_factory)

    def audit(resource_id: str, event_type: str) -> AuditEvent:
        return AuditEvent(id=_id(), actor_id=ids["u_analyst"], event_type=event_type, resource_id=resource_id,
                          action="RECORD", outcome="SUCCESS", details_json={"note": ILLUSTRATIVE})

    async with uow(a) as tx:
        allowed = await tx.proposals.add(ToolProposal(
            id=_id(), agent_id=ids["agent"], action_id="act-1", tool_name="sandbox_transfer", operation="transfer",
            idempotency_key="idem-1", trace_id="trace-1"))
        allow = await tx.decisions.add(PolicyDecision(
            id=_id(), proposal_id=allowed.id, decision="ALLOW", memory_trust="TRUSTED", policy_result="PERMITTED",
            execution_status="EXECUTED"))
        await tx.executions.add(ToolExecution(id=_id(), proposal_id=allowed.id, decision_id=allow.id))
        await tx.audit.append(audit(allowed.id, "TOOL_POLICY_DECIDED"))
    async with uow(a) as tx:
        blocked = await tx.proposals.add(ToolProposal(
            id=_id(), agent_id=ids["agent"], action_id="act-2", tool_name="sandbox_transfer", operation="transfer",
            idempotency_key="idem-2", trace_id="trace-2"))
        block = await tx.decisions.add(PolicyDecision(
            id=_id(), proposal_id=blocked.id, decision="REQUIRES_APPROVAL", memory_trust="SUSPICIOUS",
            policy_result="ELEVATED", incident_id=ids["incident"], execution_status="PENDING_APPROVAL"))
        await tx.approvals.add(Approval(id=_id(), decision_id=block.id, approver_user_id=ids["u_admin"]))
        await tx.audit.append(audit(blocked.id, "TOOL_POLICY_DECIDED"))
    async with uow(b) as tx:
        await tx.audit.append(audit(ids["rec_b"], "MEMORY_INGESTED"))
        await tx.audit.append(audit(ids["rec_b"], "MEMORY_READ"))

    # 4. Rewind of record 1 to checkpoint CP-001 (snapshot committed first, then rollback).
    coordinator = RewindCoordinator(session_factory)
    receipt = await coordinator.capture_snapshot(
        a, ids["plan"], {"records": [{"id": ids["rec1"], "current_version": 3, "checksum": "c3"}], "note": ILLUSTRATIVE})

    async def restore(rtx) -> None:
        item = await rtx.checkpoint_item_for(ids["rec1"])
        target = await rtx.session.get(MemoryVersion, item.version_id)
        await rtx.compare_and_set_current_version(ids["rec1"], expected=3, new=target.version)
        await rtx.record_action(ids["rec1"], "RESTORED_TO_CHECKPOINT")

    await coordinator.execute_rollback(a, ids["plan"], expected_snapshot_sha256=receipt.sha256, restore=restore)
    async with uow(a) as tx:
        await tx.audit.append(audit(ids["plan"], "RECOVERY_EXECUTED"))

    return SeedResult(tenant_a=a, tenant_b=b, ids=ids)
