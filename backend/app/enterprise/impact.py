"""Enterprise-Wide Incident Impact Tracing & Scoped Recovery Planning."""

from __future__ import annotations

from typing import Any, Dict, List
import uuid

from backend.app.enterprise.models import (
    ClaimTrustState,
    ConnectorAuditLogDTO,
    DiscoveredResourceDTO,
    EnterpriseMemoryLinkDTO,
    FreshnessStatus,
    ImpactTraceResponse,
    KnowledgeClaimDTO,
    ScopedRecoveryPlanResponse,
)
from backend.app.enterprise.repository import EnterpriseRepository


class EnterpriseImpactService:
    """Traces incident blast radius across connected sources, knowledge claims, memories, and agents."""

    def __init__(self, enterprise_repo: EnterpriseRepository) -> None:
        self._repo = enterprise_repo

    async def trace_impact(self, tenant_id: str, target_id: str) -> ImpactTraceResponse:
        """Trace lineage from a resource_id, memory_record_id, or claim_id."""
        resources: List[DiscoveredResourceDTO] = []
        claims: List[KnowledgeClaimDTO] = []
        memories: List[EnterpriseMemoryLinkDTO] = []

        # 1. Check if target_id is a discovered resource
        res = await self._repo.get_resource(tenant_id, target_id)
        if res is not None:
            resources.append(res)
            claims = await self._repo.list_claims(tenant_id, resource_id=res.id)
            memories = await self._repo.list_memory_links(tenant_id, resource_id=res.id)
        else:
            # 2. Check if target_id is a memory_record_id
            mem_links = await self._repo.list_memory_links(tenant_id, memory_record_id=target_id)
            if mem_links:
                memories = mem_links
                res_ids = {m.resource_id for m in mem_links}
                for rid in res_ids:
                    r = await self._repo.get_resource(tenant_id, rid)
                    if r:
                        resources.append(r)
                    claims.extend(await self._repo.list_claims(tenant_id, resource_id=rid))
            else:
                # 3. Check if target_id is a knowledge claim ID
                all_claims = await self._repo.list_claims(tenant_id)
                matched = [c for c in all_claims if c.id == target_id]
                if matched:
                    claims = matched
                    r = await self._repo.get_resource(tenant_id, matched[0].resource_id)
                    if r:
                        resources.append(r)
                        memories = await self._repo.list_memory_links(tenant_id, resource_id=r.id)

        agent_ids = sorted({m.agent_id for m in memories if m.agent_id})
        actions: List[str] = []
        if any(m.freshness_status != FreshnessStatus.CURRENT.value for m in memories):
            actions.append("QUARANTINE_OR_REFRESH_STALE_MEMORIES")
        if any(r.metadata_json.get("injection_flagged") for r in resources):
            actions.append("CONTAIN_POISONED_SOURCE_AND_BLOCK_DEPENDENT_MEMORIES")
        if any(c.trust_state == ClaimTrustState.CONFLICTING.value for c in claims):
            actions.append("HUMAN_REVIEW_CONFLICTING_KNOWLEDGE_CLAIMS")
        if not actions and (resources or memories or claims):
            actions.append("VERIFY_LINEAGE_AND_MONITOR_EXECUTIONS")

        return ImpactTraceResponse(
            target_id=target_id,
            tenant_id=tenant_id,
            source_resources=resources,
            affected_claims=claims,
            dependent_memories=memories,
            affected_agent_ids=agent_ids,
            recommended_actions=actions,
            evidence_summary={
                "resource_count": len(resources),
                "claim_count": len(claims),
                "memory_link_count": len(memories),
                "affected_agent_count": len(agent_ids),
            },
        )

    async def build_scoped_recovery_plan(
        self,
        tenant_id: str,
        actor_id: str,
        target_id: str,
        reason: str,
        require_human_approval: bool = True,
    ) -> ScopedRecoveryPlanResponse:
        impact = await self.trace_impact(tenant_id, target_id)
        steps: List[Dict[str, Any]] = []
        compensating: List[Dict[str, Any]] = []
        evidence_ids: List[str] = [r.id for r in impact.source_resources] + [m.id for m in impact.dependent_memories]

        for r in impact.source_resources:
            steps.append(
                {
                    "step": "PRESERVE_SOURCE_EVIDENCE",
                    "resource_id": r.id,
                    "external_id": r.external_id,
                    "checksum": r.content_checksum,
                    "note": "Original enterprise source is never silently overwritten.",
                }
            )
        for m in impact.dependent_memories:
            steps.append(
                {
                    "step": "QUARANTINE_AND_REWIND_MEMORY",
                    "memory_record_id": m.memory_record_id,
                    "snapshot_checksum": m.snapshot_checksum,
                    "agent_id": m.agent_id,
                }
            )
        for ag_id in impact.affected_agent_ids:
            compensating.append(
                {
                    "action": "COMPENSATE_AGENT_WORKFLOW",
                    "agent_id": ag_id,
                    "requires_approval": require_human_approval,
                    "note": "Re-verify downstream tool executions before resuming agent.",
                }
            )

        plan_id = str(uuid.uuid4())
        await self._repo.append_audit_log(
            ConnectorAuditLogDTO(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                actor_id=actor_id,
                action="SCOPED_RECOVERY_PLAN",
                status="PENDING_APPROVAL" if require_human_approval else "READY",
                details_json={
                    "plan_id": plan_id,
                    "target_id": target_id,
                    "reason": reason,
                    "step_count": len(steps),
                },
            )
        )

        return ScopedRecoveryPlanResponse(
            plan_id=plan_id,
            tenant_id=tenant_id,
            target_id=target_id,
            requires_human_approval=require_human_approval,
            steps=steps,
            compensating_actions=compensating,
            preserved_evidence_ids=evidence_ids,
            status="PENDING_APPROVAL" if require_human_approval else "READY",
        )
