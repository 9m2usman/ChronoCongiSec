"""End-to-end Detection-to-Containment pipeline orchestration (WP4-F).

Connects:
Trusted Observation -> DetectionEngine -> Deterministic Policy ->
Idempotent Incident/Evidence -> ContainmentService -> Verified Enforcement -> Audit.

ML intelligence remains strictly advisory-only and never authorizes ALLOW
or overrides a deterministic BLOCK/containment decision.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence
from uuid import UUID

from backend.app.core.exceptions import SecurityDependencyError
from backend.app.security.containment import (
    ContainmentAction,
    ContainmentOutcome,
    ContainmentReasonCode,
    ContainmentRequest,
    ContainmentService,
    ContainmentStatus,
    ContainmentType,
)
from backend.app.security.detection import (
    DetectionEngine,
    EvaluateDetectionRequest,
)
from backend.app.tenancy.context import TenantContext

logger = logging.getLogger("amsc.security.orchestration")


class DetectionToContainmentOrchestrator:
    """Deterministic orchestration from trusted observation to verified containment."""

    def __init__(
        self,
        *,
        detection_engine: DetectionEngine,
        detection_repo: Any,
        incident_repo: Any,
        containment_service: ContainmentService,
        persist_evidence: Callable[[ContainmentOutcome], Awaitable[Any]],
        ml_advisor: Any = None,
    ) -> None:
        self._detection_engine = detection_engine
        self._detection_repo = detection_repo
        self._incident_repo = incident_repo
        self._containment_service = containment_service
        self._persist_evidence = persist_evidence
        self._ml_advisor = ml_advisor

    async def process_and_contain(
        self,
        context: TenantContext,
        *,
        eval_request: EvaluateDetectionRequest,
        target_resources: Sequence[Dict[str, str]] = (),
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self._detection_engine is None or self._detection_repo is None:
            raise SecurityDependencyError("Detection engine or repository is unavailable.")
        if self._incident_repo is None or self._containment_service is None:
            raise SecurityDependencyError("Incident or containment service is unavailable.")

        # Ensure tenant/branch context is bound server-side.
        scoped_req = eval_request.model_copy(
            update={"branch_id": context.branch_id or eval_request.branch_id}
        )
        eval_response = await self._detection_engine.evaluate_all(
            tenant_id=context.tenant_id,
            request=scoped_req,
        )

        # ML intelligence is strictly advisory metadata only.
        ml_advisory: Optional[Dict[str, Any]] = None
        if self._ml_advisor is not None and callable(getattr(self._ml_advisor, "advise", None)):
            try:
                raw_adv = self._ml_advisor.advise(eval_request.model_dump())
                ml_advisory = {
                    "advisory_only": True,
                    "authoritative": False,
                    "signals": raw_adv,
                }
            except Exception as exc:  # noqa: BLE001
                ml_advisory = {"advisory_only": True, "authoritative": False, "error": type(exc).__name__}

        persisted_detection_ids: List[str] = []
        findings = list(getattr(eval_response, "detections", ()))
        for finding in findings:
            finding_dict = finding.to_dict() if hasattr(finding, "to_dict") else finding.model_dump(mode="json")
            persisted = await self._detection_repo.record_detection(finding_dict)
            persisted_detection_ids.append(str(persisted.get("id") or finding.id))

        qualifying = [
            f for f in findings
            if getattr(f.recommended_outcome, "value", f.recommended_outcome) == "BLOCK"
            and getattr(f.classification_type, "value", f.classification_type)
            in {"CONFIRMED_SECURITY_INCIDENT", "CONFIRMED_POLICY_VIOLATION"}
        ]
        if not qualifying:
            return {
                "triggered": False,
                "detection_ids": persisted_detection_ids,
                "incident_ids": [],
                "containment_outcomes": [],
                "ml_advisory": ml_advisory,
            }

        from backend.app.api.incident_management import (
            AuditEventEntity,
            IncidentEntity,
            IncidentEvidenceEntity,
        )

        incident_ids: List[str] = []
        containment_outcomes: List[ContainmentOutcome] = []
        seen_incidents: set[str] = set()

        for finding in qualifying:
            category = str(getattr(finding.detection_category, "value", finding.detection_category))
            reason_code = str((finding.details or {}).get("reason_code") or category)
            target_key = eval_request.record_id or eval_request.agent_id or "global"
            digest = hashlib.sha256(
                f"{context.tenant_id}:{target_key}:{category}:{reason_code}".encode("utf-8")
            ).hexdigest()
            incident_id = f"inc-{digest[:32]}"
            evidence_id = f"evi-{hashlib.sha256(f'{incident_id}:{finding.id}'.encode('utf-8')).hexdigest()[:32]}"

            existing = await self._incident_repo.get_incident(context.tenant_id, incident_id)
            evidence = IncidentEvidenceEntity(
                id=evidence_id,
                tenant_id=context.tenant_id,
                incident_id=incident_id,
                evidence_type="DETECTION_FINDING",
                resource_id=target_key,
                metadata_json={
                    "detection_id": finding.id,
                    "detection_category": category,
                    "reason_code": reason_code,
                    "branch_id": context.branch_id,
                    "trace_id": trace_id or finding.trace_id,
                    "ml_advisory_only": ml_advisory is not None,
                },
            )
            audit_digest = hashlib.sha256(f"{incident_id}:{finding.id}".encode("utf-8")).hexdigest()[:32]
            audit = AuditEventEntity(
                id=str(UUID(audit_digest)),
                tenant_id=context.tenant_id,
                actor_id=f"user:{context.user_id}",
                event_type="DETECTION_INCIDENT_CORRELATED",
                resource_id=incident_id,
                action="CORRELATE",
                outcome="RECORDED",
                trace_id=trace_id or finding.trace_id,
                details_json={"detection_id": finding.id, "category": category},
            )
            if existing is None:
                incident = IncidentEntity(
                    id=incident_id,
                    tenant_id=context.tenant_id,
                    title=f"Automated detection: {category}",
                    classification=category,
                    severity=str(getattr(finding.severity, "value", finding.severity)),
                    status="OPEN",
                    affected_record_id=eval_request.record_id,
                    agent_id=eval_request.agent_id,
                    evidence_json={"detection_id": finding.id, "reason_code": reason_code},
                )
                await self._incident_repo.create_incident_atomic(
                    incident=incident, evidence=[evidence], audit_event=audit
                )
            else:
                await self._incident_repo.attach_evidence_atomic(
                    tenant_id=context.tenant_id,
                    incident_id=incident_id,
                    evidence=evidence,
                    audit_event=audit,
                )

            if incident_id in seen_incidents:
                continue
            seen_incidents.add(incident_id)
            incident_ids.append(incident_id)

            actions: List[ContainmentAction] = []
            if eval_request.record_id:
                actions.append(
                    ContainmentAction(
                        containment_type=ContainmentType.MEMORY_QUARANTINE,
                        target_id=eval_request.record_id,
                    )
                )
            if eval_request.agent_id:
                actions.append(
                    ContainmentAction(
                        containment_type=ContainmentType.AGENT_SUSPENSION,
                        target_id=eval_request.agent_id,
                    )
                )
            for res in target_resources:
                rtype = res.get("resource_type")
                rid = res.get("resource_id")
                if rtype and rid:
                    actions.append(
                        ContainmentAction(
                            containment_type=ContainmentType.RESOURCE_ISOLATION,
                            target_id=rid,
                            details={"resource_type": rtype},
                        )
                    )

            if actions:
                c_req = ContainmentRequest(
                    incident_id=incident_id,
                    containment_actions=tuple(actions),
                    reason=f"Automated deterministic containment for {category} ({reason_code})",
                    reason_code=ContainmentReasonCode.AUTOMATED_DETECTION,
                    evidence_refs=(evidence_id,),
                    trace_id=trace_id or finding.trace_id,
                )
                outcome = await self._containment_service.apply_containment(
                    context,
                    c_req,
                    persist_evidence=self._persist_evidence,
                )
                containment_outcomes.append(outcome)

        all_ok = all(
            o.success and o.status in {ContainmentStatus.APPLIED, ContainmentStatus.ALREADY_APPLIED}
            for o in containment_outcomes
        )
        return {
            "triggered": True,
            "contained": all_ok and bool(containment_outcomes),
            "detection_ids": persisted_detection_ids,
            "incident_ids": incident_ids,
            "containment_outcomes": containment_outcomes,
            "ml_advisory": ml_advisory,
        }


__all__ = ["DetectionToContainmentOrchestrator"]
