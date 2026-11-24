"""Backend Security Adapter for Phase 4 ML Advisory Intelligence.

Module: backend.app.security.ml_intelligence
Owner: M4 — Security Engine & Incident Response Lead

Converts framework-neutral ``MLAdvisoryAssessment`` objects from
``ml.inference.service`` into canonical AMSC ``DetectionResult`` findings.

Architectural Invariant:
- ML findings are strictly advisory (``SUSPICIOUS_INDICATOR`` with
  ``PROBABILISTIC_INDICATOR`` or ``INDETERMINATE``).
- ML NEVER emits ``ALLOW`` to override a deterministic ``BLOCK``, NEVER
  mutates memory trust state, and NEVER modifies enterprise baselines.
"""

from __future__ import annotations

import uuid
from typing import Any, List, Mapping, Optional

from backend.app.security.detection import (
    DetectionCategory,
    DetectionClassificationType,
    DetectionMethod,
    DetectionResult,
    DetectionSeverity,
    EvidenceItem,
    RecommendedOutcome,
    UncertaintyState,
)
from ml.inference.service import MLAdvisoryAssessment, MLSecurityIntelligenceService


class MLAdvisoryDetector:
    """Thin M4-owned adapter bridging ``MLSecurityIntelligenceService`` to ``DetectionResult``."""

    def __init__(self, ml_service: Optional[MLSecurityIntelligenceService] = None) -> None:
        self.ml_service = ml_service or MLSecurityIntelligenceService()

    def assessment_to_detection(
        self,
        assessment: MLAdvisoryAssessment,
        *,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        action_id: Optional[str] = None,
        memory_refs: Optional[List[str]] = None,
        baseline_refs: Optional[List[str]] = None,
    ) -> Optional[DetectionResult]:
        """Convert an advisory assessment to a ``DetectionResult`` if suspicious or indeterminate."""
        if not assessment.is_suspicious and not assessment.fallback_used:
            return None

        if assessment.capability == "INJECTION_POISONING":
            category = DetectionCategory.PROMPT_INJECTION
            method = DetectionMethod.HEURISTIC_PATTERN
            title = "ML Advisory: Potential Indirect Prompt Injection or Memory Poisoning"
            reason_code = "ML_INJECTION_POISONING_ADVISORY"
        elif assessment.capability == "SEMANTIC_DRIFT":
            category = DetectionCategory.SEMANTIC_INTEGRITY
            method = DetectionMethod.SEMANTIC_GROUNDING
            title = "ML Advisory: Semantic Drift or Unsupported Claim Risk"
            reason_code = "ML_SEMANTIC_DRIFT_ADVISORY"
        else:
            category = DetectionCategory.BEHAVIORAL_DEVIATION
            method = DetectionMethod.STATISTICAL_FREQUENCY
            title = "ML Advisory: Behavioral or Execution-Sequence Anomaly"
            reason_code = "ML_BEHAVIORAL_ANOMALY_ADVISORY"

        if assessment.fallback_used:
            uncertainty = UncertaintyState.INDETERMINATE
            severity = DetectionSeverity.MEDIUM
            score = 0.0
            desc = (
                f"ML advisory model '{assessment.model_id}' entered safe deterministic fallback "
                f"({assessment.fallback_reason}). Human review recommended if deterministic checks are inconclusive."
            )
            reason_code = "ML_MODEL_FALLBACK_INDETERMINATE"
        else:
            uncertainty = UncertaintyState.PROBABILISTIC_INDICATOR
            score = float(assessment.risk_score or 0.0)
            severity = DetectionSeverity.HIGH if score >= 0.75 else DetectionSeverity.MEDIUM
            desc = (
                f"ML advisory model '{assessment.model_id}' ({assessment.model_version}) flagged "
                f"suspicious pattern with calibrated score {score:.3f}. Advisory signal only; "
                "deterministic policy remains authoritative."
            )

        return DetectionResult(
            id=f"det-ml-{uuid.uuid4().hex[:14]}",
            tenant_id=assessment.tenant_id,
            branch_id=assessment.branch_id,
            detection_category=category,
            classification_type=DetectionClassificationType.SUSPICIOUS_INDICATOR,
            agent_id=agent_id,
            trace_id=trace_id,
            action_id=action_id,
            detection_method=method,
            confidence_score=score,
            uncertainty_state=uncertainty,
            severity=severity,
            recommended_outcome=RecommendedOutcome.REQUIRE_HUMAN_APPROVAL,
            title=title,
            description=desc,
            memory_refs=memory_refs or [],
            baseline_refs=baseline_refs or [],
            evidence_items=[
                EvidenceItem(
                    evidence_type="ML_ADVISORY_SIGNAL",
                    description=f"Advisory output from {assessment.model_id} ({assessment.model_version}).",
                    metadata={
                        "advisory_only": True,
                        "model_id": assessment.model_id,
                        "model_version": assessment.model_version,
                        "risk_score": score,
                        "fallback_used": assessment.fallback_used,
                        "latency_ms": round(assessment.latency_ms, 3),
                        **assessment.evidence,
                    },
                )
            ],
            details={
                "reason_code": reason_code,
                "advisory_only": True,
                "model_id": assessment.model_id,
                "model_version": assessment.model_version,
                "fallback_used": assessment.fallback_used,
            },
        )

    def evaluate_content(
        self,
        *,
        tenant_id: str,
        content: str,
        branch_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        action_id: Optional[str] = None,
        memory_refs: Optional[List[str]] = None,
    ) -> Optional[DetectionResult]:
        assessment = self.ml_service.assess_text_injection_and_poisoning(
            tenant_id=tenant_id,
            text=content,
            branch_id=branch_id,
        )
        return self.assessment_to_detection(
            assessment,
            agent_id=agent_id,
            trace_id=trace_id,
            action_id=action_id,
            memory_refs=memory_refs,
        )

    def evaluate_semantic_pair(
        self,
        *,
        tenant_id: str,
        claim_text: str,
        reference_text: str,
        branch_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        action_id: Optional[str] = None,
        baseline_refs: Optional[List[str]] = None,
    ) -> Optional[DetectionResult]:
        assessment = self.ml_service.assess_semantic_drift(
            tenant_id=tenant_id,
            claim_text=claim_text,
            reference_text=reference_text,
            branch_id=branch_id,
        )
        return self.assessment_to_detection(
            assessment,
            agent_id=agent_id,
            trace_id=trace_id,
            action_id=action_id,
            baseline_refs=baseline_refs,
        )

    def evaluate_behavior(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        tool_name: str,
        operation: str,
        parameters: Optional[Mapping[str, Any]] = None,
        branch_id: Optional[str] = None,
        department: Optional[str] = None,
        timestamp: Optional[float] = None,
        trace_id: Optional[str] = None,
        action_id: Optional[str] = None,
        record_in_window: bool = True,
    ) -> Optional[DetectionResult]:
        assessment = self.ml_service.assess_behavioral_anomaly(
            tenant_id=tenant_id,
            agent_id=agent_id,
            tool_name=tool_name,
            operation=operation,
            parameters=parameters,
            branch_id=branch_id,
            department=department,
            timestamp=timestamp,
            record_in_window=record_in_window,
        )
        return self.assessment_to_detection(
            assessment,
            agent_id=agent_id,
            trace_id=trace_id,
            action_id=action_id,
        )


_default_ml_advisory_detector: Optional[MLAdvisoryDetector] = None


def get_default_ml_advisory_detector() -> MLAdvisoryDetector:
    global _default_ml_advisory_detector
    if _default_ml_advisory_detector is None:
        _default_ml_advisory_detector = MLAdvisoryDetector()
    return _default_ml_advisory_detector
