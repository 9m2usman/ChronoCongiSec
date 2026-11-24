"""Framework-Neutral ML Security Intelligence Inference Service.

Provides validated, tenant- and branch-isolated, timeout-bounded, and
integrity-verified ML advisory scoring.

Invariants:
- All outputs are strictly advisory (``advisory_only=True``).
- Never grants permissions, modifies baselines, or promotes memory trust.
- Model failures, timeouts, corrupted artifacts, or invalid outputs fail
  safely to ``uncertainty_state="INDETERMINATE"`` with ``fallback_used=True``.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from ml.features.extractor import BehavioralEvent, extract_behavioral_event
from ml.model_registry.registry import ModelIntegrityError, ModelRegistry
from ml.models.anomaly_detector.sequence_anomaly_model import BehavioralSequenceAnomalyDetector
from ml.models.injection_detector.model import TfidfLinearInjectionClassifier
from ml.models.memory_trust.semantic_drift_model import SemanticDriftAndClaimAnalyzer
from ml.preprocessing.text_sanitizer import redact_sensitive_text, sanitize_text_for_ml

logger = logging.getLogger("amsc.ml.inference")


@dataclass(frozen=True)
class MLAdvisoryAssessment:
    """Standardized, framework-neutral ML advisory output contract."""

    capability: str  # "INJECTION_POISONING", "SEMANTIC_DRIFT", "BEHAVIORAL_ANOMALY"
    tenant_id: str
    branch_id: Optional[str]
    risk_score: Optional[float]  # [0.0, 1.0], None when INDETERMINATE
    is_suspicious: bool
    uncertainty_state: str  # "PROBABILISTIC_INDICATOR" | "INDETERMINATE"
    recommended_advisory_action: str  # "NONE" | "ALERT_ONLY" | "REQUIRE_HUMAN_APPROVAL"
    model_id: str
    model_version: str
    advisory_only: bool = True
    fallback_used: bool = False
    fallback_reason: Optional[str] = None
    latency_ms: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability,
            "tenant_id": self.tenant_id,
            "branch_id": self.branch_id,
            "risk_score": round(self.risk_score, 6) if self.risk_score is not None else None,
            "is_suspicious": self.is_suspicious,
            "uncertainty_state": self.uncertainty_state,
            "recommended_advisory_action": self.recommended_advisory_action,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "advisory_only": True,
            "fallback_used": self.fallback_used,
            "fallback_reason": self.fallback_reason,
            "latency_ms": round(self.latency_ms, 3),
            "evidence": self.evidence,
        }


def _validate_probability(score: Any) -> float:
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError(f"Invalid non-numeric model score: {score!r}")
    val = float(score)
    if not math.isfinite(val) or val < 0.0 or val > 1.0:
        raise ValueError(f"Model score out of bounds [0, 1]: {val!r}")
    return val


class MLSecurityIntelligenceService:
    """Thread-safe, integrity-verified ML advisory service with deterministic fallback."""

    def __init__(
        self,
        registry_dir: Optional[Path] = None,
        timeout_ms: float = 100.0,
    ) -> None:
        self.registry = ModelRegistry(registry_dir=registry_dir)
        self.timeout_ms = timeout_ms
        self._injection_model: Optional[TfidfLinearInjectionClassifier] = None
        self._semantic_model: Optional[SemanticDriftAndClaimAnalyzer] = None
        self._behavioral_model: Optional[BehavioralSequenceAnomalyDetector] = None
        self._load_errors: Dict[str, str] = {}
        self._load_models()

    def _load_models(self) -> None:
        self._load_errors.clear()
        try:
            _, data = self.registry.load_artifact("injection_detector")
            self._injection_model = TfidfLinearInjectionClassifier.from_dict(data)
        except (ModelIntegrityError, Exception) as exc:
            self._injection_model = None
            self._load_errors["injection_detector"] = f"load_error:{type(exc).__name__}"

        try:
            _, data = self.registry.load_artifact("semantic_drift_analyzer")
            self._semantic_model = SemanticDriftAndClaimAnalyzer.from_dict(data)
        except (ModelIntegrityError, Exception) as exc:
            self._semantic_model = None
            self._load_errors["semantic_drift_analyzer"] = f"load_error:{type(exc).__name__}"

        try:
            _, data = self.registry.load_artifact("behavioral_anomaly_detector")
            self._behavioral_model = BehavioralSequenceAnomalyDetector.from_dict(data)
        except (ModelIntegrityError, Exception) as exc:
            self._behavioral_model = None
            self._load_errors["behavioral_anomaly_detector"] = f"load_error:{type(exc).__name__}"

    def _fallback(
        self,
        capability: str,
        tenant_id: str,
        branch_id: Optional[str],
        model_id: str,
        reason: str,
        start_ns: int,
    ) -> MLAdvisoryAssessment:
        elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        logger.warning("ML fallback activated for %s (%s): %s", capability, model_id, reason)
        return MLAdvisoryAssessment(
            capability=capability,
            tenant_id=tenant_id,
            branch_id=branch_id,
            risk_score=None,
            is_suspicious=False,
            uncertainty_state="INDETERMINATE",
            recommended_advisory_action="REQUIRE_HUMAN_APPROVAL",
            model_id=model_id,
            model_version="fallback/deterministic",
            advisory_only=True,
            fallback_used=True,
            fallback_reason=reason,
            latency_ms=elapsed,
            evidence={"fallback_reason": reason},
        )

    def assess_text_injection_and_poisoning(
        self,
        *,
        tenant_id: str,
        text: str,
        branch_id: Optional[str] = None,
    ) -> MLAdvisoryAssessment:
        start_ns = time.perf_counter_ns()
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError("tenant_id is required")

        if self._injection_model is None:
            return self._fallback(
                "INJECTION_POISONING",
                tenant_id,
                branch_id,
                "injection_detector",
                self._load_errors.get("injection_detector", "model_unavailable"),
                start_ns,
            )

        try:
            clean, truncated = sanitize_text_for_ml(text)
            pred = self._injection_model.predict(clean)
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            if elapsed > self.timeout_ms:
                return self._fallback(
                    "INJECTION_POISONING",
                    tenant_id,
                    branch_id,
                    "injection_detector",
                    f"inference_timeout:{elapsed:.2f}ms>{self.timeout_ms}ms",
                    start_ns,
                )
            prob = _validate_probability(pred.probability)
            thresh = _validate_probability(pred.threshold)
            if not isinstance(pred.is_suspicious, bool) or pred.is_suspicious != (prob >= thresh):
                raise ValueError("Inconsistent model decision vs probability/threshold")
            action = "REQUIRE_HUMAN_APPROVAL" if pred.is_suspicious else "NONE"
            return MLAdvisoryAssessment(
                capability="INJECTION_POISONING",
                tenant_id=tenant_id,
                branch_id=branch_id,
                risk_score=prob,
                is_suspicious=bool(pred.is_suspicious),
                uncertainty_state="PROBABILISTIC_INDICATOR",
                recommended_advisory_action=action,
                model_id="injection_detector",
                model_version=pred.model_version,
                advisory_only=True,
                fallback_used=False,
                latency_ms=elapsed,
                evidence={
                    "threshold": pred.threshold,
                    "was_truncated": truncated,
                    "top_features": [
                        [redact_sensitive_text(k), v] for k, v in pred.top_contributing_features
                    ],
                },
            )
        except Exception as exc:
            return self._fallback(
                "INJECTION_POISONING",
                tenant_id,
                branch_id,
                "injection_detector",
                f"inference_error:{type(exc).__name__}",
                start_ns,
            )

    def assess_semantic_drift(
        self,
        *,
        tenant_id: str,
        claim_text: str,
        reference_text: str,
        branch_id: Optional[str] = None,
    ) -> MLAdvisoryAssessment:
        start_ns = time.perf_counter_ns()
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError("tenant_id is required")

        if self._semantic_model is None:
            return self._fallback(
                "SEMANTIC_DRIFT",
                tenant_id,
                branch_id,
                "semantic_drift_analyzer",
                self._load_errors.get("semantic_drift_analyzer", "model_unavailable"),
                start_ns,
            )

        try:
            clean_claim, t1 = sanitize_text_for_ml(claim_text)
            clean_ref, t2 = sanitize_text_for_ml(reference_text)
            pred = self._semantic_model.predict(clean_claim, clean_ref)
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            if elapsed > self.timeout_ms:
                return self._fallback(
                    "SEMANTIC_DRIFT",
                    tenant_id,
                    branch_id,
                    "semantic_drift_analyzer",
                    f"inference_timeout:{elapsed:.2f}ms>{self.timeout_ms}ms",
                    start_ns,
                )
            prob = _validate_probability(pred.drift_risk_score)
            thresh = _validate_probability(pred.threshold)
            if not isinstance(pred.is_suspicious, bool) or pred.is_suspicious != (prob >= thresh):
                raise ValueError("Inconsistent semantic model decision vs probability/threshold")
            action = "REQUIRE_HUMAN_APPROVAL" if pred.is_suspicious else "NONE"
            return MLAdvisoryAssessment(
                capability="SEMANTIC_DRIFT",
                tenant_id=tenant_id,
                branch_id=branch_id,
                risk_score=prob,
                is_suspicious=bool(pred.is_suspicious),
                uncertainty_state="PROBABILISTIC_INDICATOR",
                recommended_advisory_action=action,
                model_id="semantic_drift_analyzer",
                model_version=pred.model_version,
                advisory_only=True,
                fallback_used=False,
                latency_ms=elapsed,
                evidence={
                    "threshold": pred.threshold,
                    "was_truncated": t1 or t2,
                    "features": pred.features,
                    "top_risk_factors": [[k, v] for k, v in pred.top_risk_factors],
                },
            )
        except Exception as exc:
            return self._fallback(
                "SEMANTIC_DRIFT",
                tenant_id,
                branch_id,
                "semantic_drift_analyzer",
                f"inference_error:{type(exc).__name__}",
                start_ns,
            )

    def assess_behavioral_anomaly(
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
        record_in_window: bool = True,
    ) -> MLAdvisoryAssessment:
        start_ns = time.perf_counter_ns()
        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError("tenant_id is required")

        if self._behavioral_model is None:
            return self._fallback(
                "BEHAVIORAL_ANOMALY",
                tenant_id,
                branch_id,
                "behavioral_anomaly_detector",
                self._load_errors.get("behavioral_anomaly_detector", "model_unavailable"),
                start_ns,
            )

        try:
            ev: BehavioralEvent = extract_behavioral_event(
                tenant_id=tenant_id,
                agent_id=agent_id,
                tool_name=tool_name,
                operation=operation,
                parameters=parameters,
                branch_id=branch_id,
                department=department,
                timestamp=timestamp,
            )
            pred = self._behavioral_model.score_event(ev, record_in_window=record_in_window)
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            if elapsed > self.timeout_ms:
                return self._fallback(
                    "BEHAVIORAL_ANOMALY",
                    tenant_id,
                    branch_id,
                    "behavioral_anomaly_detector",
                    f"inference_timeout:{elapsed:.2f}ms>{self.timeout_ms}ms",
                    start_ns,
                )
            prob = _validate_probability(pred.anomaly_score)
            thresh = _validate_probability(pred.threshold)
            if not isinstance(pred.is_anomalous, bool) or pred.is_anomalous != (prob >= thresh):
                raise ValueError("Inconsistent behavioral model decision vs score/threshold")
            action = "REQUIRE_HUMAN_APPROVAL" if pred.is_anomalous else "NONE"
            return MLAdvisoryAssessment(
                capability="BEHAVIORAL_ANOMALY",
                tenant_id=tenant_id,
                branch_id=branch_id,
                risk_score=prob,
                is_suspicious=bool(pred.is_anomalous),
                uncertainty_state="PROBABILISTIC_INDICATOR",
                recommended_advisory_action=action,
                model_id="behavioral_anomaly_detector",
                model_version=pred.model_version,
                advisory_only=True,
                fallback_used=False,
                latency_ms=elapsed,
                evidence={
                    "threshold": pred.threshold,
                    "sequence_surprise": pred.sequence_surprise,
                    "frequency_surprise": pred.frequency_surprise,
                    "parameter_zscore": pred.parameter_zscore,
                    "burst_score": pred.burst_score,
                    "reason_factors": [redact_sensitive_text(r) for r in pred.reason_factors],
                },
            )
        except Exception as exc:
            return self._fallback(
                "BEHAVIORAL_ANOMALY",
                tenant_id,
                branch_id,
                "behavioral_anomaly_detector",
                f"inference_error:{type(exc).__name__}",
                start_ns,
            )
