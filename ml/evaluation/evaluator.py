"""Reproducible Phase 4 Evaluation Framework & Baseline Comparison.

Evaluates:
1. Held-out Injection/Poisoning test split (Deterministic regex vs +ML).
2. Held-out Semantic Drift test split (Deterministic rules vs +ML).
3. End-to-End 12-Scenario Enterprise Validation Suite (Deterministic vs +ML).
4. Adversarial Robustness (Unicode homoglyphs, whitespace obfuscation, benign padding).
5. Latency (mean, p50, p95, p99 ms), memory footprint, and calibration (ECE, Brier).
"""

from __future__ import annotations

import asyncio
import json
import math
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from backend.app.security.detection import (
    DetectionClassificationType,
    DetectionEngine,
    RecommendedOutcome,
)
from ml.datasets.enterprise_benchmark import (
    ENTERPRISE_BASELINES,
    EvaluationScenarioCase,
    build_12_scenario_evaluation_suite,
    build_injection_dataset,
    build_semantic_dataset,
)
from ml.inference.service import MLSecurityIntelligenceService
from ml.security_baseline_helpers import InMemoryEvalBaselineRepo


@dataclass(frozen=True)
class BinaryMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confusion_matrix": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
            "fnr": round(self.fnr, 4),
        }


def compute_binary_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> BinaryMetrics:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    return BinaryMetrics(tp=tp, fp=fp, tn=tn, fn=fn, precision=precision, recall=recall, f1=f1, fpr=fpr, fnr=fnr)


def compute_calibration_metrics(y_true: Sequence[int], y_prob: Sequence[float], n_bins: int = 5) -> Dict[str, float]:
    if not y_true:
        return {"ece": 0.0, "brier_score": 0.0}
    n = len(y_true)
    brier = sum((p - y) ** 2 for y, p in zip(y_true, y_prob)) / n
    ece = 0.0
    for b in range(n_bins):
        lo = b / n_bins
        hi = (b + 1) / n_bins
        in_bin = [
            (y, p)
            for y, p in zip(y_true, y_prob)
            if (lo <= p < hi) or (b == n_bins - 1 and p == 1.0)
        ]
        if in_bin:
            acc = sum(y for y, _ in in_bin) / len(in_bin)
            conf = sum(p for _, p in in_bin) / len(in_bin)
            ece += (len(in_bin) / n) * abs(acc - conf)
    return {"ece": round(ece, 4), "brier_score": round(brier, 4)}


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(math.ceil((pct / 100.0) * len(sorted_vals))) - 1)
    return sorted_vals[max(0, idx)]


def _is_flagged(findings: Sequence[Any]) -> int:
    for f in findings:
        if f.classification_type in (
            DetectionClassificationType.SUSPICIOUS_INDICATOR,
            DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
            DetectionClassificationType.CONFIRMED_SECURITY_INCIDENT,
        ) or f.recommended_outcome in (
            RecommendedOutcome.BLOCK,
            RecommendedOutcome.REQUIRE_HUMAN_APPROVAL,
            RecommendedOutcome.QUARANTINE_RECORD,
        ):
            return 1
    return 0


async def _evaluate_single_case(
    engine: DetectionEngine,
    ml_svc: Optional[MLSecurityIntelligenceService],
    case: EvaluationScenarioCase,
) -> Tuple[int, float]:
    t0 = time.perf_counter_ns()
    findings: List[Any] = []

    if case.content is not None:
        findings.extend(
            await engine.detect_memory_integrity(
                tenant_id=case.tenant_id,
                content=case.content,
                agent_id=case.agent_id,
                branch_id=case.branch_id,
            )
        )

    if case.claim_text is not None:
        findings.extend(
            await engine.detect_semantic_integrity(
                tenant_id=case.tenant_id,
                claim_text=case.claim_text,
                source_text=case.source_text,
                referenced_baseline_id=case.baseline_id,
                agent_id=case.agent_id,
                branch_id=case.branch_id,
            )
        )

    if case.sequence_events:
        # Replay sequence events up to the final event
        for ev in case.sequence_events[:-1]:
            if ml_svc is not None and engine.enable_ml_advisory:
                ml_svc.assess_behavioral_anomaly(
                    tenant_id=ev.tenant_id,
                    agent_id=ev.agent_id,
                    tool_name=ev.tool_name,
                    operation=ev.operation,
                    parameters={"amount": ev.amount} if ev.amount is not None else {},
                    branch_id=ev.branch_id,
                    department=ev.department,
                    timestamp=ev.timestamp,
                    record_in_window=True,
                )
            # Also feed deterministic burst tracker
            findings_det = await engine.detect_behavioral_deviation(
                tenant_id=ev.tenant_id,
                agent_id=ev.agent_id,
                proposal_facts={
                    "tool_name": ev.tool_name,
                    "operation": ev.operation,
                    "parameters": {"amount": ev.amount} if ev.amount is not None else {},
                },
                profile=case.agent_profile,
            )
            _ = findings_det

        last_ev = case.sequence_events[-1]
        findings.extend(
            await engine.detect_behavioral_deviation(
                tenant_id=last_ev.tenant_id,
                agent_id=last_ev.agent_id,
                proposal_facts={
                    "tool_name": last_ev.tool_name,
                    "operation": last_ev.operation,
                    "parameters": {"amount": last_ev.amount, **(case.parameters or {})}
                    if last_ev.amount is not None
                    else case.parameters,
                },
                profile=case.agent_profile,
            )
        )
    elif case.tool_name and case.operation:
        findings.extend(
            await engine.detect_behavioral_deviation(
                tenant_id=case.tenant_id,
                agent_id=case.agent_id,
                proposal_facts={
                    "tool_name": case.tool_name,
                    "operation": case.operation,
                    "parameters": case.parameters,
                },
                profile=case.agent_profile,
            )
        )

    elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    return _is_flagged(findings), elapsed_ms


async def run_full_evaluation() -> Dict[str, Any]:
    """Run reproducible Phase 4 evaluation comparing Deterministic Baseline vs +ML."""
    baseline_repo = InMemoryEvalBaselineRepo(ENTERPRISE_BASELINES)

    # 1. Held-out Injection/Poisoning Test Split
    inj_test = [s for s in build_injection_dataset() if s.split == "test"]
    det_only_engine = DetectionEngine(baseline_repo=baseline_repo, enable_ml_advisory=False)
    ml_svc = MLSecurityIntelligenceService()
    ml_enabled_engine = DetectionEngine(baseline_repo=baseline_repo, enable_ml_advisory=True)
    # Share ml_svc instance so sequence windows are observable
    from backend.app.security.ml_intelligence import MLAdvisoryDetector
    ml_enabled_engine.ml_detector = MLAdvisoryDetector(ml_service=ml_svc)

    inj_y_true = [s.label for s in inj_test]
    inj_det_pred: List[int] = []
    inj_ml_pred: List[int] = []
    inj_ml_probs: List[float] = []
    inj_latencies: List[float] = []

    for s in inj_test:
        f_det = await det_only_engine.detect_memory_integrity(tenant_id="tenant-chronocorp-001", content=s.text)
        inj_det_pred.append(_is_flagged(f_det))

        t0 = time.perf_counter_ns()
        f_ml = await ml_enabled_engine.detect_memory_integrity(tenant_id="tenant-chronocorp-001", content=s.text)
        inj_latencies.append((time.perf_counter_ns() - t0) / 1_000_000.0)
        inj_ml_pred.append(_is_flagged(f_ml))

        a = ml_svc.assess_text_injection_and_poisoning(tenant_id="tenant-chronocorp-001", text=s.text)
        inj_ml_probs.append(float(a.risk_score or 0.0))

    # 2. Held-out Semantic Drift Test Split
    sem_test = [s for s in build_semantic_dataset() if s.split == "test"]
    sem_y_true = [s.label for s in sem_test]
    sem_det_pred: List[int] = []
    sem_ml_pred: List[int] = []
    sem_ml_probs: List[float] = []

    for s in sem_test:
        f_det = await det_only_engine.detect_semantic_integrity(
            tenant_id="tenant-chronocorp-001",
            claim_text=s.claim_text,
            source_text=s.reference_text,
            referenced_baseline_id=s.baseline_id,
        )
        sem_det_pred.append(_is_flagged(f_det))

        f_ml = await ml_enabled_engine.detect_semantic_integrity(
            tenant_id="tenant-chronocorp-001",
            claim_text=s.claim_text,
            source_text=s.reference_text,
            referenced_baseline_id=s.baseline_id,
        )
        sem_ml_pred.append(_is_flagged(f_ml))

        a = ml_svc.assess_semantic_drift(
            tenant_id="tenant-chronocorp-001",
            claim_text=s.claim_text,
            reference_text=s.reference_text,
        )
        sem_ml_probs.append(float(a.risk_score or 0.0))

    # 3. End-to-End 12-Scenario Suite
    suite = build_12_scenario_evaluation_suite()
    tracemalloc.start()
    s12_y_true: List[int] = []
    s12_det_pred: List[int] = []
    s12_ml_pred: List[int] = []
    s12_latencies: List[float] = []
    per_scenario: List[Dict[str, Any]] = []

    for case in suite:
        s12_y_true.append(case.label)
        det_p, _ = await _evaluate_single_case(det_only_engine, None, case)
        ml_p, lat_ms = await _evaluate_single_case(ml_enabled_engine, ml_svc, case)
        s12_det_pred.append(det_p)
        s12_ml_pred.append(ml_p)
        s12_latencies.append(lat_ms)
        per_scenario.append({
            "case_id": case.case_id,
            "scenario": case.scenario,
            "expected_label": case.label,
            "deterministic_pred": det_p,
            "ml_assisted_pred": ml_p,
            "latency_ms": round(lat_ms, 3),
        })

    _, peak_mem_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # 4. Adversarial Perturbation Robustness on Held-Out Injection Positives
    adv_positives = [s for s in inj_test if s.label == 1]
    adv_variants: List[Tuple[str, str]] = []
    for s in adv_positives:
        # Unicode fullwidth homoglyph + extra spacing + benign prefix
        homoglyph = s.text.replace("a", "\uff41").replace("e", "\uff45")
        adv_variants.append(("homoglyph_nfkc", homoglyph))
        adv_variants.append(("whitespace_obfuscated", "  ".join(s.text.split())))
        adv_variants.append(("benign_padding", "Lahore branch monthly compliance summary. " + s.text))

    adv_det_hits = 0
    adv_ml_hits = 0
    for _, vtext in adv_variants:
        if _is_flagged(await det_only_engine.detect_memory_integrity(tenant_id="tenant-chronocorp-001", content=vtext)):
            adv_det_hits += 1
        if _is_flagged(await ml_enabled_engine.detect_memory_integrity(tenant_id="tenant-chronocorp-001", content=vtext)):
            adv_ml_hits += 1

    sorted_lat = sorted(s12_latencies + inj_latencies)

    return {
        "injection_heldout_test": {
            "sample_count": len(inj_test),
            "deterministic_baseline": compute_binary_metrics(inj_y_true, inj_det_pred).to_dict(),
            "deterministic_plus_ml": compute_binary_metrics(inj_y_true, inj_ml_pred).to_dict(),
            "calibration": compute_calibration_metrics(inj_y_true, inj_ml_probs),
        },
        "semantic_drift_heldout_test": {
            "sample_count": len(sem_test),
            "deterministic_baseline": compute_binary_metrics(sem_y_true, sem_det_pred).to_dict(),
            "deterministic_plus_ml": compute_binary_metrics(sem_y_true, sem_ml_pred).to_dict(),
            "calibration": compute_calibration_metrics(sem_y_true, sem_ml_probs),
        },
        "twelve_scenario_suite": {
            "scenario_count": len(suite),
            "deterministic_baseline": compute_binary_metrics(s12_y_true, s12_det_pred).to_dict(),
            "deterministic_plus_ml": compute_binary_metrics(s12_y_true, s12_ml_pred).to_dict(),
            "per_scenario": per_scenario,
        },
        "adversarial_robustness": {
            "variant_count": len(adv_variants),
            "deterministic_recall": round(adv_det_hits / max(1, len(adv_variants)), 4),
            "ml_assisted_recall": round(adv_ml_hits / max(1, len(adv_variants)), 4),
        },
        "performance_and_resources": {
            "mean_latency_ms": round(sum(sorted_lat) / max(1, len(sorted_lat)), 3),
            "p50_latency_ms": round(_percentile(sorted_lat, 50), 3),
            "p95_latency_ms": round(_percentile(sorted_lat, 95), 3),
            "p99_latency_ms": round(_percentile(sorted_lat, 99), 3),
            "peak_traced_memory_kb": round(peak_mem_bytes / 1024.0, 2),
        },
    }


if __name__ == "__main__":
    report = asyncio.run(run_full_evaluation())
    print(json.dumps(report, indent=2))
