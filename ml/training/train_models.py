"""Reproducible Training & Calibration Pipeline for AMSC Phase 4 ML Models.

Trains only on the designated ``train`` split, calibrates temperature on ``val``,
never touches ``test``, and persists SHA-256-verified artifacts into
``ml/model_registry/artifacts/``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from ml.datasets.enterprise_benchmark import (
    build_behavioral_training_sequences,
    build_injection_dataset,
    build_semantic_dataset,
)
from ml.model_registry.registry import ModelRegistry
from ml.models.anomaly_detector.sequence_anomaly_model import BehavioralSequenceAnomalyDetector
from ml.models.injection_detector.model import TfidfLinearInjectionClassifier
from ml.models.memory_trust.semantic_drift_model import SemanticDriftAndClaimAnalyzer
from ml.preprocessing.text_sanitizer import sanitize_text_for_ml


def train_and_register_all(registry_dir: Path | None = None) -> Dict[str, str]:
    """Train all 3 Phase 4 ML models on train/val splits and register artifacts."""
    registry = ModelRegistry(registry_dir=registry_dir)

    # 1. Injection & Poisoning Classifier
    inj_data = build_injection_dataset()
    inj_train = [s for s in inj_data if s.split == "train"]
    inj_val = [s for s in inj_data if s.split == "val"]

    inj_model = TfidfLinearInjectionClassifier(version="injection-lr/1.0.0", threshold=0.46)
    inj_model.fit(
        [sanitize_text_for_ml(s.text)[0] for s in inj_train],
        [s.label for s in inj_train],
        max_vocab=2500,
        min_df=1,
        l2_reg=0.4,
        lr=0.6,
        epochs=250,
        val_texts=[sanitize_text_for_ml(s.text)[0] for s in inj_val],
        val_labels=[s.label for s in inj_val],
    )
    inj_meta = registry.save_artifact(
        model_id="injection_detector",
        version=inj_model.version,
        algorithm="TF-IDF (word 1-2, char 3-5) + L2 Logistic Regression + Temperature Scaling",
        payload=inj_model.to_dict(),
        trained_on_dataset="enterprise_benchmark_v1:injection_train+val",
        metrics={"train_size": len(inj_train), "val_size": len(inj_val), "temperature": inj_model.temperature},
    )

    # 2. Semantic Drift & Unsupported-Claim Analyzer
    sem_data = build_semantic_dataset()
    sem_train = [s for s in sem_data if s.split == "train"]
    sem_val = [s for s in sem_data if s.split == "val"]

    sem_model = SemanticDriftAndClaimAnalyzer(version="semantic-drift-lr/1.0.0", threshold=0.50)
    sem_model.fit(
        [(s.claim_text, s.reference_text) for s in sem_train],
        [s.label for s in sem_train],
        l2_reg=0.3,
        lr=0.8,
        epochs=250,
        val_pairs=[(s.claim_text, s.reference_text) for s in sem_val],
        val_labels=[s.label for s in sem_val],
    )
    sem_meta = registry.save_artifact(
        model_id="semantic_drift_analyzer",
        version=sem_model.version,
        algorithm="SemanticPairFeatures + L2 Logistic Regression + Temperature Scaling",
        payload=sem_model.to_dict(),
        trained_on_dataset="enterprise_benchmark_v1:semantic_train+val",
        metrics={"train_size": len(sem_train), "val_size": len(sem_val), "temperature": sem_model.temperature},
    )

    # 3. Behavioral & Execution-Sequence Anomaly Detector (Unsupervised)
    beh_seqs = build_behavioral_training_sequences()
    beh_model = BehavioralSequenceAnomalyDetector(version="behavior-markov-z/1.0.0", threshold=0.62)
    beh_model.fit_sequences(beh_seqs)
    beh_meta = registry.save_artifact(
        model_id="behavioral_anomaly_detector",
        version=beh_model.version,
        algorithm="Role-Conditioned First-Order Markov + Action Frequency + Amount Z-Score",
        payload=beh_model.to_dict(),
        trained_on_dataset="enterprise_benchmark_v1:behavioral_benign_sequences",
        metrics={"sequence_count": len(beh_seqs), "departments": sorted(beh_model.baselines.keys())},
    )

    return {
        "injection_detector": inj_meta.sha256,
        "semantic_drift_analyzer": sem_meta.sha256,
        "behavioral_anomaly_detector": beh_meta.sha256,
    }


if __name__ == "__main__":
    digests = train_and_register_all()
    print(json.dumps(digests, indent=2))
