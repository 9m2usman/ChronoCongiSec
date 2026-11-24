"""Semantic Drift, Contradiction & Unsupported-Claim Risk Analyzer.

Evaluates derived memory or agent claims against approved enterprise baseline
records or source documents using a calibrated L2-regularized Logistic
Regression over semantic similarity, entity coverage, constraint preservation,
negation flip, permissive expansion, and numeric discrepancy features.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from ml.features.extractor import SemanticPairFeatures, extract_semantic_pair_features

_FEATURE_NAMES: Tuple[str, ...] = (
    "cosine_similarity",
    "entity_coverage",
    "constraint_preservation",
    "negation_flip",
    "permissive_expansion",
    "numeric_expansion_ratio",
    "length_ratio",
)


def _sigmoid(z: float) -> float:
    if z >= 35.0:
        return 1.0 - 1e-15
    if z <= -35.0:
        return 1e-15
    return 1.0 / (1.0 + math.exp(-z))


@dataclass(frozen=True)
class SemanticDriftPrediction:
    """Calibrated advisory risk prediction for semantic drift / unsupported claims."""

    drift_risk_score: float
    is_suspicious: bool
    threshold: float
    features: Dict[str, float]
    top_risk_factors: Tuple[Tuple[str, float], ...]
    model_version: str


@dataclass
class SemanticDriftAndClaimAnalyzer:
    """Calibrated linear risk scorer over SemanticPairFeatures."""

    version: str = "semantic-drift-lr/1.0.0"
    weights: List[float] = field(default_factory=lambda: [0.0] * len(_FEATURE_NAMES))
    bias: float = 0.0
    temperature: float = 1.0
    threshold: float = 0.50

    def fit(
        self,
        pairs: Sequence[Tuple[str, str]],
        labels: Sequence[int],
        *,
        l2_reg: float = 0.5,
        lr: float = 0.5,
        epochs: int = 200,
        val_pairs: Sequence[Tuple[str, str]] | None = None,
        val_labels: Sequence[int] | None = None,
    ) -> "SemanticDriftAndClaimAnalyzer":
        if len(pairs) != len(labels) or not pairs:
            raise ValueError("pairs and labels must be non-empty and of equal length")

        n = len(pairs)
        vecs = [extract_semantic_pair_features(c, r).to_vector() for c, r in pairs]
        d = len(_FEATURE_NAMES)
        self.weights = [0.0] * d
        self.bias = 0.0

        for _ in range(epochs):
            grad_w = [0.0] * d
            grad_b = 0.0
            for x, y in zip(vecs, labels):
                z = self.bias + sum(self.weights[j] * x[j] for j in range(d))
                err = _sigmoid(z) - float(y)
                grad_b += err
                for j in range(d):
                    grad_w[j] += err * x[j]
            inv_n = 1.0 / n
            self.bias -= lr * (grad_b * inv_n)
            for j in range(d):
                self.weights[j] -= lr * (grad_w[j] * inv_n + (l2_reg * inv_n) * self.weights[j])

        if val_pairs and val_labels and len(val_pairs) == len(val_labels):
            self._calibrate_temperature(val_pairs, val_labels)
        return self

    def _calibrate_temperature(self, val_pairs: Sequence[Tuple[str, str]], val_labels: Sequence[int]) -> None:
        logits: List[float] = []
        for c, r in val_pairs:
            x = extract_semantic_pair_features(c, r).to_vector()
            logits.append(self.bias + sum(self.weights[j] * x[j] for j in range(len(_FEATURE_NAMES))))
        best_t = 1.0
        best_nll = float("inf")
        for candidate in [0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5]:
            nll = 0.0
            for z, y in zip(logits, val_labels):
                p = max(1e-12, min(1.0 - 1e-12, _sigmoid(z / candidate)))
                nll -= y * math.log(p) + (1 - y) * math.log(1.0 - p)
            if nll < best_nll:
                best_nll = nll
                best_t = candidate
        self.temperature = best_t

    def predict(self, claim_text: str, reference_text: str) -> SemanticDriftPrediction:
        feats: SemanticPairFeatures = extract_semantic_pair_features(claim_text, reference_text)
        x = feats.to_vector()
        z = self.bias
        risk_factors: List[Tuple[str, float]] = []
        for j, name in enumerate(_FEATURE_NAMES):
            contrib = self.weights[j] * x[j]
            z += contrib
            if contrib > 0.0:
                risk_factors.append((name, round(contrib, 4)))
        risk_factors.sort(key=lambda item: -item[1])
        prob = _sigmoid(z / max(1e-6, self.temperature))
        return SemanticDriftPrediction(
            drift_risk_score=prob,
            is_suspicious=prob >= self.threshold,
            threshold=self.threshold,
            features=feats.to_dict(),
            top_risk_factors=tuple(risk_factors[:4]),
            model_version=self.version,
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "model_type": "SemanticDriftAndClaimAnalyzer",
            "version": self.version,
            "weights": self.weights,
            "bias": self.bias,
            "temperature": self.temperature,
            "threshold": self.threshold,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "SemanticDriftAndClaimAnalyzer":
        return cls(
            version=str(data["version"]),
            weights=[float(x) for x in list(data["weights"])],  # type: ignore[arg-type]
            bias=float(data["bias"]),  # type: ignore[arg-type]
            temperature=float(data.get("temperature", 1.0)),  # type: ignore[arg-type]
            threshold=float(data.get("threshold", 0.50)),  # type: ignore[arg-type]
        )
