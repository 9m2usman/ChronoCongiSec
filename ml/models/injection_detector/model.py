"""TF-IDF + L2-Regularized Logistic Regression Injection & Poisoning Classifier.

Designed for indirect prompt-injection (AgentDojo) and memory-poisoning
(AgentPoison / MPBench) detection where paraphrasing or obfuscation evades
static regular expressions. Pure Python, deterministic, <1 ms inference,
with temperature-scaled calibration and top-k n-gram attribution.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from ml.features.extractor import TextSecurityFeatures, extract_text_security_features
from ml.preprocessing.text_sanitizer import term_frequency


def _sigmoid(z: float) -> float:
    if z >= 35.0:
        return 1.0 - 1e-15
    if z <= -35.0:
        return 1e-15
    return 1.0 / (1.0 + math.exp(-z))


@dataclass(frozen=True)
class InjectionPrediction:
    """Calibrated advisory prediction from the injection/poisoning classifier."""

    probability: float
    raw_logit: float
    is_suspicious: bool
    threshold: float
    top_contributing_features: Tuple[Tuple[str, float], ...]
    model_version: str


@dataclass
class TfidfLinearInjectionClassifier:
    """Lightweight L2-regularized linear classifier over TF-IDF + structural features."""

    version: str = "injection-lr/1.0.0"
    vocab: Dict[str, int] = field(default_factory=dict)
    idf: List[float] = field(default_factory=list)
    weights: List[float] = field(default_factory=list)
    bias: float = 0.0
    # 3 structural feature weights: directive_density, boundary_marker_count, base64_blob_count
    struct_weights: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    temperature: float = 1.0
    threshold: float = 0.50

    def _featurize(self, text: str) -> Tuple[Dict[int, float], Tuple[float, float, float]]:
        feats: TextSecurityFeatures = extract_text_security_features(text)
        tf = term_frequency(list(feats.tokens))
        vec: Dict[int, float] = {}
        norm_sq = 0.0
        for tok, count in tf.items():
            idx = self.vocab.get(tok)
            if idx is not None:
                val = (1.0 + math.log(count)) * self.idf[idx]
                vec[idx] = val
                norm_sq += val * val
        if norm_sq > 0.0:
            inv_norm = 1.0 / math.sqrt(norm_sq)
            for idx in vec:
                vec[idx] *= inv_norm
        struct = (
            feats.directive_density,
            min(1.0, feats.boundary_marker_count / 3.0),
            min(1.0, feats.base64_blob_count / 2.0),
        )
        return vec, struct

    def fit(
        self,
        texts: Sequence[str],
        labels: Sequence[int],
        *,
        max_vocab: int = 2500,
        min_df: int = 2,
        l2_reg: float = 1.0,
        lr: float = 0.4,
        epochs: int = 120,
        val_texts: Sequence[str] | None = None,
        val_labels: Sequence[int] | None = None,
    ) -> "TfidfLinearInjectionClassifier":
        """Train TF-IDF + L2-regularized Logistic Regression deterministically."""
        if len(texts) != len(labels) or not texts:
            raise ValueError("texts and labels must be non-empty and of equal length")

        n_docs = len(texts)
        doc_freq: Dict[str, int] = {}
        extracted: List[TextSecurityFeatures] = [extract_text_security_features(t) for t in texts]
        for f in extracted:
            for tok in set(f.tokens):
                doc_freq[tok] = doc_freq.get(tok, 0) + 1

        # Select top max_vocab tokens with df >= min_df
        candidates = [(tok, df) for tok, df in doc_freq.items() if df >= min_df]
        candidates.sort(key=lambda item: (-item[1], item[0]))
        selected = candidates[:max_vocab]

        self.vocab = {tok: i for i, (tok, _) in enumerate(selected)}
        self.idf = [math.log((1.0 + n_docs) / (1.0 + df)) + 1.0 for _, df in selected]
        v_size = len(self.vocab)
        self.weights = [0.0] * v_size
        self.bias = 0.0
        sw = [0.0, 0.0, 0.0]

        train_vecs = [self._featurize(t) for t in texts]

        for _ in range(epochs):
            grad_w: Dict[int, float] = {}
            grad_b = 0.0
            grad_sw = [0.0, 0.0, 0.0]

            for (vec, struct), y in zip(train_vecs, labels):
                z = self.bias
                for idx, val in vec.items():
                    z += self.weights[idx] * val
                for j in range(3):
                    z += sw[j] * struct[j]
                pred = _sigmoid(z)
                err = pred - float(y)
                grad_b += err
                for idx, val in vec.items():
                    grad_w[idx] = grad_w.get(idx, 0.0) + err * val
                for j in range(3):
                    grad_sw[j] += err * struct[j]

            inv_n = 1.0 / n_docs
            self.bias -= lr * (grad_b * inv_n)
            for idx in range(v_size):
                g = grad_w.get(idx, 0.0) * inv_n + (l2_reg * inv_n) * self.weights[idx]
                self.weights[idx] -= lr * g
            for j in range(3):
                g = grad_sw[j] * inv_n + (l2_reg * inv_n) * sw[j]
                sw[j] -= lr * g

        self.struct_weights = (sw[0], sw[1], sw[2])

        # Temperature scaling on validation set if provided (prevents overconfident probabilities)
        if val_texts and val_labels and len(val_texts) == len(val_labels):
            self._calibrate_temperature(val_texts, val_labels)

        return self

    def _calibrate_temperature(self, val_texts: Sequence[str], val_labels: Sequence[int]) -> None:
        logits = [self.raw_score(t) for t in val_texts]
        best_t = 1.0
        best_nll = float("inf")
        for candidate in [0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5]:
            nll = 0.0
            for z, y in zip(logits, val_labels):
                p = _sigmoid(z / candidate)
                p = max(1e-12, min(1.0 - 1e-12, p))
                nll -= y * math.log(p) + (1 - y) * math.log(1.0 - p)
            if nll < best_nll:
                best_nll = nll
                best_t = candidate
        self.temperature = best_t

    def raw_score(self, text: str) -> float:
        vec, struct = self._featurize(text)
        z = self.bias
        for idx, val in vec.items():
            z += self.weights[idx] * val
        for j in range(3):
            z += self.struct_weights[j] * struct[j]
        return z

    def predict(self, text: str, top_k: int = 5) -> InjectionPrediction:
        vec, struct = self._featurize(text)
        inv_vocab: Dict[int, str] = {i: tok for tok, i in self.vocab.items()}
        contributions: List[Tuple[str, float]] = []

        z = self.bias
        for idx, val in vec.items():
            c = self.weights[idx] * val
            z += c
            if c > 0.0:
                contributions.append((inv_vocab.get(idx, f"idx:{idx}"), round(c, 4)))

        struct_names = ("struct:directive_density", "struct:boundary_markers", "struct:base64_blobs")
        for j in range(3):
            c = self.struct_weights[j] * struct[j]
            z += c
            if c > 0.0:
                contributions.append((struct_names[j], round(c, 4)))

        contributions.sort(key=lambda item: -item[1])
        prob = _sigmoid(z / max(1e-6, self.temperature))
        return InjectionPrediction(
            probability=prob,
            raw_logit=z,
            is_suspicious=prob >= self.threshold,
            threshold=self.threshold,
            top_contributing_features=tuple(contributions[:top_k]),
            model_version=self.version,
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "model_type": "TfidfLinearInjectionClassifier",
            "version": self.version,
            "vocab": self.vocab,
            "idf": self.idf,
            "weights": self.weights,
            "bias": self.bias,
            "struct_weights": list(self.struct_weights),
            "temperature": self.temperature,
            "threshold": self.threshold,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "TfidfLinearInjectionClassifier":
        sw = data["struct_weights"]
        return cls(
            version=str(data["version"]),
            vocab={str(k): int(v) for k, v in dict(data["vocab"]).items()},  # type: ignore[arg-type]
            idf=[float(x) for x in list(data["idf"])],  # type: ignore[arg-type]
            weights=[float(x) for x in list(data["weights"])],  # type: ignore[arg-type]
            bias=float(data["bias"]),  # type: ignore[arg-type]
            struct_weights=(float(sw[0]), float(sw[1]), float(sw[2])),  # type: ignore[index]
            temperature=float(data.get("temperature", 1.0)),  # type: ignore[arg-type]
            threshold=float(data.get("threshold", 0.50)),  # type: ignore[arg-type]
        )
