
# Machine Learning Ownership

**Lead: M4 — Security Engine & Incident Response**

M4 owns ML architecture, security models, training, evaluation, and inference.

Responsibilities:
- Prompt injection detection
- Malicious content classification
- Memory anomaly detection
- Memory risk and trust scoring
- Dataset preparation
- Feature engineering
- Model training and evaluation
- Model versioning
- Inference integration

M3 collaborates on embeddings and memory integration.

Rules:
- ML predictions are signals, not final authorization.
- Mandatory deterministic security checks cannot be overridden.
- Keep training and evaluation datasets separated.
- Record model versions and evaluation metrics.
- Do not expose tenant data across tenant boundaries.
