# Phase 4 Evaluation Report

**Document ID:** AMSC-DOC-P4-003  
**Phase:** 4 / 6C  
**Date:** 2026-11-28  
**Reproducibility Command:** `python -m ml.evaluation.evaluator`

---

## 1. Dataset & Controlled Enterprise Environment Methodology

All evaluations use synthetic, controlled enterprise data representing one fictional company (`tenant-chronocorp-001`) with 4 branches (`branch-ho-001`, `branch-lhr-001`, `branch-khi-001`, `branch-isb-001`) and 4 departments (`HR`, `Finance`, `Customer Support`, `Operations`), plus a separate synthetic tenant (`tenant-isolation-test-002`) reserved strictly for tenant-isolation testing.

- **Leakage Prevention:** Train, validation, and held-out test splits are partitioned by **template family** (disjoint phrasing templates and attack families), never by random row shuffle.
- **Training/Inference Parity:** `ml/training/train_models.py` applies `sanitize_text_for_ml` identically to `ml/inference/service.py` so training and inference feature pipelines match.
- **Unsupervised Behavioral Fitting:** `BehavioralSequenceAnomalyDetector` is fit exclusively on benign synthetic department sequences (`build_behavioral_training_sequences()`).

---

## 2. Quantitative Results (Deterministic Baseline vs. Deterministic + ML)

### 2.1 Held-Out Injection & Poisoning Test (`n = 40`: 20 positive, 20 benign/hard-negative)

| Metric | Deterministic Baseline (Regex) | Deterministic + ML (`TfidfLinearInjectionClassifier`) |
|---|---|---|
| Confusion Matrix (`TP / FP / TN / FN`) | `3 / 0 / 20 / 17` | `20 / 2 / 18 / 0` |
| Precision | `1.0000` | `0.9091` |
| Recall | `0.1500` | `1.0000` |
| F1 Score | `0.2609` | `0.9524` |
| False-Positive Rate (FPR) | `0.0000` | `0.1000` |
| False-Negative Rate (FNR) | `0.8500` | `0.0000` |
| Calibration (ECE / Brier) | N/A | `0.1757 / 0.1009` |

### 2.2 Held-Out Semantic Drift & Unsupported-Claim Test (`n = 20`: 10 positive, 10 benign/hard-negative)

| Metric | Deterministic Baseline | Deterministic + ML (`SemanticDriftAndClaimAnalyzer`) |
|---|---|---|
| Confusion Matrix (`TP / FP / TN / FN`) | `4 / 3 / 7 / 6` | `8 / 3 / 7 / 2` |
| Precision | `0.5714` | `0.7273` |
| Recall | `0.4000` | `0.8000` |
| F1 Score | `0.4706` | `0.7619` |
| False-Positive Rate (FPR) | `0.3000` | `0.3000` |
| False-Negative Rate (FNR) | `0.6000` | `0.2000` |
| Calibration (ECE / Brier) | N/A | `0.1459 / 0.1292` |

*(Note: After fixing the mixed-polarity inversion bug in `DetectionEngine.detect_semantic_integrity` where a baseline containing both `"permitted"` and `"prohibited"` clauses false-flagged faithful summaries, `sc-01-normal-fin` no longer false-positives. Remaining FPs/FNs in the expanded 20-sample semantic split reflect lexical-overlap edge cases in deterministic grounding and small semantic training set size.)*

### 2.3 End-to-End 12-Scenario Enterprise Validation Suite (`n = 12`)

| Metric | Deterministic Baseline | Deterministic + ML |
|---|---|---|
| Confusion Matrix (`TP / FP / TN / FN`) | `6 / 0 / 2 / 4` | `10 / 0 / 2 / 0` |
| Precision | `1.0000` | `1.0000` |
| Recall | `0.6000` | `1.0000` |
| F1 Score | `0.7500` | `1.0000` |
| False-Positive Rate (FPR) | `0.0000` | `0.0000` |
| False-Negative Rate (FNR) | `0.4000` | `0.0000` |

Deterministic baseline alone missed 4 scenarios (`sc-02-mem-poison`, `sc-03-prompt-inj`, `sc-09-abnormal-seq`, `sc-10-repeated-ops`), all 4 of which were caught by the ML-assisted layer (`sc-01-normal-fin` and `sc-12-fp-benign` both passed with 0 false positives).

### 2.4 Adversarial Perturbation Robustness (`n = 60` perturbed variants)

Variants tested: Unicode full-width homoglyphs, whitespace obfuscation, and benign prefix padding on the 20 held-out injection positives.
- **Deterministic Regex Recall:** `0.1167` (`7 / 60`)
- **ML-Assisted Recall:** `0.8500` (`51 / 60`)

### 2.5 Latency & Resource Consumption

- **Mean Latency:** `1.840 ms`
- **p50 Latency:** `0.800 ms`
- **p95 Latency:** `6.271 ms`
- **p99 Latency:** `15.030 ms`
- **Peak Traced Memory (`tracemalloc`):** `134.56 KB`

---

## 3. Limitations

1. **Synthetic Benchmark Scope:** All evaluations use controlled synthetic enterprise data (`n = 40`, `n = 20`, `n = 12`). Results establish mechanism coverage on the synthetic suite, not universal real-world generalization.
2. **Held-Out Tradeoffs:** Expanding the injection held-out split to `n = 40` raised ML recall to `1.0000` with `2` benign false positives (`FPR = 0.1000`); expanding the semantic held-out split to `n = 20` yielded `F1 = 0.7000` (`FPR = 0.3000`, `FNR = 0.3000`). Larger real-world corpora are required to further reduce lexical false positives.
3. **Calibration:** ECE (`0.1757` injection, `0.1459` semantic) reflects small validation set sizes (`n = 10` and `n = 4`).
