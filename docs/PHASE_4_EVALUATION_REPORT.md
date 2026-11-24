# Phase 4 Evaluation Report

**Document ID:** AMSC-DOC-P4-003  
**Phase:** 4  
**Date:** 2026-11-24  
**Reproducibility Command:** `python -m ml.evaluation.evaluator`

---

## 1. Dataset & Controlled Enterprise Environment Methodology

All evaluations use synthetic, controlled enterprise data representing one fictional company (`tenant-chronocorp-001`) with 4 branches (`branch-ho-001`, `branch-lhr-001`, `branch-khi-001`, `branch-isb-001`) and 4 departments (`HR`, `Finance`, `Customer Support`, `Operations`), plus a separate synthetic tenant (`tenant-isolation-test-002`) reserved strictly for tenant-isolation testing.

- **Leakage Prevention:** Train, validation, and held-out test splits are partitioned by **template family** (disjoint phrasing templates and attack families), never by random row shuffle.
- **Unsupervised Behavioral Fitting:** `BehavioralSequenceAnomalyDetector` is fit exclusively on benign synthetic department sequences (`build_behavioral_training_sequences()`).

---

## 2. Quantitative Results (Deterministic Baseline vs. Deterministic + ML)

### 2.1 Held-Out Injection & Poisoning Test (`n = 20`: 10 positive, 10 benign/hard-negative)

| Metric | Deterministic Baseline (Regex) | Deterministic + ML (`TfidfLinearInjectionClassifier`) |
|---|---|---|
| Confusion Matrix (`TP / FP / TN / FN`) | `2 / 0 / 10 / 8` | `9 / 0 / 10 / 1` |
| Precision | `1.0000` | `1.0000` |
| Recall | `0.2000` | `0.9000` |
| F1 Score | `0.3333` | `0.9474` |
| False-Positive Rate (FPR) | `0.0000` | `0.0000` |
| False-Negative Rate (FNR) | `0.8000` | `0.1000` |
| Calibration (ECE / Brier) | N/A | `0.2475 / 0.0748` |

### 2.2 Held-Out Semantic Drift & Unsupported-Claim Test (`n = 8`: 4 positive, 4 benign)

| Metric | Deterministic Baseline | Deterministic + ML (`SemanticDriftAndClaimAnalyzer`) |
|---|---|---|
| Confusion Matrix (`TP / FP / TN / FN`) | `2 / 1 / 3 / 2` | `4 / 1 / 3 / 0` |
| Precision | `0.6667` | `0.8000` |
| Recall | `0.5000` | `1.0000` |
| F1 Score | `0.5714` | `0.8889` |
| False-Positive Rate (FPR) | `0.2500` | `0.2500` |
| False-Negative Rate (FNR) | `0.5000` | `0.0000` |
| Calibration (ECE / Brier) | N/A | `0.2134 / 0.0574` |

*(Note: The single FP in both configurations is from Phase 2's deterministic polarity check on `sem-te-1`, where the full baseline text contains `"prohibited"` and the claim contains `"permitted"`.)*

### 2.3 End-to-End 12-Scenario Enterprise Validation Suite (`n = 12`)

| Metric | Deterministic Baseline | Deterministic + ML |
|---|---|---|
| Confusion Matrix (`TP / FP / TN / FN`) | `6 / 1 / 1 / 4` | `9 / 1 / 1 / 1` |
| Precision | `0.8571` | `0.9000` |
| Recall | `0.6000` | `0.9000` |
| F1 Score | `0.7059` | `0.9000` |
| False-Positive Rate (FPR) | `0.5000` | `0.5000` |
| False-Negative Rate (FNR) | `0.4000` | `0.1000` |

Deterministic baseline alone missed 4 scenarios (`sc-02-mem-poison`, `sc-03-prompt-inj`, `sc-09-abnormal-seq`, `sc-10-repeated-ops`), 3 of which were flagged by the ML-assisted layer (`sc-02-mem-poison` remained a conservative false negative at threshold `0.46` after balancing short-text benign priors).

### 2.4 Adversarial Perturbation Robustness (`n = 30` perturbed variants)

Variants tested: Unicode full-width homoglyphs, whitespace obfuscation, and benign prefix padding on held-out injection positives.
- **Deterministic Regex Recall:** `0.1667` (`5 / 30`)
- **ML-Assisted Recall:** `0.8333` (`25 / 30`)

### 2.5 Latency & Resource Consumption

- **Mean Latency:** `7.233 ms`
- **p50 Latency:** `3.018 ms`
- **p95 Latency:** `33.996 ms`
- **p99 Latency:** `37.806 ms`
- **Peak Traced Memory (`tracemalloc`):** `134.98 KB`

---

## 3. Limitations

1. **Synthetic Benchmark Scope:** All evaluations use controlled synthetic enterprise data (`n = 20`, `n = 8`, `n = 12`). Results establish mechanism coverage on the synthetic suite, not universal real-world generalization.
2. **Calibration:** ECE (`0.21–0.24`) reflects small validation set sizes (`n = 10` and `n = 4`). Larger enterprise datasets are required before tightening probability thresholds.
3. **Phase 3 Recovery:** End-to-end automated recovery execution is outside Phase 4 scope and remains isolated in Phase 3.
