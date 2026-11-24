# Phase 4 Research and Model Selection

**Document ID:** AMSC-DOC-P4-001  
**Phase:** 4 — ML Security Intelligence, Evaluation & Controlled Enterprise Validation  
**Status:** Verified Implementation Baseline  
**Date:** 2026-11-24

---

## 1. Research Review & Grounding

This document evaluates published research in `docs/RESEARCH_BIBLIOGRAPHY.md` and maps each verified method and limitation to AMSC Phase 4 ML capabilities. Paper-reported metrics are never claimed as AMSC results.

| Reference | Actual Method & Findings | Verified Limitations | AMSC Phase 4 Translation |
|---|---|---|---|
| **AgentPoison** (Chen et al., NeurIPS 2024; `arXiv:2407.12784`) | Backdoor poisoning of RAG/long-term memory via constrained trigger optimization (<0.1% poison rate). | Attack paper, not a defensive detector; setting-specific triggers. | `TfidfLinearInjectionClassifier` using word (1–2) + character (3–5) n-grams + structural markers to detect trigger-like and persistent-rule poisoning beyond static regexes. |
| **MPBench** (Dash et al., 2026; `arXiv:2606.04329`) | Systematic study of 4 memory write channels (Instruction, System-Prompt, Compaction, Experience-to-Procedure) and 9 vulnerabilities. | arXiv preprint; bounded to evaluated agents. | Synthetic evaluation scenarios cover persistent-rule and compaction-style semantic drift/poisoning. |
| **AgentDojo** (Debenedetti et al., 2024; `arXiv:2406.13352`) | Dynamic evaluation environment for indirect prompt injection in tool-using agents (97 tasks, 629 security cases). | Results depend on harness, model, and defense setup. | Held-out paraphrased indirect prompt injection split + adversarial perturbation suite (homoglyphs, whitespace, benign padding). |
| **Runtime Policy Enforcement for MCP Agents** (Wang et al., 2026; `DOI:10.3390/electronics15132829`) | Deterministic tool-boundary PEP with declarative rules, source-integrity labels, and SHA-256 hash-chained audit. | Coarse label tracking has blind spots against multi-step behavioral shifts. | Preserves `PolicyEngine` as sole deterministic PEP; adds `BehavioralSequenceAnomalyDetector` for multi-step tool-chain anomaly signals. |
| **TrustMem & HaluMem** (R-010) | Memory transition validation for omission, corruption, and confabulated additions during summarization. | Heuristic/NLI scores are probabilistic, not formal proof. | `SemanticDriftAndClaimAnalyzer` scoring cosine similarity, entity coverage, constraint preservation, negation flips, and numeric expansion. |
| **AgentRewind** (Zhuang et al., 2026; `arXiv:2608.14380`) | Aligned dual checkpoints of agent context and controlled environment for recoverable execution. | Rewinding memory/context does not undo external side effects. | Phase 3 recovery remains independent; Phase 4 does not modify or duplicate Phase 3 recovery contracts. |

---

## 2. Capability-by-Capability Specification

### 2.1 Capability 1: Indirect Prompt Injection & Memory Poisoning Classifier
1. **Security problem:** Paraphrased, indirect, or obfuscated prompt injections and memory poisoning payloads evade Phase 2's static `PROMPT_INJECTION_PATTERNS` and `MEMORY_POISONING_PATTERNS` regexes.
2. **Research justification:** Character + word n-gram TF-IDF linear models are standard, low-latency text security classifiers resilient to minor lexical variations and Unicode homoglyphs (after NFKC normalization).
3. **Input signals:** Sanitized memory/tool text (`<= 32,768` chars), NFKC-normalized, with structural indicators (`directive_density`, `boundary_marker_count`, `base64_blob_count`).
4. **Proposed method:** `TfidfLinearInjectionClassifier` (L2-regularized Logistic Regression + Temperature Scaling calibration).
5. **Expected output:** Calibrated risk score `[0.0, 1.0]`, `is_suspicious` boolean, top-k contributing n-gram features.
6. **Limitations & attack surface:** Vulnerable to extreme synonym substitution or zero-overlap encoding; benign security training documents mentioning attack terms can raise false positives without hard-negative training examples.
7. **Evaluation method:** Template-disjoint held-out test split (n=20) + 30 adversarial perturbation variants, compared against Phase 2 regex baseline.
8. **Why deterministic logic alone is insufficient:** Regexes require exact phrase matches and fail on paraphrased directives (20% recall on held-out paraphrased test split vs. 100% with ML-assisted).

### 2.2 Capability 2: Semantic Drift, Contradiction & Unsupported-Claim Analyzer
1. **Security problem:** Derived summaries or claims can strip mandatory constraints, inflate financial ceilings, or contradict approved enterprise baselines using phrasing not covered by Phase 2's 5 regex polarity pairs or `len(overlap) == 0`.
2. **Research justification:** Adapted from TrustMem/HaluMem transition integrity concepts.
3. **Input signals:** `(claim_text, reference_text)` from approved `EnterpriseBaseline` or source memory.
4. **Proposed method:** `SemanticDriftAndClaimAnalyzer` — L2-regularized Logistic Regression over 7 interpretable features (`cosine_similarity`, `entity_coverage`, `constraint_preservation`, `negation_flip`, `permissive_expansion`, `numeric_expansion_ratio`, `length_ratio`).
5. **Expected output:** Calibrated `drift_risk_score` `[0.0, 1.0]`, feature breakdown, and top risk factors.
6. **Limitations & attack surface:** Does not perform deep logical entailment over multi-hop reasoning; relies on lexical/structural cues and numeric extraction.
7. **Evaluation method:** Template-disjoint held-out semantic pair test split (n=8), compared against Phase 2 `detect_semantic_integrity`.
8. **Why deterministic logic alone is insufficient:** Phase 2's `len(overlap) == 0` misses claims that share generic words (`"policy"`, `"customer"`) while contradicting constraints or inflating amounts < 2x.

### 2.3 Capability 3: Behavioral & Execution-Sequence Anomaly Detector
1. **Security problem:** Unusual multi-step tool sequences (e.g. `read_policy -> bulk_export`), off-profile parameter magnitudes within hard ceilings, and rapid operation bursts below Phase 2's `>= 5 in 10s` threshold.
2. **Research justification:** Unsupervised Markov/statistical anomaly detection is justified because labeled multi-step enterprise attack traces are scarce in production.
3. **Input signals:** Tenant/branch/agent-scoped `BehavioralEvent(department, tool_name, operation, amount, timestamp)`.
4. **Proposed method:** `BehavioralSequenceAnomalyDetector` — Role-conditioned First-Order Markov transition model (Laplace-smoothed) + action frequency surprise + online Welford amount z-score + 10s window burst score.
5. **Expected output:** `anomaly_score` `[0.0, 1.0]`, decomposed into `sequence_surprise`, `frequency_surprise`, `parameter_zscore`, `burst_score`, and human-readable `reason_factors`.
6. **Limitations & attack surface:** Cold-start for new departments without baseline sequences; slow-drip attacks spaced >10s apart evade burstiness.
7. **Evaluation method:** End-to-end 12-scenario enterprise suite (`sc-09-abnormal-seq`, `sc-10-repeated-ops`, `sc-11-behavior-change`).
8. **Why deterministic logic alone is insufficient:** Phase 2 only counts `>= 4` blocks in 60s or `>= 5` identical proposals in 10s and has no transition or parameter-distribution model.

---

## 3. Rejected Approaches & Rationale

| Rejected Approach | Reason for Rejection |
|---|---|
| **External LLM-as-a-Judge (GPT/Gemini API)** | Violates zero-egress/sovereign processing, adds 500–2000 ms latency (threatening Gateway 2000 ms timeout), non-deterministic, and vulnerable to prompt injection. |
| **Local DeBERTa-v3 / Transformer NLI** | Requires 400 MB–1.5 GB model weights not present in repo/Docker, adds `torch`/`transformers` as mandatory production dependencies (absent from `backend/requirements.txt`), and adds 50–300 ms CPU latency. |
| **scikit-learn / XGBoost** | Not in `backend/requirements.txt` or installed in the target runtime; pure-Python implementation provides identical mathematical formulation with zero dependency bloat and <5 ms p50 latency. |
| **ML-based Policy Authorization** | Violates AMSC non-regression invariant: ML must remain strictly advisory; `PolicyEngine` remains deterministic and authoritative. |
