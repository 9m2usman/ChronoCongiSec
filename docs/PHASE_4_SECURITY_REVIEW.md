# Phase 4 Security Review

**Document ID:** AMSC-DOC-P4-004  
**Phase:** 4  
**Date:** 2026-11-24

---

## 1. Threat Model for the ML Intelligence Layer

| Threat Vector | Mitigation Implemented | Verification |
|---|---|---|
| **ML Authorization Bypass** | `MLAdvisoryDetector` only emits `SUSPICIOUS_INDICATOR` (`REQUIRE_HUMAN_APPROVAL`, `advisory_only=True`). `PolicyEngine` remains deterministic and never accepts `ALLOW` from ML. | `test_ml_cannot_override_deterministic_policy_block_or_grant_allow` |
| **Model Artifact Tampering / Poisoning** | `ModelRegistry` stores SHA-256 checksums in `manifest.json` and verifies before load; tampered artifacts raise `ModelIntegrityError` and trigger `INDETERMINATE` fallback. | `test_model_registry_detects_tampered_artifact`, `test_missing_or_tampered_models_fail_safely_to_indeterminate` |
| **Model Timeout / NaN / Corrupted Output** | `MLSecurityIntelligenceService` enforces `timeout_ms` budget and finite `[0.0, 1.0]` probability validation; failures transition to `INDETERMINATE` (`fallback_used=True`). | `test_model_timeout_and_nan_output_trigger_safe_fallback` |
| **Input Evasion (Homoglyphs, Oversized Payloads, Non-Strings)** | `sanitize_text_for_ml` enforces `str` type, `32,768` char cap, control-char stripping, and Unicode NFKC normalization. | `test_sanitizer_normalizes_homoglyphs_caps_size_and_redacts_secrets`, `test_sanitizer_rejects_non_string_input` |
| **Cross-Tenant / Cross-Branch Leakage** | `BehavioralSequenceAnomalyDetector` partitions runtime sliding windows strictly by `(tenant_id, branch_id, agent_id)`. | `test_behavioral_sequence_window_is_strictly_tenant_and_branch_isolated` |
| **Sensitive Data in ML Logs/Evidence** | `redact_sensitive_text` scrubs API keys (`sk-...`, `AKIA...`), tokens/passwords, emails, and SSNs from `top_features` evidence. | `test_ml_evidence_redacts_secrets_and_pii` |

---

## 2. Remaining Risks

1. **Adaptive Synonym / Zero-Overlap Evasion:** Purely lexical n-gram models can be evaded by adversarial paraphrasing that avoids all training n-grams. Deterministic `PolicyEngine` action/tool/memory-trust boundaries remain the primary defense.
2. **In-Process Behavioral Window:** `_agent_history` is process-local in-memory; multi-worker deployments require Redis/DB-backed windowing in a future phase.
