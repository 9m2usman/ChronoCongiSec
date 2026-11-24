# Phase 4 ML Security Intelligence Architecture

**Document ID:** AMSC-DOC-P4-002  
**Phase:** 4  
**Date:** 2026-11-24

---

## 1. Architectural Separation (Advisory vs. Authoritative)

AMSC enforces a strict boundary between the **Authoritative Deterministic Security Layer** and the **Advisory ML Intelligence Layer**:

- **Authoritative Deterministic Layer (`backend/app/security/policy.py`, `trust.py`, `authorization.py`):**
  - Sole authority for `ALLOW`, `BLOCK`, and `REQUIRES_APPROVAL`.
  - Sole authority for memory trust transitions (`TRUSTED`, `UNVERIFIED`, `SUSPICIOUS`, `QUARANTINED`, `REJECTED`, `SUPERSEDED`).
  - Sole authority for enterprise baseline lifecycle and agent security profiles.
- **Advisory ML Intelligence Layer (`ml/`, `backend/app/security/ml_intelligence.py`):**
  - Emits strictly advisory `DetectionResult` items (`classification_type=SUSPICIOUS_INDICATOR`, `recommended_outcome=REQUIRE_HUMAN_APPROVAL`, `details.advisory_only=True`).
  - **Never** emits `ALLOW` to lift a deterministic `BLOCK`.
  - **Never** mutates trust state, baselines, profiles, or permissions.
  - **Never** bypasses `ProtectedExecutionGuard` or executes tools.

---

## 2. Component Boundaries & Data Flow

1. **Preprocessing (`ml/preprocessing/text_sanitizer.py`):**
   - Validates string types, caps length at `32,768` chars, applies Unicode NFKC normalization, strips control characters, and redacts secrets/PII (`sk-...`, `AKIA...`, emails, SSNs, `token=...`) before any diagnostic logging.
2. **Feature Extraction (`ml/features/extractor.py`):**
   - Extracts `TextSecurityFeatures`, `SemanticPairFeatures`, and tenant/branch-scoped `BehavioralEvent` objects.
3. **Model Registry (`ml/model_registry/registry.py`):**
   - Stores versioned JSON artifacts in `ml/model_registry/artifacts/` with a SHA-256 `manifest.json`.
   - Verifies SHA-256 checksum on load; rejects missing, malformed, or tampered artifacts with `ModelIntegrityError`.
4. **Inference Service (`ml/inference/service.py`):**
   - Enforces mandatory `tenant_id`, per-call timeout budget (`100 ms` default), and finite `[0.0, 1.0]` probability validation.
   - Enters deterministic fallback (`uncertainty_state="INDETERMINATE"`, `fallback_used=True`) on missing/corrupted models, timeouts, or invalid/NaN outputs.
5. **Backend Integration (`backend/app/security/ml_intelligence.py` & `detection.py`):**
   - `MLAdvisoryDetector` converts `MLAdvisoryAssessment` into canonical `DetectionResult` objects compatible with `detection_results` (Alembic `0014`).
   - Wired into `DetectionEngine.detect_memory_integrity`, `detect_semantic_integrity`, and `detect_behavioral_deviation` as an additive advisory check.

---

## 3. Tenant, Branch & Phase 3 Independence

- **Tenant & Branch Isolation:** `BehavioralSequenceAnomalyDetector` keys all runtime sliding windows by `(tenant_id, branch_id, agent_id)`. Events from one tenant or branch never influence another.
- **Phase 3 Independence:** No Phase 3 recovery files (`backend/app/recovery/`) were modified or replaced.
- **M2/M3/M6 Boundaries:** No M2 Gateway internals, M3 memory internals, or M6 Alembic migrations were altered.
