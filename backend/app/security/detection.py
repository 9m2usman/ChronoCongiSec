"""Framework-neutral Detection Engine and Security Result Contracts (Phase 2).

Module: backend.app.security.detection
Owner: AMSC Enterprise Security & Architecture Council

Implements Phase 2 Detection Capabilities:
A. Memory and Knowledge Integrity:
   - Suspicious or unauthorized memory modifications
   - Cryptographic checksum tamper detection
   - Memory poisoning indicators
   - Indirect prompt injection indicators
   - Missing, invalid, or inconsistent provenance
   - Expired, revoked, or superseded baseline knowledge
   - Unauthorized changes to trusted knowledge
   - Suspicious transformations of trusted content into derived memory
   - Inadmissible promotion guard (never promote suspicious or recovered content to TRUSTED)

B. Semantic Integrity and Claim Validation:
   - Grounding in approved enterprise baseline knowledge
   - Summary meaning and constraint preservation
   - Direct contradiction detection between source and derived memory
   - Staleness and invalidity detection
   - Unsupported information presented as authoritative policy
   - Explicit confidence and uncertainty states; distinguishes deterministic from model-assisted assessment

C. Agent Behavior and Purpose Deviation:
   - Purpose and goal boundary enforcement against authoritative AgentSecurityProfile
   - Data classification and branch access scope violations
   - Unexpected tool usage
   - Tampering with privileged instructions (profiles, baseline)
   - Abnormal repeated action sequences and brute-force iterations
   - Benign anomaly handling (preserves legitimate variance without false alarm)

D. Tool and Execution Threat Detection:
   - Pre-execution proposal evaluation across tool, parameters, ceilings, and approvals
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from pydantic import BaseModel, ConfigDict, Field

from backend.app.memory.integrity import sha256_hex
from backend.app.security.authorization import Role

logger = logging.getLogger("amsc.security.detection")

DETECTION_POLICY_VERSION = "amsc-detection/1.0.0"


# =============================================================================
# 1. Enums and Classification Contracts
# =============================================================================

class DetectionCategory(str, Enum):
    """Canonical categories for security detection results."""
    MEMORY_INTEGRITY = "MEMORY_INTEGRITY"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    PROVENANCE_INTEGRITY = "PROVENANCE_INTEGRITY"
    KNOWLEDGE_INTEGRITY = "KNOWLEDGE_INTEGRITY"
    SEMANTIC_INTEGRITY = "SEMANTIC_INTEGRITY"
    BEHAVIORAL_DEVIATION = "BEHAVIORAL_DEVIATION"
    TOOL_EXECUTION_THREAT = "TOOL_EXECUTION_THREAT"


class DetectionClassificationType(str, Enum):
    """Distinguishes observations, suspicious indicators, violations, and incidents."""
    OBSERVATION = "OBSERVATION"
    SUSPICIOUS_INDICATOR = "SUSPICIOUS_INDICATOR"
    CONFIRMED_POLICY_VIOLATION = "CONFIRMED_POLICY_VIOLATION"
    CONFIRMED_SECURITY_INCIDENT = "CONFIRMED_SECURITY_INCIDENT"


class DetectionMethod(str, Enum):
    """Method utilized to evaluate the condition."""
    DETERMINISTIC_RULE = "DETERMINISTIC_RULE"
    CRYPTOGRAPHIC_HASH = "CRYPTOGRAPHIC_HASH"
    POLICY_VERIFICATION = "POLICY_VERIFICATION"
    HEURISTIC_PATTERN = "HEURISTIC_PATTERN"
    STATISTICAL_FREQUENCY = "STATISTICAL_FREQUENCY"
    SEMANTIC_GROUNDING = "SEMANTIC_GROUNDING"


class UncertaintyState(str, Enum):
    """Explicit confidence and uncertainty state for transparency."""
    DEFINITIVE = "DEFINITIVE"                          # Cryptographic / deterministic proof
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"                # Exact rule / authoritative profile mismatch
    PROBABILISTIC_INDICATOR = "PROBABILISTIC_INDICATOR" # Pattern / heuristic match without formal proof
    INDETERMINATE = "INDETERMINATE"                    # Dependency unavailable / ambiguous input


class DetectionSeverity(str, Enum):
    """Severity of the detected finding."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RecommendedOutcome(str, Enum):
    """Security action recommended by the detection finding."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    QUARANTINE_RECORD = "QUARANTINE_RECORD"
    ALERT_ONLY = "ALERT_ONLY"


class DetectionStatus(str, Enum):
    """Lifecycle status of the detection."""
    DETECTED = "DETECTED"
    EVALUATED = "EVALUATED"
    CONFIRMED_VIOLATION = "CONFIRMED_VIOLATION"
    CONFIRMED_INCIDENT = "CONFIRMED_INCIDENT"
    DISMISSED_FALSE_POSITIVE = "DISMISSED_FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


# =============================================================================
# 2. Pydantic DTOs & Detection Contract
# =============================================================================

class EvidenceItem(BaseModel):
    """Structured evidence item supporting a detection finding."""
    model_config = ConfigDict(extra="ignore")

    evidence_type: str = Field(..., description="Category of evidence (MEMORY_RECORD, BASELINE_RECORD, etc.)")
    resource_id: Optional[str] = Field(None, description="Resource identifier if applicable")
    sha256_digest: Optional[str] = Field(None, description="Cryptographic digest of evidence content")
    description: str = Field(..., description="Summary of evidence")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Redacted forensic metadata")


class DetectionResult(BaseModel):
    """Canonical detection result contract matching Phase 2 specifications."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique detection identifier")
    tenant_id: str = Field(..., description="Authoritative tenant scope")
    branch_id: Optional[str] = Field(None, description="Branch scope if applicable")
    detection_category: DetectionCategory = Field(..., description="Domain category")
    classification_type: DetectionClassificationType = Field(..., description="Observation vs Violation vs Incident")
    agent_id: Optional[str] = Field(None, description="Associated agent ID")
    profile_version: Optional[str] = Field(None, description="Agent security profile version evaluated")
    execution_id: Optional[str] = Field(None, description="Agent execution ID")
    task_id: Optional[str] = Field(None, description="Current task ID")
    trace_id: Optional[str] = Field(None, description="W3C / correlation trace ID")
    action_id: Optional[str] = Field(None, description="Tool action ID")
    detection_method: DetectionMethod = Field(..., description="Method used to produce finding")
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score [0.0, 1.0]")
    uncertainty_state: UncertaintyState = Field(..., description="Definitive vs Probabilistic vs Indeterminate")
    severity: DetectionSeverity = Field(..., description="Severity level")
    recommended_outcome: RecommendedOutcome = Field(..., description="Recommended security disposition")
    policy_decision_id: Optional[str] = Field(None, description="Linked policy decision ID")
    status: DetectionStatus = Field(default=DetectionStatus.DETECTED, description="Audit lifecycle status")
    title: str = Field(..., description="Concise human-readable finding title")
    description: str = Field(..., description="Detailed description of detection rationale")
    memory_refs: List[str] = Field(default_factory=list, description="Referenced memory record IDs")
    baseline_refs: List[str] = Field(default_factory=list, description="Referenced enterprise baseline record IDs")
    evidence_items: List[EvidenceItem] = Field(default_factory=list, description="Supporting evidence items")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional context and reason codes")
    audit_history: List[Dict[str, Any]] = Field(default_factory=list, description="Audit and review transition history")
    created_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        if isinstance(data.get("created_at"), datetime):
            data["created_at"] = data["created_at"].isoformat()
        if isinstance(data.get("updated_at"), datetime):
            data["updated_at"] = data["updated_at"].isoformat()
        return data


class EvaluateDetectionRequest(BaseModel):
    """Ad-hoc evaluation request payload."""
    model_config = ConfigDict(extra="ignore")

    content: Optional[str] = None
    claim_text: Optional[str] = None
    source_text: Optional[str] = None
    record_id: Optional[str] = None
    parent_record_id: Optional[str] = None
    expected_checksum: Optional[str] = None
    agent_id: Optional[str] = None
    branch_id: Optional[str] = None
    tool_name: Optional[str] = None
    operation: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    memory_refs: List[str] = Field(default_factory=list)
    trace_id: Optional[str] = None
    action_id: Optional[str] = None


class EvaluateDetectionResponse(BaseModel):
    """Response containing aggregated detection outcomes."""
    model_config = ConfigDict(extra="ignore")

    findings_count: int
    highest_severity: DetectionSeverity
    recommended_outcome: RecommendedOutcome
    has_confirmed_violation: bool
    has_confirmed_incident: bool
    detections: List[DetectionResult]


# =============================================================================
# 3. Pattern Signatures and Detection Constants
# =============================================================================

# Indirect Prompt Injection Signatures
PROMPT_INJECTION_PATTERNS = [
    # Direct instruction overrides
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:directions|prompts|rules|instructions)\b"),
    re.compile(r"(?i)\bsystem\s+override\b"),
    re.compile(r"(?i)\bnew\s+system\s+(?:directive|instruction|prompt)\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:maintenance|developer|god|unrestricted|unfiltered|DAN)\s+mode\b"),
    re.compile(r"(?i)\bact\s+as\s+(?:a\s+)?(?:root\s+administrator|system\s+core|unrestricted\s+model)\b"),
    re.compile(r"(?i)\bbypass\s+(?:all\s+)?(?:security|safety|filtering|policy)\s+(?:checks|guards|mechanisms)\b"),
    re.compile(r"(?i)\bdo\s+not\s+follow\s+safety\s+guidelines\b"),
    # Delimiters and role fabrication
    re.compile(r"(?i)<\s*\|\s*im_start\s*\|\s*>"),
    re.compile(r"(?i)<\s*\|\s*system\s*\|\s*>"),
    re.compile(r"(?i)\[\s*SYSTEM\s+(?:DIRECTIVE|INSTRUCTION|OVERRIDE)\s*\]"),
    re.compile(r"(?i)---\s*BEGIN\s+SYSTEM\s+PROMPT\s*---"),
    re.compile(r"(?i)```\s*system"),
    re.compile(r"(?i)\[ADMINISTRATIVE_OVERRIDE\]"),
]

# Memory Poisoning Signatures
MEMORY_POISONING_PATTERNS = [
    re.compile(r"(?i)\b(?:exfiltrate|send|post|transmit)\s+(?:all\s+)?(?:passwords|tokens|keys|secrets|data)\s+to\b"),
    re.compile(r"(?i)\bAUTHORIZED:\s*(?:TRUE|YES|GRANTED|ALL)\b"),
    re.compile(r"(?i)\bOVERRIDE_FLAG:\s*TRUE\b"),
    re.compile(r"(?i)\bCLEARANCE_LEVEL:\s*(?:TOP_SECRET|MAXIMUM|ADMIN)\b"),
    re.compile(r"(?i)\bcurl\s+-X\s*POST\s+http"),
    re.compile(r"(?i)\bwebhook\.site\/[a-zA-Z0-9_\-]+"),
]

# Privileged instruction modification targeting AMSC structures
PRIVILEGED_INSTRUCTION_TARGETS = [
    "agent_security_profiles",
    "enterprise_baseline_records",
    "enterprise_baseline_versions",
    "trust_decisions",
    "policy_decisions",
    "agent_tool_permissions",
    "roles_permissions",
    "memberships",
    "approvals",
]


# =============================================================================
# 4. Detection Engine Implementation
# =============================================================================

class DetectionEngine:
    """Framework-neutral Security Detection Engine for AMSC."""

    def __init__(
        self,
        detection_repo: Optional[Any] = None,
        baseline_repo: Optional[Any] = None,
        agent_repo: Optional[Any] = None,
    ) -> None:
        self.detection_repo = detection_repo
        self.baseline_repo = baseline_repo
        self.agent_repo = agent_repo
        # Process-local sequence tracker for abnormal repeated action detection:
        # Key: (tenant_id, agent_id) -> list of timestamps of blocked events
        self._recent_blocks: Dict[Tuple[str, str], List[float]] = {}
        # Key: (tenant_id, agent_id) -> list of (timestamp, action_signature)
        self._recent_actions: Dict[Tuple[str, str], List[Tuple[float, str]]] = {}

    def _track_block(self, tenant_id: str, agent_id: str, now_ts: float) -> int:
        """Record a blocked action and return recent count within 60 seconds."""
        key = (tenant_id, agent_id)
        timestamps = self._recent_blocks.setdefault(key, [])
        cutoff = now_ts - 60.0
        pruned = [t for t in timestamps if t >= cutoff]
        pruned.append(now_ts)
        self._recent_blocks[key] = pruned
        return len(pruned)

    def record_blocked_event(self, tenant_id: str, agent_id: str, now_ts: Optional[float] = None) -> int:
        """Record an authoritative blocked action."""
        ts = now_ts if now_ts is not None else datetime.now(timezone.utc).timestamp()
        return self._track_block(tenant_id, agent_id, ts)

    def _get_recent_block_count(self, tenant_id: str, agent_id: str, now_ts: float) -> int:
        """Inspect recent block count within 60 seconds without mutating state."""
        key = (tenant_id, agent_id)
        timestamps = self._recent_blocks.get(key, [])
        cutoff = now_ts - 60.0
        return len([t for t in timestamps if t >= cutoff])

    def _track_and_check_repeated_proposals(
        self,
        tenant_id: str,
        agent_id: str,
        action_fp: str,
        now_ts: float,
    ) -> int:
        """Track action proposal and return count of identical proposals in past 10 seconds."""
        key = (tenant_id, agent_id)
        entries = self._recent_actions.setdefault(key, [])
        cutoff = now_ts - 10.0
        pruned = [(ts, fp) for ts, fp in entries if ts >= cutoff]
        pruned.append((now_ts, action_fp))
        self._recent_actions[key] = pruned
        return sum(1 for ts, fp in pruned if fp == action_fp)

    # -------------------------------------------------------------------------
    # A. Memory and Knowledge Integrity Detection
    # -------------------------------------------------------------------------

    async def detect_memory_integrity(
        self,
        tenant_id: str,
        content: Optional[str] = None,
        record: Optional[Any] = None,
        record_id: Optional[str] = None,
        expected_checksum: Optional[str] = None,
        source_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        branch_id: Optional[str] = None,
        parent_record_id: Optional[str] = None,
        relation_type: Optional[str] = None,
        memory_repo: Optional[Any] = None,
        trace_id: Optional[str] = None,
        action_id: Optional[str] = None,
        target_trust_state: Optional[str] = None,
        actor_role: Optional[str] = None,
    ) -> List[DetectionResult]:
        """Evaluate memory modification, content authenticity, prompt injection, and provenance."""
        findings: List[DetectionResult] = []
        target_record_id = record_id or (getattr(record, "id", None) if record else None) or "unrecorded"

        # 1. Cryptographic Checksum Integrity & Tamper Detection
        if content is not None and expected_checksum is not None:
            actual_digest = sha256_hex(content)
            if actual_digest.lower() != expected_checksum.strip().lower():
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.MEMORY_INTEGRITY,
                    classification_type=DetectionClassificationType.CONFIRMED_SECURITY_INCIDENT,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.CRYPTOGRAPHIC_HASH,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.CRITICAL,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Cryptographic Checksum Tamper Detected",
                    description=(
                        f"Memory content SHA-256 digest ({actual_digest}) differs from expected "
                        f"cryptographic checksum ({expected_checksum}). Potential in-flight or storage tampering."
                    ),
                    memory_refs=[target_record_id] if target_record_id != "unrecorded" else [],
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="CRYPTOGRAPHIC_DIGEST_MISMATCH",
                            resource_id=target_record_id,
                            sha256_digest=actual_digest,
                            description="Actual content digest does not match expected checksum.",
                            metadata={"expected": expected_checksum, "actual": actual_digest},
                        )
                    ],
                    details={"reason_code": "MEMORY_CHECKSUM_TAMPER"},
                ))

        # 2. Inadmissible Promotion Guard (Never promote suspicious or recovered content to TRUSTED)
        curr_state = getattr(record, "trust_state", None) if record else None
        req_target_state = target_trust_state or getattr(record, "target_trust_state", None)
        if req_target_state == "TRUSTED":
            if curr_state in ("QUARANTINED", "REJECTED", "SUPERSEDED", "RECOVERED") or (actor_role and actor_role.startswith("AGENT")):
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.MEMORY_INTEGRITY,
                    classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.POLICY_VERIFICATION,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.CRITICAL,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Inadmissible Promotion to TRUSTED Status",
                    description=(
                        f"Attempted to promote record '{target_record_id}' (current state '{curr_state}') "
                        "directly to TRUSTED status. Inadmissible promotion guard triggered: suspicious, "
                        "quarantined, or recovered content requires formal administrative governance."
                    ),
                    memory_refs=[target_record_id] if target_record_id != "unrecorded" else [],
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="INADMISSIBLE_PROMOTION",
                            resource_id=target_record_id,
                            description=f"Direct promotion from {curr_state} to TRUSTED prohibited.",
                            metadata={"current_state": str(curr_state), "target_state": "TRUSTED"},
                        )
                    ],
                    details={"reason_code": "INADMISSIBLE_TRUST_PROMOTION"},
                ))

        # 3. Modification of Inactive, Quarantined, or Revoked Memory
        if record is not None:
            state = getattr(record, "trust_state", None)
            if state in ("QUARANTINED", "REJECTED", "SUPERSEDED"):
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.MEMORY_INTEGRITY,
                    classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.POLICY_VERIFICATION,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.HIGH,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Unauthorized Mutation of Locked Memory Record",
                    description=(
                        f"Attempted write/mutation on memory record in terminal or quarantined "
                        f"state '{state}'. Direct modification of quarantined memory is strictly prohibited."
                    ),
                    memory_refs=[target_record_id],
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="MEMORY_RECORD_STATE",
                            resource_id=target_record_id,
                            description=f"Record current state is {state}.",
                            metadata={"trust_state": state},
                        )
                    ],
                    details={"reason_code": "MUTATION_OF_LOCKED_MEMORY", "trust_state": state},
                ))

            # Unauthorized Changes to Trusted Knowledge
            if state == "TRUSTED":
                if agent_id or (actor_role and actor_role not in (Role.TENANT_ADMIN.value, Role.SECURITY_ANALYST.value)):
                    findings.append(DetectionResult(
                        id=f"det-{uuid.uuid4().hex[:16]}",
                        tenant_id=tenant_id,
                        branch_id=branch_id,
                        detection_category=DetectionCategory.KNOWLEDGE_INTEGRITY,
                        classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                        agent_id=agent_id,
                        trace_id=trace_id,
                        action_id=action_id,
                        detection_method=DetectionMethod.POLICY_VERIFICATION,
                        confidence_score=1.0,
                        uncertainty_state=UncertaintyState.DEFINITIVE,
                        severity=DetectionSeverity.CRITICAL,
                        recommended_outcome=RecommendedOutcome.BLOCK,
                        title="Unauthorized Mutation of Trusted Knowledge",
                        description=(
                            f"Principal '{agent_id or 'unknown'}' attempted direct mutation on record '{target_record_id}' "
                            "in TRUSTED state. Trusted knowledge can only be modified via administrative governance."
                        ),
                        memory_refs=[target_record_id],
                        evidence_items=[
                            EvidenceItem(
                                evidence_type="UNAUTHORIZED_TRUSTED_MUTATION",
                                resource_id=target_record_id,
                                description="Direct mutation attempted on TRUSTED memory record.",
                                metadata={"actor": agent_id, "current_state": "TRUSTED"},
                            )
                        ],
                        details={"reason_code": "UNAUTHORIZED_TRUSTED_KNOWLEDGE_MUTATION"},
                    ))

            # Cross-Agent Memory Mutation Check
            record_agent_id = getattr(record, "agent_id", None)
            if record_agent_id and agent_id and record_agent_id != agent_id:
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.MEMORY_INTEGRITY,
                    classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.POLICY_VERIFICATION,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.HIGH,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Unauthorized Cross-Agent Memory Modification",
                    description=(
                        f"Agent '{agent_id}' attempted to mutate memory record owned by '{record_agent_id}'. "
                        "Agents may not modify memory belonging to other principals."
                    ),
                    memory_refs=[target_record_id],
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="AGENT_OWNERSHIP_MISMATCH",
                            resource_id=target_record_id,
                            description=f"Record owned by {record_agent_id}, mutation attempted by {agent_id}.",
                            metadata={"owner_agent_id": record_agent_id, "actor_agent_id": agent_id},
                        )
                    ],
                    details={"reason_code": "CROSS_AGENT_MEMORY_MUTATION"},
                ))

        # 3. Indirect Prompt Injection Indicators in Untrusted Content
        if content:
            injection_matches = []
            for pattern in PROMPT_INJECTION_PATTERNS:
                m = pattern.search(content)
                if m:
                    injection_matches.append(m.group(0))

            # Base64 hidden instruction detection
            b64_matches = re.findall(r"\b[A-Za-z0-9+/]{30,}={0,2}\b", content)
            for blob in b64_matches:
                try:
                    decoded = base64.b64decode(blob).decode("utf-8", errors="ignore")
                    for pattern in PROMPT_INJECTION_PATTERNS:
                        if pattern.search(decoded):
                            injection_matches.append(f"base64_encoded_directive({pattern.pattern[:30]})")
                            break
                except Exception:
                    pass

            if injection_matches:
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.PROMPT_INJECTION,
                    classification_type=DetectionClassificationType.CONFIRMED_SECURITY_INCIDENT,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.HEURISTIC_PATTERN,
                    confidence_score=0.98,
                    uncertainty_state=UncertaintyState.HIGH_CONFIDENCE,
                    severity=DetectionSeverity.CRITICAL,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Indirect Prompt Injection Indicator Detected",
                    description=(
                        f"Content contains {len(injection_matches)} indirect prompt-injection indicator(s): "
                        f"{', '.join(injection_matches[:3])}. Direct instruction override detected."
                    ),
                    memory_refs=[target_record_id] if target_record_id != "unrecorded" else [],
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="PROMPT_INJECTION_SIGNATURE",
                            resource_id=target_record_id,
                            sha256_digest=sha256_hex(content),
                            description="Identified prompt injection patterns in content.",
                            metadata={"matched_signatures": injection_matches[:5]},
                        )
                    ],
                    details={"matched_patterns": injection_matches[:5], "reason_code": "PROMPT_INJECTION_DETECTED"},
                ))

            # 4. Memory Poisoning Indicators
            poison_matches = []
            for pattern in MEMORY_POISONING_PATTERNS:
                m = pattern.search(content)
                if m:
                    poison_matches.append(m.group(0))

            if poison_matches:
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.MEMORY_INTEGRITY,
                    classification_type=DetectionClassificationType.CONFIRMED_SECURITY_INCIDENT,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.HEURISTIC_PATTERN,
                    confidence_score=0.95,
                    uncertainty_state=UncertaintyState.HIGH_CONFIDENCE,
                    severity=DetectionSeverity.CRITICAL,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Memory Poisoning Indicators Detected",
                    description=(
                        f"Content exhibits memory poisoning signatures: {', '.join(poison_matches[:3])}. "
                        "Fabricated authorization claims or exfiltration commands identified."
                    ),
                    memory_refs=[target_record_id] if target_record_id != "unrecorded" else [],
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="POISONING_INDICATORS",
                            resource_id=target_record_id,
                            description="Identified memory poisoning patterns.",
                            metadata={"poison_matches": poison_matches[:5]},
                        )
                    ],
                    details={"poison_matches": poison_matches[:5], "reason_code": "MEMORY_POISONING_DETECTED"},
                ))

        # 5. Missing, Invalid, or Inconsistent Provenance Detection
        if parent_record_id is not None:
            # Self-reference cycle
            if target_record_id != "unrecorded" and parent_record_id == target_record_id:
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.PROVENANCE_INTEGRITY,
                    classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.DETERMINISTIC_RULE,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.HIGH,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Cyclic Provenance Lineage Detected",
                    description="Record specifies itself as its parent (direct cyclic DAG violation).",
                    memory_refs=[target_record_id, parent_record_id],
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="CYCLIC_PROVENANCE",
                            resource_id=target_record_id,
                            description="Record ID equals parent ID.",
                            metadata={"record_id": target_record_id, "parent_record_id": parent_record_id},
                        )
                    ],
                    details={"reason_code": "CYCLIC_PROVENANCE_EDGE"},
                ))

            # Parent record existence and tenant verification
            if memory_repo is not None:
                parent_rec = None
                try:
                    if hasattr(memory_repo, "get_record"):
                        res = memory_repo.get_record(parent_record_id, tenant_id)
                        import inspect
                        if inspect.isawaitable(res):
                            parent_rec = await res
                        else:
                            parent_rec = res
                except Exception:
                    parent_rec = None

                if parent_rec is None:
                    findings.append(DetectionResult(
                        id=f"det-{uuid.uuid4().hex[:16]}",
                        tenant_id=tenant_id,
                        branch_id=branch_id,
                        detection_category=DetectionCategory.PROVENANCE_INTEGRITY,
                        classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                        agent_id=agent_id,
                        trace_id=trace_id,
                        action_id=action_id,
                        detection_method=DetectionMethod.DETERMINISTIC_RULE,
                        confidence_score=1.0,
                        uncertainty_state=UncertaintyState.DEFINITIVE,
                        severity=DetectionSeverity.HIGH,
                        recommended_outcome=RecommendedOutcome.BLOCK,
                        title="Missing Parent in Provenance Lineage",
                        description=f"Specified parent record '{parent_record_id}' does not exist in tenant '{tenant_id}'.",
                        memory_refs=[target_record_id, parent_record_id],
                        evidence_items=[
                            EvidenceItem(
                                evidence_type="ORPHAN_PROVENANCE",
                                resource_id=parent_record_id,
                                description="Parent record not found in tenant repository.",
                                metadata={"parent_record_id": parent_record_id, "tenant_id": tenant_id},
                            )
                        ],
                        details={"reason_code": "PARENT_RECORD_NOT_FOUND"},
                    ))
                elif getattr(parent_rec, "trust_state", None) in ("QUARANTINED", "REJECTED"):
                    findings.append(DetectionResult(
                        id=f"det-{uuid.uuid4().hex[:16]}",
                        tenant_id=tenant_id,
                        branch_id=branch_id,
                        detection_category=DetectionCategory.PROVENANCE_INTEGRITY,
                        classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                        agent_id=agent_id,
                        trace_id=trace_id,
                        action_id=action_id,
                        detection_method=DetectionMethod.POLICY_VERIFICATION,
                        confidence_score=1.0,
                        uncertainty_state=UncertaintyState.DEFINITIVE,
                        severity=DetectionSeverity.HIGH,
                        recommended_outcome=RecommendedOutcome.BLOCK,
                        title="Lineage Derived from Quarantined/Rejected Ancestor",
                        description=(
                            f"Parent record '{parent_record_id}' is currently in state '{parent_rec.trust_state}'. "
                            "Deriving memory from quarantined or rejected ancestors is prohibited."
                        ),
                        memory_refs=[target_record_id, parent_record_id],
                        evidence_items=[
                            EvidenceItem(
                                evidence_type="TAINTED_ANCESTOR",
                                resource_id=parent_record_id,
                                description=f"Parent state is {parent_rec.trust_state}.",
                                metadata={"parent_trust_state": str(parent_rec.trust_state)},
                            )
                        ],
                        details={"reason_code": "TAINTED_PARENT_LINEAGE"},
                    ))
                else:
                    # Check Suspicious Transformations of Trusted Content into Derived Memory
                    parent_content = getattr(parent_rec, "content", None) or (parent_rec.get("content") if isinstance(parent_rec, dict) else None)
                    if not parent_content and memory_repo and hasattr(memory_repo, "get_latest_version"):
                        try:
                            ver_res = memory_repo.get_latest_version(parent_record_id, tenant_id)
                            import inspect
                            if inspect.isawaitable(ver_res):
                                ver_obj = await ver_res
                            else:
                                ver_obj = ver_res
                            if ver_obj:
                                parent_content = getattr(ver_obj, "content", None) or (ver_obj.get("content") if isinstance(ver_obj, dict) else None)
                        except Exception:
                            pass
                    if parent_content and content:
                        parent_has_inj = any(p.search(parent_content) for p in PROMPT_INJECTION_PATTERNS)
                        derived_has_inj = any(p.search(content) for p in PROMPT_INJECTION_PATTERNS)
                        if not parent_has_inj and derived_has_inj:
                            findings.append(DetectionResult(
                                id=f"det-{uuid.uuid4().hex[:16]}",
                                tenant_id=tenant_id,
                                branch_id=branch_id,
                                detection_category=DetectionCategory.MEMORY_INTEGRITY,
                                classification_type=DetectionClassificationType.CONFIRMED_SECURITY_INCIDENT,
                                agent_id=agent_id,
                                trace_id=trace_id,
                                action_id=action_id,
                                detection_method=DetectionMethod.HEURISTIC_PATTERN,
                                confidence_score=0.99,
                                uncertainty_state=UncertaintyState.HIGH_CONFIDENCE,
                                severity=DetectionSeverity.CRITICAL,
                                recommended_outcome=RecommendedOutcome.BLOCK,
                                title="Suspicious Transformation: Injection Introduced in Derived Memory",
                                description=(
                                    f"Derived memory contains indirect prompt injection instructions absent from "
                                    f"parent record '{parent_record_id}'. Malicious transformation detected."
                                ),
                                memory_refs=[target_record_id, parent_record_id],
                                evidence_items=[
                                    EvidenceItem(
                                        evidence_type="DERIVATION_INJECTION",
                                        resource_id=target_record_id,
                                        description="Injection instructions introduced during derivation.",
                                        metadata={"parent_id": parent_record_id},
                                    )
                                ],
                                details={"reason_code": "SUSPICIOUS_TRANSFORMATION_INJECTION"},
                            ))

                        # Check constraint stripping from parent to derived memory
                        constraint_patterns = [
                            r"\b(?:must\s+never|strictly\s+prohibited|cannot|do\s+not|forbidden|confidential)\b",
                            r"\b(?:requires?\s+(?:prior\s+)?approval|subject\s+to\s+approval)\b",
                        ]
                        for c_pat in constraint_patterns:
                            if re.search(c_pat, parent_content.lower()) and not re.search(c_pat, content.lower()):
                                if re.search(r"\b(?:permitted|allowed|authorized|unrestricted)\b", content.lower()):
                                    findings.append(DetectionResult(
                                        id=f"det-{uuid.uuid4().hex[:16]}",
                                        tenant_id=tenant_id,
                                        branch_id=branch_id,
                                        detection_category=DetectionCategory.SEMANTIC_INTEGRITY,
                                        classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                                        agent_id=agent_id,
                                        trace_id=trace_id,
                                        action_id=action_id,
                                        detection_method=DetectionMethod.DETERMINISTIC_RULE,
                                        confidence_score=0.92,
                                        uncertainty_state=UncertaintyState.HIGH_CONFIDENCE,
                                        severity=DetectionSeverity.HIGH,
                                        recommended_outcome=RecommendedOutcome.BLOCK,
                                        title="Constraint Stripped During Memory Transformation",
                                        description=(
                                            f"Derived memory strips mandatory security constraints present in source parent '{parent_record_id}' "
                                            "and asserts unrestricted authorization."
                                        ),
                                        memory_refs=[target_record_id, parent_record_id],
                                        evidence_items=[
                                            EvidenceItem(
                                                evidence_type="CONSTRAINT_STRIPPED",
                                                resource_id=target_record_id,
                                                description="Mandatory parent constraint omitted in derived summary.",
                                                metadata={"parent_id": parent_record_id},
                                            )
                                        ],
                                        details={"reason_code": "TRANSFORMATION_CONSTRAINT_STRIPPED"},
                                    ))
                                    break

        return findings

    # -------------------------------------------------------------------------
    # B. Semantic Integrity and Claim Validation
    # -------------------------------------------------------------------------

    async def detect_semantic_integrity(
        self,
        tenant_id: str,
        claim_text: str,
        source_text: Optional[str] = None,
        referenced_baseline_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        branch_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        action_id: Optional[str] = None,
    ) -> List[DetectionResult]:
        """Evaluate claim grounding against approved enterprise baseline, summary preservation, and contradictions."""
        findings: List[DetectionResult] = []
        now = datetime.now(timezone.utc)

        # 1. Grounding in Approved Enterprise Baseline Knowledge
        if referenced_baseline_id and self.baseline_repo:
            baseline_rec = None
            try:
                res = self.baseline_repo.get_baseline_record(tenant_id, referenced_baseline_id)
                import inspect
                if inspect.isawaitable(res):
                    baseline_rec = await res
                else:
                    baseline_rec = res
            except Exception:
                baseline_rec = None

            if baseline_rec is None:
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.KNOWLEDGE_INTEGRITY,
                    classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                    agent_id=agent_id,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.POLICY_VERIFICATION,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.HIGH,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Referenced Enterprise Baseline Record Not Found",
                    description=(
                        f"Agent presented authoritative claim citing baseline record '{referenced_baseline_id}', "
                        f"which does not exist in authoritative enterprise baseline for tenant '{tenant_id}'."
                    ),
                    baseline_refs=[referenced_baseline_id],
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="NONEXISTENT_BASELINE_REFERENCE",
                            resource_id=referenced_baseline_id,
                            description="Referenced baseline does not exist.",
                            metadata={"baseline_id": referenced_baseline_id},
                        )
                    ],
                    details={"reason_code": "BASELINE_RECORD_NOT_FOUND"},
                ))
            else:
                lifecycle = baseline_rec.get("lifecycle_status")
                # Check for Expired, Revoked, or Superseded Knowledge
                if lifecycle in ("SUPERSEDED", "REVOKED", "ARCHIVED"):
                    findings.append(DetectionResult(
                        id=f"det-{uuid.uuid4().hex[:16]}",
                        tenant_id=tenant_id,
                        branch_id=branch_id,
                        detection_category=DetectionCategory.KNOWLEDGE_INTEGRITY,
                        classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                        agent_id=agent_id,
                        trace_id=trace_id,
                        action_id=action_id,
                        detection_method=DetectionMethod.POLICY_VERIFICATION,
                        confidence_score=1.0,
                        uncertainty_state=UncertaintyState.DEFINITIVE,
                        severity=DetectionSeverity.HIGH,
                        recommended_outcome=RecommendedOutcome.BLOCK,
                        title=f"Referenced Enterprise Baseline is {lifecycle}",
                        description=(
                            f"Claim references baseline record '{referenced_baseline_id}' which has lifecycle "
                            f"status '{lifecycle}'. Expired or superseded enterprise knowledge cannot justify actions."
                        ),
                        baseline_refs=[referenced_baseline_id],
                        evidence_items=[
                            EvidenceItem(
                                evidence_type="SUPERSEDED_BASELINE_REFERENCE",
                                resource_id=referenced_baseline_id,
                                description=f"Baseline status is {lifecycle}.",
                                metadata={"lifecycle_status": lifecycle},
                            )
                        ],
                        details={"reason_code": f"BASELINE_{lifecycle}"},
                    ))

                # Check expiration date
                raw_exp = baseline_rec.get("expires_at")
                if raw_exp:
                    exp_dt = datetime.fromisoformat(raw_exp) if isinstance(raw_exp, str) else raw_exp
                    if exp_dt and exp_dt < now:
                        findings.append(DetectionResult(
                            id=f"det-{uuid.uuid4().hex[:16]}",
                            tenant_id=tenant_id,
                            branch_id=branch_id,
                            detection_category=DetectionCategory.KNOWLEDGE_INTEGRITY,
                            classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                            agent_id=agent_id,
                            trace_id=trace_id,
                            action_id=action_id,
                            detection_method=DetectionMethod.POLICY_VERIFICATION,
                            confidence_score=1.0,
                            uncertainty_state=UncertaintyState.DEFINITIVE,
                            severity=DetectionSeverity.HIGH,
                            recommended_outcome=RecommendedOutcome.BLOCK,
                            title="Referenced Enterprise Baseline Has Expired",
                            description=(
                                f"Baseline record '{referenced_baseline_id}' expired at {exp_dt.isoformat()}. "
                                "Stale or expired policy cannot be treated as authoritative."
                            ),
                            baseline_refs=[referenced_baseline_id],
                            evidence_items=[
                                EvidenceItem(
                                    evidence_type="EXPIRED_BASELINE_POLICY",
                                    resource_id=referenced_baseline_id,
                                    description=f"Expired on {exp_dt.isoformat()}.",
                                    metadata={"expires_at": exp_dt.isoformat()},
                                )
                            ],
                            details={"reason_code": "BASELINE_EXPIRED"},
                        ))

                # Semantic Grounding & Contradiction Check Against Approved Baseline Content
                baseline_content = None
                try:
                    if hasattr(self.baseline_repo, "get_baseline_versions"):
                        v_res = self.baseline_repo.get_baseline_versions(tenant_id, referenced_baseline_id)
                        import inspect
                        if inspect.isawaitable(v_res):
                            v_res = await v_res
                        if v_res and isinstance(v_res, list):
                            baseline_content = v_res[-1].get("content")
                    elif "content" in baseline_rec:
                        baseline_content = baseline_rec.get("content")
                except Exception:
                    baseline_content = None

                if baseline_content and claim_text:
                    base_lower = baseline_content.lower()
                    claim_lower = claim_text.lower()

                    # Contradiction check against baseline
                    polarity_inversions = [
                        (r"\bis\s+authorized\b|\bauthorized\b", r"\bis\s+not\s+authorized\b|\bunauthorized\b|\bnot\s+authorized\b"),
                        (r"\bis\s+permitted\b|\bpermitted\b", r"\bis\s+not\s+permitted\b|\bnot\s+permitted\b|\bis\s+forbidden\b|\bis\s+prohibited\b|\bforbidden\b|\bprohibited\b"),
                        (r"\brequires?\s+(?:prior\s+)?approval\b|\bsubject\s+to\s+approval\b", r"\b(?:does\s+not\s+require|do\s+not\s+require|without)\s+(?:prior\s+)?approval\b|\bunrestricted\b"),
                        (r"\bactive\b", r"\binactive\b|\bterminated\b"),
                        (r"\ballowed\b|\bis\s+allowed\b", r"\bdisallowed\b|\bblocked\b|\bnot\s+allowed\b|\bis\s+not\s+allowed\b"),
                    ]
                    for pos_pat, neg_pat in polarity_inversions:
                        has_pos_base = bool(re.search(pos_pat, base_lower))
                        has_neg_claim = bool(re.search(neg_pat, claim_lower))
                        has_neg_base = bool(re.search(neg_pat, base_lower))
                        has_pos_claim = bool(re.search(pos_pat, claim_lower))

                        if (has_pos_base and has_neg_claim) or (has_neg_base and has_pos_claim):
                            findings.append(DetectionResult(
                                id=f"det-{uuid.uuid4().hex[:16]}",
                                tenant_id=tenant_id,
                                branch_id=branch_id,
                                detection_category=DetectionCategory.SEMANTIC_INTEGRITY,
                                classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                                agent_id=agent_id,
                                trace_id=trace_id,
                                action_id=action_id,
                                detection_method=DetectionMethod.SEMANTIC_GROUNDING,
                                confidence_score=0.96,
                                uncertainty_state=UncertaintyState.HIGH_CONFIDENCE,
                                severity=DetectionSeverity.CRITICAL,
                                recommended_outcome=RecommendedOutcome.BLOCK,
                                title="Claim Directly Contradicts Approved Enterprise Baseline Policy",
                                description=(
                                    f"Claim directly inverts authorization rules in approved baseline record '{referenced_baseline_id}'."
                                ),
                                baseline_refs=[referenced_baseline_id],
                                evidence_items=[
                                    EvidenceItem(
                                        evidence_type="BASELINE_CONTRADICTION",
                                        resource_id=referenced_baseline_id,
                                        description="Claim polarity inverts baseline policy directive.",
                                        metadata={"baseline_snippet": baseline_content[:200], "claim_snippet": claim_text[:200]},
                                    )
                                ],
                                details={"reason_code": "CLAIM_CONTRADICTS_BASELINE"},
                            ))
                            break

                    # Lexical & conceptual grounding check
                    base_words = set(re.findall(r"\b[a-z]{4,}\b", base_lower))
                    claim_words = set(re.findall(r"\b[a-z]{4,}\b", claim_lower))
                    stop_words = {"this", "that", "with", "from", "have", "been", "were", "what", "when", "where", "which", "will", "would", "shall", "should", "their", "there", "about", "under"}
                    base_words -= stop_words
                    claim_words -= stop_words

                    if claim_words and base_words:
                        overlap = claim_words.intersection(base_words)
                        if len(overlap) == 0:
                            findings.append(DetectionResult(
                                id=f"det-{uuid.uuid4().hex[:16]}",
                                tenant_id=tenant_id,
                                branch_id=branch_id,
                                detection_category=DetectionCategory.SEMANTIC_INTEGRITY,
                                classification_type=DetectionClassificationType.SUSPICIOUS_INDICATOR,
                                agent_id=agent_id,
                                trace_id=trace_id,
                                action_id=action_id,
                                detection_method=DetectionMethod.SEMANTIC_GROUNDING,
                                confidence_score=0.85,
                                uncertainty_state=UncertaintyState.PROBABILISTIC_INDICATOR,
                                severity=DetectionSeverity.HIGH,
                                recommended_outcome=RecommendedOutcome.REQUIRE_HUMAN_APPROVAL,
                                title="Claim Entirely Ungrounded in Cited Enterprise Baseline",
                                description=(
                                    f"Claim cites baseline record '{referenced_baseline_id}' but shares zero substantive concepts "
                                    "with the approved baseline content. Potential fabricated authorization citation."
                                ),
                                baseline_refs=[referenced_baseline_id],
                                evidence_items=[
                                    EvidenceItem(
                                        evidence_type="ZERO_GROUNDING_OVERLAP",
                                        resource_id=referenced_baseline_id,
                                        description="Zero substantive keyword overlap between baseline and claim.",
                                        metadata={"baseline_id": referenced_baseline_id},
                                    )
                                ],
                                details={"reason_code": "CLAIM_NOT_GROUNDED_IN_BASELINE"},
                            ))

        # 2. Contradiction Detection Between Derived Memory and Source
        if source_text and claim_text:
            # Check for direct negation polarity flips
            source_lower = source_text.lower()
            claim_lower = claim_text.lower()

            polarity_inversions = [
                (r"\bis\s+authorized\b", r"\bis\s+not\s+authorized\b|\bunauthorized\b"),
                (r"\bis\s+permitted\b", r"\bis\s+not\s+permitted\b|\bnot\s+permitted\b|\bis\s+forbidden\b|\bis\s+prohibited\b"),
                (r"\brequires\s+approval\b", r"\bdoes\s+not\s+require\s+approval\b|\bwithout\s+approval\b"),
                (r"\bactive\b", r"\binactive\b|\bterminated\b"),
                (r"\ballowed\b|\bis\s+allowed\b", r"\bdisallowed\b|\bblocked\b|\bnot\s+allowed\b|\bis\s+not\s+allowed\b"),
            ]

            for pos_pat, neg_pat in polarity_inversions:
                has_pos_source = bool(re.search(pos_pat, source_lower))
                has_neg_claim = bool(re.search(neg_pat, claim_lower))
                has_neg_source = bool(re.search(neg_pat, source_lower))
                has_pos_claim = bool(re.search(pos_pat, claim_lower))

                if (has_pos_source and has_neg_claim) or (has_neg_source and has_pos_claim):
                    findings.append(DetectionResult(
                        id=f"det-{uuid.uuid4().hex[:16]}",
                        tenant_id=tenant_id,
                        branch_id=branch_id,
                        detection_category=DetectionCategory.SEMANTIC_INTEGRITY,
                        classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                        agent_id=agent_id,
                        trace_id=trace_id,
                        action_id=action_id,
                        detection_method=DetectionMethod.SEMANTIC_GROUNDING,
                        confidence_score=0.92,
                        uncertainty_state=UncertaintyState.HIGH_CONFIDENCE,
                        severity=DetectionSeverity.HIGH,
                        recommended_outcome=RecommendedOutcome.BLOCK,
                        title="Semantic Contradiction Between Derived Memory and Source",
                        description=(
                            "Derived memory statement directly contradicts polarity/meaning of the source content. "
                            "Authorization or permission assertion has been inverted."
                        ),
                        evidence_items=[
                            EvidenceItem(
                                evidence_type="SOURCE_CLAIM_CONTRADICTION",
                                description="Polarity inversion between source and derived claim.",
                                metadata={"source_snippet": source_text[:200], "claim_snippet": claim_text[:200]},
                            )
                        ],
                        details={"reason_code": "DERIVED_MEMORY_CONTRADICTION"},
                    ))
                    break

            # 3. Numeric discrepancy check in financial/operational summaries
            source_amounts = re.findall(r"\$\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?)", source_text)
            claim_amounts = re.findall(r"\$\s*([0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?)", claim_text)
            if source_amounts and claim_amounts:
                # If claim introduces amounts exceeding maximum in source by > 5x
                try:
                    s_max = max(float(a.replace(",", "")) for a in source_amounts)
                    c_max = max(float(a.replace(",", "")) for a in claim_amounts)
                    if c_max > s_max * 2.0:
                        findings.append(DetectionResult(
                            id=f"det-{uuid.uuid4().hex[:16]}",
                            tenant_id=tenant_id,
                            branch_id=branch_id,
                            detection_category=DetectionCategory.SEMANTIC_INTEGRITY,
                            classification_type=DetectionClassificationType.SUSPICIOUS_INDICATOR,
                            agent_id=agent_id,
                            trace_id=trace_id,
                            action_id=action_id,
                            detection_method=DetectionMethod.SEMANTIC_GROUNDING,
                            confidence_score=0.88,
                            uncertainty_state=UncertaintyState.PROBABILISTIC_INDICATOR,
                            severity=DetectionSeverity.HIGH,
                            recommended_outcome=RecommendedOutcome.REQUIRE_HUMAN_APPROVAL,
                            title="Significant Numeric Discrepancy in Derived Summary",
                            description=(
                                f"Derived text specifies financial ceiling/amount (${c_max:,.2f}) exceeding "
                                f"source maximum (${s_max:,.2f}) by more than 200%. Potential hallucination or tampering."
                            ),
                            evidence_items=[
                                EvidenceItem(
                                    evidence_type="NUMERIC_INCONSISTENCY",
                                    description="Claim amount exceeds source ceiling.",
                                    metadata={"source_max": s_max, "claim_max": c_max},
                                )
                            ],
                            details={"reason_code": "NUMERIC_SUMMARY_DISCREPANCY"},
                        ))
                except Exception:
                    pass

            # 4. Summary Constraint Preservation (detecting stripped constraints)
            constraint_terms = [
                (r"\b(?:must\s+never|strictly\s+prohibited|cannot|do\s+not|forbidden)\b", "PROHIBITION"),
                (r"\b(?:requires?\s+(?:prior\s+)?approval|subject\s+to\s+approval)\b", "APPROVAL_MANDATE"),
                (r"\b(?:confidential|strictly\s+restricted|internal\s+only)\b", "CLASSIFICATION_MANDATE"),
            ]
            for pat, c_type in constraint_terms:
                if re.search(pat, source_lower) and not re.search(pat, claim_lower):
                    if re.search(r"\b(?:permitted|allowed|without\s+approval|unrestricted)\b", claim_lower):
                        findings.append(DetectionResult(
                            id=f"det-{uuid.uuid4().hex[:16]}",
                            tenant_id=tenant_id,
                            branch_id=branch_id,
                            detection_category=DetectionCategory.SEMANTIC_INTEGRITY,
                            classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                            agent_id=agent_id,
                            trace_id=trace_id,
                            action_id=action_id,
                            detection_method=DetectionMethod.DETERMINISTIC_RULE,
                            confidence_score=0.93,
                            uncertainty_state=UncertaintyState.HIGH_CONFIDENCE,
                            severity=DetectionSeverity.HIGH,
                            recommended_outcome=RecommendedOutcome.BLOCK,
                            title="Summary Failed to Preserve Mandatory Source Constraints",
                            description=(
                                f"Derived summary stripped mandatory {c_type} present in source text "
                                "and asserted unrestricted permissions."
                            ),
                            evidence_items=[
                                EvidenceItem(
                                    evidence_type="SUMMARY_CONSTRAINT_LOSS",
                                    description=f"Stripped {c_type} from source.",
                                    metadata={"constraint_type": c_type},
                                )
                            ],
                            details={"reason_code": "SUMMARY_CONSTRAINT_LOSS", "constraint_type": c_type},
                        ))
                        break

        # 4. Unsupported Claims Presented as Authoritative Enterprise Mandate
        if not referenced_baseline_id and re.search(r"(?i)\b(?:company\s+policy|executive\s+directive|security\s+standard|compliance\s+mandate)\s+(?:states|specifies|mandates|allows)\b", claim_text):
            findings.append(DetectionResult(
                id=f"det-{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                branch_id=branch_id,
                detection_category=DetectionCategory.SEMANTIC_INTEGRITY,
                classification_type=DetectionClassificationType.SUSPICIOUS_INDICATOR,
                agent_id=agent_id,
                trace_id=trace_id,
                action_id=action_id,
                detection_method=DetectionMethod.HEURISTIC_PATTERN,
                confidence_score=0.85,
                uncertainty_state=UncertaintyState.PROBABILISTIC_INDICATOR,
                severity=DetectionSeverity.MEDIUM,
                recommended_outcome=RecommendedOutcome.REQUIRE_HUMAN_APPROVAL,
                title="Unsupported Assertion Presented as Authoritative Enterprise Policy",
                description=(
                    "Agent asserted that company policy or executive directives mandate or permit an action, "
                    "without providing an approved enterprise baseline record ID reference."
                ),
                evidence_items=[
                    EvidenceItem(
                        evidence_type="UNGROUNDED_POLICY_CLAIM",
                        description="Claim asserts company policy without baseline citation.",
                        metadata={"claim_snippet": claim_text[:200]},
                    )
                ],
                details={"reason_code": "UNGROUNDED_POLICY_ASSERTION"},
            ))

        return findings

    # -------------------------------------------------------------------------
    # C. Agent Behavior and Purpose Deviation Detection
    # -------------------------------------------------------------------------

    async def detect_behavioral_deviation(
        self,
        tenant_id: str,
        agent_id: str,
        proposal_facts: Any,
        profile: Optional[Dict[str, Any]] = None,
        agent_repo: Optional[Any] = None,
        trace_id: Optional[str] = None,
        action_id: Optional[str] = None,
    ) -> List[DetectionResult]:
        """Compare observed behavior with authoritative AgentSecurityProfile."""
        findings: List[DetectionResult] = []
        now_ts = datetime.now(timezone.utc).timestamp()

        # Fetch profile if not supplied
        active_profile = profile
        if active_profile is None and (agent_repo or self.agent_repo):
            repo = agent_repo or self.agent_repo
            try:
                if hasattr(repo, "get_agent_profile"):
                    res = repo.get_agent_profile(agent_id, tenant_id)
                    import inspect
                    if inspect.isawaitable(res):
                        active_profile = await res
                    else:
                        active_profile = res
            except Exception:
                active_profile = None

        if active_profile is None:
            # If no authoritative profile exists, this is an unregistered or unprofiled agent
            findings.append(DetectionResult(
                id=f"det-{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                agent_id=agent_id,
                trace_id=trace_id,
                action_id=action_id,
                detection_method=DetectionMethod.POLICY_VERIFICATION,
                confidence_score=1.0,
                uncertainty_state=UncertaintyState.DEFINITIVE,
                severity=DetectionSeverity.CRITICAL,
                recommended_outcome=RecommendedOutcome.BLOCK,
                title="Unregistered Agent Profile / Missing Security Governance",
                description=f"Agent '{agent_id}' has no authoritative AgentSecurityProfile registered in tenant '{tenant_id}'.",
                evidence_items=[
                    EvidenceItem(
                        evidence_type="MISSING_AGENT_PROFILE",
                        resource_id=agent_id,
                        description="Authoritative security profile does not exist.",
                        metadata={"agent_id": agent_id, "tenant_id": tenant_id},
                    )
                ],
                details={"reason_code": "AGENT_PROFILE_MISSING"},
            ))
            return findings

        profile_version = active_profile.get("profile_version", "v1.0.0")
        branch_id = active_profile.get("branch_id")

        # 1. Profile Status Check
        p_status = active_profile.get("status", "ACTIVE")
        if p_status != "ACTIVE":
            findings.append(DetectionResult(
                id=f"det-{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                branch_id=branch_id,
                detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                agent_id=agent_id,
                profile_version=profile_version,
                trace_id=trace_id,
                action_id=action_id,
                detection_method=DetectionMethod.POLICY_VERIFICATION,
                confidence_score=1.0,
                uncertainty_state=UncertaintyState.DEFINITIVE,
                severity=DetectionSeverity.CRITICAL,
                recommended_outcome=RecommendedOutcome.BLOCK,
                title=f"Agent Profile Status is {p_status}",
                description=f"Agent profile status is '{p_status}'. Only ACTIVE agents are permitted to operate.",
                evidence_items=[
                    EvidenceItem(
                        evidence_type="AGENT_PROFILE_STATUS",
                        resource_id=agent_id,
                        description=f"Profile status is {p_status}.",
                        metadata={"status": p_status},
                    )
                ],
                details={"reason_code": f"AGENT_PROFILE_{p_status}"},
            ))

        tool_name = getattr(proposal_facts, "tool_name", None) or (proposal_facts.get("tool_name") if isinstance(proposal_facts, dict) else None)
        operation = getattr(proposal_facts, "operation", None) or (proposal_facts.get("operation") if isinstance(proposal_facts, dict) else None)
        params = getattr(proposal_facts, "parameters", {}) or (proposal_facts.get("parameters") if isinstance(proposal_facts, dict) else {})
        if not isinstance(params, dict):
            params = {}

        # 2. Action Outside Authorized Purpose or Scope
        purpose = active_profile.get("approved_purpose", "")
        # Heuristic check for departmental cross-domain violations:
        # e.g. Customer Support agent attempting financial transfers or HR payroll modifications
        dept = active_profile.get("owner_department", "")
        if "customer" in dept.lower() or "support" in dept.lower():
            if tool_name in ("sandbox_transfer", "payroll_tool", "admin_database", "execute_sql"):
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                    classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                    agent_id=agent_id,
                    profile_version=profile_version,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.POLICY_VERIFICATION,
                    confidence_score=0.99,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.CRITICAL,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Action Exceeds Authorized Departmental Purpose",
                    description=(
                        f"Agent '{agent_id}' from department '{dept}' (purpose: '{purpose}') proposed privileged tool "
                        f"'{tool_name}'. Action is entirely outside approved departmental purpose."
                    ),
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="PURPOSE_DEVIATION",
                            resource_id=agent_id,
                            description="Tool call contradicts approved purpose.",
                            metadata={"department": dept, "purpose": purpose, "proposed_tool": tool_name},
                        )
                    ],
                    details={"reason_code": "ACTION_OUTSIDE_AUTHORIZED_PURPOSE"},
                ))

        # 3. Operational Restrictions in Profile
        restrictions = active_profile.get("operational_restrictions") or {}
        disallowed_tools = restrictions.get("disallowed_tools") or []
        if tool_name in disallowed_tools:
            findings.append(DetectionResult(
                id=f"det-{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                branch_id=branch_id,
                detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                agent_id=agent_id,
                profile_version=profile_version,
                trace_id=trace_id,
                action_id=action_id,
                detection_method=DetectionMethod.POLICY_VERIFICATION,
                confidence_score=1.0,
                uncertainty_state=UncertaintyState.DEFINITIVE,
                severity=DetectionSeverity.HIGH,
                recommended_outcome=RecommendedOutcome.BLOCK,
                title="Tool Prohibited by Authoritative Operational Restrictions",
                description=f"Tool '{tool_name}' is explicitly blacklisted in agent's operational restrictions.",
                evidence_items=[
                    EvidenceItem(
                        evidence_type="DISALLOWED_TOOL_RESTRICTION",
                        resource_id=agent_id,
                        description="Tool is disallowed in profile restrictions.",
                        metadata={"tool_name": tool_name, "disallowed_tools": disallowed_tools},
                    )
                ],
                details={"reason_code": "TOOL_EXPLICITLY_DISALLOWED"},
            ))

        disallowed_ops = restrictions.get("disallowed_operations") or []
        if operation in disallowed_ops:
            findings.append(DetectionResult(
                id=f"det-{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                branch_id=branch_id,
                detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                agent_id=agent_id,
                profile_version=profile_version,
                trace_id=trace_id,
                action_id=action_id,
                detection_method=DetectionMethod.POLICY_VERIFICATION,
                confidence_score=1.0,
                uncertainty_state=UncertaintyState.DEFINITIVE,
                severity=DetectionSeverity.HIGH,
                recommended_outcome=RecommendedOutcome.BLOCK,
                title="Operation Prohibited by Authoritative Operational Restrictions",
                description=f"Operation '{operation}' is explicitly blacklisted in agent's operational restrictions.",
                evidence_items=[
                    EvidenceItem(
                        evidence_type="DISALLOWED_OPERATION_RESTRICTION",
                        resource_id=agent_id,
                        description="Operation is disallowed in profile restrictions.",
                        metadata={"operation": operation, "disallowed_operations": disallowed_ops},
                    )
                ],
                details={"reason_code": "OPERATION_EXPLICITLY_DISALLOWED"},
            ))

        # Check parameter ceiling limits from operational_restrictions
        max_amount = restrictions.get("max_amount")
        if max_amount is not None and "amount" in params:
            try:
                prop_amt = float(params["amount"])
                if prop_amt > float(max_amount):
                    findings.append(DetectionResult(
                        id=f"det-{uuid.uuid4().hex[:16]}",
                        tenant_id=tenant_id,
                        branch_id=branch_id,
                        detection_category=DetectionCategory.TOOL_EXECUTION_THREAT,
                        classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                        agent_id=agent_id,
                        profile_version=profile_version,
                        trace_id=trace_id,
                        action_id=action_id,
                        detection_method=DetectionMethod.POLICY_VERIFICATION,
                        confidence_score=1.0,
                        uncertainty_state=UncertaintyState.DEFINITIVE,
                        severity=DetectionSeverity.HIGH,
                        recommended_outcome=RecommendedOutcome.BLOCK,
                        title="Profile Operational Ceiling Exceeded",
                        description=f"Proposed amount {prop_amt} exceeds profile ceiling {max_amount}.",
                        evidence_items=[
                            EvidenceItem(
                                evidence_type="CEILING_EXCEEDED",
                                description="Parameter exceeds profile maximum.",
                                metadata={"parameter": "amount", "value": prop_amt, "ceiling": max_amount},
                            )
                        ],
                        details={"reason_code": "PROFILE_CEILING_EXCEEDED"},
                    ))
            except (ValueError, TypeError):
                pass

        # 4. Data Scope and Classification Enforcement
        data_scope = active_profile.get("data_scope") or []
        target_classification = params.get("data_classification") or params.get("classification")
        if target_classification:
            # Canonical sensitivity order: PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED < PII < SECRETS
            if data_scope and target_classification not in data_scope:
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                    classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                    agent_id=agent_id,
                    profile_version=profile_version,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.POLICY_VERIFICATION,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.HIGH,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Access to Data Classification Outside Authorized Scope",
                    description=(
                        f"Action requested data classified as '{target_classification}', but agent's "
                        f"authorized data scope is limited to: {', '.join(data_scope)}."
                    ),
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="DATA_SCOPE_VIOLATION",
                            description="Requested classification not in data_scope.",
                            metadata={"requested": target_classification, "authorized_scope": data_scope},
                        )
                    ],
                    details={"reason_code": "DATA_SCOPE_EXCEEDED"},
                ))

        # 5. Branch Boundary Isolation
        target_branch = params.get("target_branch_id") or params.get("branch_id")
        if branch_id and target_branch and target_branch != "ALL_BRANCHES":
            if branch_id != target_branch:
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                    classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                    agent_id=agent_id,
                    profile_version=profile_version,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.POLICY_VERIFICATION,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.HIGH,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Cross-Branch Resource Access Boundary Violation",
                    description=(
                        f"Agent is scoped to branch '{branch_id}', but attempted action targets resource "
                        f"in branch '{target_branch}'. Branch isolation violation."
                    ),
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="BRANCH_BOUNDARY_VIOLATION",
                            description="Agent branch does not match target resource branch.",
                            metadata={"agent_branch": branch_id, "target_branch": target_branch},
                        )
                    ],
                    details={"reason_code": "BRANCH_ISOLATION_VIOLATION"},
                ))

        # 6. Attempts to Modify Privileged Instructions or Security Profiles
        param_str = json.dumps(params).lower()
        for priv_target in PRIVILEGED_INSTRUCTION_TARGETS:
            if priv_target in param_str:
                findings.append(DetectionResult(
                    id=f"det-{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    branch_id=branch_id,
                    detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                    classification_type=DetectionClassificationType.CONFIRMED_SECURITY_INCIDENT,
                    agent_id=agent_id,
                    profile_version=profile_version,
                    trace_id=trace_id,
                    action_id=action_id,
                    detection_method=DetectionMethod.POLICY_VERIFICATION,
                    confidence_score=1.0,
                    uncertainty_state=UncertaintyState.DEFINITIVE,
                    severity=DetectionSeverity.CRITICAL,
                    recommended_outcome=RecommendedOutcome.BLOCK,
                    title="Attempted Tampering with Privileged Security Baseline",
                    description=(
                        f"Action payload directly targets privileged AMSC security structure '{priv_target}'. "
                        "Agents are strictly forbidden from modifying baseline or security profiles."
                    ),
                    evidence_items=[
                        EvidenceItem(
                            evidence_type="PRIVILEGED_INSTRUCTION_TAMPER",
                            description="Privileged table/resource targeted in payload.",
                            metadata={"targeted_structure": priv_target},
                        )
                    ],
                    details={"reason_code": "PRIVILEGED_STRUCTURE_TAMPERING"},
                ))
                break

        # 7. Abnormal Repeated Actions / Sequences Tracking
        recent_blocks = self._get_recent_block_count(tenant_id, agent_id, now_ts)
        if recent_blocks >= 4:
            findings.append(DetectionResult(
                id=f"det-{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                branch_id=branch_id,
                detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                classification_type=DetectionClassificationType.CONFIRMED_POLICY_VIOLATION,
                agent_id=agent_id,
                profile_version=profile_version,
                trace_id=trace_id,
                action_id=action_id,
                detection_method=DetectionMethod.STATISTICAL_FREQUENCY,
                confidence_score=0.94,
                uncertainty_state=UncertaintyState.HIGH_CONFIDENCE,
                severity=DetectionSeverity.HIGH,
                recommended_outcome=RecommendedOutcome.BLOCK,
                title="Abnormal Repeated Blocked Actions Sequence Detected",
                description=(
                    f"Agent '{agent_id}' has generated {recent_blocks} consecutive blocked or failed proposals "
                    "within 60 seconds. Potential automated brute force or compromised execution loop."
                ),
                evidence_items=[
                    EvidenceItem(
                        evidence_type="STATISTICAL_FREQUENCY_BURST",
                        description=f"{recent_blocks} blocks in 60s.",
                        metadata={"recent_blocks_count": recent_blocks, "window_seconds": 60},
                    )
                ],
                details={"reason_code": "REPEATED_ACTION_BURST", "block_count": recent_blocks},
            ))

        # Check for rapid identical proposal runaway loop (>= 5 identical proposals in 10s)
        action_sig = f"{tool_name}:{operation}:{json.dumps(params, sort_keys=True)}"
        identical_count = self._track_and_check_repeated_proposals(tenant_id, agent_id, action_sig, now_ts)
        if identical_count >= 5:
            findings.append(DetectionResult(
                id=f"det-{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                branch_id=branch_id,
                detection_category=DetectionCategory.BEHAVIORAL_DEVIATION,
                classification_type=DetectionClassificationType.SUSPICIOUS_INDICATOR,
                agent_id=agent_id,
                profile_version=profile_version,
                trace_id=trace_id,
                action_id=action_id,
                detection_method=DetectionMethod.STATISTICAL_FREQUENCY,
                confidence_score=0.89,
                uncertainty_state=UncertaintyState.PROBABILISTIC_INDICATOR,
                severity=DetectionSeverity.HIGH,
                recommended_outcome=RecommendedOutcome.REQUIRE_HUMAN_APPROVAL,
                title="Suspicious Identical Action Burst Detected",
                description=(
                    f"Agent '{agent_id}' submitted {identical_count} identical proposals for '{tool_name}.{operation}' "
                    "within 10 seconds. Potential runaway loop."
                ),
                evidence_items=[
                    EvidenceItem(
                        evidence_type="IDENTICAL_ACTION_BURST",
                        description=f"{identical_count} identical proposals in 10s.",
                        metadata={"identical_count": identical_count, "action_sig": action_sig[:100]},
                    )
                ],
                details={"reason_code": "IDENTICAL_ACTION_BURST", "count": identical_count},
            ))

        # 8. Benign Anomaly Handling (Normal variance within approved scope)
        if not findings and tool_name and operation:
            # Emit benign observation without false alarm
            findings.append(DetectionResult(
                id=f"det-{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                branch_id=branch_id,
                detection_category=DetectionCategory.TOOL_EXECUTION_THREAT,
                classification_type=DetectionClassificationType.OBSERVATION,
                agent_id=agent_id,
                profile_version=profile_version,
                trace_id=trace_id,
                action_id=action_id,
                detection_method=DetectionMethod.POLICY_VERIFICATION,
                confidence_score=1.0,
                uncertainty_state=UncertaintyState.DEFINITIVE,
                severity=DetectionSeverity.INFORMATIONAL,
                recommended_outcome=RecommendedOutcome.ALLOW,
                title="Routine Action Verified Within Security Profile",
                description=f"Action '{tool_name}.{operation}' complies with authoritative profile purpose and scope.",
                evidence_items=[
                    EvidenceItem(
                        evidence_type="ROUTINE_PROFILE_ALIGNMENT",
                        description="Action verified within operational bounds.",
                        metadata={"tool_name": tool_name, "operation": operation},
                    )
                ],
                details={"reason_code": "ROUTINE_OPERATION_VERIFIED"},
            ))

        return findings

    # -------------------------------------------------------------------------
    # D. Tool and Execution Threat Detection
    # -------------------------------------------------------------------------

    async def detect_tool_threat(
        self,
        tenant_id: str,
        proposal_facts: Any,
        agent_profile: Optional[Dict[str, Any]] = None,
        baseline_repo: Optional[Any] = None,
        trace_id: Optional[str] = None,
        action_id: Optional[str] = None,
    ) -> List[DetectionResult]:
        """Pre-execution evaluation across proposal, baseline policies, and tool threats."""
        findings: List[DetectionResult] = []

        agent_id = getattr(proposal_facts, "agent_id", None) or (proposal_facts.get("agent_id") if isinstance(proposal_facts, dict) else None)
        params = getattr(proposal_facts, "parameters", {}) or (proposal_facts.get("parameters") if isinstance(proposal_facts, dict) else {})
        if not isinstance(params, dict):
            params = {}

        # Heuristic command injection checks in tool parameters
        cmd_injection_patterns = [
            re.compile(r"[;&|`$]\s*(?:cat|rm|sh|bash|curl|wget|python|powershell|cmd)\b"),
            re.compile(r"(?i)\bUNION\s+SELECT\b"),
            re.compile(r"(?i)\bDROP\s+TABLE\b"),
            re.compile(r"(?i)\bOR\s+1\s*=\s*1\b"),
        ]

        for k, v in params.items():
            if isinstance(v, str):
                for pat in cmd_injection_patterns:
                    if pat.search(v):
                        findings.append(DetectionResult(
                            id=f"det-{uuid.uuid4().hex[:16]}",
                            tenant_id=tenant_id,
                            detection_category=DetectionCategory.TOOL_EXECUTION_THREAT,
                            classification_type=DetectionClassificationType.CONFIRMED_SECURITY_INCIDENT,
                            agent_id=agent_id,
                            trace_id=trace_id,
                            action_id=action_id,
                            detection_method=DetectionMethod.HEURISTIC_PATTERN,
                            confidence_score=0.99,
                            uncertainty_state=UncertaintyState.DEFINITIVE,
                            severity=DetectionSeverity.CRITICAL,
                            recommended_outcome=RecommendedOutcome.BLOCK,
                            title="Command / SQL Injection Signature in Parameter",
                            description=(
                                f"Parameter '{k}' contains command or SQL injection pattern: '{v[:60]}'. "
                                "Exploitation attempt blocked before execution."
                            ),
                            evidence_items=[
                                EvidenceItem(
                                    evidence_type="INJECTION_PAYLOAD",
                                    description="Injection signature identified in parameter value.",
                                    metadata={"parameter_name": k, "sample": v[:80]},
                                )
                            ],
                            details={"reason_code": "PARAMETER_INJECTION_DETECTED", "parameter": k},
                        ))
                        break

        return findings

    # -------------------------------------------------------------------------
    # Comprehensive Evaluation Dispatcher
    # -------------------------------------------------------------------------

    async def evaluate_all(
        self,
        tenant_id: str,
        request: EvaluateDetectionRequest,
    ) -> EvaluateDetectionResponse:
        """Run all relevant detection checks on an ad-hoc or incoming proposal request."""
        all_results: List[DetectionResult] = []

        # 1. Memory and content checks
        if request.content is not None or request.expected_checksum is not None:
            mem_findings = await self.detect_memory_integrity(
                tenant_id=tenant_id,
                content=request.content,
                record_id=request.record_id,
                expected_checksum=request.expected_checksum,
                agent_id=request.agent_id,
                branch_id=request.branch_id,
                parent_record_id=request.parent_record_id,
                trace_id=request.trace_id,
                action_id=request.action_id,
            )
            all_results.extend(mem_findings)

        # 2. Semantic integrity checks
        if request.claim_text is not None:
            sem_findings = await self.detect_semantic_integrity(
                tenant_id=tenant_id,
                claim_text=request.claim_text,
                source_text=request.source_text,
                agent_id=request.agent_id,
                branch_id=request.branch_id,
                trace_id=request.trace_id,
                action_id=request.action_id,
            )
            all_results.extend(sem_findings)

        # 3. Behavioral deviation checks
        if request.agent_id is not None and (request.tool_name or request.operation):
            facts = {
                "agent_id": request.agent_id,
                "tool_name": request.tool_name,
                "operation": request.operation,
                "parameters": request.parameters,
                "branch_id": request.branch_id,
            }
            beh_findings = await self.detect_behavioral_deviation(
                tenant_id=tenant_id,
                agent_id=request.agent_id,
                proposal_facts=facts,
                trace_id=request.trace_id,
                action_id=request.action_id,
            )
            all_results.extend(beh_findings)

            # 4. Tool threat checks
            tool_findings = await self.detect_tool_threat(
                tenant_id=tenant_id,
                proposal_facts=facts,
                trace_id=request.trace_id,
                action_id=request.action_id,
            )
            all_results.extend(tool_findings)

        # Record findings in repository if configured
        if self.detection_repo:
            for r in all_results:
                try:
                    res = self.detection_repo.record_detection(r.to_dict())
                    import inspect
                    if inspect.isawaitable(res):
                        await res
                except Exception as exc:
                    logger.warning(f"Failed to record detection result: {exc}")

        # Compute aggregate outcome
        severities = [r.severity for r in all_results]
        highest_sev = DetectionSeverity.INFORMATIONAL
        for s in (DetectionSeverity.CRITICAL, DetectionSeverity.HIGH, DetectionSeverity.MEDIUM, DetectionSeverity.LOW):
            if s in severities:
                highest_sev = s
                break

        outcomes = [r.recommended_outcome for r in all_results]
        rec_outcome = RecommendedOutcome.ALLOW
        if RecommendedOutcome.BLOCK in outcomes or RecommendedOutcome.QUARANTINE_RECORD in outcomes:
            rec_outcome = RecommendedOutcome.BLOCK
        elif RecommendedOutcome.REQUIRE_HUMAN_APPROVAL in outcomes:
            rec_outcome = RecommendedOutcome.REQUIRE_HUMAN_APPROVAL

        has_violation = any(r.classification_type == DetectionClassificationType.CONFIRMED_POLICY_VIOLATION for r in all_results)
        has_incident = any(r.classification_type == DetectionClassificationType.CONFIRMED_SECURITY_INCIDENT for r in all_results)

        return EvaluateDetectionResponse(
            findings_count=len(all_results),
            highest_severity=highest_sev,
            recommended_outcome=rec_outcome,
            has_confirmed_violation=has_violation,
            has_confirmed_incident=has_incident,
            detections=all_results,
        )


_default_detection_engine: Optional[DetectionEngine] = None


def get_default_detection_engine() -> DetectionEngine:
    global _default_detection_engine
    if _default_detection_engine is None:
        from backend.app.database.repositories.detection import get_default_detection_repository
        _default_detection_engine = DetectionEngine(detection_repo=get_default_detection_repository())
    return _default_detection_engine
