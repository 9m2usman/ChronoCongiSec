export type DetectionCategory =
  | 'MEMORY_INTEGRITY'
  | 'PROMPT_INJECTION'
  | 'PROVENANCE_INTEGRITY'
  | 'KNOWLEDGE_INTEGRITY'
  | 'SEMANTIC_INTEGRITY'
  | 'BEHAVIORAL_DEVIATION'
  | 'TOOL_EXECUTION_THREAT';

export type DetectionClassificationType =
  | 'OBSERVATION'
  | 'SUSPICIOUS_INDICATOR'
  | 'CONFIRMED_POLICY_VIOLATION'
  | 'CONFIRMED_SECURITY_INCIDENT';

export type DetectionMethod =
  | 'DETERMINISTIC_RULE'
  | 'CRYPTOGRAPHIC_HASH'
  | 'POLICY_VERIFICATION'
  | 'HEURISTIC_PATTERN'
  | 'STATISTICAL_FREQUENCY'
  | 'SEMANTIC_GROUNDING';

export type UncertaintyState =
  | 'DEFINITIVE'
  | 'HIGH_CONFIDENCE'
  | 'PROBABILISTIC_INDICATOR'
  | 'INDETERMINATE';

export type DetectionSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

export type RecommendedOutcome =
  | 'ALLOW'
  | 'BLOCK'
  | 'REQUIRE_HUMAN_APPROVAL'
  | 'QUARANTINE_RECORD'
  | 'ALERT_ONLY';

export type DetectionStatus =
  | 'DETECTED'
  | 'EVALUATED'
  | 'CONFIRMED_VIOLATION'
  | 'CONFIRMED_INCIDENT'
  | 'DISMISSED_FALSE_POSITIVE'
  | 'RESOLVED';

export interface EvidenceItem {
  evidence_type: string;
  resource_id?: string | null;
  sha256_digest?: string | null;
  description: string;
  metadata?: Record<string, any>;
}

export interface DetectionResult {
  id: string;
  tenant_id: string;
  branch_id?: string | null;
  detection_category: DetectionCategory;
  classification_type: DetectionClassificationType;
  agent_id?: string | null;
  profile_version?: string | null;
  execution_id?: string | null;
  task_id?: string | null;
  trace_id?: string | null;
  action_id?: string | null;
  detection_method: DetectionMethod;
  confidence_score: number;
  uncertainty_state: UncertaintyState;
  severity: DetectionSeverity;
  recommended_outcome: RecommendedOutcome;
  policy_decision_id?: string | null;
  status: DetectionStatus;
  title: string;
  description: string;
  memory_refs: string[];
  baseline_refs: string[];
  evidence_items: EvidenceItem[];
  details: Record<string, any>;
  audit_history?: Array<{ status: string; reviewer_user_id: string; reviewed_at: string; notes?: string }> | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface EvaluateDetectionRequest {
  content?: string | null;
  claim_text?: string | null;
  source_text?: string | null;
  record_id?: string | null;
  parent_record_id?: string | null;
  expected_checksum?: string | null;
  agent_id?: string | null;
  branch_id?: string | null;
  tool_name?: string | null;
  operation?: string | null;
  parameters?: Record<string, any>;
  memory_refs?: string[];
  trace_id?: string | null;
  action_id?: string | null;
}

export interface EvaluateDetectionResponse {
  findings_count: number;
  highest_severity: DetectionSeverity;
  recommended_outcome: RecommendedOutcome;
  has_confirmed_violation: boolean;
  has_confirmed_incident: boolean;
  detections: DetectionResult[];
}

export interface DetectionReviewRequest {
  status: 'CONFIRMED_VIOLATION' | 'CONFIRMED_INCIDENT' | 'DISMISSED_FALSE_POSITIVE' | 'RESOLVED';
  notes?: string | null;
}
