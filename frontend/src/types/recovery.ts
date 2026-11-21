export interface Checkpoint {
  id: string;
  tenant_id: string;
  name: string;
  agent_id?: string;
  checksum: string;
  created_at: string;
}

export interface AffectedRecord {
  record_id: string;
  /** RESTORED_TO_CHECKPOINT | QUARANTINED_INTERMEDIARY | UNCHANGED_REJECTED */
  action: string;
  /** null for records that are not in the checkpoint (intermediaries are quarantined, not restored) */
  checkpoint_version: number | null;
  target_checksum: string | null;
  current_version?: number;
  current_trust_state?: string;
}

export interface RecoveryPlanPreview {
  checkpoint_id: string;
  checkpoint_name: string;
  affected_records_count: number;
  affected_records: AffectedRecord[];
  irreversible_external_actions: number;
  irreversible_execution_ids?: string[];
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
  target_record_id?: string;
  /** Always UNVERIFIED: recovery never restores trust (TRD §18). */
  restored_records_become?: 'UNVERIFIED';
}

export interface RecoveryPlanPreviewResponse {
  plan_id: string;
  status: string;
  preview: RecoveryPlanPreview;
}

export interface RecoveryExecuteRequest {
  plan_id: string;
  pre_recovery_snapshot_confirmed?: boolean;
}

/** EXECUTED (200) is the only success. FAILED (409/503) changed no content; RECONCILIATION_REQUIRED (500)
 * means the rollback committed but a follow-up step failed and records remain restricted. */
export type RecoveryStatus = 'EXECUTED' | 'FAILED' | 'RECONCILIATION_REQUIRED';

export interface RecoveryExecuteResponse {
  plan_id: string;
  status: RecoveryStatus;
  success: boolean;
  executed_at: string | null;
  restored_records: string[];
  restored_records_count: number;
  quarantined_intermediary_ids: string[];
  irreversible_external_actions: number;
  audit_event_id: string | null;
  restored_records_trust_state: 'UNVERIFIED' | null;
  reason_codes: string[];
  message: string;
}
