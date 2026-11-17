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
  action: string;
  checkpoint_version: number;
  target_checksum: string;
}

export interface RecoveryPlanPreview {
  checkpoint_id: string;
  checkpoint_name: string;
  affected_records_count: number;
  affected_records: AffectedRecord[];
  irreversible_external_actions: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface RecoveryPlanPreviewResponse {
  plan_id: string;
  status: string;
  preview: RecoveryPlanPreview;
}

export interface RecoveryExecuteRequest {
  plan_id: string;
  pre_recovery_snapshot_confirmed: boolean;
}

export interface RecoveryExecuteResponse {
  plan_id: string;
  status: 'EXECUTED';
  executed_at: string;
  restored_records: string[];
  audit_event_id: string;
  message: string;
}
