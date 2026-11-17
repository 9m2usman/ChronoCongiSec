export interface SecurityIncident {
  id: string;
  tenant_id: string;
  title: string;
  threat_type: string;
  classification: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  target_agent_id?: string;
  target_agent_name?: string;
  tainted_chunk_id?: string;
  gateway_status: string;
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';
  evidence_summary: string;
  evidence_details?: Record<string, unknown>;
  created_at: string;
}

export interface SecurityAlertsSummary {
  total_alerts: number;
  critical_count: number;
  quarantined_records_count: number;
  blocked_actions_24h: number;
}
