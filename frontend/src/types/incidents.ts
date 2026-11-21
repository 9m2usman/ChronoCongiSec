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
  /** Backend lifecycle (Doc 05 Table 20) plus CLOSED used by fixtures. */
  status: 'OPEN' | 'INVESTIGATING' | 'QUARANTINED' | 'RESOLVED' | 'CLOSED';
  evidence_summary: string;
  evidence_details?: Record<string, unknown>;
  created_at: string;
}

/** Backend IncidentSummaryResponse (GET /security/incidents -> { items: IncidentSummary[] }). */
export interface IncidentSummary {
  id: string;
  tenant_id: string;
  title: string;
  classification: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'QUARANTINED' | 'RESOLVED';
  affected_record_id?: string | null;
  agent_id?: string | null;
  evidence_count: number;
  created_at: string;
}

export interface IncidentListEnvelope {
  items: IncidentSummary[];
  limit: number;
  offset: number;
  has_more: boolean;
  total?: number | null;
}

export interface SecurityAlertsSummary {
  total_alerts: number;
  critical_count: number;
  quarantined_records_count: number;
  blocked_actions_24h: number;
}
