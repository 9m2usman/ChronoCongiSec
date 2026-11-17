export interface AuditEvent {
  id: string;
  tenant_id: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  evidence_sha256: string;
  metadata?: Record<string, unknown>;
}
