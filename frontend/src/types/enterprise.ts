export type ConnectorType =
  | 'DATABASE'
  | 'FILESYSTEM'
  | 'DOCUMENT_REPO'
  | 'CLOUD_STORAGE'
  | 'INTERNAL_API'
  | 'KNOWLEDGE_BASE'
  | 'AGENT_FRAMEWORK'
  | 'ENTERPRISE_APP';

export type ConnectorStatus =
  | 'PENDING_AUTH'
  | 'AUTHORIZED'
  | 'PAUSED'
  | 'REVOKED'
  | 'DISCONNECTED'
  | 'ERROR'
  | 'UNAVAILABLE';

export interface EnterpriseConnector {
  id: string;
  tenant_id: string;
  name: string;
  connector_type: ConnectorType;
  status: ConnectorStatus;
  auth_mode: string;
  config_json: Record<string, any>;
  secret_ref?: string | null;
  scope_json: Record<string, any>;
  monitoring_coverage_json: {
    observed_events?: string[];
    inferred_events?: string[];
    unsupported_events?: string[];
  };
  last_sync_at?: string | null;
  last_sync_status?: string | null;
  last_error?: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface DiscoveredResource {
  id: string;
  tenant_id: string;
  connector_id: string;
  source_id?: string | null;
  resource_type: string;
  external_id: string;
  name: string;
  owner?: string | null;
  access_scope: string;
  classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  sync_status: string;
  source_version?: string | null;
  content_checksum?: string | null;
  metadata_json: Record<string, any>;
  retention_policy: string;
  last_synced_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface SyncJob {
  id: string;
  tenant_id: string;
  connector_id: string;
  strategy: string;
  status: string;
  resources_discovered: number;
  resources_synced: number;
  resources_changed: number;
  resources_deleted: number;
  resources_failed: number;
  checkpoint_json: Record<string, any>;
  error_message?: string | null;
  started_at: string;
  completed_at?: string | null;
}

export interface KnowledgeClaim {
  id: string;
  tenant_id: string;
  resource_id: string;
  source_id?: string | null;
  claim_type: string;
  subject: string;
  predicate: string;
  object_value: string;
  department?: string | null;
  provenance_json: Record<string, any>;
  trust_state: string;
  confidence: number;
  conflict_group_id?: string | null;
  superseded_by_id?: string | null;
  created_at: string;
}

export interface EnterpriseMemoryLink {
  id: string;
  tenant_id: string;
  memory_record_id: string;
  memory_version: number;
  resource_id: string;
  source_version?: string | null;
  agent_id?: string | null;
  extraction_purpose: string;
  confidence: number;
  freshness_status: string;
  snapshot_checksum: string;
  snapshot_json: Record<string, any>;
  retrieved_at: string;
}

export interface ConnectorAuditLog {
  id: string;
  tenant_id: string;
  connector_id?: string | null;
  actor_id: string;
  action: string;
  status: string;
  details_json: Record<string, any>;
  created_at: string;
}

export interface ImpactTrace {
  target_id: string;
  tenant_id: string;
  source_resources: DiscoveredResource[];
  affected_claims: KnowledgeClaim[];
  dependent_memories: EnterpriseMemoryLink[];
  affected_agent_ids: string[];
  recommended_actions: string[];
  evidence_summary: Record<string, number>;
}
