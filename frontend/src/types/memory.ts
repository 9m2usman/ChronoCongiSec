export type RecordType = 'KNOWLEDGE' | 'CONVERSATION' | 'SCRATCHPAD';

export type TrustState =
  | 'UNVERIFIED'
  | 'TRUSTED'
  | 'SUSPICIOUS'
  | 'QUARANTINED'
  | 'REJECTED'
  | 'SUPERSEDED';

export type ProvenanceRelationType =
  | 'DERIVED_FROM'
  | 'TRANSFORMED_INTO'
  | 'SUPERSEDES';

export interface MemoryRecord {
  id: string;
  tenant_id: string;
  agent_id?: string | null;
  source_id?: string | null;
  record_type: string;
  trust_state: string;
  current_version: number;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface MemoryVersion {
  id: string;
  tenant_id: string;
  record_id: string;
  version: number;
  content: string;
  checksum: string;
  created_at?: string | null;
}

export interface ProvenanceEdge {
  id: string;
  tenant_id: string;
  from_record_id: string;
  to_record_id: string;
  relation_type: string;
  created_at?: string | null;
}

export interface MemoryIngestRequest {
  content: string;
  record_type?: string;
  source_id?: string | null;
  parent_record_id?: string | null;
  agent_id?: string | null;
}

export interface MemoryRecordResponse {
  id: string;
  tenant_id: string;
  agent_id?: string | null;
  source_id?: string | null;
  record_type: string;
  trust_state: string;
  current_version: number;
  checksum?: string | null;
  content?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface MemoryDetailResponse {
  record: MemoryRecord;
  versions: MemoryVersion[];
  provenance: ProvenanceEdge[];
}

export interface QuarantineRequest {
  reason: string;
  analyst_notes?: string;
}

export interface QuarantineResponse {
  id: string;
  previous_state: string;
  trust_state: string;
  message: string;
}

export interface KnowledgeGraphNode {
  id: string;
  record_type: string;
  trust_state: string;
  current_version: number;
  agent_id?: string | null;
}

export interface KnowledgeGraphEdge {
  id: string;
  from_record_id: string;
  to_record_id: string;
  relation_type: string;
}

export interface KnowledgeGraphResponse {
  nodes: KnowledgeGraphNode[];
  edges: KnowledgeGraphEdge[];
  complete: boolean;
  truncated_reason?: string | null;
}
