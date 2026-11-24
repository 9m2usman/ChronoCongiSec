export interface BaselineRecord {
  id: string;
  tenant_id: string;
  branch_id?: string | null;
  title: string;
  category: 'POLICY' | 'PROCEDURE' | 'APPROVED_KNOWLEDGE' | string;
  source_type: 'INTERNAL_POLICY' | 'REGULATORY_STANDARD' | 'OPERATIONAL_DIRECTIVE' | 'LEGAL_COMPLIANCE' | string;
  lifecycle_status: 'DRAFT' | 'IN_REVIEW' | 'APPROVED' | 'ACTIVE' | 'SUPERSEDED' | 'REVOKED' | 'ARCHIVED' | string;
  provenance: string;
  classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | string;
  access_scope: string[];
  current_version: string;
  source_uri?: string | null;
  effective_from?: string | null;
  expires_at?: string | null;
  superseded_by_id?: string | null;
  created_by_user_id: string;
  approved_by_user_id?: string | null;
  content: string;
  content_digest: string;
  digest_algorithm: string;
  created_at: string;
  updated_at: string;
}

export interface BaselineVersionSnapshot {
  id: string;
  baseline_record_id: string;
  version_number: string;
  content: string;
  content_digest: string;
  change_summary: string;
  author_id: string;
  created_at: string;
}

export interface BaselineListEnvelope {
  items: BaselineRecord[];
  total: number;
  limit: number;
  offset: number;
}
