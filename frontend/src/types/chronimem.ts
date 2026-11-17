export interface ChroniMemVersion {
  version: number;
  time_display: string;
  checksum: string;
  author: string;
  trust_state: string;
  content: string;
  created_at: string;
}

export interface ChroniMemRecordTimeline {
  record_id: string;
  tenant_id: string;
  current_version: number;
  versions: ChroniMemVersion[];
}
