export interface ExecutionSpan {
  id: string;
  trace_id: string;
  timestamp: string;
  time_display: string;
  agent_id: string;
  agent_name: string;
  action_label: string;
  action_detail: string;
  memory_ref?: string;
  status: 'OK' | 'TAINTED' | 'BLOCKED' | 'INTERCEPTED';
  details?: Record<string, unknown>;
}

export interface MemorySpan {
  id: string;
  record_id: string;
  timestamp: string;
  time_display: string;
  label: string;
  trust_state: string;
  checksum: string;
  source_uri?: string;
}

export interface DualTraceData {
  trace_id: string;
  execution_spans: ExecutionSpan[];
  memory_spans: MemorySpan[];
}
