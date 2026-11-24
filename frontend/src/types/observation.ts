export interface ObservationEvent {
  id: string;
  tenant_id: string;
  branch_id?: string | null;
  event_type: string;
  event_category: string;
  agent_id?: string | null;
  agent_runtime?: string | null;
  execution_id?: string | null;
  trace_id?: string | null;
  parent_span_id?: string | null;
  source_component: string;
  related_memory_id?: string | null;
  related_memory_version?: number | null;
  tool_name?: string | null;
  action_id?: string | null;
  policy_decision_id?: string | null;
  execution_receipt_id?: string | null;
  baseline_version?: string | null;
  outcome: string;
  payload: Record<string, any>;
  occurred_at?: string;
  created_at?: string;
}

export interface ObservationListEnvelope {
  items: ObservationEvent[];
  total: number;
  limit: number;
  offset: number;
}
