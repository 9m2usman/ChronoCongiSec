export interface ActionProposal {
  action_id: string;
  agent_id: string;
  tool_name: string;
  operation: string;
  parameters: Record<string, unknown>;
  memory_refs: string[];
  idempotency_key: string;
  trace_id: string;
}

export interface PolicyDecision {
  action_id: string;
  proposal_id: string;
  agent_name?: string;
  tool_name?: string;
  decision: 'ALLOW' | 'BLOCK' | 'REQUIRES_APPROVAL';
  memory_trust: string;
  policy_result: string;
  reasons: string[];
  execution_status: 'EXECUTED' | 'NOT_EXECUTED';
  result?: unknown;
  created_at: string;
}
