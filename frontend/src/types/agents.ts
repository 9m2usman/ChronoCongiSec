export interface Agent {
  id: string;
  tenant_id: string;
  name: string;
  runtime: string;
  model: string;
  system_prompt: string;
  trust_tier: 'RESTRICTED' | 'STANDARD' | 'ELEVATED';
  status: 'ACTIVE' | 'STANDBY' | 'SUSPENDED';
  tools: string[];
  last_heartbeat?: string;
  created_at?: string;
  updated_at?: string;
}

export interface AgentRegisterRequest {
  name: string;
  runtime: string;
  model: string;
  system_prompt: string;
}

export interface ToolPermission {
  tool_id: string;
  tool_name: string;
  allowed_operations: string[];
  parameter_constraints?: Record<string, unknown>;
}
