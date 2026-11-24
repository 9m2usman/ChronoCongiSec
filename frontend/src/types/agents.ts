export interface Agent {
  id: string;
  tenant_id: string;
  name: string;
  runtime: string;
  model: string;
  system_prompt?: string;
  trust_tier?: 'RESTRICTED' | 'STANDARD' | 'ELEVATED' | string;
  status: 'ACTIVE' | 'STANDBY' | 'SUSPENDED' | 'ISOLATED' | 'DEPRECATED' | string;
  tools?: string[];
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

export interface AgentSecurityProfile {
  agent_id: string;
  tenant_id: string;
  department: string;
  approved_purpose: string;
  approved_goals: string[];
  authorized_data_scope: string[];
  operational_restrictions: string[];
  approval_requirements: string[];
  profile_version: string;
  is_active: boolean;
  branch_id?: string | null;
  tools: ToolPermission[];
  updated_at: string;
}

export interface AgentToolPermissionGrantRequest {
  tool_id: string;
  tool_name?: string;
  allowed_operations?: string[];
  parameter_constraints?: Record<string, unknown>;
}
