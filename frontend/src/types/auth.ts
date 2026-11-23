export interface TenantInfo {
  id: string;
  name: string;
  slug: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  tenant_slug: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  active_tenant: TenantInfo;
  role: string;
  branch_id?: string | null;
  expires_in: number;
}

export interface UserProfileResponse {
  user_id: string;
  email: string;
  full_name: string;
  active_tenant: TenantInfo;
  role: string;
  branch_id?: string | null;
}

export interface BranchInfo {
  id: string;
  tenant_id: string;
  name: string;
  code: string;
  status: string;
}

export interface RegisterRequest {
  full_name: string;
  email: string;
  password: string;
  requested_branch_code: string;
  tenant_slug?: string;
}

export interface RegisterResponse {
  request_id: string;
  email: string;
  status: string;
  requested_branch_code: string;
  created_at: string;
  message: string;
}

export interface RegistrationStatusResponse {
  request_id: string;
  email_masked: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | string;
  requested_branch_code: string;
  created_at?: string | null;
  reviewed_at?: string | null;
  reason?: string | null;
}

export interface RegistrationRequestDetail {
  id: string;
  tenant_id: string;
  full_name: string;
  email: string;
  requested_branch_code: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | string;
  created_at?: string | null;
  reviewed_at?: string | null;
  reviewed_by_user_id?: string | null;
  review_reason?: string | null;
  assigned_role?: string | null;
  assigned_branch_id?: string | null;
  requested_role?: Role | string | null;
  target_branch_id?: string | null;
}

export type Role = 'TENANT_ADMIN' | 'SECURITY_ANALYST' | 'AI_DEVELOPER' | 'AUDITOR';

export interface TenantMember {
  user_id: string;
  email: string;
  full_name: string;
  role: Role | string;
  branch_id?: string | null;
  branch_name?: string | null;
  branch_code?: string | null;
  status: string;
  is_active?: boolean;
}

export interface ApproveRegistrationPayload {
  role?: Role;
  assigned_role?: Role;
  branch_id?: string | null;
  assigned_branch_id?: string | null;
  reason?: string;
}

export interface UpdateMemberPayload {
  role?: Role;
  branch_id?: string | null;
  status?: 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | string;
}
