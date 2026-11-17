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
  expires_in: number;
}

export interface UserProfileResponse {
  user_id: string;
  email: string;
  full_name: string;
  active_tenant: TenantInfo;
  role: string;
}
