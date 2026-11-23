import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { getTenantFixtures } from './fixtures';
import {
  LoginRequest,
  LoginResponse,
  UserProfileResponse,
  BranchInfo,
  RegisterRequest,
  RegisterResponse,
  RegistrationStatusResponse,
  RegistrationRequestDetail,
  TenantMember,
  ApproveRegistrationPayload,
  UpdateMemberPayload,
  TenantWorkspaceSummary,
  MemoryRecordResponse,
  MemoryDetailResponse,
  MemoryIngestRequest,
  QuarantineRequest,
  QuarantineResponse,
  Agent,
  PolicyDecision,
  SecurityIncident,
  IncidentSummary,
  SecurityAlertsSummary,
  DualTraceData,
  ChroniMemRecordTimeline,
  DriftObservation,
  RecoveryPlanPreviewResponse,
  RecoveryExecuteResponse,
  AuditEvent,
} from '@/types';

const API_BASE_URL = '/api/v1';
const REQUEST_TIMEOUT_MS = 15000;

/** Map the backend IncidentSummaryResponse to the UI SecurityIncident shape without inventing data. */
export function toSecurityIncident(item: IncidentSummary): SecurityIncident {
  return {
    id: item.id,
    tenant_id: item.tenant_id,
    title: item.title,
    classification: item.classification,
    threat_type: item.classification,
    severity: item.severity,
    status: item.status,
    tainted_chunk_id: item.affected_record_id ?? undefined,
    target_agent_id: item.agent_id ?? undefined,
    gateway_status: 'NOT_REPORTED',
    evidence_summary: `${item.evidence_count} evidence item(s)`,
    created_at: item.created_at,
  };
}

export class ApiError extends Error {
  public status: number;
  public details?: any;

  constructor(message: string, status: number, details?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

export class AuthenticationError extends ApiError {
  constructor(message = 'Invalid credentials or expired session', status = 401) {
    super(message, status);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends ApiError {
  constructor(message = 'Insufficient permissions to perform this security operation', status = 403) {
    super(message, status);
    this.name = 'AuthorizationError';
  }
}

interface FetchOptions extends RequestInit {
  timeoutMs?: number;
}

class ApiClient {
  private getHeaders(tenantId?: string): HeadersInit {
    const store = useWorkstationStore.getState();
    const effectiveTenantId = tenantId || store.activeTenant.id;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Tenant-ID': effectiveTenantId,
      'X-Trace-ID': `tr-${Date.now()}`,
    };

    // Use verified JWT token if user is authenticated; never forge mock bearer token
    if (store.authToken) {
      headers['Authorization'] = `Bearer ${store.authToken}`;
    }

    return headers;
  }

  private async fetchWithTimeout(url: string, options: FetchOptions = {}): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timeout);
      return response;
    } catch (err: any) {
      clearTimeout(timeout);
      if (err.name === 'AbortError') {
        throw new ApiError(`Request to ${url} timed out after ${options.timeoutMs || REQUEST_TIMEOUT_MS}ms`, 504);
      }
      throw new ApiError(err.message || `Network error connecting to ${url}`, 0);
    }
  }

  private setApiStatus(isLive: boolean) {
    const currentMode = useWorkstationStore.getState().apiMode;
    const targetMode = isLive ? 'LIVE_CONNECTED' : 'SCHEMA_FALLBACK';
    if (currentMode !== targetMode) {
      useWorkstationStore.getState().setApiMode(targetMode);
    }
  }

  // --- 1. Liveness & Health ---
  async checkHealth(): Promise<{ status: string; service: string }> {
    try {
      const res = await this.fetchWithTimeout('/health');
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      const v1Res = await this.fetchWithTimeout(`${API_BASE_URL}/health`);
      if (v1Res.ok) {
        this.setApiStatus(true);
        return await v1Res.json();
      }
      throw new ApiError(`Health check returned HTTP ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      return { status: 'fallback', service: 'amsc-mock-contract' };
    }
  }

  // --- 2. Auth Endpoints ---
  async login(payload: LoginRequest): Promise<LoginResponse> {
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      this.setApiStatus(true);
      const data: LoginResponse = await res.json();
      useWorkstationStore.getState().setAuth(data.access_token, {
        user_id: data.user_id,
        email: payload.email,
        full_name: payload.email.split('@')[0],
        active_tenant: data.active_tenant,
        role: data.role,
      });
      return data;
    }

    this.setApiStatus(false);
    let errMsg = `Login failed with HTTP ${res.status}`;
    try {
      const errBody = await res.json();
      if (errBody?.detail) errMsg = typeof errBody.detail === 'string' ? errBody.detail : JSON.stringify(errBody.detail);
      if (errBody?.message) errMsg = errBody.message;
    } catch {
      // Ignore body parsing failure
    }

    if (res.status === 401) {
      throw new AuthenticationError(errMsg, res.status);
    }
    if (res.status === 403) {
      throw new AuthorizationError(errMsg, res.status);
    }
    throw new ApiError(errMsg, res.status);
  }

  async getMe(tenantId?: string): Promise<UserProfileResponse> {
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/auth/me`, {
      headers: this.getHeaders(tenantId),
    });

    if (res.ok) {
      this.setApiStatus(true);
      const profile: UserProfileResponse = await res.json();
      useWorkstationStore.getState().currentUser = profile;
      return profile;
    }

    this.setApiStatus(false);
    if (res.status === 401) {
      useWorkstationStore.getState().logout();
      throw new AuthenticationError('Session expired or unauthenticated. Please log in.', 401);
    }
    if (res.status === 403) {
      throw new AuthorizationError('Access denied: Caller has no membership in target tenant.', 403);
    }
    throw new ApiError(`GET /auth/me returned HTTP ${res.status}`, res.status);
  }

  async logout(): Promise<void> {
    try {
      await this.fetchWithTimeout(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
    } catch {
      // Best-effort server notification
    } finally {
      useWorkstationStore.getState().logout();
    }
  }

  async register(payload: RegisterRequest): Promise<RegisterResponse> {
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }

    let errMsg = `Registration failed with HTTP ${res.status}`;
    try {
      const errBody = await res.json();
      if (errBody?.detail) errMsg = typeof errBody.detail === 'string' ? errBody.detail : JSON.stringify(errBody.detail);
      if (errBody?.message) errMsg = errBody.message;
    } catch {
      // Ignore body parsing failure
    }
    throw new ApiError(errMsg, res.status);
  }

  async getRegistrationStatus(requestId: string): Promise<RegistrationStatusResponse> {
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/auth/registration-status/${encodeURIComponent(requestId)}`);
    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }
    let errMsg = `Status check failed with HTTP ${res.status}`;
    try {
      const errBody = await res.json();
      if (errBody?.detail) errMsg = typeof errBody.detail === 'string' ? errBody.detail : JSON.stringify(errBody.detail);
      if (errBody?.message) errMsg = errBody.message;
    } catch {}
    if (res.status === 404) {
      throw new ApiError('Registration request not found.', 404);
    }
    throw new ApiError(errMsg, res.status);
  }

  async getBranches(tenantSlug?: string): Promise<BranchInfo[]> {
    const url = tenantSlug
      ? `${API_BASE_URL}/branches?tenant_slug=${encodeURIComponent(tenantSlug)}`
      : `${API_BASE_URL}/branches`;
    try {
      const res = await this.fetchWithTimeout(url);
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
    } catch {}
    return [
      { id: 'branch-ho-001', tenant_id: 'tenant-a-uuid-001', name: 'Head Office - Core Security', code: 'HO', status: 'ACTIVE' },
      { id: 'branch-lhr-002', tenant_id: 'tenant-a-uuid-001', name: 'Finance & Regional Operations Branch (Lahore)', code: 'LHR', status: 'ACTIVE' },
      { id: 'branch-khi-003', tenant_id: 'tenant-a-uuid-001', name: 'Maritime & Logistics Operations Branch (Karachi)', code: 'KHI', status: 'ACTIVE' },
      { id: 'branch-isb-004', tenant_id: 'tenant-a-uuid-001', name: 'Corporate Affairs & HR Branch (Islamabad)', code: 'ISB', status: 'ACTIVE' },
    ];
  }

  async getPendingRegistrations(statusFilter?: string): Promise<RegistrationRequestDetail[]> {
    const url = statusFilter
      ? `${API_BASE_URL}/admin/registrations?status_filter=${encodeURIComponent(statusFilter)}`
      : `${API_BASE_URL}/admin/registrations`;
    const res = await this.fetchWithTimeout(url, {
      headers: this.getHeaders(),
    });
    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }
    if (res.status === 403) {
      throw new AuthorizationError('Tenant administrator access required to review registrations.', 403);
    }
    throw new ApiError(`Failed to fetch registration requests (HTTP ${res.status})`, res.status);
  }

  async approveRegistration(
    requestId: string,
    payload: ApproveRegistrationPayload
  ): Promise<{ message: string; user_id: string; membership_id: string; role: string; branch_id?: string | null }> {
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/admin/registrations/${encodeURIComponent(requestId)}/approve`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }
    let errMsg = `Approval failed (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err?.detail) errMsg = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail);
      if (err?.message) errMsg = err.message;
    } catch {}
    if (res.status === 403) throw new AuthorizationError(errMsg, 403);
    throw new ApiError(errMsg, res.status);
  }

  async rejectRegistration(requestId: string, reason: string): Promise<{ message: string; request_id: string }> {
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/admin/registrations/${encodeURIComponent(requestId)}/reject`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ reason }),
    });
    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }
    let errMsg = `Rejection failed (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err?.detail) errMsg = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail);
      if (err?.message) errMsg = err.message;
    } catch {}
    if (res.status === 403) throw new AuthorizationError(errMsg, 403);
    throw new ApiError(errMsg, res.status);
  }

  async getUsers(): Promise<TenantMember[]> {
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/admin/users`, {
      headers: this.getHeaders(),
    });
    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }
    if (res.status === 403) {
      throw new AuthorizationError('Tenant administrator access required to view members.', 403);
    }
    throw new ApiError(`Failed to fetch tenant members (HTTP ${res.status})`, res.status);
  }

  async updateUserMembership(
    userId: string,
    payload: UpdateMemberPayload
  ): Promise<{ message: string; user_id: string; role: string; branch_id?: string | null; status: string }> {
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/admin/users/${encodeURIComponent(userId)}/membership`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }
    let errMsg = `Failed to update member (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err?.detail) errMsg = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail);
      if (err?.message) errMsg = err.message;
    } catch {}
    if (res.status === 403) throw new AuthorizationError(errMsg, 403);
    throw new ApiError(errMsg, res.status);
  }

  // --- 3. Tenants Endpoints ---
  async listTenants(): Promise<TenantWorkspaceSummary[]> {
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/tenants`, {
        headers: this.getHeaders(),
      });
      if (res.ok) {
        this.setApiStatus(true);
        const data = await res.json();
        return data;
      }
      throw new ApiError(`GET /tenants returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const store = useWorkstationStore.getState();
      const fixtures = getTenantFixtures(store.activeTenant.id);
      return fixtures.tenants;
    }
  }

  async getTenant(tenantId: string): Promise<TenantWorkspaceSummary> {
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/tenants/${tenantId}`, {
        headers: this.getHeaders(tenantId),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new ApiError(`GET /tenants/${tenantId} returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(tenantId);
      const match = fixtures.tenants.find((t) => t.id === tenantId);
      if (!match) throw new ApiError(`Tenant workspace '${tenantId}' not found`, 404);
      return match;
    }
  }

  // --- 4. Memory Endpoints ---
  async listMemories(tenantId?: string, trustState?: string, forForensic?: boolean): Promise<MemoryRecordResponse[]> {
    const store = useWorkstationStore.getState();
    const effectiveTenant = tenantId || store.activeTenant.id;
    const userRole = (store.currentUser?.role || '').toUpperCase();

    // Check if user has SecOps or Admin privileges
    const isSecOps =
      userRole === 'SECURITY_ANALYST' ||
      userRole === 'TENANT_ADMIN' ||
      userRole === 'SECURITY_ADMIN' ||
      userRole === 'ADMIN';

    // Auto-enable for_forensic if filtering for QUARANTINED or SUSPICIOUS records and user has SecOps role,
    // or if explicitly passed as true
    const isNonTrustedFilter = trustState && (trustState.toUpperCase() === 'QUARANTINED' || trustState.toUpperCase() === 'SUSPICIOUS');
    const shouldAppendForensic = forForensic ?? (isSecOps && isNonTrustedFilter);

    const queryParams = new URLSearchParams();
    if (trustState) queryParams.set('trust_state', trustState);
    if (shouldAppendForensic) queryParams.set('for_forensic', 'true');

    const queryString = queryParams.toString() ? `?${queryParams.toString()}` : '';
    const url = `${API_BASE_URL}/memory${queryString}`;

    try {
      const res = await this.fetchWithTimeout(url, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      // If server returned 403 because quarantined records are restricted from standard agent query
      if (res.status === 403 && trustState === 'QUARANTINED') {
        throw new AuthorizationError('Quarantined records are restricted from regular agent queries. Forensic access required.', 403);
      }
      throw new ApiError(`GET /memory returned ${res.status}`, res.status);
    } catch (err: any) {
      if (err instanceof AuthorizationError) throw err;
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      if (trustState) {
        return fixtures.memories.filter((m) => m.trust_state === trustState);
      }
      return fixtures.memories;
    }
  }

  /**
   * Alias for listMemories matching Section 4 audit recommendation.
   */
  async fetchMemories(tenantId?: string, trustState?: string, forForensic?: boolean): Promise<MemoryRecordResponse[]> {
    return this.listMemories(tenantId, trustState, forForensic);
  }

  /**
   * Memory detail. Forensic access is a request, not an authorization: the backend serves it only
   * through M4 ForensicAccess (analyst/admin role from the verified session, an investigation
   * reason, audit written before the read). Server errors (403/404/503) are surfaced, never
   * replaced with fixture data; fixtures are used only when the server is unreachable.
   */
  async getMemoryDetail(
    recordId: string,
    tenantId?: string,
    forForensic?: boolean,
    forensicReason?: string,
  ): Promise<MemoryDetailResponse> {
    const store = useWorkstationStore.getState();
    const effectiveTenant = tenantId || store.activeTenant.id;
    const userRole = (store.currentUser?.role || '').toUpperCase();
    const isSecOps =
      userRole === 'SECURITY_ANALYST' ||
      userRole === 'TENANT_ADMIN' ||
      userRole === 'SECURITY_ADMIN' ||
      userRole === 'ADMIN';
    const shouldRequestForensic = forForensic ?? isSecOps;

    try {
      // GAP-012: no forensic flag on the normal route; forensic reads use the dedicated audited route.
      const res = shouldRequestForensic
        ? await this.fetchWithTimeout(`${API_BASE_URL}/memory/${recordId}/forensic-access`, {
            method: 'POST',
            headers: { ...this.getHeaders(effectiveTenant), 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: forensicReason || `Security Center inspection of ${recordId}` }),
          })
        : await this.fetchWithTimeout(`${API_BASE_URL}/memory/${recordId}`, {
            headers: this.getHeaders(effectiveTenant),
          });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      if (res.status === 403) throw new AuthorizationError(`GET /memory/${recordId} forbidden`, res.status);
      throw new ApiError(`GET /memory/${recordId} returned ${res.status}`, res.status);
    } catch (err) {
      if (err instanceof ApiError) throw err;   // a real server answer is never masked by fixtures
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      const match = fixtures.memoryDetails[recordId];
      if (match) return match;
      const mem = fixtures.memories.find((m) => m.id === recordId);
      if (mem) {
        return {
          record: mem,
          versions: [
            {
              id: `ver-${mem.id}-1`,
              tenant_id: mem.tenant_id,
              record_id: mem.id,
              version: mem.current_version,
              content: mem.content || 'Content unrecorded in version index',
              checksum: mem.checksum || '0000000000000000000000000000000000000000000000000000000000000000',
              created_at: mem.created_at,
            },
          ],
          provenance: [],
        };
      }
      throw new ApiError(`Memory record '${recordId}' not found in workspace`, 404);
    }
  }

  async ingestMemory(payload: MemoryIngestRequest, tenantId?: string): Promise<MemoryRecordResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/memory`, {
      method: 'POST',
      headers: this.getHeaders(effectiveTenant),
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }

    // Never pretend mutation succeeded when in live mode or when server failed
    let errMsg = `POST /memory returned HTTP ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson?.detail) errMsg = errJson.detail;
    } catch {
      // Ignore
    }
    throw new ApiError(errMsg, res.status);
  }

  /**
   * Quarantine a memory record with strict error propagation.
   * NEVER returns a fake success object on failure or 404.
   */
  async quarantineMemory(recordId: string, payload: QuarantineRequest, tenantId?: string): Promise<QuarantineResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/memory/${recordId}/quarantine`, {
      method: 'POST',
      headers: this.getHeaders(effectiveTenant),
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }

    let errMsg = `POST /memory/${recordId}/quarantine failed (HTTP ${res.status})`;
    try {
      const errData = await res.json();
      if (errData?.detail) errMsg = typeof errData.detail === 'string' ? errData.detail : JSON.stringify(errData.detail);
    } catch {
      // Ignore
    }

    if (res.status === 403) {
      throw new AuthorizationError(errMsg, res.status);
    }
    if (res.status === 404) {
      throw new ApiError(`Quarantine endpoint not available on server (HTTP 404: route unbuilt or record missing). Operation NOT performed.`, 404);
    }
    throw new ApiError(errMsg, res.status);
  }

  // --- 5. Agents Endpoints ---
  async listAgents(tenantId?: string): Promise<Agent[]> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/agents`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new ApiError(`GET /agents returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      return fixtures.agents;
    }
  }

  // --- 6. Gateway Endpoints ---
  async listGatewayDecisions(tenantId?: string): Promise<PolicyDecision[]> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/gateway/decisions`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new ApiError(`GET /gateway/decisions returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      return fixtures.decisions;
    }
  }

  // --- 7. Security Center Endpoints ---
  /**
   * Incidents. The backend returns the canonical paginated envelope (TRD §22):
   * { items: IncidentSummary[], limit, offset, has_more, total }. Items are mapped to the UI's
   * SecurityIncident shape; fields the backend does not provide are marked NOT_REPORTED rather
   * than invented. A shape mismatch is an error, not a reason to show fixtures.
   */
  async listIncidents(tenantId?: string): Promise<SecurityIncident[]> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    let res: Response;
    try {
      res = await this.fetchWithTimeout(`${API_BASE_URL}/security/incidents`, {
        headers: this.getHeaders(effectiveTenant),
      });
    } catch {
      // Server unreachable: labelled fixture fallback (DualModeBadge shows CONTRACT FALLBACK).
      this.setApiStatus(false);
      return getTenantFixtures(effectiveTenant).incidents;
    }
    if (!res.ok) {
      if (res.status === 403) throw new AuthorizationError('GET /security/incidents forbidden', res.status);
      throw new ApiError(`GET /security/incidents returned ${res.status}`, res.status);
    }
    this.setApiStatus(true);
    const body = await res.json();
    if (!body || !Array.isArray(body.items)) {
      throw new ApiError('GET /security/incidents returned an unexpected shape (expected { items: [...] })', 502);
    }
    return body.items.map(toSecurityIncident);
  }

  async getSecurityAlerts(tenantId?: string): Promise<SecurityAlertsSummary> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/security/alerts`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new ApiError(`GET /security/alerts returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      return fixtures.alerts;
    }
  }

  // --- 8. Dual Trace Scrubber Endpoints ---
  async getDualTrace(traceId = 'trace-default', tenantId?: string): Promise<DualTraceData> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/traces/${traceId}/dual-trace`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new ApiError(`GET /traces/${traceId}/dual-trace returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      const trace = fixtures.traces[traceId] || Object.values(fixtures.traces)[0];
      if (trace) return trace;
      throw new ApiError(`Dual trace '${traceId}' not found`, 404);
    }
  }

  // --- 9. ChroniMem Endpoints ---
  async getChroniMemTimeline(recordId: string, tenantId?: string): Promise<ChroniMemRecordTimeline> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/chronimem/timeline?record_id=${encodeURIComponent(recordId)}`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new ApiError(`GET /chronimem/timeline returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      const match = fixtures.chronimem[recordId];
      if (match) return match;

      // Construct dynamic timeline from memoryDetails if present
      const memDetail = fixtures.memoryDetails[recordId];
      if (memDetail && memDetail.versions?.length > 0) {
        return {
          record_id: recordId,
          tenant_id: effectiveTenant,
          current_version: memDetail.record.current_version,
          versions: memDetail.versions.map((v) => ({
            version: v.version,
            time_display: `Version ${v.version}`,
            checksum: v.checksum,
            author: 'Ingest Pipeline',
            trust_state: memDetail.record.trust_state as any,
            content: v.content,
            created_at: v.created_at || new Date().toISOString(),
          })),
        };
      }
      throw new ApiError(`ChroniMem history for record '${recordId}' unavailable`, 404);
    }
  }

  // --- 10. Drift Monitor Endpoints ---
  async listDriftObservations(tenantId?: string): Promise<DriftObservation[]> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/drift/observations`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new ApiError(`GET /drift/observations returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      return fixtures.drift;
    }
  }

  // --- 11. Rewind & Atomic Recovery Endpoints ---
  async previewRecoveryPlan(checkpointId: string, targetRecordId: string, tenantId?: string): Promise<RecoveryPlanPreviewResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/recovery/plans/preview`, {
        method: 'POST',
        headers: this.getHeaders(effectiveTenant),
        body: JSON.stringify({ checkpoint_id: checkpointId, target_record_id: targetRecordId }),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      let message = `POST /recovery/plans/preview failed (HTTP ${res.status})`;
      try {
        const body = await res.json();
        message = body?.error?.message || body?.detail || body?.message || message;
      } catch {
        // keep the generic message
      }
      if (res.status === 403) throw new AuthorizationError(message, res.status);
      throw new ApiError(message, res.status);
    } catch (err) {
      // Never fabricate a recovery plan: a preview that the server did not produce cannot be executed.
      if (err instanceof ApiError || err instanceof AuthorizationError) throw err;
      this.setApiStatus(false);
      throw new ApiError('Recovery preview unavailable: the server could not be reached.', 0);
    }
  }

  /**
   * Execute atomic memory rewind with strict error propagation.
   * NEVER returns a fake success object on failure or 404.
   */
  async executeAtomicRewind(planId: string, tenantId?: string): Promise<RecoveryExecuteResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    // The previewed plan fixes the target records; the client sends only the plan id.
    const res = await this.fetchWithTimeout(`${API_BASE_URL}/recovery/plans/execute`, {
      method: 'POST',
      headers: this.getHeaders(effectiveTenant),
      body: JSON.stringify({ plan_id: planId }),
    });

    if (res.ok) {
      this.setApiStatus(true);
      return await res.json();
    }

    let errMsg = `POST /recovery/plans/execute failed (HTTP ${res.status})`;
    let outcome: Partial<RecoveryExecuteResponse> | undefined;
    try {
      const errJson = await res.json();
      if (errJson?.status && Array.isArray(errJson?.reason_codes)) {
        // Honest server outcome (FAILED / RECONCILIATION_REQUIRED): surface it, never treat it as success.
        outcome = errJson;
        errMsg = `${errJson.status}: ${errJson.message ?? ''} [${errJson.reason_codes.join(', ')}]`;
      } else if (errJson?.error?.message) {
        errMsg = errJson.error.message;
      } else if (errJson?.detail) {
        errMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // Ignore
    }
    if (outcome) {
      throw new ApiError(errMsg, res.status, outcome);
    }

    if (res.status === 403) {
      throw new AuthorizationError(errMsg, res.status);
    }
    if (res.status === 404) {
      throw new ApiError(`Recovery execution route unavailable on server (HTTP 404). Rollback NOT executed.`, 404);
    }
    throw new ApiError(errMsg, res.status);
  }

  // --- 12. Audit Center Endpoints ---
  async listAuditEvents(tenantId?: string): Promise<AuditEvent[]> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/audit/events`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new ApiError(`GET /audit/events returned ${res.status}`, res.status);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      return fixtures.auditLogs;
    }
  }
}

export const apiClient = new ApiClient();
