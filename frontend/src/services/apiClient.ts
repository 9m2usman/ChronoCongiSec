import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { getTenantFixtures } from './fixtures';
import {
  LoginRequest,
  LoginResponse,
  UserProfileResponse,
  TenantWorkspaceSummary,
  MemoryRecordResponse,
  MemoryDetailResponse,
  MemoryIngestRequest,
  QuarantineRequest,
  QuarantineResponse,
  Agent,
  PolicyDecision,
  SecurityIncident,
  SecurityAlertsSummary,
  DualTraceData,
  ChroniMemRecordTimeline,
  DriftObservation,
  RecoveryPlanPreviewResponse,
  RecoveryExecuteResponse,
  AuditEvent,
} from '@/types';

const API_BASE_URL = '/api/v1';
const REQUEST_TIMEOUT_MS = 2500;

interface FetchOptions extends RequestInit {
  timeoutMs?: number;
}

class ApiClient {
  private getHeaders(tenantId?: string): HeadersInit {
    const store = useWorkstationStore.getState();
    const effectiveTenantId = tenantId || store.activeTenant.id;
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer mock_token_${effectiveTenantId}`,
      'X-Tenant-ID': effectiveTenantId,
      'X-Trace-ID': `tr-${Date.now()}`,
    };
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
    } catch (err) {
      clearTimeout(timeout);
      throw err;
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
      throw new Error('Health check failed');
    } catch {
      this.setApiStatus(false);
      return { status: 'fallback', service: 'amsc-mock-contract' };
    }
  }

  // --- 2. Auth Endpoints ---
  async login(payload: LoginRequest): Promise<LoginResponse> {
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`Login failed with HTTP ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const store = useWorkstationStore.getState();
      return {
        access_token: `amsc_jwt_${store.activeTenant.id}_token`,
        token_type: 'bearer',
        user_id: 'usr-secops-sarah-01',
        active_tenant: {
          id: store.activeTenant.id,
          name: store.activeTenant.name,
          slug: store.activeTenant.slug,
        },
        role: 'SECURITY_ANALYST',
        expires_in: 3600,
      };
    }
  }

  async getMe(tenantId?: string): Promise<UserProfileResponse> {
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/auth/me`, {
        headers: this.getHeaders(tenantId),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`GET /auth/me returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const store = useWorkstationStore.getState();
      return {
        user_id: 'usr-secops-sarah-01',
        email: 'sarah.secops@alphacorp.internal',
        full_name: 'Sarah Connor',
        active_tenant: {
          id: store.activeTenant.id,
          name: store.activeTenant.name,
          slug: store.activeTenant.slug,
        },
        role: 'SECURITY_ANALYST',
      };
    }
  }

  // --- 3. Tenants Endpoints ---
  async listTenants(): Promise<TenantWorkspaceSummary[]> {
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/tenants`, {
        headers: this.getHeaders(),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`GET /tenants returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const store = useWorkstationStore.getState();
      return getTenantFixtures(store.activeTenant.id).tenants;
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
      throw new Error(`GET /tenants/${tenantId} returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const store = useWorkstationStore.getState();
      const match = getTenantFixtures(store.activeTenant.id).tenants.find((t) => t.id === tenantId);
      return match || { id: tenantId, name: store.activeTenant.name, slug: store.activeTenant.slug, status: 'ACTIVE' };
    }
  }

  // --- 4. Memory Endpoints (GET, POST, GET by ID, Quarantine) ---
  async listMemories(tenantId?: string): Promise<MemoryRecordResponse[]> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/memory`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`GET /memory returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      return getTenantFixtures(effectiveTenant).memories;
    }
  }

  async getMemoryDetail(recordId: string, tenantId?: string): Promise<MemoryDetailResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/memory/${recordId}`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`GET /memory/${recordId} returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      return (
        fixtures.memoryDetails[recordId] || {
          record: {
            id: recordId,
            tenant_id: effectiveTenant,
            record_type: 'KNOWLEDGE',
            trust_state: 'SUSPICIOUS',
            current_version: 1,
            created_at: new Date().toISOString(),
          },
          versions: [],
          provenance: [],
        }
      );
    }
  }

  async ingestMemory(payload: MemoryIngestRequest, tenantId?: string): Promise<MemoryRecordResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/memory`, {
        method: 'POST',
        headers: this.getHeaders(effectiveTenant),
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`POST /memory returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      const newRec: MemoryRecordResponse = {
        id: `rec-mock-${Date.now()}`,
        tenant_id: effectiveTenant,
        agent_id: payload.agent_id || null,
        source_id: payload.source_id || null,
        record_type: payload.record_type || 'KNOWLEDGE',
        trust_state: 'UNVERIFIED',
        current_version: 1,
        content: payload.content,
        checksum: `sha256_${Date.now()}`,
        created_at: new Date().toISOString(),
      };
      fixtures.memories.unshift(newRec);
      return newRec;
    }
  }

  async quarantineMemory(recordId: string, payload: QuarantineRequest, tenantId?: string): Promise<QuarantineResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/memory/${recordId}/quarantine`, {
        method: 'POST',
        headers: this.getHeaders(effectiveTenant),
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`POST /memory/${recordId}/quarantine returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      // Update in-memory fixture state
      const targetMem = fixtures.memories.find((m) => m.id === recordId);
      const prevState = targetMem?.trust_state || 'SUSPICIOUS';
      if (targetMem) {
        targetMem.trust_state = 'QUARANTINED';
      }
      if (fixtures.memoryDetails[recordId]) {
        fixtures.memoryDetails[recordId].record.trust_state = 'QUARANTINED';
      }

      // Append immutable audit log event
      fixtures.auditLogs.unshift({
        id: `aud-${Date.now()}`,
        tenant_id: effectiveTenant,
        timestamp: new Date().toISOString(),
        actor: 'secops:sarah',
        action: 'MEMORY_RECORD_QUARANTINED',
        target: recordId,
        evidence_sha256: targetMem?.checksum || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        metadata: { reason: payload.reason, notes: payload.analyst_notes },
      });

      return {
        id: recordId,
        previous_state: prevState,
        trust_state: 'QUARANTINED',
        message: 'Record successfully quarantined and excluded from protected agent retrieval.',
      };
    }
  }

  // --- 5. Unbuilt M2/M4 Fallback Endpoints ---
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
      throw new Error(`GET /agents returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      return getTenantFixtures(effectiveTenant).agents;
    }
  }

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
      throw new Error(`GET /gateway/decisions returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      return getTenantFixtures(effectiveTenant).decisions;
    }
  }

  async listIncidents(tenantId?: string): Promise<SecurityIncident[]> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/security/incidents`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`GET /security/incidents returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      return getTenantFixtures(effectiveTenant).incidents;
    }
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
      throw new Error(`GET /security/alerts returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      return getTenantFixtures(effectiveTenant).alerts;
    }
  }

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
      throw new Error(`GET /traces/${traceId}/dual-trace returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      return fixtures.traces[traceId] || fixtures.traces['trace-default'];
    }
  }

  async getChroniMemTimeline(recordId = 'rec-8812-441a', tenantId?: string): Promise<ChroniMemRecordTimeline> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/chronimem/timeline?record_id=${recordId}`, {
        headers: this.getHeaders(effectiveTenant),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`GET /chronimem/timeline returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      return (
        fixtures.chronimem[recordId] ||
        fixtures.chronimem['rec-8812-441a'] || {
          record_id: recordId,
          tenant_id: effectiveTenant,
          current_version: 1,
          versions: [],
        }
      );
    }
  }

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
      throw new Error(`GET /drift/observations returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      return getTenantFixtures(effectiveTenant).drift;
    }
  }

  async previewRecoveryPlan(checkpointId: string, recordId: string, tenantId?: string): Promise<RecoveryPlanPreviewResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/recovery/plans/preview`, {
        method: 'POST',
        headers: this.getHeaders(effectiveTenant),
        body: JSON.stringify({ checkpoint_id: checkpointId, target_record_id: recordId }),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`POST /recovery/plans/preview returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      return {
        plan_id: `plan-rec-${Date.now()}`,
        status: 'PREVIEWED',
        preview: {
          checkpoint_id: checkpointId,
          checkpoint_name: 'Verified Baseline Treasury Checkpoint (v1)',
          affected_records_count: 2,
          affected_records: [
            {
              record_id: recordId,
              action: 'ROLLBACK_TO_CHECKPOINT',
              checkpoint_version: 1,
              target_checksum: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
            },
          ],
          irreversible_external_actions: 0,
          risk_level: 'LOW',
        },
      };
    }
  }

  async executeAtomicRewind(planId: string, targetRecordId = 'rec-8812-441a', tenantId?: string): Promise<RecoveryExecuteResponse> {
    const effectiveTenant = tenantId || useWorkstationStore.getState().activeTenant.id;
    try {
      const res = await this.fetchWithTimeout(`${API_BASE_URL}/recovery/plans/execute`, {
        method: 'POST',
        headers: this.getHeaders(effectiveTenant),
        body: JSON.stringify({ plan_id: planId }),
      });
      if (res.ok) {
        this.setApiStatus(true);
        return await res.json();
      }
      throw new Error(`POST /recovery/plans/execute returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      const fixtures = getTenantFixtures(effectiveTenant);
      // Update memory record back to trusted state
      const targetMem = fixtures.memories.find((m) => m.id === targetRecordId);
      if (targetMem) {
        targetMem.trust_state = 'TRUSTED';
        targetMem.current_version = 1;
        targetMem.content = 'Official Policy: Accounts Payable disbursements exceeding $50,000 require dual-officer sign-off.';
      }
      if (fixtures.memoryDetails[targetRecordId]) {
        fixtures.memoryDetails[targetRecordId].record.trust_state = 'TRUSTED';
        fixtures.memoryDetails[targetRecordId].record.current_version = 1;
      }

      // Append immutable audit log event
      const auditId = `aud-rewind-${Date.now()}`;
      fixtures.auditLogs.unshift({
        id: auditId,
        tenant_id: effectiveTenant,
        timestamp: new Date().toISOString(),
        actor: 'secops:sarah',
        action: 'ATOMIC_RECOVERY_EXECUTED',
        target: targetRecordId,
        evidence_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        metadata: { plan_id: planId, pre_recovery_snapshot: 'SEC-007_PERSISTED' },
      });

      return {
        plan_id: planId,
        status: 'EXECUTED',
        executed_at: new Date().toISOString(),
        restored_records: [targetRecordId],
        audit_event_id: auditId,
        message: 'Atomic rollback completed. Pre-recovery state snapshot preserved.',
      };
    }
  }

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
      throw new Error(`GET /audit/events returned ${res.status}`);
    } catch {
      this.setApiStatus(false);
      return getTenantFixtures(effectiveTenant).auditLogs;
    }
  }
}

export const apiClient = new ApiClient();
