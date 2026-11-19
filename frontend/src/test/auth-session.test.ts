import { apiClient, AuthenticationError, AuthorizationError, ApiError } from '../services/apiClient';
import { useWorkstationStore } from '../stores/useWorkstationStore';

describe('Auth & Session Management (P1 Finding A)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useWorkstationStore.getState().logout();
  });

  it('rejects invalid credentials and does NOT forge a fake session on 401', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Invalid credentials or user inactive' }),
    });

    await expect(
      apiClient.login({
        email: 'attacker@evil.com',
        password: 'wrongpassword',
        tenant_slug: 'alphacorp',
      })
    ).rejects.toThrow(AuthenticationError);

    const state = useWorkstationStore.getState();
    expect(state.authToken).toBeNull();
    expect(state.currentUser).toBeNull();
  });

  it('rejects on server 500 error and propagates ApiError without fake login', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ message: 'Internal Server Error' }),
    });

    await expect(
      apiClient.login({
        email: 'sarah@alphacorp.internal',
        password: 'anypassword',
        tenant_slug: 'alphacorp',
      })
    ).rejects.toThrow(ApiError);

    const state = useWorkstationStore.getState();
    expect(state.authToken).toBeNull();
  });

  it('sets store token and user profile on successful login', async () => {
    const mockToken = 'jwt-signed-token-xyz-12345';
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        access_token: mockToken,
        token_type: 'bearer',
        user_id: 'usr-sarah-101',
        active_tenant: { id: 'tenant-alphacorp', name: 'AlphaCorp', slug: 'alphacorp' },
        role: 'SECURITY_ANALYST',
        expires_in: 3600,
      }),
    });

    const res = await apiClient.login({
      email: 'sarah@alphacorp.internal',
      password: 'validpassword',
      tenant_slug: 'alphacorp',
    });

    expect(res.access_token).toBe(mockToken);
    const state = useWorkstationStore.getState();
    expect(state.authToken).toBe(mockToken);
    expect(state.currentUser?.role).toBe('SECURITY_ANALYST');
  });

  it('getMe clears session and throws AuthenticationError on 401', async () => {
    useWorkstationStore.getState().setAuth('expired-token', {
      user_id: 'usr-1',
      email: 'sarah@test.com',
      full_name: 'Sarah',
      active_tenant: { id: 'tenant-alphacorp', name: 'AlphaCorp', slug: 'alphacorp' },
      role: 'SECURITY_ANALYST',
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Token has expired' }),
    });

    await expect(apiClient.getMe()).rejects.toThrow(AuthenticationError);

    const state = useWorkstationStore.getState();
    expect(state.authToken).toBeNull();
    expect(state.currentUser).toBeNull();
  });

  describe('SecOps Forensic Query Integration (for_forensic=true & GAP-004)', () => {
    it('appends for_forensic=true when SECURITY_ANALYST queries QUARANTINED records', async () => {
      useWorkstationStore.getState().setAuth('analyst-token', {
        user_id: 'usr-analyst-1',
        email: 'analyst@alphacorp.internal',
        full_name: 'SecOps Lead',
        active_tenant: { id: 'tenant-alphacorp', name: 'AlphaCorp', slug: 'alphacorp' },
        role: 'SECURITY_ANALYST',
      });

      let requestedUrl = '';
      global.fetch = vi.fn().mockImplementation(async (url: string) => {
        requestedUrl = url;
        return {
          ok: true,
          status: 200,
          json: async () => [{ id: 'rec-quar-1', trust_state: 'QUARANTINED' }],
        };
      });

      const memories = await apiClient.fetchMemories('tenant-alphacorp', 'QUARANTINED');

      expect(requestedUrl).toContain('/api/v1/memory?trust_state=QUARANTINED&for_forensic=true');
      expect(memories).toHaveLength(1);
      expect(memories[0].trust_state).toBe('QUARANTINED');
    });

    it('appends for_forensic=true when TENANT_ADMIN queries SUSPICIOUS records', async () => {
      useWorkstationStore.getState().setAuth('admin-token', {
        user_id: 'usr-admin-1',
        email: 'admin@alphacorp.internal',
        full_name: 'Tenant Admin',
        active_tenant: { id: 'tenant-alphacorp', name: 'AlphaCorp', slug: 'alphacorp' },
        role: 'TENANT_ADMIN',
      });

      let requestedUrl = '';
      global.fetch = vi.fn().mockImplementation(async (url: string) => {
        requestedUrl = url;
        return {
          ok: true,
          status: 200,
          json: async () => [{ id: 'rec-sus-1', trust_state: 'SUSPICIOUS' }],
        };
      });

      await apiClient.listMemories('tenant-alphacorp', 'SUSPICIOUS');

      expect(requestedUrl).toContain('/api/v1/memory?trust_state=SUSPICIOUS&for_forensic=true');
    });

    it('does NOT append for_forensic=true when ordinary DEVELOPER queries QUARANTINED records', async () => {
      useWorkstationStore.getState().setAuth('dev-token', {
        user_id: 'usr-dev-1',
        email: 'dev@alphacorp.internal',
        full_name: 'Software Dev',
        active_tenant: { id: 'tenant-alphacorp', name: 'AlphaCorp', slug: 'alphacorp' },
        role: 'DEVELOPER',
      });

      let requestedUrl = '';
      global.fetch = vi.fn().mockImplementation(async (url: string) => {
        requestedUrl = url;
        return {
          ok: false,
          status: 403,
          json: async () => ({ detail: 'Normal agent retrieval is strictly restricted to TRUSTED memory records.' }),
        };
      });

      await expect(
        apiClient.fetchMemories('tenant-alphacorp', 'QUARANTINED')
      ).rejects.toThrow(AuthorizationError);

      expect(requestedUrl).toBe('/api/v1/memory?trust_state=QUARANTINED');
      expect(requestedUrl).not.toContain('for_forensic=true');
    });

    it('does NOT append for_forensic=true when SECURITY_ANALYST queries normal TRUSTED records', async () => {
      useWorkstationStore.getState().setAuth('analyst-token', {
        user_id: 'usr-analyst-1',
        email: 'analyst@alphacorp.internal',
        full_name: 'SecOps Lead',
        active_tenant: { id: 'tenant-alphacorp', name: 'AlphaCorp', slug: 'alphacorp' },
        role: 'SECURITY_ANALYST',
      });

      let requestedUrl = '';
      global.fetch = vi.fn().mockImplementation(async (url: string) => {
        requestedUrl = url;
        return {
          ok: true,
          status: 200,
          json: async () => [{ id: 'rec-trust-1', trust_state: 'TRUSTED' }],
        };
      });

      await apiClient.fetchMemories('tenant-alphacorp', 'TRUSTED');

      expect(requestedUrl).toBe('/api/v1/memory?trust_state=TRUSTED');
      expect(requestedUrl).not.toContain('for_forensic=true');
    });
  });
});
