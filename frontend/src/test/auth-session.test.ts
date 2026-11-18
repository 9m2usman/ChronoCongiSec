import { describe, it, expect, beforeEach, vi } from 'vitest';
import { apiClient, AuthenticationError, ApiError } from '../services/apiClient';
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
});
