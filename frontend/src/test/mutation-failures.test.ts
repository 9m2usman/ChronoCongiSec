import { describe, it, expect, beforeEach, vi } from 'vitest';
import { apiClient, AuthorizationError, ApiError } from '../services/apiClient';

describe('Mutation Failure & Honest Error Propagation (P1 Finding B)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('quarantineMemory', () => {
    it('throws ApiError on HTTP 404 and does NOT return fake success or mutate local fixtures', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ detail: 'Route /memory/rec-8812-441a/quarantine not found' }),
      });

      await expect(
        apiClient.quarantineMemory('rec-8812-441a', {
          reason: 'Poisoned record test',
          analyst_notes: 'Checking 404 handling',
        })
      ).rejects.toThrow(ApiError);
    });

    it('throws AuthorizationError on HTTP 403 Forbidden', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        json: async () => ({ detail: 'Only SECURITY_ANALYST role can quarantine records' }),
      });

      await expect(
        apiClient.quarantineMemory('rec-8812-441a', {
          reason: 'Unauthorized test',
        })
      ).rejects.toThrow(AuthorizationError);
    });

    it('returns valid QuarantineResponse on server 200 OK', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          id: 'rec-8812-441a',
          previous_state: 'SUSPICIOUS',
          trust_state: 'QUARANTINED',
          message: 'Record quarantined successfully by server.',
        }),
      });

      const res = await apiClient.quarantineMemory('rec-8812-441a', {
        reason: 'Valid quarantine',
      });

      expect(res.trust_state).toBe('QUARANTINED');
      expect(res.id).toBe('rec-8812-441a');
    });
  });

  describe('executeAtomicRewind', () => {
    it('throws ApiError on HTTP 404 and does NOT fabricate an executed rollback', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ detail: 'Recovery execute route unavailable' }),
      });

      await expect(
        apiClient.executeAtomicRewind('plan-rec-8812', 'rec-8812-441a')
      ).rejects.toThrow(ApiError);
    });

    it('throws AuthorizationError on HTTP 403', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        json: async () => ({ detail: 'Insufficient permissions for atomic recovery' }),
      });

      await expect(
        apiClient.executeAtomicRewind('plan-rec-8812', 'rec-8812-441a')
      ).rejects.toThrow(AuthorizationError);
    });

    it('returns RecoveryExecuteResponse on verified server 200 OK', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          plan_id: 'plan-rec-8812',
          status: 'EXECUTED',
          executed_at: new Date().toISOString(),
          restored_records: ['rec-8812-441a'],
          audit_event_id: 'aud-rewind-101',
          message: 'Atomic rollback completed.',
        }),
      });

      const res = await apiClient.executeAtomicRewind('plan-rec-8812', 'rec-8812-441a');
      expect(res.status).toBe('EXECUTED');
      expect(res.restored_records).toContain('rec-8812-441a');
    });
  });
});
