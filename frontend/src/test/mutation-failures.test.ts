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
        apiClient.executeAtomicRewind('plan-rec-8812')
      ).rejects.toThrow(ApiError);
    });

    it('throws AuthorizationError on HTTP 403', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        json: async () => ({ detail: 'Insufficient permissions for atomic recovery' }),
      });

      await expect(
        apiClient.executeAtomicRewind('plan-rec-8812')
      ).rejects.toThrow(AuthorizationError);
    });

    it('returns RecoveryExecuteResponse on verified server 200 OK', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          plan_id: 'plan-rec-8812',
          status: 'EXECUTED',
          success: true,
          executed_at: new Date().toISOString(),
          restored_records: ['rec-8812-441a'],
          restored_records_count: 1,
          quarantined_intermediary_ids: [],
          irreversible_external_actions: 0,
          audit_event_id: 'aud-rewind-101',
          restored_records_trust_state: 'UNVERIFIED',
          reason_codes: ['RECOVERY_COMPLETED'],
          message: 'Rollback committed.',
        }),
      });

      const res = await apiClient.executeAtomicRewind('plan-rec-8812');
      expect(res.status).toBe('EXECUTED');
      expect(res.restored_records).toContain('rec-8812-441a');
      expect(res.restored_records_trust_state).toBe('UNVERIFIED');
    });

    it('sends only the previewed plan id (no client-chosen target record)', async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ plan_id: 'plan-1', status: 'EXECUTED', success: true, reason_codes: [] }),
      });
      global.fetch = fetchMock;
      await apiClient.executeAtomicRewind('plan-1');
      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body).toEqual({ plan_id: 'plan-1' });
    });

    it.each([
      [409, 'FAILED', 'PLAN_STALE'],
      [503, 'FAILED', 'ROLLBACK_FAILED'],
      [500, 'RECONCILIATION_REQUIRED', 'AUDIT_FAILED'],
    ])('surfaces a non-success server outcome (HTTP %i, %s) as an error with details', async (status, outcome, code) => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status,
        json: async () => ({ plan_id: 'plan-1', status: outcome, success: false, reason_codes: [code], message: 'x' }),
      });
      const err = await apiClient.executeAtomicRewind('plan-1').catch((e) => e);
      expect(err).toBeInstanceOf(ApiError);
      expect(err.details.status).toBe(outcome);
      expect(err.details.success).toBe(false);
      expect(err.message).toContain(code);
    });
  });

  describe('previewRecoveryPlan', () => {
    it('throws on server error instead of fabricating a recovery plan', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ error: { message: 'Recovery target or checkpoint not found.' } }),
      });
      await expect(apiClient.previewRecoveryPlan('cp-1', 'rec-1')).rejects.toThrow(ApiError);
    });

    it('throws when the server is unreachable instead of returning a fake plan', async () => {
      global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
      await expect(apiClient.previewRecoveryPlan('cp-1', 'rec-1')).rejects.toThrow(ApiError);
    });

    it('maps 403 to AuthorizationError', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 403, json: async () => ({ detail: 'nope' }) });
      await expect(apiClient.previewRecoveryPlan('cp-1', 'rec-1')).rejects.toThrow(AuthorizationError);
    });
  });
});
