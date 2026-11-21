import { apiClient, ApiError, AuthorizationError } from '../services/apiClient';

describe('Backend contract alignment (incidents envelope, forensic memory detail)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('parses the canonical incident envelope and maps items without inventing data', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [
          {
            id: 'inc-1', tenant_id: 'tenant-a-uuid-001', title: 'Prompt injection', classification: 'PROMPT_INJECTION',
            severity: 'HIGH', status: 'QUARANTINED', affected_record_id: 'mem-1', agent_id: null,
            evidence_count: 2, created_at: '2026-11-21T00:00:00Z',
          },
        ],
        limit: 50, offset: 0, has_more: false, total: 1,
      }),
    });
    const incidents = await apiClient.listIncidents('tenant-a-uuid-001');
    expect(incidents).toHaveLength(1);
    expect(incidents[0].status).toBe('QUARANTINED');
    expect(incidents[0].tainted_chunk_id).toBe('mem-1');
    expect(incidents[0].gateway_status).toBe('NOT_REPORTED');
    expect(incidents[0].evidence_summary).toBe('2 evidence item(s)');
  });

  it('throws on an unexpected incident shape instead of showing fixtures', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => [{ id: 'x' }] });
    await expect(apiClient.listIncidents('tenant-a-uuid-001')).rejects.toThrow(ApiError);
  });

  it('surfaces an incident 403 instead of showing fixtures', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 403, json: async () => ({}) });
    await expect(apiClient.listIncidents('tenant-a-uuid-001')).rejects.toThrow(AuthorizationError);
  });

  it('uses the dedicated audited forensic route with an investigation reason', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ record: {}, versions: [], provenance: [] }) });
    global.fetch = fetchMock;
    await apiClient.getMemoryDetail('mem-1', 'tenant-a-uuid-001', true, 'INC-001 root cause analysis');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/memory/mem-1/forensic-access');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body)).toEqual({ reason: 'INC-001 root cause analysis' });
    expect(String(url)).not.toContain('for_forensic');
  });

  it('does not request forensic access when not asked', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ record: {}, versions: [], provenance: [] }) });
    global.fetch = fetchMock;
    await apiClient.getMemoryDetail('mem-1', 'tenant-a-uuid-001', false);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/memory/mem-1');
    expect(init.method ?? 'GET').toBe('GET');
  });

  it.each([403, 404, 503])('surfaces a memory-detail HTTP %i instead of returning fixture data', async (status) => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status, json: async () => ({}) });
    await expect(apiClient.getMemoryDetail('mem-a-quarantined-001', 'tenant-a-uuid-001', true, 'reason text'))
      .rejects.toBeInstanceOf(ApiError);
  });
});
