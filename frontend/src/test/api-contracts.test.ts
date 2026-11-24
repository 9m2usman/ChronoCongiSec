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

  it('fetches agent security profile with authoritative purpose and permissions', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        agent_id: 'agent-crew-support-001',
        tenant_id: 'tenant-a-uuid-001',
        department: 'Customer Service',
        approved_purpose: 'Enterprise Customer Support',
        approved_goals: ['Assist customers with returns'],
        authorized_data_scope: ['customer_faq', 'order_status'],
        operational_restrictions: ['Cannot process refunds over $300'],
        approval_requirements: ['Dual-custody for high-value items'],
        profile_version: 'v1.0.0',
        is_active: true,
        branch_id: 'branch-ho-001',
        tools: [{ tool_id: 'tool-lookup', tool_name: 'customer_lookup', allowed_operations: ['read'] }],
        updated_at: '2026-11-24T00:00:00Z',
      }),
    });
    const profile = await apiClient.getAgentProfile('agent-crew-support-001', 'tenant-a-uuid-001');
    expect(profile).not.toBeNull();
    expect(profile?.agent_id).toBe('agent-crew-support-001');
    expect(profile?.department).toBe('Customer Service');
    expect(profile?.tools).toHaveLength(1);
  });

  it('queries enterprise baseline records independently from agent memory', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [
          {
            id: 'base-fin-gov-001',
            tenant_id: 'tenant-a-uuid-001',
            title: 'Enterprise Financial Governance',
            category: 'POLICY',
            source_type: 'INTERNAL_POLICY',
            lifecycle_status: 'ACTIVE',
            provenance: 'Internal Governance Board',
            classification: 'CONFIDENTIAL',
            access_scope: ['*'],
            current_version: 'v1.0.0',
            created_by_user_id: 'usr-admin-001',
            content: 'Approved policy content',
            content_digest: 'sha256_mock_digest',
            digest_algorithm: 'SHA-256',
            created_at: '2026-11-24T00:00:00Z',
            updated_at: '2026-11-24T00:00:00Z',
          },
        ],
        total: 1,
        limit: 50,
        offset: 0,
      }),
    });
    global.fetch = fetchMock;
    const records = await apiClient.listBaselineRecords('POLICY', 'ACTIVE', undefined, 'tenant-a-uuid-001');
    expect(records).toHaveLength(1);
    expect(records[0].category).toBe('POLICY');
    expect(records[0].lifecycle_status).toBe('ACTIVE');
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain('/api/v1/baseline?');
    expect(url).toContain('category=POLICY');
    expect(url).toContain('lifecycle_status=ACTIVE');
  });

  it('queries observation events foundation with structured filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        items: [
          {
            id: 'obs-001',
            tenant_id: 'tenant-a-uuid-001',
            event_type: 'AGENT_EXECUTION_START',
            event_category: 'AGENT_EXECUTION_LIFECYCLE',
            agent_id: 'agent-crew-support-001',
            agent_runtime: 'CREWAI',
            execution_id: 'exec-001',
            trace_id: 'tr-001',
            source_component: 'amsc.crewai.client',
            outcome: 'SUCCESS',
            payload: {},
            created_at: '2026-11-24T00:00:00Z',
          },
        ],
        total: 1,
        limit: 50,
        offset: 0,
      }),
    });
    global.fetch = fetchMock;
    const events = await apiClient.listObservationEvents('agent-crew-support-001', 'AGENT_EXECUTION_LIFECYCLE', undefined, 'tenant-a-uuid-001');
    expect(events).toHaveLength(1);
    expect(events[0].event_type).toBe('AGENT_EXECUTION_START');
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain('/api/v1/observation/events?');
    expect(url).toContain('agent_id=agent-crew-support-001');
  });

  it('queries detection findings across categories with branch and tenant filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => [
        {
          id: 'det-001',
          tenant_id: 'tenant-a-uuid-001',
          branch_id: 'branch-lhr-002',
          detection_category: 'PROMPT_INJECTION',
          classification_type: 'CONFIRMED_SECURITY_INCIDENT',
          agent_id: 'agent-crew-support-001',
          detection_method: 'HEURISTIC_PATTERN',
          confidence_score: 0.98,
          uncertainty_state: 'HIGH_CONFIDENCE',
          severity: 'CRITICAL',
          recommended_outcome: 'BLOCK',
          status: 'DETECTED',
          title: 'Indirect Prompt Injection Indicator Detected',
          description: 'Instruction override directive identified in memory input.',
          memory_refs: ['mem-001'],
          baseline_refs: [],
          evidence_items: [
            {
              evidence_type: 'PROMPT_INJECTION_SIGNATURE',
              description: 'Matched override directive pattern',
            },
          ],
          details: { reason_code: 'PROMPT_INJECTION_DETECTED' },
          created_at: '2026-11-24T00:00:00Z',
        },
      ],
    });
    global.fetch = fetchMock;
    const findings = await apiClient.listDetections('PROMPT_INJECTION', 'CRITICAL', 'DETECTED', 'branch-lhr-002', 'tenant-a-uuid-001');
    expect(findings).toHaveLength(1);
    expect(findings[0].detection_category).toBe('PROMPT_INJECTION');
    expect(findings[0].classification_type).toBe('CONFIRMED_SECURITY_INCIDENT');
    expect(findings[0].recommended_outcome).toBe('BLOCK');
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain('/api/v1/detection/results?');
    expect(url).toContain('category=PROMPT_INJECTION');
    expect(url).toContain('severity=CRITICAL');
  });

  it('executes ad-hoc detection evaluation via POST /detection/evaluate', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        findings_count: 1,
        highest_severity: 'CRITICAL',
        recommended_outcome: 'BLOCK',
        has_confirmed_violation: false,
        has_confirmed_incident: true,
        detections: [
          {
            id: 'det-eval-001',
            tenant_id: 'tenant-a-uuid-001',
            detection_category: 'MEMORY_INTEGRITY',
            classification_type: 'CONFIRMED_SECURITY_INCIDENT',
            detection_method: 'CRYPTOGRAPHIC_HASH',
            confidence_score: 1.0,
            uncertainty_state: 'DEFINITIVE',
            severity: 'CRITICAL',
            recommended_outcome: 'BLOCK',
            status: 'DETECTED',
            title: 'Cryptographic Checksum Tamper Detected',
            description: 'SHA-256 digest mismatch.',
            memory_refs: ['mem-tampered-001'],
            baseline_refs: [],
            evidence_items: [],
            details: { reason_code: 'MEMORY_CHECKSUM_TAMPER' },
          },
        ],
      }),
    });
    global.fetch = fetchMock;
    const res = await apiClient.evaluateDetection(
      { content: 'tampered payload', expected_checksum: '0000000000000000000000000000000000000000000000000000000000000000' },
      'tenant-a-uuid-001'
    );
    expect(res.findings_count).toBe(1);
    expect(res.highest_severity).toBe('CRITICAL');
    expect(res.recommended_outcome).toBe('BLOCK');
    expect(res.has_confirmed_incident).toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/detection/evaluate');
    expect(init.method).toBe('POST');
  });

  it('reviews and transitions detection status via POST /detection/results/{id}/review', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        id: 'det-001',
        tenant_id: 'tenant-a-uuid-001',
        detection_category: 'BEHAVIORAL_DEVIATION',
        classification_type: 'CONFIRMED_POLICY_VIOLATION',
        status: 'CONFIRMED_VIOLATION',
        detection_method: 'POLICY_VERIFICATION',
        confidence_score: 1.0,
        uncertainty_state: 'DEFINITIVE',
        severity: 'HIGH',
        recommended_outcome: 'BLOCK',
        title: 'Action Exceeds Authorized Departmental Purpose',
        description: 'Customer service agent proposed financial transfer.',
        memory_refs: [],
        baseline_refs: [],
        evidence_items: [],
        details: {},
      }),
    });
    global.fetch = fetchMock;
    const res = await apiClient.reviewDetection(
      'det-001',
      { status: 'CONFIRMED_VIOLATION', notes: 'Confirmed unauthorized departmental action' },
      'tenant-a-uuid-001'
    );
    expect(res.id).toBe('det-001');
    expect(res.status).toBe('CONFIRMED_VIOLATION');
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/detection/results/det-001/review');
    expect(init.method).toBe('POST');
  });
});
