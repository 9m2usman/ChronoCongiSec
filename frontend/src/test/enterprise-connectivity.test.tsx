import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { EnterpriseConnectivityPage } from '@/pages/EnterpriseConnectivityPage';
import { apiClient } from '@/services/apiClient';

describe('EnterpriseConnectivityPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders live backend connectors and monitoring coverage', async () => {
    vi.spyOn(apiClient, 'listEnterpriseConnectors').mockResolvedValue([
      {
        id: 'conn-1',
        tenant_id: 'tenant-a-uuid-001',
        name: 'Acme ERP SQLite',
        connector_type: 'DATABASE',
        status: 'AUTHORIZED',
        auth_mode: 'LOCAL_SCOPED',
        config_json: {},
        scope_json: { max_classification: 'CONFIDENTIAL' },
        monitoring_coverage_json: {
          observed_events: ['SCHEMA_DISCOVERY'],
          inferred_events: ['RECORD_CHANGE_FROM_CHECKSUM'],
          unsupported_events: ['REALTIME_WAL_CDC_STREAM'],
        },
        created_by: 'admin-1',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ]);
    vi.spyOn(apiClient, 'listEnterpriseResources').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listEnterpriseSyncJobs').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listEnterpriseClaims').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listEnterpriseMemoryProvenance').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listEnterpriseAuditLogs').mockResolvedValue([]);

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <EnterpriseConnectivityPage />
      </QueryClientProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('Acme ERP SQLite')).toBeInTheDocument();
      expect(screen.getByText('AUTHORIZED')).toBeInTheDocument();
      expect(screen.getByText(/SCHEMA_DISCOVERY/)).toBeInTheDocument();
    });
  });

  it('switches to provenance tab and displays impact trace when Trace Impact is clicked', async () => {
    vi.spyOn(apiClient, 'listEnterpriseConnectors').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listEnterpriseResources').mockResolvedValue([
      {
        id: 'res-1',
        tenant_id: 'tenant-a-uuid-001',
        connector_id: 'conn-1',
        resource_type: 'POLICY_DOC',
        external_id: 'fs://policies/procurement.md',
        name: 'procurement.md',
        access_scope: 'READ_ONLY_PATH:policies/procurement.md',
        classification: 'CONFIDENTIAL',
        sync_status: 'SYNCED',
        metadata_json: {},
        retention_policy: 'STANDARD_90D',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ]);
    vi.spyOn(apiClient, 'listEnterpriseSyncJobs').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listEnterpriseClaims').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listEnterpriseMemoryProvenance').mockResolvedValue([]);
    vi.spyOn(apiClient, 'listEnterpriseAuditLogs').mockResolvedValue([]);
    vi.spyOn(apiClient, 'traceEnterpriseImpact').mockResolvedValue({
      target_id: 'res-1',
      tenant_id: 'tenant-a-uuid-001',
      source_resources: [],
      affected_claims: [],
      dependent_memories: [],
      affected_agent_ids: ['ag-fin-1'],
      recommended_actions: ['CONTAIN_POISONED_SOURCE_AND_BLOCK_DEPENDENT_MEMORIES'],
      evidence_summary: {},
    });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <EnterpriseConnectivityPage />
      </QueryClientProvider>
    );

    fireEvent.click(screen.getByText('Discovered Inventory'));
    await waitFor(() => {
      expect(screen.getByText('procurement.md')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Trace Impact'));
    await waitFor(() => {
      expect(screen.getByText(/Incident Impact Trace for res-1/)).toBeInTheDocument();
      expect(screen.getByText(/ag-fin-1/)).toBeInTheDocument();
    });
  });
});
