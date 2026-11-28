import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { EmployeeWorkstationPage } from '../pages/EmployeeWorkstationPage';
import { apiClient } from '../services/apiClient';
import { useWorkstationStore } from '../stores/useWorkstationStore';

describe('EmployeeWorkstationPage', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    useWorkstationStore.setState({
      authToken: 'test-token',
      demoMode: false,
      activeTenant: { id: 'tenant-a-uuid-001', name: 'AlphaCorp', slug: 'alphacorp' },
      currentUser: {
        user_id: 'usr-dev-dave-03',
        email: 'dave.developer@alphacorp.com',
        full_name: 'Dave',
        role: 'DEVELOPER',
        tenant_id: 'tenant-a-uuid-001',
        tenant_slug: 'alphacorp',
        tenant_name: 'AlphaCorp',
        branch_id: 'branch-khi-003',
      } as any,
    });

    vi.spyOn(apiClient, 'listWorkspaces').mockResolvedValue({
      items: [
        {
          id: 'ws-1',
          tenant_id: 'tenant-a-uuid-001',
          branch_id: 'branch-khi-003',
          owner_user_id: 'usr-dev-dave-03',
          name: 'Karachi Ops',
          description: 'Branch workspace',
          visibility: 'BRANCH',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
        },
      ],
      total: 1,
    });
    vi.spyOn(apiClient, 'listCompanyFiles').mockResolvedValue({
      items: [
        {
          id: 'file-1',
          tenant_id: 'tenant-a-uuid-001',
          workspace_id: 'ws-1',
          branch_id: 'branch-khi-003',
          owner_user_id: 'usr-dev-dave-03',
          name: 'vendor-policy.txt',
          content_type: 'text/plain',
          current_version: 1,
          status: 'ACTIVE',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
        },
      ],
      total: 1,
    });
    vi.spyOn(apiClient, 'listFileTransfers').mockResolvedValue({ items: [], total: 0 });
    vi.spyOn(apiClient, 'listCompanyTasks').mockResolvedValue({ items: [], total: 0 });
    vi.spyOn(apiClient, 'listCompanyMessages').mockResolvedValue({ items: [], total: 0 });
    vi.spyOn(apiClient, 'listCompanyNotifications').mockResolvedValue({ items: [], total: 0 });
    vi.spyOn(apiClient, 'listCompanyActivity').mockResolvedValue({ items: [], total: 0 });
    vi.spyOn(apiClient, 'listAgents').mockResolvedValue([
      {
        id: 'agent-crew-branch-004',
        name: 'Branch Ops Agent',
        status: 'ACTIVE',
      } as any,
    ]);
  });

  function renderPage(initialTab: 'workspaces' | 'files' | 'tasks' | 'messages' | 'agent-exec' = 'workspaces') {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <EmployeeWorkstationPage initialTab={initialTab} />
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  it('renders workspaces and switches to files tab', async () => {
    renderPage('workspaces');
    expect(await screen.findByText('Karachi Ops')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /Files & Transfers/i }));
    expect(await screen.findByText('vendor-policy.txt')).toBeInTheDocument();
  });

  it('submits governed agent execution via gateway', async () => {
    const proposeSpy = vi.spyOn(apiClient, 'proposeGatewayAction').mockResolvedValue({
      proposal_id: 'prop-1',
      decision_id: 'dec-1',
      decision: 'ALLOW',
      execution_status: 'EXECUTED',
      reason_codes: [],
    });

    renderPage('agent-exec');
    const agentOption = await screen.findByText(/Branch Ops Agent/i);
    const selectEl = agentOption.closest('select')!;
    fireEvent.change(selectEl, { target: { value: 'agent-crew-branch-004' } });
    fireEvent.click(screen.getByRole('button', { name: /Execute via Gateway/i }));
    await waitFor(() => expect(proposeSpy).toHaveBeenCalledTimes(1));
  });
});
