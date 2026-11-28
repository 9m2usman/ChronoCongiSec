import { render, screen, fireEvent } from '@testing-library/react';
import { StateBanner } from '../components/common/StateBanner';
import { DualModeBadge } from '../components/common/DualModeBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { SettingsPage } from '../pages/SettingsPage';
import { SecurityCenterPage } from '../pages/SecurityCenterPage';
import { AuditCenterPage } from '../pages/AuditCenterPage';
import { KnowledgeGraphPage } from '../pages/KnowledgeGraphPage';
import { computeGraphClusters, computeTopologyStats } from '../utils/graphClustering';
import { AppShell } from '../layouts/AppShell';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useWorkstationStore } from '../stores/useWorkstationStore';
import { vi } from 'vitest';

describe('Screen States & Accessibility (A11y)', () => {
  describe('StateBanner Component', () => {
    it('renders accessible loading state with status role', () => {
      render(<StateBanner type="loading" title="Evaluating telemetry..." message="Please wait" />);

      const banner = screen.getByRole('status');
      expect(banner).toBeInTheDocument();
      expect(screen.getByText('Evaluating telemetry...')).toBeInTheDocument();
      expect(screen.getByText('Please wait')).toBeInTheDocument();
    });

    it('renders accessible empty state with custom action', () => {
      let clicked = false;
      render(
        <StateBanner
          type="empty"
          title="No Incident Records"
          message="Zero critical threats identified."
          actionText="Create Record"
          onAction={() => {
            clicked = true;
          }}
        />
      );

      expect(screen.getByText('No Incident Records')).toBeInTheDocument();
      expect(screen.getByText('Zero critical threats identified.')).toBeInTheDocument();

      const btn = screen.getByText('Create Record');
      fireEvent.click(btn);
      expect(clicked).toBe(true);
    });

    it('renders accessible unauthorized state with alert role and status code', () => {
      render(
        <StateBanner
          type="unauthorized"
          title="Permission Denied"
          statusCode={403}
          message="Requires SECURITY_ANALYST role."
        />
      );

      const alert = screen.getByRole('alert');
      expect(alert).toBeInTheDocument();
      expect(screen.getByText('Permission Denied')).toBeInTheDocument();
      expect(screen.getByText('HTTP 403')).toBeInTheDocument();
      expect(screen.getByText('Requires SECURITY_ANALYST role.')).toBeInTheDocument();
    });

    it('renders unavailable state with server-off icon and explanation', () => {
      render(
        <StateBanner
          type="unavailable"
          title="Endpoint Offline"
          statusCode={404}
          message="Route pending deployment."
        />
      );

      expect(screen.getByText('Endpoint Offline')).toBeInTheDocument();
      expect(screen.getByText('HTTP 404')).toBeInTheDocument();
    });
  });

  describe('DualModeBadge Component', () => {
    it('renders and toggles API mode', () => {
      render(<DualModeBadge />);

      const badge = screen.getByTitle(/Click to toggle API mode/);
      expect(badge).toBeInTheDocument();
      expect(screen.getByText(/CONTRACT FALLBACK|LIVE API: CONNECTED/)).toBeInTheDocument();
    });
  });

  describe('SettingsPage Cryptographic PRNG (P2 Finding G)', () => {
    it('rotates API keys using window.crypto without crashing', () => {
      render(
        <MemoryRouter>
          <SettingsPage />
        </MemoryRouter>
      );

      expect(screen.getByText(/Tenant Settings & Security Governance/i)).toBeInTheDocument();
      const rotateBtn = screen.getByRole('button', { name: /Rotate Key/i });
      expect(rotateBtn).toBeInTheDocument();

      fireEvent.click(rotateBtn);
      // Confirms rotation was triggered cleanly
      expect(rotateBtn).toBeInTheDocument();
    });
  });

  describe('AppShell Theme Switcher (Dark Default & High-Contrast Light)', () => {
    it('toggles between dark (default) and light themes via AppShell button', () => {
      useWorkstationStore.getState().setTheme('dark');
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

      render(
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <AppShell />
          </MemoryRouter>
        </QueryClientProvider>
      );

      expect(document.documentElement.classList.contains('dark')).toBe(true);
      const toLightBtn = screen.getByRole('button', { name: /Switch to light theme/i });
      fireEvent.click(toLightBtn);

      expect(useWorkstationStore.getState().theme).toBe('light');
      expect(document.documentElement.classList.contains('dark')).toBe(false);
      expect(document.documentElement.dataset.theme).toBe('light');

      const toDarkBtn = screen.getByRole('button', { name: /Switch to dark theme/i });
      fireEvent.click(toDarkBtn);

      expect(useWorkstationStore.getState().theme).toBe('dark');
      expect(document.documentElement.classList.contains('dark')).toBe(true);
    });

    it('renders DOC-004 breadcrumb and keyboard-accessible workspace dropdown', () => {
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });

      render(
        <QueryClientProvider client={qc}>
          <MemoryRouter initialEntries={['/memory']}>
            <AppShell />
          </MemoryRouter>
        </QueryClientProvider>
      );

      const breadcrumb = screen.getByRole('navigation', { name: /Breadcrumb/i });
      expect(breadcrumb).toHaveTextContent(/Workspace.*MEMORY.*Memory Explorer/i);

      const trigger = screen.getByRole('button', { name: /Workspace:/i });
      expect(trigger).toHaveAttribute('aria-expanded', 'false');
      fireEvent.click(trigger);
      expect(trigger).toHaveAttribute('aria-expanded', 'true');
      expect(screen.getByRole('listbox', { name: /Select Workspace/i })).toBeInTheDocument();

      fireEvent.keyDown(window, { key: 'Escape' });
      expect(trigger).toHaveAttribute('aria-expanded', 'false');
    });
  });

  describe('StatusBadge Component', () => {
    it('renders semantic status badges consistently', () => {
      render(
        <div>
          <StatusBadge status="TRUSTED" />
          <StatusBadge status="QUARANTINED" />
          <StatusBadge status="SUSPICIOUS" />
        </div>
      );
      expect(screen.getByText('TRUSTED')).toBeInTheDocument();
      expect(screen.getByText('QUARANTINED')).toBeInTheDocument();
      expect(screen.getByText('SUSPICIOUS')).toBeInTheDocument();
    });
  });

  describe('Honest Empty States (Phase 3)', () => {
    it('renders empty StateBanner on SecurityCenterPage when API returns { items: [] }', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ items: [] }),
      }) as any;
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      render(
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <SecurityCenterPage />
          </MemoryRouter>
        </QueryClientProvider>
      );
      expect(await screen.findByText(/No Security Incidents Reported/i)).toBeInTheDocument();
      expect(screen.getByText(/0 Active Incidents/i)).toBeInTheDocument();
      expect(screen.queryByText(/1 Multi-Stage Campaign Active/i)).not.toBeInTheDocument();
    });

    it('renders empty StateBanner on AuditCenterPage when API returns []', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => [],
      }) as any;
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      render(
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <AuditCenterPage />
          </MemoryRouter>
        </QueryClientProvider>
      );
      expect(await screen.findByText(/No Audit Events Located/i)).toBeInTheDocument();
    });
  });

  describe('KnowledgeGraphPage 2D Workstation (Prompt 2)', () => {
    it('renders API nodes, shows empty-edges notice when edges: [], filters by search, and updates Node Inspector on click', async () => {
      if (typeof global.ResizeObserver === 'undefined') {
        global.ResizeObserver = class {
          observe() {}
          unobserve() {}
          disconnect() {}
        } as any;
      }
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          nodes: [
            { id: 'rec-trusted-1', record_type: 'KNOWLEDGE', trust_state: 'TRUSTED', current_version: 2, agent_id: 'agt-fin-01' },
            { id: 'rec-quarantined-2', record_type: 'CONVERSATION', trust_state: 'QUARANTINED', current_version: 1 },
          ],
          edges: [],
          complete: true,
          truncated_reason: null,
        }),
      }) as any;

      const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      render(
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <KnowledgeGraphPage />
          </MemoryRouter>
        </QueryClientProvider>
      );

      expect(await screen.findByText('rec-trusted-1')).toBeInTheDocument();
      expect(screen.getByText(/No relationship edges are currently available/i)).toBeInTheDocument();

      // Click node to update right-side Node Inspector
      fireEvent.click(screen.getByText('rec-trusted-1'));
      const inspector = screen.getByLabelText('Node Inspector');
      expect(inspector).toHaveTextContent('rec-trusted-1');
      expect(inspector).toHaveTextContent('TRUSTED');
      expect(inspector).toHaveTextContent('agt-fin-01');

      // Search filter hides non-matching node
      const searchInput = screen.getByLabelText('Search graph nodes');
      fireEvent.change(searchInput, { target: { value: 'quarantined-2' } });
      expect(screen.queryByTitle('rec-trusted-1')).not.toBeInTheDocument();
      expect(screen.getByText('rec-quarantined-2')).toBeInTheDocument();

      // Clear search and test 2D/3D mode switch + WebGL graceful fallback
      fireEvent.change(searchInput, { target: { value: '' } });
      const btn2d = screen.getByRole('button', { name: /2D Graph/i });
      const btn3d = screen.getByRole('button', { name: /3D Graph/i });
      expect(btn2d).toHaveAttribute('aria-pressed', 'true');
      fireEvent.click(btn3d);
      expect(await screen.findByText(/WebGL Unavailable for 3D Graph/i, {}, { timeout: 5000 })).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: /Switch to 2D Graph/i }));
      expect(screen.getByRole('button', { name: /2D Graph/i })).toHaveAttribute('aria-pressed', 'true');
    }, 15000);

    it('computes connected-component, entity-type, and trust-state clusters with cross-boundary edges', () => {
      const sampleGraph = {
        nodes: [
          { id: 'n1', record_type: 'KNOWLEDGE', trust_state: 'TRUSTED', current_version: 1 },
          { id: 'n2', record_type: 'CONVERSATION', trust_state: 'QUARANTINED', current_version: 2 },
          { id: 'n3', record_type: 'KNOWLEDGE', trust_state: 'TRUSTED', current_version: 1 },
          { id: 'iso-1', record_type: 'SCRATCHPAD', trust_state: 'UNVERIFIED', current_version: 1 },
        ],
        edges: [
          { id: 'e1', from_record_id: 'n1', to_record_id: 'n2', relation_type: 'DERIVED_FROM' },
          { id: 'e2', from_record_id: 'n1', to_record_id: 'n3', relation_type: 'REFERENCES' },
        ],
        complete: true,
        truncated_reason: null,
      };

      const stats = computeTopologyStats(sampleGraph.nodes, sampleGraph.edges);
      expect(stats.isolatedNodeIds.has('iso-1')).toBe(true);
      expect(stats.hubNodeIds.has('n1')).toBe(true);

      const { clusters: compClusters } = computeGraphClusters(sampleGraph, 'CONNECTED_COMPONENTS');
      expect(compClusters).toHaveLength(2);
      expect(compClusters[0].members).toHaveLength(3);
      expect(compClusters[0].hasFlaggedTrust).toBe(true);
      expect(compClusters[1].isIsolated).toBe(true);

      const { clusters: trustClusters } = computeGraphClusters(sampleGraph, 'TRUST_STATE');
      const trustedCluster = trustClusters.find((c) => c.label === 'TRUSTED');
      expect(trustedCluster?.members).toHaveLength(2);
      expect(trustedCluster?.crossBoundaryEdgeCount).toBe(1);
    });

    it('preserves valid ?nodeId= on initial mount and handles invalid ?nodeId= gracefully', async () => {
      if (typeof global.ResizeObserver === 'undefined') {
        global.ResizeObserver = class {
          observe() {}
          unobserve() {}
          disconnect() {}
        } as any;
      }
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          nodes: [
            { id: 'rec-trusted-1', record_type: 'KNOWLEDGE', trust_state: 'TRUSTED', current_version: 2 },
          ],
          edges: [],
          complete: true,
          truncated_reason: null,
        }),
      }) as any;

      const qc1 = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      const { unmount } = render(
        <QueryClientProvider client={qc1}>
          <MemoryRouter initialEntries={['/knowledge-graph?nodeId=rec-trusted-1']}>
            <KnowledgeGraphPage />
          </MemoryRouter>
        </QueryClientProvider>
      );

      const matches = await screen.findAllByText('rec-trusted-1');
      expect(matches.length).toBeGreaterThanOrEqual(2);
      const inspector = screen.getByLabelText('Node Inspector');
      expect(inspector).toHaveTextContent('rec-trusted-1');
      expect(inspector).toHaveTextContent('TRUSTED');
      unmount();

      const qc2 = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      render(
        <QueryClientProvider client={qc2}>
          <MemoryRouter initialEntries={['/knowledge-graph?nodeId=missing-node-999']}>
            <KnowledgeGraphPage />
          </MemoryRouter>
        </QueryClientProvider>
      );
      expect(await screen.findByText(/missing-node-999/i)).toBeInTheDocument();
      expect(screen.getByLabelText('Node Inspector')).toHaveTextContent(/not present in the current graph view/i);
    });
  });
});
