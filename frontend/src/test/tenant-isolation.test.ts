import { getTenantFixtures, TenantIsolationError } from '../services/fixtures';
import { useWorkstationStore } from '../stores/useWorkstationStore';

describe('Strict Multi-Tenant Isolation (P1 Finding F & SEC-004)', () => {
  it('loads isolated fixtures for authorized AlphaCorp tenant', () => {
    const data = getTenantFixtures('tenant-alphacorp');
    expect(data).toBeDefined();
    expect(data.agents.some((a) => a.id === 'agt-fin-001')).toBe(true);
    expect(data.memories.some((m) => m.id === 'rec-8812-441a')).toBe(true);
  });

  it('loads isolated fixtures for BetaShield with zero AlphaCorp records', () => {
    const data = getTenantFixtures('tenant-betashield');
    expect(data).toBeDefined();
    // Must contain its own cybersecurity agent and memories
    expect(data.agents.some((a) => a.id === 'agt-cyber-001')).toBe(true);
    expect(data.memories.some((m) => m.id === 'rec-beta-101')).toBe(true);

    // Must NOT contain AlphaCorp's financial poisoning memories
    expect(data.memories.some((m) => m.id === 'rec-8812-441a')).toBe(false);
    expect(data.agents.some((a) => a.id === 'agt-fin-001')).toBe(false);
  });

  it('loads isolated fixtures for GammaAI with zero AlphaCorp or BetaShield records', () => {
    const data = getTenantFixtures('tenant-gammaai');
    expect(data).toBeDefined();
    expect(data.agents.some((a) => a.id === 'agt-ops-001')).toBe(true);
    expect(data.memories.some((m) => m.id === 'rec-gamma-201')).toBe(true);

    expect(data.memories.some((m) => m.id === 'rec-8812-441a')).toBe(false);
    expect(data.memories.some((m) => m.id === 'rec-beta-101')).toBe(false);
  });

  it('throws TenantIsolationError when accessing an unauthorized or unknown tenant ID', () => {
    expect(() => getTenantFixtures('tenant-unknown-attacker')).toThrow(TenantIsolationError);
    expect(() => getTenantFixtures('')).toThrow(TenantIsolationError);
    expect(() => getTenantFixtures('tenant-corp-evil')).toThrow(/Access denied under SEC-004/);
  });

  it('asserts tenant workspace switching in useWorkstationStore', () => {
    const store = useWorkstationStore.getState();
    const beta = { id: 'tenant-betashield', name: 'BetaShield', slug: 'betashield' };
    store.setActiveTenant(beta);

    expect(useWorkstationStore.getState().activeTenant.id).toBe('tenant-betashield');
  });

  it('purges selected memory, entity, inspector, trace, and filters on tenant switch to prevent state ghosting', () => {
    const store = useWorkstationStore.getState();

    // Populate active transient state for AlphaCorp
    store.setSelectedEntity({ id: 'agt-fin-001', name: 'Financial Agent' });
    store.setSelectedMemory({ id: 'rec-8812-441a', content: 'Secret AlphaCorp data' });
    store.openInspector({
      title: 'Memory rec-8812-441a',
      type: 'RECORD',
      id: 'rec-8812-441a',
      details: { account: '12345' },
    });
    store.setActiveTraceId('trace-alphacorp-999');
    store.setActiveFilter('QUARANTINED');
    store.setTableFilters({ status: 'QUARANTINED', tier: 'ELEVATED' });
    store.setGraphFilters({ minDepth: 2, showTainted: true });

    // Verify state was populated
    expect(useWorkstationStore.getState().selectedEntity).not.toBeNull();
    expect(useWorkstationStore.getState().selectedMemory).not.toBeNull();
    expect(useWorkstationStore.getState().inspectorOpen).toBe(true);
    expect(useWorkstationStore.getState().activeTraceId).toBe('trace-alphacorp-999');
    expect(useWorkstationStore.getState().tableFilters.status).toBe('QUARANTINED');

    // Act: Switch to BetaShield workspace
    const beta = { id: 'tenant-betashield', name: 'BetaShield', slug: 'betashield' };
    store.setActiveTenant(beta);

    // Assert: All stale entity and filter state is purged immediately
    const newState = useWorkstationStore.getState();
    expect(newState.activeTenant.id).toBe('tenant-betashield');
    expect(newState.selectedEntity).toBeNull();
    expect(newState.selectedMemory).toBeNull();
    expect(newState.inspectorOpen).toBe(false);
    expect(newState.inspectorPayload).toBeNull();
    expect(newState.activeTraceId).toBeNull();
    expect(newState.activeFilter).toBeNull();
    expect(newState.tableFilters).toEqual({});
    expect(newState.graphFilters).toEqual({});
  });

  it('supports explicit purgeTenantState call', () => {
    const store = useWorkstationStore.getState();
    store.setSelectedMemory({ id: 'mem-1' });
    store.setActiveTraceId('trace-123');

    store.purgeTenantState();

    const state = useWorkstationStore.getState();
    expect(state.selectedMemory).toBeNull();
    expect(state.activeTraceId).toBeNull();
    expect(state.inspectorOpen).toBe(false);
  });
});
