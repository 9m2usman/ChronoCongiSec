import { describe, it, expect } from 'vitest';
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
});
