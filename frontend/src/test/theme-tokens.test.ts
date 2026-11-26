import { describe, it, expect, beforeEach } from 'vitest';
import { getThemeTokens, getStatusColor } from '../styles/tokens';
import { useWorkstationStore } from '../stores/useWorkstationStore';

describe('ChronoCongiSec Brand Identity & Theme Tokens', () => {
  beforeEach(() => {
    localStorage.clear();
    useWorkstationStore.getState().setTheme('dark');
  });

  it('provides exact ChronoCongiSec dark theme tokens as default', () => {
    const tokens = getThemeTokens('dark');
    expect(tokens.brand.primary).toBe('#635BFF');
    expect(tokens.brand.hover).toBe('#5148E5');
    expect(tokens.brand.teal).toBe('#14B8A6');
    expect(tokens.canvas).toBe('#0D1321');
    expect(tokens.surface).toBe('#131C2E');
    expect(tokens.elevated).toBe('#1A2740');
    expect(tokens.border).toBe('#2A3850');
    expect(tokens.textPrimary).toBe('#E6EDF7');
    expect(tokens.textMuted).toBe('#A0AEC0');
    expect(tokens.status.trusted).toBe('#4ADE80');
    expect(tokens.status.warning).toBe('#FBBF24');
    expect(tokens.status.critical).toBe('#F87171');
    expect(tokens.status.info).toBe('#38BDF8');
    expect(tokens.status.unknown).toBe('#CBD5E1');
  });

  it('provides exact ChronoCongiSec high-contrast light theme tokens', () => {
    const tokens = getThemeTokens('light');
    expect(tokens.brand.primary).toBe('#635BFF');
    expect(tokens.brand.hover).toBe('#5148E5');
    expect(tokens.brand.teal).toBe('#14B8A6');
    expect(tokens.canvas).toBe('#F4F7FB');
    expect(tokens.surface).toBe('#FFFFFF');
    expect(tokens.elevated).toBe('#EDF2F8');
    expect(tokens.border).toBe('#D7E0EC');
    expect(tokens.textPrimary).toBe('#182235');
    expect(tokens.textMuted).toBe('#53627A');
    expect(tokens.status.trusted).toBe('#166534');
    expect(tokens.status.warning).toBe('#92400E');
    expect(tokens.status.critical).toBe('#991B1B');
    expect(tokens.status.info).toBe('#075985');
    expect(tokens.status.unknown).toBe('#475569');
  });

  it('maps security status colors accurately across dark and light modes', () => {
    expect(getStatusColor('TRUSTED', 'dark')).toBe('#4ADE80');
    expect(getStatusColor('TRUSTED', 'light')).toBe('#166534');
    expect(getStatusColor('QUARANTINED', 'dark')).toBe('#F87171');
    expect(getStatusColor('QUARANTINED', 'light')).toBe('#991B1B');
    expect(getStatusColor('SUSPICIOUS', 'dark')).toBe('#FBBF24');
    expect(getStatusColor('SUSPICIOUS', 'light')).toBe('#92400E');
    expect(getStatusColor('SUPERSEDED', 'dark')).toBe('#38BDF8');
    expect(getStatusColor('SUPERSEDED', 'light')).toBe('#075985');
    expect(getStatusColor('UNVERIFIED', 'dark')).toBe('#CBD5E1');
    expect(getStatusColor('UNVERIFIED', 'light')).toBe('#475569');
  });

  it('switches themes via Zustand store, updates DOM class, and persists to localStorage', () => {
    expect(useWorkstationStore.getState().theme).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);

    useWorkstationStore.getState().toggleTheme();

    expect(useWorkstationStore.getState().theme).toBe('light');
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(localStorage.getItem('amsc_theme')).toBe('light');

    useWorkstationStore.getState().toggleTheme();

    expect(useWorkstationStore.getState().theme).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(localStorage.getItem('amsc_theme')).toBe('dark');
  });
});
