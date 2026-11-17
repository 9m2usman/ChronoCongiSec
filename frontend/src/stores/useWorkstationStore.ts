import { create } from 'zustand';

export type TenantId = 'tenant-alphacorp' | 'tenant-betashield' | 'tenant-gammaai';

export interface TenantInfo {
  id: TenantId;
  name: string;
  slug: string;
  badge: string;
}

export const AVAILABLE_TENANTS: TenantInfo[] = [
  { id: 'tenant-alphacorp', name: 'AlphaCorp (Company A)', slug: 'alphacorp', badge: 'FINANCIAL_AI' },
  { id: 'tenant-betashield', name: 'BetaShield (Company B)', slug: 'betashield', badge: 'DEFENSE_CYBER' },
  { id: 'tenant-gammaai', name: 'GammaAI (Company C)', slug: 'gammaai', badge: 'AUTONOMOUS_OPS' },
];

export interface InspectorPayload {
  title: string;
  type: 'RECORD' | 'AGENT' | 'DECISION' | 'INCIDENT' | 'SPAN';
  id: string;
  sha256?: string;
  trustState?: 'TRUSTED' | 'SUSPICIOUS' | 'QUARANTINED' | 'UNVERIFIED';
  details: Record<string, unknown>;
}

interface WorkstationState {
  // Tenancy
  activeTenant: TenantInfo;
  setActiveTenant: (tenant: TenantInfo) => void;

  // Sidebar
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;

  // Inspector Drawer
  inspectorOpen: boolean;
  inspectorPayload: InspectorPayload | null;
  openInspector: (payload: InspectorPayload) => void;
  closeInspector: () => void;

  // Command Palette
  commandPaletteOpen: boolean;
  setCommandPaletteOpen: (open: boolean) => void;

  // Attack Replay Simulation
  attackReplayOpen: boolean;
  setAttackReplayOpen: (open: boolean) => void;

  // API Mode
  apiMode: 'LIVE_CONNECTED' | 'SCHEMA_FALLBACK';
  setApiMode: (mode: 'LIVE_CONNECTED' | 'SCHEMA_FALLBACK') => void;
}

export const useWorkstationStore = create<WorkstationState>((set) => ({
  activeTenant: AVAILABLE_TENANTS[0],
  setActiveTenant: (tenant) => set({ activeTenant: tenant }),

  sidebarCollapsed: false,
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),

  inspectorOpen: false,
  inspectorPayload: null,
  openInspector: (payload) => set({ inspectorOpen: true, inspectorPayload: payload }),
  closeInspector: () => set({ inspectorOpen: false, inspectorPayload: null }),

  commandPaletteOpen: false,
  setCommandPaletteOpen: (open) => set({ commandPaletteOpen: open }),

  attackReplayOpen: false,
  setAttackReplayOpen: (open) => set({ attackReplayOpen: open }),

  apiMode: 'SCHEMA_FALLBACK', // Default to resilient fallback until live backend ping
  setApiMode: (mode) => set({ apiMode: mode }),
}));
