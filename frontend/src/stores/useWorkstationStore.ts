import { create } from 'zustand';
import { UserProfileResponse } from '@/types';

export type TenantId = 'tenant-alphacorp' | 'tenant-betashield' | 'tenant-gammaai' | string;

export interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  badge?: string;
}

export const DEFAULT_AVAILABLE_TENANTS: TenantInfo[] = [
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
  details: Record<string, any>;
}

export type ApiMode = 'LIVE_CONNECTED' | 'SCHEMA_FALLBACK' | 'BACKEND_OFFLINE';

interface WorkstationState {
  // Session Authentication
  authToken: string | null;
  currentUser: UserProfileResponse | null;
  setAuth: (token: string | null, user: UserProfileResponse | null) => void;
  logout: () => void;

  // Tenancy
  availableTenants: TenantInfo[];
  setAvailableTenants: (tenants: TenantInfo[]) => void;
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
  apiMode: ApiMode;
  setApiMode: (mode: ApiMode) => void;
}

const INITIAL_TOKEN = typeof window !== 'undefined' ? sessionStorage.getItem('amsc_auth_token') : null;

export const useWorkstationStore = create<WorkstationState>((set) => ({
  authToken: INITIAL_TOKEN,
  currentUser: null,
  setAuth: (token, user) => {
    if (typeof window !== 'undefined') {
      if (token) {
        sessionStorage.setItem('amsc_auth_token', token);
      } else {
        sessionStorage.removeItem('amsc_auth_token');
      }
    }
    set({ authToken: token, currentUser: user });
  },
  logout: () => {
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem('amsc_auth_token');
    }
    set({
      authToken: null,
      currentUser: null,
      apiMode: 'SCHEMA_FALLBACK',
    });
  },

  availableTenants: DEFAULT_AVAILABLE_TENANTS,
  setAvailableTenants: (tenants) => set({ availableTenants: tenants }),

  activeTenant: DEFAULT_AVAILABLE_TENANTS[0],
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

  apiMode: 'SCHEMA_FALLBACK',
  setApiMode: (mode) => set({ apiMode: mode }),
}));

// Backwards compatibility alias
export const AVAILABLE_TENANTS = DEFAULT_AVAILABLE_TENANTS;
