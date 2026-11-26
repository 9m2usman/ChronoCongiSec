export type WorkstationTheme = 'dark' | 'light';

export interface ThemeTokenSet {
  brand: {
    primary: string;
    hover: string;
    teal: string;
  };
  canvas: string;
  surface: string;
  elevated: string;
  border: string;
  textPrimary: string;
  textMuted: string;
  status: {
    trusted: string;
    warning: string;
    critical: string;
    info: string;
    unknown: string;
  };
}

const DARK_TOKENS: ThemeTokenSet = {
  brand: {
    primary: '#635BFF',
    hover: '#5148E5',
    teal: '#14B8A6',
  },
  canvas: '#0D1321',
  surface: '#131C2E',
  elevated: '#1A2740',
  border: '#2A3850',
  textPrimary: '#E6EDF7',
  textMuted: '#A0AEC0',
  status: {
    trusted: '#4ADE80',
    warning: '#FBBF24',
    critical: '#F87171',
    info: '#38BDF8',
    unknown: '#CBD5E1',
  },
};

const LIGHT_TOKENS: ThemeTokenSet = {
  brand: {
    primary: '#635BFF',
    hover: '#5148E5',
    teal: '#14B8A6',
  },
  canvas: '#F4F7FB',
  surface: '#FFFFFF',
  elevated: '#EDF2F8',
  border: '#D7E0EC',
  textPrimary: '#182235',
  textMuted: '#53627A',
  status: {
    trusted: '#166534',
    warning: '#92400E',
    critical: '#991B1B',
    info: '#075985',
    unknown: '#475569',
  },
};

export function getThemeTokens(theme: WorkstationTheme): ThemeTokenSet {
  return theme === 'light' ? LIGHT_TOKENS : DARK_TOKENS;
}

export function getStatusColor(
  state: string | undefined,
  theme: WorkstationTheme
): string {
  const tokens = getThemeTokens(theme);
  switch ((state || '').toUpperCase()) {
    case 'TRUSTED':
    case 'ALLOW':
    case 'ALLOWED':
    case 'ACTIVE':
    case 'VERIFIED':
    case 'COMPLETED':
      return tokens.status.trusted;
    case 'SUSPICIOUS':
    case 'REQUIRES_APPROVAL':
    case 'WARNING':
    case 'PENDING':
      return tokens.status.warning;
    case 'QUARANTINED':
    case 'BLOCK':
    case 'BLOCKED':
    case 'CRITICAL':
    case 'REJECTED':
    case 'FAILED':
      return tokens.status.critical;
    case 'SUPERSEDED':
    case 'INFO':
    case 'INFORMATION':
      return tokens.status.info;
    default:
      return tokens.status.unknown;
  }
}
