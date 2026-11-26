/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: 'var(--brand-primary)',
          hover: 'var(--brand-hover)',
          teal: 'var(--signal-teal)',
          tint: 'var(--brand-primary-bg)',
          tealTint: 'var(--signal-teal-bg)',
        },
        canvas: 'var(--bg-canvas)',
        surface: 'var(--bg-surface)',
        elevated: 'var(--bg-elevated)',
        borderc: 'var(--border-color)',
        ink: {
          DEFAULT: 'var(--text-primary)',
          muted: 'var(--text-muted)',
        },
        status: {
          trusted: 'var(--status-trusted)',
          trustedBg: 'var(--status-trusted-bg)',
          warning: 'var(--status-warning)',
          warningBg: 'var(--status-warning-bg)',
          critical: 'var(--status-critical)',
          criticalBg: 'var(--status-critical-bg)',
          info: 'var(--status-info)',
          infoBg: 'var(--status-info-bg)',
          unknown: 'var(--status-unknown)',
          unknownBg: 'var(--status-unknown-bg)',
        },
        // Legacy amsc aliases mapped to active CSS variables for full theme compatibility
        amsc: {
          deep: 'var(--bg-canvas)',
          surface: 'var(--bg-surface)',
          muted: 'var(--bg-elevated)',
          subtle: 'var(--border-color)',
          strong: 'var(--border-color)',
          blue: 'var(--brand-primary)',
          cyan: 'var(--signal-teal)',
          purple: 'var(--brand-primary)',
          trusted: 'var(--status-trusted)',
          warning: 'var(--status-warning)',
          danger: 'var(--status-critical)',
          unverified: 'var(--status-unknown)',
          superseded: 'var(--status-info)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
