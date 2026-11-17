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
        amsc: {
          deep: '#0B0F19',
          surface: '#111827',
          muted: '#1F2937',
          subtle: '#374151',
          strong: '#4B5563',
          blue: '#3B82F6',
          cyan: '#06B6D4',
          purple: '#8B5CF6',
          trusted: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
          unverified: '#6B7280',
          superseded: '#8B5CF6',
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
