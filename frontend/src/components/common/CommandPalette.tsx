import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWorkstationStore, AVAILABLE_TENANTS } from '@/stores/useWorkstationStore';
import {
  Search,
  LayoutDashboard,
  Bot,
  Database,
  Shield,
  Activity,
  History,
  GitBranch,
  TrendingDown,
  RotateCcw,
  FileCheck,
  Settings,
  Zap,
  Building,
  X,
} from 'lucide-react';

export const CommandPalette: React.FC = () => {
  const { commandPaletteOpen, setCommandPaletteOpen, setAttackReplayOpen, setActiveTenant, activeTenant } =
    useWorkstationStore();
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  // Listen for Ctrl+K or Cmd+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(!commandPaletteOpen);
      }
      if (e.key === 'Escape' && commandPaletteOpen) {
        setCommandPaletteOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [commandPaletteOpen, setCommandPaletteOpen]);

  if (!commandPaletteOpen) return null;

  const NAVIGATION_COMMANDS = [
    { title: 'Overview Dashboard', path: '/', icon: LayoutDashboard, category: 'Screens' },
    { title: 'Agent Registry', path: '/agents', icon: Bot, category: 'Screens' },
    { title: 'Memory Explorer', path: '/memory', icon: Database, category: 'Screens' },
    { title: 'Security Center', path: '/security', icon: Shield, category: 'Screens' },
    { title: 'Dual Trace Scrubber', path: '/traces', icon: Activity, category: 'Screens' },
    { title: 'ChroniMem Timeline', path: '/chronimem', icon: History, category: 'Screens' },
    { title: 'Knowledge Graph', path: '/knowledge-graph', icon: GitBranch, category: 'Screens' },
    { title: 'Drift Monitor', path: '/drift', icon: TrendingDown, category: 'Screens' },
    { title: 'Agent Rewinding', path: '/rewind', icon: RotateCcw, category: 'Screens' },
    { title: 'Audit Center', path: '/audit', icon: FileCheck, category: 'Screens' },
    { title: 'Settings & Governance', path: '/settings', icon: Settings, category: 'Screens' },
  ];

  const filteredScreens = NAVIGATION_COMMANDS.filter((cmd) =>
    cmd.title.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-xl bg-surface border border-borderc rounded-lg shadow-2xl overflow-hidden text-ink">
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3 border-b border-borderc">
          <Search className="w-4 h-4 text-ink-muted mr-2 shrink-0" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search screens, forensic actions, tenant contexts (ESC to close)..."
            autoFocus
            className="w-full bg-transparent text-sm text-ink placeholder-ink-muted focus:outline-none font-mono"
          />
          <button
            onClick={() => setCommandPaletteOpen(false)}
            className="text-ink-muted hover:text-ink transition-colors"
            aria-label="Close Command Palette"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Action Results */}
        <div className="max-h-80 overflow-y-auto p-2 divide-y divide-borderc font-mono text-xs">
          {/* Action Trigger */}
          <div className="py-1">
            <div className="px-3 py-1 text-[10px] text-ink-muted uppercase tracking-wider font-semibold">
              Forensic Simulation
            </div>
            <button
              onClick={() => {
                setCommandPaletteOpen(false);
                setAttackReplayOpen(true);
              }}
              className="w-full flex items-center gap-2.5 px-3 py-2 rounded text-left hover:bg-elevated text-status-warning transition-colors"
            >
              <Zap className="w-3.5 h-3.5 text-status-warning" />
              <span>Simulate Memory Poisoning & Gateway Interception Replay</span>
            </button>
          </div>

          {/* Tenant Switchers */}
          <div className="py-1">
            <div className="px-3 py-1 text-[10px] text-ink-muted uppercase tracking-wider font-semibold">
              Tenant Context Switcher
            </div>
            {AVAILABLE_TENANTS.map((tenant) => (
              <button
                key={tenant.id}
                onClick={() => {
                  setActiveTenant(tenant);
                  setCommandPaletteOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3 py-1.5 rounded text-left hover:bg-elevated transition-colors ${
                  activeTenant.id === tenant.id ? 'bg-brand-tint text-brand font-bold' : 'text-ink'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Building className="w-3.5 h-3.5 text-ink-muted" />
                  <span>{tenant.name}</span>
                </div>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-canvas border border-borderc text-ink-muted">
                  {tenant.badge}
                </span>
              </button>
            ))}
          </div>

          {/* Navigation Items */}
          <div className="py-1">
            <div className="px-3 py-1 text-[10px] text-ink-muted uppercase tracking-wider font-semibold">
              Workstation Navigation
            </div>
            {filteredScreens.map((cmd) => {
              const Icon = cmd.icon;
              return (
                <button
                  key={cmd.path}
                  onClick={() => {
                    navigate(cmd.path);
                    setCommandPaletteOpen(false);
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded text-left hover:bg-elevated text-ink hover:text-brand transition-colors"
                >
                  <Icon className="w-3.5 h-3.5 text-ink-muted" />
                  <span>{cmd.title}</span>
                  <span className="ml-auto text-[10px] text-ink-muted">{cmd.path}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Footer shortcuts */}
        <div className="flex items-center justify-between px-4 py-2 bg-elevated border-t border-borderc text-[10px] text-ink-muted font-mono">
          <span>Navigate: ↑ ↓</span>
          <span>Select: ↵</span>
          <span>Close: ESC</span>
        </div>
      </div>
    </div>
  );
};
