import { NavLink, Outlet } from 'react-router-dom';
import { useWorkstationStore, AVAILABLE_TENANTS } from '@/stores/useWorkstationStore';
import { useHealthCheck } from '@/hooks';
import { DualModeBadge } from '@/components/common/DualModeBadge';
import { CommandPalette } from '@/components/common/CommandPalette';
import { AttackReplayModal } from '@/components/common/AttackReplayModal';
import { InspectorDrawer } from '@/components/common/InspectorDrawer';
import {
  LayoutDashboard,
  Bot,
  Database,
  History,
  GitBranch,
  ShieldAlert,
  Activity,
  TrendingDown,
  RotateCcw,
  FileCheck,
  Settings,
  ChevronDown,
  Search,
  Zap,
  Shield,
  Menu,
  ChevronLeft,
} from 'lucide-react';

export const AppShell: React.FC = () => {
  useHealthCheck();

  const {
    activeTenant,
    setActiveTenant,
    sidebarCollapsed,
    toggleSidebar,
    setCommandPaletteOpen,
    setAttackReplayOpen,
  } = useWorkstationStore();

  const NAV_SECTIONS = [
    {
      heading: 'WORKSPACE',
      items: [
        { label: 'Overview', path: '/', icon: LayoutDashboard },
        { label: 'Agent Registry', path: '/agents', icon: Bot },
      ],
    },
    {
      heading: 'MEMORY',
      items: [
        { label: 'Memory Explorer', path: '/memory', icon: Database },
        { label: 'ChroniMem', path: '/chronimem', icon: History },
        { label: 'Knowledge Graph', path: '/knowledge-graph', icon: GitBranch },
      ],
    },
    {
      heading: 'SECURITY',
      items: [
        { label: 'Security Center', path: '/security', icon: ShieldAlert },
        { label: 'Dual Trace', path: '/traces', icon: Activity },
        { label: 'Drift Monitor', path: '/drift', icon: TrendingDown },
      ],
    },
    {
      heading: 'RECOVERY',
      items: [{ label: 'Agent Rewinding', path: '/rewind', icon: RotateCcw }],
    },
    {
      heading: 'GOVERNANCE',
      items: [
        { label: 'Audit Center', path: '/audit', icon: FileCheck },
        { label: 'Settings & Gov.', path: '/settings', icon: Settings },
      ],
    },
  ];

  return (
    <div className="flex h-screen w-screen bg-[#0B0F19] text-slate-100 overflow-hidden font-sans">
      {/* 1. Global Left Sidebar */}
      <aside
        className={`flex flex-col border-r border-slate-800 bg-[#111827] transition-all duration-200 z-30 ${
          sidebarCollapsed ? 'w-16' : 'w-60'
        }`}
      >
        {/* Sidebar Brand Header */}
        <div className="flex items-center justify-between px-4 h-14 border-b border-slate-800">
          {!sidebarCollapsed && (
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-500 shrink-0" />
              <div className="flex flex-col leading-tight">
                <span className="font-bold tracking-wider text-xs text-slate-100">AMSC</span>
                <span className="text-[9px] text-slate-500 font-mono">SEC-WORKSTATION</span>
              </div>
            </div>
          )}
          {sidebarCollapsed && (
            <Shield className="w-5 h-5 text-blue-500 mx-auto" />
          )}
          <button
            onClick={toggleSidebar}
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200"
            title={sidebarCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {sidebarCollapsed ? <Menu className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Sidebar Navigation Links */}
        <div className="flex-1 overflow-y-auto py-3 px-2 space-y-4 font-mono text-xs">
          {NAV_SECTIONS.map((sec) => (
            <div key={sec.heading}>
              {!sidebarCollapsed && (
                <div className="px-3 pb-1 text-[10px] uppercase tracking-wider text-slate-500 font-bold">
                  {sec.heading}
                </div>
              )}
              <div className="space-y-0.5">
                {sec.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 px-3 py-2 rounded transition-colors ${
                          isActive
                            ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 font-semibold'
                            : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                        } ${sidebarCollapsed ? 'justify-center px-0' : ''}`
                      }
                      title={sidebarCollapsed ? item.label : undefined}
                    >
                      <Icon className="w-4 h-4 shrink-0" />
                      {!sidebarCollapsed && <span className="truncate">{item.label}</span>}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Sidebar Footer */}
        <div className="p-3 border-t border-slate-800 text-[10px] text-slate-500 font-mono flex items-center justify-between">
          {!sidebarCollapsed && <span>AMSC Core v1.0</span>}
          <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-emerald-400">
            P95 &lt; 50ms
          </span>
        </div>
      </aside>

      {/* 2. Main Workstation Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navigation Bar */}
        <header className="h-14 bg-[#111827] border-b border-slate-800 flex items-center justify-between px-5 z-20 shrink-0 font-mono">
          {/* Left: Tenant Switcher */}
          <div className="flex items-center gap-3">
            <div className="relative group">
              <button className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-xs text-slate-200 hover:border-slate-500 transition-colors">
                <span className="text-slate-500 text-[10px]">Workspace:</span>
                <span className="font-bold text-slate-100">{activeTenant.name}</span>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>

              {/* Tenant Dropdown */}
              <div className="absolute top-full left-0 mt-1 w-64 bg-slate-900 border border-slate-700 rounded shadow-2xl py-1 text-xs hidden group-hover:block z-50">
                {AVAILABLE_TENANTS.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setActiveTenant(t)}
                    className={`w-full text-left px-3 py-2 flex items-center justify-between hover:bg-slate-800 ${
                      activeTenant.id === t.id ? 'bg-slate-800/80 text-blue-400 font-bold' : 'text-slate-300'
                    }`}
                  >
                    <span>{t.name}</span>
                    <span className="text-[10px] px-1 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                      {t.badge}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Ctrl+K Search Trigger */}
            <button
              onClick={() => setCommandPaletteOpen(true)}
              className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-400 hover:text-slate-200 hover:border-slate-700 text-xs transition-colors"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Command Palette</span>
              <kbd className="px-1.5 py-0.5 bg-slate-950 rounded text-[10px] text-slate-500 border border-slate-800">
                Ctrl+K
              </kbd>
            </button>
          </div>

          {/* Right: Actions, Badges & SecOps Identity */}
          <div className="flex items-center gap-3">
            {/* Top-bar Simulate Attack Replay Button */}
            <button
              onClick={() => setAttackReplayOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1 bg-amber-950/60 hover:bg-amber-900/60 border border-amber-500/50 text-amber-300 rounded text-xs font-semibold transition-colors"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span className="hidden sm:inline">Simulate Attack Replay</span>
            </button>

            {/* DUAL-MODE API Status Badge */}
            <DualModeBadge />

            {/* Operator Persona */}
            <div className="hidden lg:flex items-center gap-2 pl-2 border-l border-slate-800 text-xs">
              <div className="w-6 h-6 rounded-full bg-blue-900 border border-blue-500 flex items-center justify-center font-bold text-[10px] text-blue-200">
                SA
              </div>
              <div className="flex flex-col text-[11px] leading-tight">
                <span className="text-slate-200 font-semibold">Sarah (SecOps)</span>
                <span className="text-[9px] text-emerald-400 font-mono">MEMBER_M5</span>
              </div>
            </div>
          </div>
        </header>

        {/* Main Viewport */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#0B0F19]">
          <Outlet />
        </main>
      </div>

      {/* Global Modals & Contextual Drawers */}
      <InspectorDrawer />
      <CommandPalette />
      <AttackReplayModal />
    </div>
  );
};
