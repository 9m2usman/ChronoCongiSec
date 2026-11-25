import React, { useState, useEffect, useRef } from 'react';
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useHealthCheck, useTenants } from '@/hooks';
import { apiClient } from '@/services/apiClient';
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
  ChevronRight,
  Search,
  Zap,
  Shield,
  Menu,
  ChevronLeft,
  LogOut,
  Sun,
  Moon,
} from 'lucide-react';

export const AppShell: React.FC = () => {
  useHealthCheck();
  const navigate = useNavigate();
  const location = useLocation();
  const { data: liveTenants } = useTenants();

  const [tenantMenuOpen, setTenantMenuOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const tenantMenuRef = useRef<HTMLDivElement>(null);

  const {
    activeTenant,
    setActiveTenant,
    availableTenants,
    setAvailableTenants,
    currentUser,
    sidebarCollapsed,
    toggleSidebar,
    setCommandPaletteOpen,
    setAttackReplayOpen,
    theme,
    toggleTheme,
  } = useWorkstationStore();

  useEffect(() => {
    if (Array.isArray(liveTenants) && liveTenants.length > 0) {
      const mapped = liveTenants.map((t) => ({
        id: t.id,
        name: t.name,
        slug: t.slug,
        badge: t.status || 'WORKSPACE',
      }));
      setAvailableTenants(mapped);
      const currentMatch = mapped.find((t) => t.id === activeTenant.id || t.slug === activeTenant.slug);
      if (currentMatch && (currentMatch.name !== activeTenant.name || currentMatch.badge !== activeTenant.badge)) {
        setActiveTenant(currentMatch);
      }
    }
  }, [liveTenants, setAvailableTenants, activeTenant.id, activeTenant.slug, activeTenant.name, activeTenant.badge, setActiveTenant]);

  useEffect(() => {
    setMobileNavOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileNavOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [mobileNavOpen]);

  useEffect(() => {
    if (!tenantMenuOpen) return;
    const handleClickOutside = (e: MouseEvent) => {
      if (tenantMenuRef.current && !tenantMenuRef.current.contains(e.target as Node)) {
        setTenantMenuOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setTenantMenuOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [tenantMenuOpen]);

  const handleLogout = async () => {
    try {
      await apiClient.logout();
    } finally {
      navigate('/login');
    }
  };

  const NAV_SECTIONS = [
    {
      heading: 'WORKSPACE',
      items: [
        { label: 'Overview', path: '/', icon: LayoutDashboard },
        { label: 'Enterprise Connect', path: '/enterprise', icon: Database },
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

  const ROUTE_ALIAS_MAP: Record<string, string> = {
    '/overview': '/',
    '/dual-trace': '/traces',
    '/graph': '/knowledge-graph',
  };
  const normalizedPath = ROUTE_ALIAS_MAP[location.pathname] || location.pathname;
  const activeBreadcrumb = (() => {
    for (const sec of NAV_SECTIONS) {
      const match = sec.items.find((item) => item.path === normalizedPath);
      if (match) return { section: sec.heading, page: match.label };
    }
    return { section: 'WORKSPACE', page: 'Overview' };
  })();

  return (
    <div className="flex h-screen w-screen bg-canvas text-ink overflow-hidden font-sans">
      {/* Mobile / Tablet Drawer Backdrop */}
      {mobileNavOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setMobileNavOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* 1. Global Left Sidebar (Slide-over drawer < lg, collapsible rail >= lg) */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-borderc bg-surface transition-all duration-200 w-60 ${
          mobileNavOpen ? 'translate-x-0' : '-translate-x-full'
        } lg:static lg:translate-x-0 lg:z-30 ${sidebarCollapsed ? 'lg:w-16' : 'lg:w-60'}`}
      >
        {/* Sidebar Brand Header */}
        <div className="flex items-center justify-between px-4 h-14 border-b border-borderc">
          {!sidebarCollapsed && (
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-brand shrink-0" />
              <div className="flex flex-col leading-tight">
                <span className="font-bold tracking-wider text-xs text-ink">ChronoCongiSec</span>
                <span className="text-[9px] text-ink-muted font-mono">AMSC WORKSTATION</span>
              </div>
            </div>
          )}
          {sidebarCollapsed && (
            <Shield className="w-5 h-5 text-brand mx-auto" />
          )}
          <button
            type="button"
            onClick={toggleSidebar}
            className="p-1 rounded hover:bg-elevated text-ink-muted hover:text-ink transition-colors focus:outline-none focus:ring-2 focus:ring-brand"
            aria-expanded={!sidebarCollapsed}
            aria-label={sidebarCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
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
                <div className="px-3 pb-1 text-[10px] uppercase tracking-wider text-ink-muted font-bold">
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
                            ? 'bg-brand-tint text-brand border border-brand/30 font-semibold'
                            : 'text-ink-muted hover:bg-elevated hover:text-ink'
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
        <div className="p-3 border-t border-borderc text-[10px] text-ink-muted font-mono flex items-center justify-between">
          {!sidebarCollapsed && <span>AMSC Core v1.0</span>}
          <span className="px-1.5 py-0.5 rounded bg-elevated border border-borderc text-status-trusted">
            P95 &lt; 50ms
          </span>
        </div>
      </aside>

      {/* 2. Main Workstation Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navigation Bar */}
        <header className="h-14 bg-surface border-b border-borderc flex items-center justify-between px-3 sm:px-5 gap-2 z-20 shrink-0 font-mono min-w-0">
          {/* Left: Mobile/Tablet Drawer Trigger + Tenant Switcher */}
          <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
            <button
              type="button"
              onClick={() => setMobileNavOpen((prev) => !prev)}
              aria-label={mobileNavOpen ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={mobileNavOpen}
              className="lg:hidden p-1.5 rounded bg-elevated border border-borderc text-ink-muted hover:text-ink transition-colors shrink-0"
            >
              <Menu className="w-4 h-4" />
            </button>

            <div className="relative min-w-0" ref={tenantMenuRef}>
              <button
                type="button"
                onClick={() => setTenantMenuOpen((prev) => !prev)}
                aria-haspopup="listbox"
                aria-expanded={tenantMenuOpen}
                className="flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-3 py-1.5 rounded bg-elevated border border-borderc text-xs text-ink hover:border-brand/50 transition-colors focus:outline-none focus:ring-2 focus:ring-brand min-w-0 max-w-full"
              >
                <span className="text-ink-muted text-[10px] hidden sm:inline shrink-0">Workspace:</span>
                <span className="font-bold text-ink truncate max-w-[110px] sm:max-w-[150px] lg:max-w-[140px] xl:max-w-[200px]">
                  {activeTenant.name}
                </span>
                <ChevronDown className={`w-3.5 h-3.5 text-ink-muted shrink-0 transition-transform ${tenantMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* Tenant Dropdown */}
              {tenantMenuOpen && (
                <div
                  role="listbox"
                  aria-label="Select Workspace"
                  className="absolute top-full left-0 mt-1 w-64 bg-surface border border-borderc rounded shadow-2xl py-1 text-xs z-50"
                >
                  {availableTenants.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      role="option"
                      aria-selected={activeTenant.id === t.id}
                      onClick={() => {
                        setActiveTenant(t);
                        setTenantMenuOpen(false);
                      }}
                      className={`w-full text-left px-3 py-2 flex items-center justify-between hover:bg-elevated transition-colors ${
                        activeTenant.id === t.id ? 'bg-brand-tint text-brand font-bold' : 'text-ink'
                      }`}
                    >
                      <span>{t.name}</span>
                      <span className="text-[10px] px-1 py-0.5 rounded bg-canvas border border-borderc text-ink-muted">
                        {t.badge || 'WORKSPACE'}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Ctrl+K Search Trigger */}
            <button
              onClick={() => setCommandPaletteOpen(true)}
              className="hidden md:flex items-center gap-2 px-2.5 py-1.5 bg-elevated border border-borderc rounded text-ink-muted hover:text-ink hover:border-brand/40 text-xs transition-colors shrink-0 whitespace-nowrap"
            >
              <Search className="w-3.5 h-3.5 shrink-0" />
              <span className="hidden 2xl:inline">Command Palette</span>
              <span className="2xl:hidden">Search</span>
              <kbd className="px-1.5 py-0.5 bg-canvas rounded text-[10px] text-ink-muted border border-borderc">
                Ctrl+K
              </kbd>
            </button>
          </div>

          {/* Right: Actions, Badges, Theme Switcher & SecOps Identity */}
          <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
            {/* Top-bar Simulate Attack Replay Button */}
            <button
              onClick={() => setAttackReplayOpen(true)}
              title="Simulate Attack Replay"
              className="flex items-center gap-1.5 px-2 sm:px-3 py-1 bg-status-warningBg hover:opacity-90 border border-status-warning/40 text-status-warning rounded text-xs font-semibold transition-opacity shrink-0"
            >
              <Zap className="w-3.5 h-3.5 shrink-0" />
              <span className="hidden xl:inline whitespace-nowrap">Simulate Attack Replay</span>
            </button>

            {/* DUAL-MODE API Status Badge */}
            <div className="hidden sm:flex shrink-0">
              <DualModeBadge />
            </div>

            {/* Theme Switcher */}
            <button
              type="button"
              onClick={toggleTheme}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-elevated hover:bg-brand-tint text-ink-muted hover:text-ink border border-borderc text-xs transition-colors"
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            >
              {theme === 'dark' ? (
                <Sun className="w-3.5 h-3.5 text-status-warning" />
              ) : (
                <Moon className="w-3.5 h-3.5 text-brand" />
              )}
              <span className="hidden xl:inline">{theme === 'dark' ? 'Light' : 'Dark'}</span>
            </button>

            {/* Operator Persona */}
            <div className="hidden lg:flex items-center gap-2 pl-2 border-l border-borderc text-xs">
              <div className="w-6 h-6 rounded-full bg-brand-tint border border-brand/50 flex items-center justify-center font-bold text-[10px] text-brand">
                {currentUser?.full_name ? currentUser.full_name.substring(0, 2).toUpperCase() : 'SA'}
              </div>
              <div className="flex flex-col text-[11px] leading-tight">
                <span className="text-ink font-semibold">{currentUser?.full_name || 'Sarah (SecOps)'}</span>
                <span className="text-[9px] text-status-trusted font-mono">{currentUser?.role || 'MEMBER_M5'}</span>
              </div>
              {currentUser?.branch_id && (
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-brand-tealTint border border-brand-teal/40 text-brand-teal font-mono">
                  {currentUser.branch_id.replace('branch-', '').toUpperCase()}
                </span>
              )}
            </div>

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-elevated hover:bg-brand-tint text-ink-muted hover:text-ink border border-borderc text-xs transition-colors"
              title="Logout from AMSC Workstation"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Logout</span>
            </button>
          </div>
        </header>

        {/* Main Viewport */}
        <main className="flex-1 overflow-y-auto p-3 sm:p-6 bg-canvas min-w-0">
          {/* DOC-004 Workstation Breadcrumb Trail */}
          <nav aria-label="Breadcrumb" className="mb-4 flex items-center gap-1.5 text-[11px] font-mono text-ink-muted">
            <span>Workspace</span>
            <ChevronRight className="w-3 h-3" />
            <span className="uppercase tracking-wider">{activeBreadcrumb.section}</span>
            <ChevronRight className="w-3 h-3" />
            <span className="text-ink font-semibold">{activeBreadcrumb.page}</span>
          </nav>
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
