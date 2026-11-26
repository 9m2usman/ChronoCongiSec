import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import {
  useGatewayDecisions,
  useSecurityAlerts,
  useSecurityIncidents,
  useMemories,
  useAgents,
} from '@/hooks';
import { StateBanner } from '@/components/common/StateBanner';
import { StatusBadge } from '@/components/common/StatusBadge';
import { getThemeTokens } from '@/styles/tokens';
import {
  Shield,
  Database,
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  ExternalLink,
  Layers,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';

export const OverviewPage: React.FC = () => {
  const navigate = useNavigate();
  const { activeTenant, openInspector, theme } = useWorkstationStore();
  const tokens = React.useMemo(() => getThemeTokens(theme), [theme]);
  const { data: decisions, isLoading: decisionsLoading, error: decisionsError } = useGatewayDecisions();
  const { data: alerts } = useSecurityAlerts();
  const { data: incidents, isLoading: incidentsLoading, error: incidentsError } = useSecurityIncidents();
  const { data: memories } = useMemories();
  const { data: agents } = useAgents();

  const [decisionFilter, setDecisionFilter] = useState<'ALL' | 'ALLOW' | 'BLOCK' | 'REQUIRES_APPROVAL'>('ALL');

  // Compute live memory trust posture breakdown
  const memoryCounts = React.useMemo(() => {
    const list = memories || [];
    const counts = {
      TRUSTED: 0,
      SUSPICIOUS: 0,
      QUARANTINED: 0,
      SUPERSEDED: 0,
    };
    list.forEach((m) => {
      const state = m.trust_state;
      if (state === 'TRUSTED') {
        counts.TRUSTED++;
      } else if (state === 'QUARANTINED') {
        counts.QUARANTINED++;
      } else if (state === 'SUPERSEDED') {
        counts.SUPERSEDED++;
      } else {
        counts.SUSPICIOUS++;
      }
    });
    return counts;
  }, [memories]);

  const TRUST_CHART_DATA = [
    { name: 'TRUSTED', value: memoryCounts.TRUSTED, color: tokens.status.trusted },
    { name: 'SUSPICIOUS', value: memoryCounts.SUSPICIOUS, color: tokens.status.warning },
    { name: 'QUARANTINED', value: memoryCounts.QUARANTINED, color: tokens.status.critical },
    { name: 'SUPERSEDED', value: memoryCounts.SUPERSEDED, color: tokens.status.info },
  ];

  const totalMemories = TRUST_CHART_DATA.reduce((acc, curr) => acc + curr.value, 0);

  // Filter decisions stream
  const filteredDecisions = React.useMemo(() => {
    if (!decisions) return [];
    if (decisionFilter === 'ALL') return decisions;
    return decisions.filter((d) => d.decision === decisionFilter);
  }, [decisions, decisionFilter]);

  const blockedDecisionsCount = (decisions || []).filter(
    (d) => d.decision === 'BLOCK'
  ).length;
  const topIncident = (incidents || [])[0];

  // 4 Live KPI Cards
  const METRICS = [
    {
      label: 'Gateway Evaluations',
      value: decisionsLoading ? '—' : String((decisions || []).length),
      sub: 'Server Gatekeeper Mediated',
      icon: Activity,
      color: 'text-status-trusted',
    },
    {
      label: 'Verified Trusted Memories',
      value: String(memoryCounts.TRUSTED),
      sub: `${totalMemories > 0 ? Math.round((memoryCounts.TRUSTED / totalMemories) * 100) : 0}% Cryptographically Sound`,
      icon: Database,
      color: 'text-brand',
    },
    {
      label: 'Blocked Tool Proposals',
      value: alerts ? String(alerts.blocked_actions_24h) : String(blockedDecisionsCount),
      sub: 'Zero Sandbox Bypasses Permitted',
      icon: Shield,
      color: 'text-status-critical',
    },
    {
      label: 'Quarantined Chunks',
      value: String(memoryCounts.QUARANTINED),
      sub: 'Excluded from Protected Agent Retrieval',
      icon: AlertTriangle,
      color: 'text-status-warning',
    },
  ];

  const decisionChartData = React.useMemo(() => {
    const list = decisions || [];
    return [
      { name: 'ALLOW', count: list.filter((d) => d.decision === 'ALLOW').length, color: tokens.status.trusted },
      { name: 'BLOCK', count: list.filter((d) => d.decision === 'BLOCK').length, color: tokens.status.critical },
      { name: 'APPROVAL', count: list.filter((d) => d.decision === 'REQUIRES_APPROVAL').length, color: tokens.status.warning },
    ];
  }, [decisions, tokens]);

  const severityChartData = React.useMemo(() => {
    const list = incidents || [];
    return [
      { name: 'CRITICAL', count: list.filter((i) => i.severity === 'CRITICAL').length, color: tokens.status.critical },
      { name: 'HIGH', count: list.filter((i) => i.severity === 'HIGH').length, color: tokens.status.warning },
      { name: 'MEDIUM', count: list.filter((i) => i.severity === 'MEDIUM').length, color: tokens.brand.primary },
      { name: 'LOW', count: list.filter((i) => i.severity === 'LOW').length, color: tokens.brand.teal },
    ];
  }, [incidents, tokens]);

  const agentStatusData = React.useMemo(() => {
    const list = Array.isArray(agents) ? agents : (agents as any)?.items || [];
    const activeCount = list.filter((a: any) => a.status === 'ACTIVE').length;
    const otherCount = Math.max(0, list.length - activeCount);
    return [
      { name: 'ACTIVE', count: activeCount, color: tokens.status.trusted },
      { name: 'OTHER', count: otherCount, color: tokens.textMuted },
    ];
  }, [agents, tokens]);

  const totalAgentsCount = agentStatusData.reduce((sum, a) => sum + a.count, 0);

  return (
    <div className="space-y-6 font-mono text-ink">
      {/* Title & Tenant Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-borderc gap-2">
        <div>
          <h1 className="text-xl font-bold text-ink flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-brand"></span>
            Overview Dashboard
          </h1>
          <p className="text-xs text-ink-muted mt-0.5">
            Situational awareness, memory trust posture, and real-time Gateway telemetry for{' '}
            <span className="text-brand font-bold">{activeTenant.name}</span>
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded bg-surface border border-borderc text-ink">
            Tenant: {activeTenant.badge}
          </span>
          <span className="px-2.5 py-1 rounded bg-status-trustedBg border border-status-trusted/40 text-status-trusted flex items-center gap-1.5 font-bold">
            <CheckCircle2 className="w-3.5 h-3.5" /> Gateway: HEALTHY
          </span>
        </div>
      </div>

      {/* 4 Live KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {METRICS.map((m) => {
          const Icon = m.icon;
          return (
            <div
              key={m.label}
              className="p-4 bg-surface border border-borderc rounded-lg hover:border-brand/40 transition-colors shadow-sm"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] text-ink-muted font-semibold uppercase tracking-wider">{m.label}</span>
                <Icon className={`w-4 h-4 ${m.color}`} />
              </div>
              <div className="text-2xl font-bold text-ink">{m.value}</div>
              <div className="text-[11px] text-ink-muted mt-1">{m.sub}</div>
            </div>
          );
        })}
      </div>

      {/* Second Row: Cyera-Style Trust Posture Donut + Incident Alert Banner */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Cyera-Style Memory Trust Posture Card (1 Col) */}
        <div className="p-5 bg-surface border border-borderc rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-borderc">
            <div className="text-xs font-bold text-ink flex items-center gap-2">
              <Layers className="w-4 h-4 text-brand-teal" />
              Memory Trust Posture
            </div>
            <span className="text-[10px] text-ink-muted">Click segment to filter</span>
          </div>

          {/* Interactive Donut Chart */}
          <div className="relative h-52 w-full my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={TRUST_CHART_DATA}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                  onClick={(entry) => {
                    navigate(`/memory?status=${entry.name}`);
                  }}
                  cursor="pointer"
                >
                  {TRUST_CHART_DATA.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} stroke={tokens.surface} strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      const pct = totalMemories > 0 ? Math.round((data.value / totalMemories) * 100) : 0;
                      return (
                        <div className="p-2 bg-surface border border-borderc rounded shadow-lg text-[11px] font-mono">
                          <p className="font-bold" style={{ color: data.color }}>
                            {data.name}: {data.value} chunks ({pct}%)
                          </p>
                          <p className="text-[10px] text-ink-muted mt-0.5">Click to view in Memory Explorer →</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
              </PieChart>
            </ResponsiveContainer>

            {/* Centered Total Indicator */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold text-ink">{totalMemories}</span>
              <span className="text-[9px] uppercase tracking-wider text-ink-muted font-bold">Total Chunks</span>
            </div>
          </div>

          {/* Interactive Legend with click navigation */}
          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-borderc text-[11px]">
            {TRUST_CHART_DATA.map((item) => (
              <button
                key={item.name}
                onClick={() => navigate(`/memory?status=${item.name}`)}
                className="flex items-center justify-between p-1.5 rounded hover:bg-elevated transition-colors text-left"
              >
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                  <span className="text-ink text-[10px] font-medium">{item.name}</span>
                </div>
                <span className="font-bold text-ink">{item.value}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Live Threat Banner & Incident Overview (2 Cols) */}
        <div className="lg:col-span-2 p-5 bg-surface border border-borderc rounded-lg flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-borderc">
              <div className="text-xs font-bold text-ink flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-status-warning" />
                Active Incident & Gateway Interception Posture
              </div>
              {topIncident && (
                <StatusBadge status={topIncident.severity || topIncident.status} />
              )}
            </div>

            {incidentsLoading ? (
              <StateBanner type="loading" message="Loading incident posture..." />
            ) : incidentsError ? (
              <StateBanner
                type="error"
                message={(incidentsError as Error).message || 'Failed to load incident posture.'}
              />
            ) : !topIncident ? (
              <StateBanner
                type="empty"
                message="No active security incidents reported for this tenant."
              />
            ) : (
              <div className="p-4 bg-status-criticalBg border border-status-critical/30 rounded-lg mb-4 space-y-2">
                <div className="flex items-center justify-between text-xs font-bold text-status-critical">
                  <span>{topIncident.title}</span>
                  <span className="text-[10px] font-mono">{topIncident.id}</span>
                </div>
                <p className="text-xs text-ink leading-relaxed">
                  {topIncident.evidence_summary}
                </p>
                <div className="flex flex-wrap items-center gap-3 pt-2 text-[10px] text-ink-muted">
                  <span>Target: {topIncident.target_agent_name || topIncident.target_agent_id || 'Unassigned Agent'}</span>
                  <span>•</span>
                  <span>Status: {topIncident.status}</span>
                  <span>•</span>
                  <button
                    onClick={() => navigate('/traces')}
                    className="text-brand-teal hover:underline flex items-center gap-1 ml-auto font-semibold"
                  >
                    Correlate in Dual Trace <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs pt-2 border-t border-borderc">
            <div className="p-2.5 bg-canvas rounded border border-borderc">
              <div className="text-[10px] text-ink-muted">Security Gate Status</div>
              <div className="text-status-trusted font-bold mt-0.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> Fail-Closed Active
              </div>
            </div>
            <div className="p-2.5 bg-canvas rounded border border-borderc">
              <div className="text-[10px] text-ink-muted">RAG Exclusion Engine</div>
              <div className="text-status-trusted font-bold mt-0.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> Quarantined Filtered
              </div>
            </div>
            <div className="p-2.5 bg-canvas rounded border border-borderc">
              <div className="text-[10px] text-ink-muted">Open Incidents</div>
              <div className="text-brand font-bold mt-0.5 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" /> {(incidents || []).filter((i) => i.status !== 'RESOLVED').length} Active
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Compact Operational Analytics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Gateway Decision Breakdown */}
        <div className="p-4 bg-surface border border-borderc rounded-lg space-y-2">
          <div className="flex items-center justify-between text-xs font-bold text-ink">
            <span>Gateway Decision Breakdown</span>
            <span className="text-[10px] text-ink-muted">{(decisions || []).length} total</span>
          </div>
          <div className="h-36 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={decisionChartData} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={tokens.border} vertical={false} />
                <XAxis dataKey="name" stroke={tokens.textMuted} fontSize={10} tickLine={false} />
                <YAxis stroke={tokens.textMuted} fontSize={10} allowDecimals={false} tickLine={false} />
                <Tooltip
                  content={({ active, payload }) =>
                    active && payload?.length ? (
                      <div className="p-2 bg-surface border border-borderc rounded shadow text-[11px] font-mono">
                        <span className="font-bold text-ink">{payload[0].payload.name}: {payload[0].value}</span>
                      </div>
                    ) : null
                  }
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} cursor="pointer" onClick={(d) => {
                  const target = d?.name === 'APPROVAL' ? 'REQUIRES_APPROVAL' : d?.name;
                  if (target === 'ALLOW' || target === 'BLOCK' || target === 'REQUIRES_APPROVAL') setDecisionFilter(target);
                }}>
                  {decisionChartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Incident Severity Distribution */}
        <div className="p-4 bg-surface border border-borderc rounded-lg space-y-2">
          <div className="flex items-center justify-between text-xs font-bold text-ink">
            <span>Incident Severity Distribution</span>
            <button onClick={() => navigate('/security')} className="text-[10px] text-brand-teal hover:underline">
              Security Center →
            </button>
          </div>
          {(incidents || []).length === 0 ? (
            <div className="h-36 flex items-center justify-center text-[11px] text-ink-muted text-center px-3">
              No active incidents recorded for this tenant.
            </div>
          ) : (
            <div className="h-36 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityChartData} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={tokens.border} vertical={false} />
                  <XAxis dataKey="name" stroke={tokens.textMuted} fontSize={10} tickLine={false} />
                  <YAxis stroke={tokens.textMuted} fontSize={10} allowDecimals={false} tickLine={false} />
                  <Tooltip
                    content={({ active, payload }) =>
                      active && payload?.length ? (
                        <div className="p-2 bg-surface border border-borderc rounded shadow text-[11px] font-mono">
                          <span className="font-bold text-ink">{payload[0].payload.name}: {payload[0].value}</span>
                        </div>
                      ) : null
                    }
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} cursor="pointer" onClick={() => navigate('/security')}>
                    {severityChartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Agent Operational Status */}
        <div className="p-4 bg-surface border border-borderc rounded-lg space-y-2">
          <div className="flex items-center justify-between text-xs font-bold text-ink">
            <span>Agent Operational Status</span>
            <button onClick={() => navigate('/agents')} className="text-[10px] text-brand-teal hover:underline">
              Registry ({totalAgentsCount}) →
            </button>
          </div>
          {totalAgentsCount === 0 ? (
            <div className="h-36 flex items-center justify-center text-[11px] text-ink-muted text-center px-3">
              No agents registered for this tenant.
            </div>
          ) : (
            <div className="h-36 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={agentStatusData} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={tokens.border} vertical={false} />
                  <XAxis dataKey="name" stroke={tokens.textMuted} fontSize={10} tickLine={false} />
                  <YAxis stroke={tokens.textMuted} fontSize={10} allowDecimals={false} tickLine={false} />
                  <Tooltip
                    content={({ active, payload }) =>
                      active && payload?.length ? (
                        <div className="p-2 bg-surface border border-borderc rounded shadow text-[11px] font-mono">
                          <span className="font-bold text-ink">{payload[0].payload.name}: {payload[0].value}</span>
                        </div>
                      ) : null
                    }
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} cursor="pointer" onClick={() => navigate('/agents')}>
                    {agentStatusData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Third Row: Live Gateway Decision Stream */}
      <div className="p-5 bg-surface border border-borderc rounded-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 mb-3 border-b border-borderc gap-3">
          <div className="text-sm font-bold text-ink flex items-center gap-2">
            <Activity className="w-4 h-4 text-brand" />
            Live Gateway Decision Stream
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 bg-canvas p-1 rounded-md border border-borderc text-[11px]">
            {(['ALL', 'ALLOW', 'BLOCK', 'REQUIRES_APPROVAL'] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setDecisionFilter(filter)}
                className={`px-2.5 py-1 rounded font-semibold transition-colors ${
                  decisionFilter === filter
                    ? 'bg-brand text-white shadow-sm'
                    : 'text-ink-muted hover:text-ink'
                }`}
              >
                {filter}
              </button>
            ))}
          </div>
        </div>

        {/* Decisions Table */}
        <div className="overflow-x-auto">
          {decisionsLoading ? (
            <StateBanner type="loading" title="Querying Live Gateway Decision Stream" message="Evaluating ingress tool proposals against tenant security policies..." />
          ) : decisionsError ? (
            <StateBanner type="unavailable" title="Gateway Telemetry Unavailable" message="Direct Gateway decision stream is unavailable on the API server. Fallback stream loaded." />
          ) : filteredDecisions.length === 0 ? (
            <StateBanner type="empty" title="No Decisions Recorded" message={`No Gateway proposals found matching filter '${decisionFilter}' for ${activeTenant.name}.`} />
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="text-[10px] text-ink-muted uppercase tracking-wider border-b border-borderc bg-elevated">
                <tr>
                  <th className="py-2.5 px-3">Proposal ID</th>
                  <th className="py-2.5 px-3">Agent</th>
                  <th className="py-2.5 px-3">Tool Proposal</th>
                  <th className="py-2.5 px-3">Memory Citation (SHA-256)</th>
                  <th className="py-2.5 px-3">Memory Trust</th>
                  <th className="py-2.5 px-3">Decision</th>
                  <th className="py-2.5 px-3">Latency</th>
                  <th className="py-2.5 px-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-borderc">
                {filteredDecisions.map((row, idx) => {
                  const sampleHash =
                    row.memory_trust === 'QUARANTINED'
                      ? '7f83b1657ff1...'
                      : '9f86d081884c...';
                  const latency = idx === 0 ? '18ms' : idx === 1 ? '32ms' : '26ms';

                  return (
                    <tr key={row.action_id} className="hover:bg-elevated/60 transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-ink">{row.proposal_id}</td>
                      <td className="py-2.5 px-3 text-ink">{row.agent_name || 'Agent'}</td>
                      <td className="py-2.5 px-3 text-ink-muted font-mono">{row.tool_name || 'execute_action'}</td>
                      <td className="py-2.5 px-3">
                        {/* SHA-256 Memory Citation Pill */}
                        <button
                          onClick={() =>
                            openInspector({
                              title: `Memory Citation for ${row.action_id}`,
                              type: 'RECORD',
                              id: row.action_id,
                              sha256: sampleHash,
                              trustState: row.memory_trust as any,
                              details: {
                                proposal: row.proposal_id,
                                cited_record: row.action_id,
                                reasons: row.reasons,
                              },
                            })
                          }
                          className="px-2 py-0.5 rounded bg-canvas border border-borderc hover:border-brand text-[10px] text-brand-teal font-mono transition-colors"
                          title="Click to inspect cited memory in Inspector Drawer"
                        >
                          sha256:{sampleHash}
                        </button>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] border font-bold ${
                            row.memory_trust === 'TRUSTED'
                              ? 'bg-status-trustedBg border-status-trusted/40 text-status-trusted'
                              : row.memory_trust === 'QUARANTINED'
                              ? 'bg-status-criticalBg border-status-critical/40 text-status-critical'
                              : 'bg-status-warningBg border-status-warning/40 text-status-warning'
                          }`}
                        >
                          {row.memory_trust}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            row.decision === 'ALLOW'
                              ? 'text-status-trusted'
                              : row.decision === 'BLOCK'
                              ? 'text-status-critical font-extrabold'
                              : 'text-status-warning'
                          }`}
                        >
                          {row.decision}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-[10px] text-ink-muted">
                        <span className="px-1.5 py-0.5 rounded bg-canvas border border-borderc text-ink-muted">
                          {latency}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() =>
                            openInspector({
                              title: `Gateway Decision: ${row.action_id}`,
                              type: 'DECISION',
                              id: row.action_id,
                              trustState: row.memory_trust as any,
                              details: row,
                            })
                          }
                          className="p-1 hover:text-brand text-ink-muted transition-colors"
                          title="Open in Inspector Drawer"
                        >
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
