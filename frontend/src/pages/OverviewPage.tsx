import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useGatewayDecisions, useSecurityAlerts, useAgents } from '@/hooks';
import { Bot, Shield, Database, Activity, AlertTriangle, ArrowUpRight, CheckCircle2, Loader2 } from 'lucide-react';

export const OverviewPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: decisions, isLoading: decisionsLoading } = useGatewayDecisions();
  const { data: alerts } = useSecurityAlerts();
  const { data: agents } = useAgents();

  const METRICS = [
    {
      label: 'Active Monitored Agents',
      value: agents ? String(agents.length) : '14',
      sub: '3 Standby / 11 Active',
      icon: Bot,
      color: 'text-blue-400',
    },
    {
      label: 'Evaluated Actions (24h)',
      value: '1,420',
      sub: '100% Gatekeeper Med.',
      icon: Activity,
      color: 'text-emerald-400',
    },
    {
      label: 'Blocked Proposals',
      value: alerts ? String(alerts.blocked_actions_24h) : '14',
      sub: 'Tainted Memory / Risk Violations',
      icon: Shield,
      color: 'text-red-400',
    },
    {
      label: 'Quarantined Chunks',
      value: alerts ? String(alerts.quarantined_records_count) : '3',
      sub: 'Cryptographically Isolated',
      icon: Database,
      color: 'text-amber-400',
    },
  ];

  return (
    <div className="space-y-6 font-mono">
      {/* Page Title & Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
            Overview Dashboard
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time memory security posture and gateway decision telemetry for{' '}
            <span className="text-blue-400 font-bold">{activeTenant.name}</span>
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
            Tenant: {activeTenant.badge}
          </span>
          <span className="px-2.5 py-1 rounded bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" /> Gateway: HEALTHY
          </span>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {METRICS.map((m) => {
          const Icon = m.icon;
          return (
            <div
              key={m.label}
              className="p-4 bg-slate-900 border border-slate-800 rounded-lg hover:border-slate-700 transition-colors"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">{m.label}</span>
                <Icon className={`w-4 h-4 ${m.color}`} />
              </div>
              <div className="text-2xl font-bold text-slate-100">{m.value}</div>
              <div className="text-[11px] text-slate-500 mt-1">{m.sub}</div>
            </div>
          );
        })}
      </div>

      {/* Dual Panel Layout: Gateway Activity & Security Incident Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gateway Stream (2 Cols) */}
        <div className="lg:col-span-2 p-4 bg-slate-900 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <div className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              Live Gateway Decision Activity Stream
            </div>
            <span className="text-[10px] text-slate-500">Auto-refreshing: 5s polling</span>
          </div>

          <div className="overflow-x-auto">
            {decisionsLoading ? (
              <div className="p-8 flex items-center justify-center text-slate-400 gap-2 text-xs">
                <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                Polling live gateway events...
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/40">
                  <tr>
                    <th className="py-2 px-3">Proposal ID</th>
                    <th className="py-2 px-3">Agent</th>
                    <th className="py-2 px-3">Tool Proposal</th>
                    <th className="py-2 px-3">Memory Trust</th>
                    <th className="py-2 px-3">Gate Outcome</th>
                    <th className="py-2 px-3">Created</th>
                    <th className="py-2 px-3 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {decisions?.map((row) => (
                    <tr key={row.action_id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-slate-300">{row.proposal_id}</td>
                      <td className="py-2.5 px-3 text-slate-300">{row.agent_name || 'Agent'}</td>
                      <td className="py-2.5 px-3 text-slate-400">{row.tool_name || 'execute_action'}</td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] border font-bold ${
                            row.memory_trust === 'TRUSTED'
                              ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                              : row.memory_trust === 'QUARANTINED'
                              ? 'bg-red-950/40 border-red-500/50 text-red-300'
                              : 'bg-amber-950/40 border-amber-500/50 text-amber-300'
                          }`}
                        >
                          {row.memory_trust}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            row.decision === 'ALLOW'
                              ? 'text-emerald-400'
                              : row.decision === 'BLOCK'
                              ? 'text-red-400 font-extrabold'
                              : 'text-amber-400'
                          }`}
                        >
                          {row.decision}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-500">Just now</td>
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
                          className="p-1 hover:text-blue-400 text-slate-400"
                          title="Open in Inspector Drawer"
                        >
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Security Alert Feed & Quarantine Health (1 Col) */}
        <div className="space-y-4">
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
              <div className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Active Threat Incidents
              </div>
              <span className="px-1.5 py-0.5 text-[10px] bg-red-950 border border-red-800 text-red-300 rounded font-bold">
                1 CRITICAL
              </span>
            </div>

            <div className="p-3 bg-red-950/20 border border-red-900/40 rounded-lg mb-3">
              <div className="flex items-center justify-between text-xs font-bold text-red-300 mb-1">
                <span>INC-2026-0812</span>
                <span className="text-[10px] text-red-400">High Blast Radius</span>
              </div>
              <p className="text-[11px] text-slate-300 mb-2">
                Memory Poisoning attempt detected on vendor invoice processing. 1 agent intercepted from executing
                unauthorized wire.
              </p>
              <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
                <span>Target: FinOps-01</span>
                <button
                  onClick={() =>
                    openInspector({
                      title: 'Incident INC-2026-0812',
                      type: 'INCIDENT',
                      id: 'INC-2026-0812',
                      trustState: 'QUARANTINED',
                      details: {
                        threat: 'Prompt Injection / Memory Tampering',
                        affectedChunk: 'rec-8812-441a',
                        interception: 'Wire transfer blocked at Gateway',
                      },
                    })
                  }
                  className="text-blue-400 hover:underline"
                >
                  Inspect Evidence →
                </button>
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded border border-slate-800 text-xs">
              <div className="text-[11px] text-slate-400 mb-1 font-semibold">Gateway Defense Posture:</div>
              <div className="flex items-center gap-2 text-emerald-400 text-[11px]">
                <CheckCircle2 className="w-3.5 h-3.5" /> Fail-Closed Rule Enforced
              </div>
              <div className="flex items-center gap-2 text-emerald-400 text-[11px] mt-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Quarantined Memories Excluded from RAG
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
