import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useAgents } from '@/hooks';
import { Bot, ArrowUpRight, Search, Loader2 } from 'lucide-react';

export const AgentRegistryPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: agents, isLoading } = useAgents();

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Bot className="w-5 h-5 text-blue-400" />
            Agent Registry & Permissions
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Registered autonomous agents, trust tier assignments, and server-side tool permissions for {activeTenant.name}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center px-3 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-300">
            <Search className="w-3.5 h-3.5 text-slate-400 mr-2" />
            <input
              type="text"
              placeholder="Filter agents by name or ID..."
              className="bg-transparent focus:outline-none placeholder-slate-500 w-48 text-xs"
            />
          </div>
        </div>
      </div>

      {/* Agents Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 flex items-center justify-center text-slate-400 gap-2 text-xs">
            <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
            Loading registered agents for tenant...
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/40">
              <tr>
                <th className="py-2.5 px-4">Agent Name / ID</th>
                <th className="py-2.5 px-4">Base LLM</th>
                <th className="py-2.5 px-4">Trust Tier</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Assigned Protected Tools</th>
                <th className="py-2.5 px-4">Heartbeat</th>
                <th className="py-2.5 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {agents?.map((agent) => (
                <tr key={agent.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-bold text-slate-200">{agent.name}</div>
                    <div className="text-[10px] text-slate-500">{agent.id}</div>
                  </td>
                  <td className="py-3 px-4 text-slate-300">{agent.model}</td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        agent.trust_tier === 'ELEVATED'
                          ? 'bg-purple-950/40 border-purple-500/50 text-purple-300'
                          : agent.trust_tier === 'STANDARD'
                          ? 'bg-blue-950/40 border-blue-500/50 text-blue-300'
                          : 'bg-amber-950/40 border-amber-500/50 text-amber-300'
                      }`}
                    >
                      {agent.trust_tier}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        agent.status === 'ACTIVE'
                          ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {agent.status}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {agent.tools.map((t) => (
                        <span
                          key={t}
                          className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-400"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4 text-slate-500">{agent.last_heartbeat || 'Active'}</td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() =>
                        openInspector({
                          title: agent.name,
                          type: 'AGENT',
                          id: agent.id,
                          details: agent,
                        })
                      }
                      className="p-1 hover:text-blue-400 text-slate-400"
                      title="Inspect Agent Configuration"
                    >
                      <ArrowUpRight className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
