import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useAgents, useMemories } from '@/hooks';
import { StateBanner } from '@/components/common/StateBanner';
import { StatusBadge } from '@/components/common/StatusBadge';
import { Agent } from '@/types';
import {
  Bot,
  ArrowUpRight,
  Search,
  SlidersHorizontal,
} from 'lucide-react';

export const AgentRegistryPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: agents, isLoading, error } = useAgents();
  const { data: memories } = useMemories();

  const [searchQuery, setSearchQuery] = useState('');
  const [tierFilter, setTierFilter] = useState<'ALL' | 'RESTRICTED' | 'STANDARD' | 'ELEVATED'>('ALL');

  // Safely extract agent array whether returned as array or paginated envelope { items: [...] }
  const agentList: Agent[] = React.useMemo(() => {
    if (!agents) return [];
    if (Array.isArray(agents)) return agents;
    if (Array.isArray((agents as any)?.items)) return (agents as any).items;
    return [];
  }, [agents]);

  // Filtered agents
  const filteredAgents = React.useMemo(() => {
    return agentList.filter((agent) => {
      const matchesTier = tierFilter === 'ALL' || agent.trust_tier === tierFilter;
      const q = searchQuery.toLowerCase();
      const agentTools = Array.isArray(agent.tools) ? agent.tools : [];
      const matchesSearch =
        !searchQuery ||
        (agent.name && agent.name.toLowerCase().includes(q)) ||
        (agent.id && agent.id.toLowerCase().includes(q)) ||
        (agent.model && agent.model.toLowerCase().includes(q)) ||
        agentTools.some((t: string) => typeof t === 'string' && t.toLowerCase().includes(q));
      return matchesTier && matchesSearch;
    });
  }, [agentList, tierFilter, searchQuery]);

  // Compute active memory count per agent
  const getAgentMemoryCount = (agentId: string) => {
    if (!memories || !Array.isArray(memories)) return 0;
    return memories.filter((m) => m.agent_id === agentId).length;
  };

  return (
    <div className="space-y-6 font-mono text-ink">
      {/* Title & Description */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-borderc gap-3">
        <div>
          <h1 className="text-xl font-bold text-ink flex items-center gap-2">
            <Bot className="w-5 h-5 text-brand" />
            Agent Registry & Entitlement Matrix
          </h1>
          <p className="text-xs text-ink-muted mt-0.5">
            Identity-to-tool entitlement verification, trust boundaries, and scoped credentials for{' '}
            <span className="text-brand font-bold">{activeTenant.name}</span>
          </p>
        </div>

        {/* Search Bar */}
        <div className="flex items-center px-3 py-1.5 bg-surface border border-borderc rounded text-xs text-ink">
          <Search className="w-3.5 h-3.5 text-ink-muted mr-2 shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search agents, models, or tools..."
            className="bg-transparent focus:outline-none placeholder-ink-muted w-56 text-xs font-mono text-ink"
          />
        </div>
      </div>

      {/* Trust Tier Filter Tabs & Stats Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-surface border border-borderc rounded-lg">
        <div className="flex items-center gap-1.5">
          <SlidersHorizontal className="w-4 h-4 text-ink-muted mr-1" />
          <span className="text-[11px] text-ink-muted font-bold uppercase tracking-wider mr-2">Trust Tier:</span>
          {(['ALL', 'RESTRICTED', 'STANDARD', 'ELEVATED'] as const).map((tier) => (
            <button
              key={tier}
              onClick={() => setTierFilter(tier)}
              className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                tierFilter === tier
                  ? 'bg-brand text-white shadow-sm'
                  : 'text-ink-muted hover:text-ink hover:bg-elevated'
              }`}
            >
              {tier}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3 text-xs text-ink-muted">
          <span>
            Total Identities: <strong className="text-ink">{agentList.length}</strong>
          </span>
          <span>•</span>
          <span>
            Active in RAG: <strong className="text-status-trusted">{filteredAgents.length}</strong>
          </span>
        </div>
      </div>

      {/* Entitlement Matrix Table */}
      <div className="bg-surface border border-borderc rounded-lg overflow-x-auto">
        {isLoading ? (
          <StateBanner type="loading" title="Loading Agent Entitlement Matrix..." message="Verifying runtime identity and tool access boundaries..." />
        ) : error ? (
          <StateBanner type="unavailable" title="Agent Registry Unavailable" message="Direct agent registry endpoint is unavailable on the API server. Loaded tenant fallback entitlements." />
        ) : filteredAgents.length === 0 ? (
          <StateBanner type="empty" title="No Registered Agents Found" message={`No agents registered in ${activeTenant.name} matching filter criteria.`} />
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-[10px] text-ink-muted uppercase tracking-wider border-b border-borderc bg-elevated">
              <tr>
                <th className="py-3 px-4">Agent Identity</th>
                <th className="py-3 px-4">Trust Tier</th>
                <th className="py-3 px-4">Branch / Framework</th>
                <th className="py-3 px-4">Active Memories</th>
                <th className="py-3 px-4">Allowed Tool Adapters</th>
                <th className="py-3 px-4">Policy Enforcement</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-borderc">
              {filteredAgents.map((agent) => {
                const memoryCount = getAgentMemoryCount(agent.id);
                const runtimeLabel = [
                  (agent as any).branch_id ? `branch:${(agent as any).branch_id}` : null,
                  (agent as any).framework || null,
                ]
                  .filter(Boolean)
                  .join(' • ');

                return (
                  <tr key={agent.id} className="hover:bg-elevated/60 transition-colors">
                    {/* Identity */}
                    <td className="py-3 px-4">
                      <div className="font-bold text-ink flex items-center gap-1.5">
                        <Bot className="w-3.5 h-3.5 text-brand" />
                        {agent.name}
                      </div>
                      <div className="text-[10px] text-ink-muted mt-0.5 font-mono">
                        {agent.id} • <span>{agent.model}</span>
                      </div>
                    </td>

                    {/* Trust Tier */}
                    <td className="py-3 px-4">
                      <StatusBadge status={agent.trust_tier || 'STANDARD'} />
                    </td>

                    {/* Branch / Framework */}
                    <td className="py-3 px-4">
                      <span className="font-mono text-[11px] text-ink-muted">
                        {runtimeLabel || 'Not returned by API'}
                      </span>
                    </td>

                    {/* Active Memories */}
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-canvas border border-borderc text-[11px] font-semibold text-brand-teal">
                        {memoryCount} records
                      </span>
                    </td>

                    {/* Allowed Tool Adapters */}
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1 max-w-[240px]">
                        {(agent.tools || []).length > 0 ? (
                          (agent.tools || []).map((t: string) => (
                            <span
                              key={t}
                              className="px-1.5 py-0.5 rounded bg-status-trustedBg border border-status-trusted/40 text-[10px] text-status-trusted font-mono"
                            >
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-[10px] text-ink-muted">None declared</span>
                        )}
                      </div>
                    </td>

                    {/* Policy Enforcement */}
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-canvas border border-borderc text-[10px] text-ink-muted font-mono">
                        Evaluated server-side
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      <StatusBadge status={agent.status || 'UNKNOWN'} />
                    </td>

                    {/* Inspect */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() =>
                          openInspector({
                            title: `Agent: ${agent.name}`,
                            type: 'AGENT',
                            id: agent.id,
                            details: {
                              ...agent,
                              memoryCount,
                            },
                          })
                        }
                        className="p-1 hover:text-brand text-ink-muted transition-colors"
                        title="Inspect Entitlement Policy in Drawer"
                      >
                        <ArrowUpRight className="w-4 h-4" />
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
  );
};
