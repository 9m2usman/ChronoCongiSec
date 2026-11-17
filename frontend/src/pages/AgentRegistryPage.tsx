import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useAgents, useMemories } from '@/hooks';
import {
  Bot,
  ArrowUpRight,
  Search,
  Loader2,
  Key,
  Check,
  Copy,
  SlidersHorizontal,
} from 'lucide-react';

export const AgentRegistryPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: agents, isLoading } = useAgents();
  const { data: memories } = useMemories();

  const [searchQuery, setSearchQuery] = useState('');
  const [tierFilter, setTierFilter] = useState<'ALL' | 'RESTRICTED' | 'STANDARD' | 'ELEVATED'>('ALL');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Filtered agents
  const filteredAgents = React.useMemo(() => {
    if (!agents) return [];
    return agents.filter((agent) => {
      const matchesTier = tierFilter === 'ALL' || agent.trust_tier === tierFilter;
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !searchQuery ||
        agent.name.toLowerCase().includes(q) ||
        agent.id.toLowerCase().includes(q) ||
        agent.model.toLowerCase().includes(q) ||
        agent.tools.some((t) => t.toLowerCase().includes(q));
      return matchesTier && matchesSearch;
    });
  }, [agents, tierFilter, searchQuery]);

  // Compute active memory count per agent
  const getAgentMemoryCount = (agentId: string) => {
    if (!memories) return 2;
    return memories.filter((m) => m.agent_id === agentId).length || 1;
  };

  // Blocked tools by trust tier (fail-closed security architecture)
  const getBlockedToolsForTier = (tier: string) => {
    if (tier === 'RESTRICTED') {
      return ['shell_exec (FAIL_CLOSED)', 'direct_db_write (BLOCKED)', 'export_raw_pii (BLOCKED)'];
    }
    if (tier === 'STANDARD') {
      return ['shell_exec (FAIL_CLOSED)', 'override_policy (BLOCKED)'];
    }
    return ['destructive_drop (FAIL_CLOSED)'];
  };

  return (
    <div className="space-y-6 font-mono text-slate-100">
      {/* Title & Description */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Bot className="w-5 h-5 text-blue-400" />
            Agent Registry & Entitlement Matrix
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Reco AI-style identity-to-tool entitlement verification, trust boundaries, and scoped credentials for{' '}
            <span className="text-blue-400 font-bold">{activeTenant.name}</span>
          </p>
        </div>

        {/* Search Bar */}
        <div className="flex items-center px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-slate-300">
          <Search className="w-3.5 h-3.5 text-slate-400 mr-2 shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search agents, models, or tools..."
            className="bg-transparent focus:outline-none placeholder-slate-500 w-56 text-xs font-mono"
          />
        </div>
      </div>

      {/* Reco AI-Style Trust Tier Filter Tabs & Stats Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="flex items-center gap-1.5">
          <SlidersHorizontal className="w-4 h-4 text-slate-400 mr-1" />
          <span className="text-[11px] text-slate-400 font-bold uppercase tracking-wider mr-2">Trust Tier:</span>
          {(['ALL', 'RESTRICTED', 'STANDARD', 'ELEVATED'] as const).map((tier) => (
            <button
              key={tier}
              onClick={() => setTierFilter(tier)}
              className={`px-3 py-1 rounded text-xs font-semibold transition-all ${
                tierFilter === tier
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {tier}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span>
            Total Identities: <strong className="text-slate-200">{agents?.length || 0}</strong>
          </span>
          <span>•</span>
          <span>
            Active in RAG: <strong className="text-emerald-400">{filteredAgents.length}</strong>
          </span>
        </div>
      </div>

      {/* Entitlement Matrix Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 flex items-center justify-center text-slate-400 gap-2 text-xs">
            <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
            Loading agent entitlement matrix...
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/50">
              <tr>
                <th className="py-3 px-4">Agent Identity</th>
                <th className="py-3 px-4">Trust Tier</th>
                <th className="py-3 px-4">Scoped API Key Prefix</th>
                <th className="py-3 px-4">Active Memories</th>
                <th className="py-3 px-4">Allowed Tool Adapters</th>
                <th className="py-3 px-4">Fail-Closed Blocked Tools</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAgents.map((agent) => {
                const keyPrefix = `amsc_agt_${agent.id.replace('agt-', '')}_${activeTenant.slug}`;
                const blockedTools = getBlockedToolsForTier(agent.trust_tier);
                const memoryCount = getAgentMemoryCount(agent.id);

                return (
                  <tr key={agent.id} className="hover:bg-slate-800/40 transition-colors">
                    {/* Identity */}
                    <td className="py-3 px-4">
                      <div className="font-bold text-slate-100 flex items-center gap-1.5">
                        <Bot className="w-3.5 h-3.5 text-blue-400" />
                        {agent.name}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5 font-mono">
                        {agent.id} • <span className="text-slate-400">{agent.model}</span>
                      </div>
                    </td>

                    {/* Trust Tier */}
                    <td className="py-3 px-4">
                      <span
                        className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${
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

                    {/* Scoped API Key */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-300">
                        <Key className="w-3 h-3 text-slate-500 shrink-0" />
                        <span className="truncate max-w-[120px]" title={keyPrefix}>
                          {keyPrefix}
                        </span>
                        <button
                          onClick={() => handleCopy(keyPrefix, agent.id)}
                          className="p-1 hover:text-blue-400 text-slate-500 transition-colors"
                          title="Copy Key Prefix"
                        >
                          {copiedKey === agent.id ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>

                    {/* Active Memories */}
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[11px] font-semibold text-cyan-300">
                        {memoryCount} records
                      </span>
                    </td>

                    {/* Allowed Tool Adapters */}
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1 max-w-[240px]">
                        {agent.tools.map((t) => (
                          <span
                            key={t}
                            className="px-1.5 py-0.5 rounded bg-emerald-950/30 border border-emerald-500/40 text-[10px] text-emerald-300 font-mono"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Fail-Closed Blocked Tools */}
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1 max-w-[220px]">
                        {blockedTools.map((b) => (
                          <span
                            key={b}
                            className="px-1.5 py-0.5 rounded bg-red-950/30 border border-red-500/40 text-[10px] text-red-300 font-mono"
                          >
                            {b}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            agent.status === 'ACTIVE' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
                          }`}
                        />
                        <span className="text-[11px] font-semibold text-slate-300">{agent.status}</span>
                      </div>
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
                              keyPrefix,
                              memoryCount,
                              blockedTools,
                            },
                          })
                        }
                        className="p-1 hover:text-blue-400 text-slate-400 transition-colors"
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
