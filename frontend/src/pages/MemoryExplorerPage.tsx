import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useMemories, useIngestMemoryMutation, useBaselineRecords } from '@/hooks';
import { StateBanner } from '@/components/common/StateBanner';
import {
  Database,
  ArrowUpRight,
  Search,
  Loader2,
  Plus,
  X,
  CheckCircle2,
  Filter,
  FileText,
  AlertCircle,
  FileCheck,
  ShieldCheck,
} from 'lucide-react';

export const MemoryExplorerPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const { activeTenant, openInspector } = useWorkstationStore();
  const [activeTab, setActiveTab] = useState<'MEMORY' | 'BASELINE'>('MEMORY');
  const { data: memories, isLoading, error } = useMemories();
  const { data: baselineRecords, isLoading: isBaselineLoading } = useBaselineRecords();
  const ingestMutation = useIngestMemoryMutation();

  // Status Filter: URL query param sync
  const statusParam = (searchParams.get('status')?.toUpperCase() || 'ALL') as
    | 'ALL'
    | 'TRUSTED'
    | 'SUSPICIOUS'
    | 'QUARANTINED'
    | 'SUPERSEDED';

  const [statusFilter, setStatusFilter] = useState<string>(statusParam);
  const [searchQuery, setSearchQuery] = useState('');

  // Sync state with URL parameter if it changes
  useEffect(() => {
    if (statusParam && statusParam !== statusFilter) {
      setStatusFilter(statusParam);
    }
  }, [statusParam]);

  const handleFilterChange = (filter: string) => {
    setStatusFilter(filter);
    if (filter === 'ALL') {
      searchParams.delete('status');
      setSearchParams(searchParams);
    } else {
      setSearchParams({ status: filter });
    }
  };

  // Ingest Modal State
  const [ingestModalOpen, setIngestModalOpen] = useState(false);
  const [sourceId, setSourceId] = useState('src-accounting-policy-v2.pdf');
  const [customSourceId, setCustomSourceId] = useState('');
  const [agentId, setAgentId] = useState('agent-crew-finance-003');
  const [customAgentId, setCustomAgentId] = useState('');
  const [recordType, setRecordType] = useState('KNOWLEDGE');
  const [content, setContent] = useState('');
  const [ingestSuccessChecksum, setIngestSuccessChecksum] = useState<string | null>(null);

  const handleIngestSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    const finalSourceId = sourceId === 'custom' ? customSourceId.trim() : sourceId;
    const finalAgentId = agentId === 'custom' ? customAgentId.trim() : agentId;
    if (!finalSourceId || !finalAgentId) return;

    ingestMutation.mutate(
      {
        content,
        record_type: recordType,
        source_id: finalSourceId,
        agent_id: finalAgentId,
      },
      {
        onSuccess: (res) => {
          setIngestSuccessChecksum(res.checksum || 'sha256_e3b0c44298fc1c149afbf4c8996fb924');
          setContent('');
        },
      }
    );
  };

  // Filter memories
  const filteredMemories = React.useMemo(() => {
    if (!memories) return [];
    return memories.filter((mem) => {
      const matchesStatus =
        statusFilter === 'ALL' ||
        mem.trust_state === statusFilter ||
        (statusFilter === 'SUSPICIOUS' && mem.trust_state === 'UNVERIFIED');
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !searchQuery ||
        mem.id.toLowerCase().includes(q) ||
        (mem.source_id && mem.source_id.toLowerCase().includes(q)) ||
        (mem.checksum && mem.checksum.toLowerCase().includes(q)) ||
        (mem.content && mem.content.toLowerCase().includes(q));
      return matchesStatus && matchesSearch;
    });
  }, [memories, statusFilter, searchQuery]);

  return (
    <div className="space-y-6 font-mono text-slate-100">
      {/* Title & Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Database className="w-5 h-5 text-emerald-400" />
            Memory Explorer & Provenance Catalog
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic SHA-256 verification and trust status for ingested memory chunks in{' '}
            <span className="text-blue-400 font-bold">{activeTenant.name}</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Search Box */}
          <div className="flex items-center px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-slate-300">
            <Search className="w-3.5 h-3.5 text-slate-400 mr-2 shrink-0" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search ID, hash, or text..."
              className="bg-transparent focus:outline-none placeholder-slate-500 w-48 text-xs font-mono"
            />
          </div>

          {/* + Ingest Memory Record Button */}
          <button
            onClick={() => {
              setIngestSuccessChecksum(null);
              setIngestModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" /> Ingest Memory Record
          </button>
        </div>
      </div>

      {/* Category Tabs: Mutable Agent Memory vs Authoritative Enterprise Baseline */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('MEMORY')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold transition-colors ${
            activeTab === 'MEMORY'
              ? 'bg-slate-800 text-emerald-400 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          Mutable Agent Memory ({memories?.length || 0})
        </button>
        <button
          onClick={() => setActiveTab('BASELINE')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold transition-colors ${
            activeTab === 'BASELINE'
              ? 'bg-slate-800 text-blue-400 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCheck className="w-3.5 h-3.5" />
          Authoritative Enterprise Baseline ({baselineRecords?.length || 0})
        </button>
      </div>

      {activeTab === 'BASELINE' ? (
        <div className="space-y-4">
          <div className="p-3 bg-blue-950/30 border border-blue-500/30 rounded-lg flex items-center justify-between text-xs text-blue-300">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-blue-400 shrink-0" />
              <span>
                <strong>Independently Governed Enterprise Baseline:</strong> Authoritative enterprise policies, operational procedures, and approved knowledge. Governed via formal cryptographic lifecycle (Draft → Review → Approve → Activate). Agent memory writes cannot modify or supersede baseline records.
              </span>
            </div>
            <span className="px-2 py-0.5 rounded bg-blue-900/50 border border-blue-600 text-[10px] font-bold shrink-0">
              SHA-256 Digest Signed
            </span>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            {isBaselineLoading ? (
              <StateBanner type="loading" title="Loading Enterprise Baseline..." message="Fetching authoritative policies and cryptographic digests..." />
            ) : (!baselineRecords || baselineRecords.length === 0) ? (
              <StateBanner
                type="empty"
                title="No Baseline Records Found"
                message={`No baseline policies found for tenant ${activeTenant.name}.`}
              />
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/50">
                  <tr>
                    <th className="py-3 px-4">Policy / Baseline Record</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Branch Scope</th>
                    <th className="py-3 px-4">SHA-256 Digest</th>
                    <th className="py-3 px-4">Classification</th>
                    <th className="py-3 px-4 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {baselineRecords.map((rec) => (
                    <tr key={rec.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-bold text-slate-100 flex items-center gap-1.5">
                          <FileCheck className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                          {rec.title}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                          {rec.id} • {rec.source_type}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-950 border border-slate-800 text-cyan-300">
                          {rec.category}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            rec.lifecycle_status === 'ACTIVE'
                              ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                              : rec.lifecycle_status === 'APPROVED'
                              ? 'bg-blue-950/40 border-blue-500/50 text-blue-300'
                              : 'bg-amber-950/40 border-amber-500/50 text-amber-300'
                          }`}
                        >
                          {rec.lifecycle_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">{rec.current_version}</td>
                      <td className="py-3 px-4">
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-400 font-mono">
                          {rec.branch_id || 'ENTERPRISE_WIDE'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[10px] text-emerald-400 font-mono">
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 truncate block max-w-[130px]" title={rec.content_digest}>
                          {rec.content_digest}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-purple-950/40 border border-purple-500/40 text-purple-300 font-bold">
                          {rec.classification}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() =>
                            openInspector({
                              title: `Baseline: ${rec.title}`,
                              type: 'RECORD',
                              id: rec.id,
                              sha256: rec.content_digest,
                              trustState: rec.lifecycle_status === 'ACTIVE' ? 'TRUSTED' : 'UNVERIFIED',
                              details: {
                                ...rec,
                                governance_type: 'INDEPENDENT_ENTERPRISE_BASELINE',
                                immutability: 'CRYPTOGRAPHICALLY_SEALED',
                              },
                            })
                          }
                          className="p-1 hover:text-blue-400 text-slate-400 transition-colors"
                          title="Inspect Baseline Governance Record"
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
      ) : (
        <>
          {/* Filter Tabs Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="flex items-center gap-1.5">
              <Filter className="w-4 h-4 text-slate-400 mr-1" />
              <span className="text-[11px] text-slate-400 font-bold uppercase tracking-wider mr-2">Trust State:</span>
              {(['ALL', 'TRUSTED', 'SUSPICIOUS', 'QUARANTINED', 'SUPERSEDED'] as const).map((status) => (
                <button
                  key={status}
                  onClick={() => handleFilterChange(status)}
                  className={`px-3 py-1 rounded text-xs font-semibold transition-all ${
                    statusFilter === status
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>

            <div className="text-xs text-slate-400">
              Showing <strong className="text-slate-200">{filteredMemories.length}</strong> of{' '}
              <strong className="text-slate-200">{memories?.length || 0}</strong> chunks
            </div>
          </div>

          {/* Memory Data Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            {isLoading ? (
              <StateBanner type="loading" title="Querying Tenant Knowledge Chunks..." message="Fetching cryptographic checksums and trust assertions..." />
            ) : error ? (
              <StateBanner
                type="unauthorized"
                title="Knowledge Retrieval Restrained"
                statusCode={403}
                message="Quarantined records are isolated under SEC-004. Standard agent queries cannot retrieve them."
              />
            ) : filteredMemories.length === 0 ? (
              <StateBanner
                type="empty"
                title="No Knowledge Chunks Located"
                message={`No records in ${activeTenant.name} match status '${statusFilter}' and search '${searchQuery}'.`}
                actionText="+ Ingest First Record"
                onAction={() => setIngestModalOpen(true)}
              />
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/50">
                  <tr>
                    <th className="py-3 px-4">Chunk ID</th>
                    <th className="py-3 px-4">Source ID / Document</th>
                    <th className="py-3 px-4">SHA-256 Checksum</th>
                    <th className="py-3 px-4">Trust State</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Content Preview</th>
                    <th className="py-3 px-4 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredMemories.map((chunk) => (
                    <tr key={chunk.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-bold text-slate-200">{chunk.id}</td>
                      <td className="py-3 px-4 text-slate-300 font-mono flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                        <span className="truncate max-w-[160px]">{chunk.source_id || 'unassigned'}</span>
                      </td>
                      <td className="py-3 px-4 text-[10px] text-emerald-400 font-mono">
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 truncate block max-w-[140px]">
                          {chunk.checksum || 'pending_calculation'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            chunk.trust_state === 'TRUSTED'
                              ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                              : chunk.trust_state === 'QUARANTINED'
                              ? 'bg-red-950/40 border-red-500/50 text-red-300 font-extrabold'
                              : 'bg-amber-950/40 border-amber-500/50 text-amber-300'
                          }`}
                        >
                          {chunk.trust_state}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400">v{chunk.current_version}</td>
                      <td className="py-3 px-4 text-slate-300 max-w-[220px] truncate font-sans">
                        {chunk.content || 'Protected chunk content block'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() =>
                            openInspector({
                              title: `Memory Chunk: ${chunk.id}`,
                              type: 'RECORD',
                              id: chunk.id,
                              sha256: chunk.checksum || undefined,
                              trustState: chunk.trust_state as any,
                              details: chunk,
                            })
                          }
                          className="p-1 hover:text-blue-400 text-slate-400 transition-colors"
                          title="Inspect Chunk Provenance & Lineage"
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
        </>
      )}

      {/* + Ingest Memory Record Modal */}
      {ingestModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-700 rounded-lg shadow-2xl overflow-hidden text-slate-100 font-mono">
            {/* Modal Header */}
            <div className="flex items-center justify-between px-5 py-3.5 bg-slate-950 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-bold text-slate-100">Ingest Knowledge Chunk & Hash (POST /memory)</h3>
              </div>
              <button
                onClick={() => setIngestModalOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleIngestSubmit} className="p-5 space-y-4">
              {ingestSuccessChecksum ? (
                <div className="p-4 bg-emerald-950/50 border border-emerald-500/50 rounded space-y-2">
                  <div className="flex items-center gap-2 text-emerald-300 text-xs font-bold">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Memory Record Successfully Ingested!</span>
                  </div>
                  <div className="text-[11px] text-slate-300">
                    Assigned Canonical SHA-256 Checksum:
                  </div>
                  <div className="text-[10px] text-emerald-400 bg-slate-950 p-2 rounded break-all border border-slate-800">
                    {ingestSuccessChecksum}
                  </div>
                  <div className="pt-2 flex justify-end">
                    <button
                      type="button"
                      onClick={() => setIngestSuccessChecksum(null)}
                      className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-slate-200"
                    >
                      Ingest Another Record
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Source URI / Document:</label>
                    <div className="space-y-1.5">
                      <select
                        value={sourceId}
                        onChange={(e) => setSourceId(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                      >
                        <option value="src-accounting-policy-v2.pdf">src-accounting-policy-v2.pdf (Accounting Policy v2)</option>
                        <option value="src-doc-001">src-doc-001 (Treasury Policy Memo)</option>
                        <option value="src-hr-handbook-v1.pdf">src-hr-handbook-v1.pdf (HR Employee Handbook)</option>
                        <option value="src-support-guide-v1.pdf">src-support-guide-v1.pdf (Customer Support Protocols)</option>
                        <option value="src-branch-ops-v1.pdf">src-branch-ops-v1.pdf (Branch Operations Manual)</option>
                        <option value="src-workflow-gov-v1.pdf">src-workflow-gov-v1.pdf (Cross-Department Workflow Governance)</option>
                        <option value="custom">-- Custom Source Identifier --</option>
                      </select>
                      {sourceId === 'custom' && (
                        <input
                          type="text"
                          value={customSourceId}
                          onChange={(e) => setCustomSourceId(e.target.value)}
                          required
                          placeholder="e.g. src-custom-feed-001"
                          className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                        />
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">Target Agent ID:</label>
                      <div className="space-y-1.5">
                        <select
                          value={agentId}
                          onChange={(e) => setAgentId(e.target.value)}
                          className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                        >
                          <option value="agent-crew-finance-003">Finance Ops (agent-crew-finance-003)</option>
                          <option value="agent-crew-support-001">Customer Support (agent-crew-support-001)</option>
                          <option value="agent-crew-hr-002">HR Operations (agent-crew-hr-002)</option>
                          <option value="agent-crew-branch-004">Branch Operations (agent-crew-branch-004)</option>
                          <option value="agent-crew-coord-005">Workflow Coord (agent-crew-coord-005)</option>
                          <option value="agent-001">Finance Bot (agent-001)</option>
                          <option value="agent-head-office-001">Head Office Lead (agent-head-office-001)</option>
                          <option value="agt-fin-001">Finance Alias (agt-fin-001)</option>
                          <option value="custom">-- Custom Agent ID --</option>
                        </select>
                        {agentId === 'custom' && (
                          <input
                            type="text"
                            value={customAgentId}
                            onChange={(e) => setCustomAgentId(e.target.value)}
                            required
                            placeholder="e.g. agent-custom-001"
                            className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                          />
                        )}
                      </div>
                    </div>
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">Record Type:</label>
                      <select
                        value={recordType}
                        onChange={(e) => setRecordType(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                      >
                        <option value="KNOWLEDGE">KNOWLEDGE</option>
                        <option value="CONVERSATION">CONVERSATION</option>
                        <option value="SCRATCHPAD">SCRATCHPAD</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">Memory Content Chunk:</label>
                    <textarea
                      value={content}
                      onChange={(e) => setContent(e.target.value)}
                      required
                      rows={4}
                      placeholder="Enter raw text payload to be ingested and hashed..."
                      className="w-full bg-slate-950 border border-slate-700 rounded p-2.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                    />
                  </div>

                  {ingestMutation.isError && (
                    <div className="p-3 bg-red-950/60 border border-red-500/60 rounded text-xs text-red-300 flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                      <span>{ingestMutation.error?.message || 'Failed to ingest knowledge record.'}</span>
                    </div>
                  )}

                  <div className="pt-2 flex items-center justify-end gap-2 border-t border-slate-800">
                    <button
                      type="button"
                      onClick={() => setIngestModalOpen(false)}
                      className="px-3.5 py-1.5 rounded text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={ingestMutation.isPending}
                      className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors disabled:opacity-50"
                    >
                      {ingestMutation.isPending && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                      Ingest & Compute SHA-256
                    </button>
                  </div>
                </>
              )}
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
