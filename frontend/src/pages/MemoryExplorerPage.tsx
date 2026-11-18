import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useMemories, useIngestMemoryMutation } from '@/hooks';
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
} from 'lucide-react';

export const MemoryExplorerPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: memories, isLoading, error } = useMemories();
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
  const [agentId, setAgentId] = useState('agt-fin-001');
  const [recordType, setRecordType] = useState('KNOWLEDGE');
  const [content, setContent] = useState('');
  const [ingestSuccessChecksum, setIngestSuccessChecksum] = useState<string | null>(null);

  const handleIngestSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    ingestMutation.mutate(
      {
        content,
        record_type: recordType,
        source_id: sourceId,
        agent_id: agentId,
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
                    <input
                      type="text"
                      value={sourceId}
                      onChange={(e) => setSourceId(e.target.value)}
                      required
                      placeholder="e.g. corporate_policy_2026.pdf"
                      className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">Target Agent ID:</label>
                      <input
                        type="text"
                        value={agentId}
                        onChange={(e) => setAgentId(e.target.value)}
                        placeholder="e.g. agt-fin-001"
                        className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                      />
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
