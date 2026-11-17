import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useMemories } from '@/hooks';
import { Database, ArrowUpRight, Search, Loader2 } from 'lucide-react';

export const MemoryExplorerPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: memories, isLoading } = useMemories();

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Database className="w-5 h-5 text-emerald-400" />
            Memory Explorer & Provenance Catalog
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic SHA-256 verification and trust status for ingested memory chunks in {activeTenant.name}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center px-3 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-300">
            <Search className="w-3.5 h-3.5 text-slate-400 mr-2" />
            <input
              type="text"
              placeholder="Filter by chunk ID or SHA-256..."
              className="bg-transparent focus:outline-none placeholder-slate-500 w-52 text-xs"
            />
          </div>
        </div>
      </div>

      {/* Memory Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 flex items-center justify-center text-slate-400 gap-2 text-xs">
            <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
            Loading cryptographic memory catalog...
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/40">
              <tr>
                <th className="py-2.5 px-4">Chunk ID</th>
                <th className="py-2.5 px-4">Source ID</th>
                <th className="py-2.5 px-4">SHA-256 Checksum</th>
                <th className="py-2.5 px-4">Trust State</th>
                <th className="py-2.5 px-4">Version</th>
                <th className="py-2.5 px-4">Content Preview</th>
                <th className="py-2.5 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {memories?.map((chunk) => (
                <tr key={chunk.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 font-bold text-slate-200">{chunk.id}</td>
                  <td className="py-3 px-4 text-slate-300">{chunk.source_id || 'unassigned'}</td>
                  <td className="py-3 px-4 text-[10px] text-slate-400 max-w-[140px] truncate">
                    {chunk.checksum || 'pending_calculation'}
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        chunk.trust_state === 'TRUSTED'
                          ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                          : chunk.trust_state === 'QUARANTINED'
                          ? 'bg-red-950/40 border-red-500/50 text-red-300'
                          : 'bg-amber-950/40 border-amber-500/50 text-amber-300'
                      }`}
                    >
                      {chunk.trust_state}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-400">v{chunk.current_version}</td>
                  <td className="py-3 px-4 text-slate-300 max-w-[200px] truncate">
                    {chunk.content || 'Encrypted content block'}
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
                      className="p-1 hover:text-blue-400 text-slate-400"
                      title="Inspect Chunk Provenance"
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
