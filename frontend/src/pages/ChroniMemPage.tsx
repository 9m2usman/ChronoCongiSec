import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useChroniMemTimeline } from '@/hooks';
import { History, ShieldCheck, AlertOctagon, Loader2 } from 'lucide-react';

export const ChroniMemPage: React.FC = () => {
  const { activeTenant } = useWorkstationStore();
  const { data: timelineData, isLoading } = useChroniMemTimeline('rec-8812-441a');
  const [selectedVersion, setSelectedVersion] = useState<number>(2);

  const versions = timelineData?.versions || [];
  const v1 = versions.find((v) => v.version === 1);
  const v2 = versions.find((v) => v.version === 2);

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <History className="w-5 h-5 text-purple-400" />
            ChroniMem: Temporal Memory & Lineage Explorer
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Point-in-time state checkpoint navigation and cryptographic version diffing for {activeTenant.name}
          </p>
        </div>
      </div>

      {isLoading ? (
        <div className="p-12 flex items-center justify-center text-slate-400 gap-2 text-xs">
          <Loader2 className="w-5 h-5 animate-spin text-purple-400" />
          Loading temporal memory checkpoints...
        </div>
      ) : (
        <>
          {/* Version Selector Slider Bar */}
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-xs font-bold text-slate-200 mb-3 flex items-center justify-between">
              <span>Memory Checkpoint Milestones ({timelineData?.record_id || 'rec-8812-441a'})</span>
              <span className="text-[11px] text-purple-400">Comparing Version v1 vs v2</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {versions.map((v) => (
                <div
                  key={v.version}
                  onClick={() => setSelectedVersion(v.version)}
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    selectedVersion === v.version
                      ? 'bg-purple-950/30 border-purple-500 ring-1 ring-purple-500/50'
                      : 'bg-slate-950 border-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-slate-100">Version v{v.version}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        v.trust_state === 'TRUSTED'
                          ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                          : 'bg-red-950/40 border-red-500/50 text-red-300'
                      }`}
                    >
                      {v.trust_state}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">{v.time_display}</div>
                  <div className="text-[10px] text-slate-500 mt-1 truncate">Source: {v.author}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Side-by-Side Diff View */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Baseline v1 */}
            <div className="p-4 bg-slate-900 border border-emerald-500/30 rounded-lg">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
                <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" /> Version 1 (Trusted Baseline)
                </span>
                <span className="text-[10px] text-slate-400 truncate max-w-[200px]">
                  SHA-256: {v1?.checksum.slice(0, 16)}...
                </span>
              </div>
              <div className="p-3 bg-slate-950 rounded text-xs text-slate-200 border border-slate-800/80 leading-relaxed">
                {v1?.content || 'Official baseline policy document'}
              </div>
            </div>

            {/* Poisoned v2 */}
            <div className="p-4 bg-slate-900 border border-red-500/30 rounded-lg">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
                <span className="text-xs font-bold text-red-400 flex items-center gap-1.5">
                  <AlertOctagon className="w-4 h-4" /> Version 2 (Poisoned Drift)
                </span>
                <span className="text-[10px] text-slate-400 truncate max-w-[200px]">
                  SHA-256: {v2?.checksum.slice(0, 16)}...
                </span>
              </div>
              <div className="p-3 bg-red-950/20 rounded text-xs text-red-300 border border-red-900/40 leading-relaxed font-bold">
                {v2?.content || 'Injected adversary instruction payload'}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
