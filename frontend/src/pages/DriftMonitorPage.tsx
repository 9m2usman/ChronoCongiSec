import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useDriftObservations } from '@/hooks';
import { TrendingDown, Loader2 } from 'lucide-react';

export const DriftMonitorPage: React.FC = () => {
  const { activeTenant } = useWorkstationStore();
  const { data: driftEntries, isLoading } = useDriftObservations();

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <TrendingDown className="w-5 h-5 text-amber-400" />
            Semantic Memory Drift & Anomaly Monitor
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Vector embedding divergence and cosine similarity tracking for {activeTenant.name}
          </p>
        </div>
      </div>

      {/* Drift Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 flex items-center justify-center text-slate-400 gap-2 text-xs">
            <Loader2 className="w-4 h-4 animate-spin text-amber-400" />
            Calculating semantic vector drift across memories...
          </div>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/40">
              <tr>
                <th className="py-2.5 px-4">Record ID / Name</th>
                <th className="py-2.5 px-4">Cosine Divergence</th>
                <th className="py-2.5 px-4">Anomaly Confidence</th>
                <th className="py-2.5 px-4">Classification</th>
                <th className="py-2.5 px-4">Comparative Baseline</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {driftEntries?.map((entry) => (
                <tr key={entry.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-bold text-slate-200">{entry.record_name}</div>
                    <div className="text-[10px] text-slate-500">{entry.record_id}</div>
                  </td>
                  <td className="py-3 px-4 font-bold text-amber-400">{entry.cosine_divergence} Δ</td>
                  <td className="py-3 px-4 text-slate-300">{entry.anomaly_confidence}</td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        entry.status === 'HIGH_DRIFT'
                          ? 'bg-red-950/40 border-red-500/50 text-red-300'
                          : entry.status === 'MODERATE_DRIFT'
                          ? 'bg-amber-950/40 border-amber-500/50 text-amber-300'
                          : 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                      }`}
                    >
                      {entry.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-400">{entry.baseline_doc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
