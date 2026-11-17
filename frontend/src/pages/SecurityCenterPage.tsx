import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useSecurityIncidents } from '@/hooks';
import { ShieldAlert, ArrowUpRight, Loader2 } from 'lucide-react';

export const SecurityCenterPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: incidents, isLoading } = useSecurityIncidents();

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            Security Center & Incident Triage
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Active threat detection, quarantine enforcement, and gateway intervention records for {activeTenant.name}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded bg-red-950/60 border border-red-500/40 text-red-300 text-xs font-bold">
            {incidents?.filter((i) => i.severity === 'CRITICAL').length || 1} Critical Open
          </span>
        </div>
      </div>

      {/* Incident List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="p-8 flex items-center justify-center text-slate-400 gap-2 text-xs">
            <Loader2 className="w-4 h-4 animate-spin text-red-400" />
            Loading security incident tickets...
          </div>
        ) : (
          incidents?.map((inc) => (
            <div key={inc.id} className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 bg-red-950 border border-red-800 text-red-300 rounded font-bold text-xs">
                    {inc.severity}
                  </span>
                  <span className="font-bold text-slate-200 text-sm">{inc.id}</span>
                  <span className="text-slate-400 text-xs">— {inc.threat_type}</span>
                </div>
                <span className="text-xs text-slate-500">Recently detected</span>
              </div>

              <p className="text-xs text-slate-300 bg-slate-950 p-3 rounded border border-slate-800/80">
                {inc.evidence_summary}
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500">Target Agent</div>
                  <div className="font-semibold text-slate-200 mt-0.5">{inc.target_agent_name || 'Agent'}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500">Tainted Memory Chunk</div>
                  <div className="font-semibold text-red-400 mt-0.5">{inc.tainted_chunk_id || 'rec-8812-441a'}</div>
                </div>
                <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500">Gateway Intervention</div>
                  <div className="font-semibold text-emerald-400 mt-0.5">{inc.gateway_status}</div>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800/60">
                <button
                  onClick={() =>
                    openInspector({
                      title: `Incident: ${inc.id}`,
                      type: 'INCIDENT',
                      id: inc.id,
                      trustState: 'QUARANTINED',
                      details: inc,
                    })
                  }
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs border border-slate-700"
                >
                  Inspect Evidence <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
