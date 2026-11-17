import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { ShieldAlert, ArrowUpRight } from 'lucide-react';

export const SecurityCenterPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();

  const INCIDENTS = [
    {
      id: 'INC-2026-0812',
      threatType: 'Indirect Prompt Injection / Memory Tampering',
      severity: 'CRITICAL',
      targetAgent: 'FinancialOperationsAgent-01',
      taintedChunk: 'rec-8812-441a',
      gatewayStatus: 'INTERCEPTED & BLOCKED',
      timestamp: '15m ago',
      evidenceSummary: 'External vendor invoice injected instructions diverting corporate ACH wire payments to an unauthorized SWIFT endpoint.',
    },
    {
      id: 'INC-2026-0744',
      threatType: 'Prompt Injection / Privilege Escalation',
      severity: 'MEDIUM',
      targetAgent: 'CustomerSupportAgent-02',
      taintedChunk: 'rec-5511-331d',
      gatewayStatus: 'MITIGATED',
      timestamp: '2h ago',
      evidenceSummary: 'User chat prompt attempted jailbreak using base64 encoded system prompt override.',
    },
  ];

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
            1 Open Critical Incident
          </span>
        </div>
      </div>

      {/* Incident List */}
      <div className="space-y-4">
        {INCIDENTS.map((inc) => (
          <div key={inc.id} className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-3">
                <span className="px-2 py-0.5 bg-red-950 border border-red-800 text-red-300 rounded font-bold text-xs">
                  {inc.severity}
                </span>
                <span className="font-bold text-slate-200 text-sm">{inc.id}</span>
                <span className="text-slate-400 text-xs">— {inc.threatType}</span>
              </div>
              <span className="text-xs text-slate-500">{inc.timestamp}</span>
            </div>

            <p className="text-xs text-slate-300 bg-slate-950 p-3 rounded border border-slate-800/80">
              {inc.evidenceSummary}
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                <div className="text-[10px] text-slate-500">Target Agent</div>
                <div className="font-semibold text-slate-200 mt-0.5">{inc.targetAgent}</div>
              </div>
              <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                <div className="text-[10px] text-slate-500">Tainted Memory Chunk</div>
                <div className="font-semibold text-red-400 mt-0.5">{inc.taintedChunk}</div>
              </div>
              <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                <div className="text-[10px] text-slate-500">Gateway Intervention</div>
                <div className="font-semibold text-emerald-400 mt-0.5">{inc.gatewayStatus}</div>
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
        ))}
      </div>
    </div>
  );
};
