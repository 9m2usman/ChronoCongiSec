import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { FileCheck, Download } from 'lucide-react';

export const AuditCenterPage: React.FC = () => {
  const { activeTenant } = useWorkstationStore();

  const AUDIT_EVENTS = [
    {
      id: 'aud-99120',
      timestamp: '2026-11-16 10:41:03',
      actor: 'system:gateway',
      action: 'GATEWAY_PROPOSAL_BLOCKED',
      target: 'agt-fin-001',
      tenantId: activeTenant.id,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    {
      id: 'aud-99119',
      timestamp: '2026-11-16 10:35:12',
      actor: 'secops:sarah',
      action: 'MEMORY_RECORD_QUARANTINED',
      target: 'rec-8812-441a',
      tenantId: activeTenant.id,
      sha256: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
    },
    {
      id: 'aud-99118',
      timestamp: '2026-11-16 10:20:00',
      actor: 'system:ingestion',
      action: 'INGEST_DOCUMENT_CHUNK',
      target: 'rec-8812-441a',
      tenantId: activeTenant.id,
      sha256: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
    },
  ];

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileCheck className="w-5 h-5 text-blue-400" />
            Audit Center & Compliance Ledger
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Immutable forensic audit records (Append-Only SEC-010) strictly scoped to {activeTenant.name}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => alert('Exporting SOC2/ISO27001 Cryptographic Audit Evidence Bundle')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded text-xs"
          >
            <Download className="w-3.5 h-3.5" /> Export Evidence
          </button>
        </div>
      </div>

      {/* Audit Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/40">
            <tr>
              <th className="py-2.5 px-4">Audit ID</th>
              <th className="py-2.5 px-4">Timestamp (UTC)</th>
              <th className="py-2.5 px-4">Actor</th>
              <th className="py-2.5 px-4">Action Type</th>
              <th className="py-2.5 px-4">Target Entity</th>
              <th className="py-2.5 px-4">Cryptographic Evidence Hash</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {AUDIT_EVENTS.map((event) => (
              <tr key={event.id} className="hover:bg-slate-800/40 transition-colors">
                <td className="py-3 px-4 font-bold text-slate-200">{event.id}</td>
                <td className="py-3 px-4 text-slate-400">{event.timestamp}</td>
                <td className="py-3 px-4 text-slate-300 font-semibold">{event.actor}</td>
                <td className="py-3 px-4">
                  <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-300 text-[10px] font-bold">
                    {event.action}
                  </span>
                </td>
                <td className="py-3 px-4 text-slate-300">{event.target}</td>
                <td className="py-3 px-4 text-[10px] text-slate-500 truncate max-w-[150px]">
                  {event.sha256}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
