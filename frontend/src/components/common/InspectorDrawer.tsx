import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { X, Copy, ExternalLink, Check, Ban } from 'lucide-react';

export const InspectorDrawer: React.FC = () => {
  const { inspectorOpen, inspectorPayload, closeInspector } = useWorkstationStore();
  const [copied, setCopied] = React.useState(false);

  if (!inspectorOpen || !inspectorPayload) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-96 bg-slate-900 border-l border-slate-700 shadow-2xl flex flex-col font-mono text-xs text-slate-200 animate-slide-in">
      {/* Drawer Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-950 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950 border border-blue-700 text-blue-300">
            {inspectorPayload.type}
          </span>
          <span className="font-semibold text-slate-100 truncate max-w-[180px]">
            {inspectorPayload.title}
          </span>
        </div>
        <button
          onClick={closeInspector}
          className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-100"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Drawer Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Identifier & Status */}
        <div className="p-3 bg-slate-950 rounded border border-slate-800">
          <div className="text-[10px] text-slate-400 mb-1">Entity ID:</div>
          <div className="flex items-center justify-between font-bold text-slate-100">
            <span className="truncate">{inspectorPayload.id}</span>
            <button
              onClick={() => handleCopy(inspectorPayload.id)}
              className="p-1 hover:text-blue-400 text-slate-500"
              title="Copy ID"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          {inspectorPayload.trustState && (
            <div className="mt-2 flex items-center gap-1.5">
              <span className="text-[10px] text-slate-400">Trust State:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  inspectorPayload.trustState === 'TRUSTED'
                    ? 'bg-emerald-950/60 border-emerald-500 text-emerald-300'
                    : inspectorPayload.trustState === 'QUARANTINED'
                    ? 'bg-red-950/60 border-red-500 text-red-300'
                    : 'bg-amber-950/60 border-amber-500 text-amber-300'
                }`}
              >
                {inspectorPayload.trustState}
              </span>
            </div>
          )}
        </div>

        {/* Cryptographic SHA-256 Checksum */}
        {inspectorPayload.sha256 && (
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <div className="text-[10px] text-slate-400 mb-1">Cryptographic Checksum (SHA-256):</div>
            <div className="text-[10px] text-emerald-400 break-all bg-slate-900 p-2 rounded border border-slate-800/80">
              {inspectorPayload.sha256}
            </div>
          </div>
        )}

        {/* Forensic Metadata & Details */}
        <div className="p-3 bg-slate-950 rounded border border-slate-800">
          <div className="text-[10px] text-slate-400 mb-1">Raw Forensic Payload:</div>
          <pre className="text-[10px] text-slate-300 bg-slate-900 p-2 rounded max-h-56 overflow-y-auto border border-slate-800/80">
            {JSON.stringify(inspectorPayload.details, null, 2)}
          </pre>
        </div>

        {/* Forensic Action Triggers */}
        <div className="space-y-2 pt-2 border-t border-slate-800">
          <button
            onClick={() => alert(`Triggering Emergency Quarantine for ${inspectorPayload.id}`)}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-red-950/80 hover:bg-red-900/80 text-red-300 border border-red-800/80 rounded font-semibold text-xs transition-colors"
          >
            <Ban className="w-3.5 h-3.5" /> Quarantine Entity
          </button>
          <button
            onClick={() => alert(`Investigating Lineage for ${inspectorPayload.id}`)}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded font-semibold text-xs transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" /> Trace Lineage in ChroniMem
          </button>
        </div>
      </div>
    </div>
  );
};
