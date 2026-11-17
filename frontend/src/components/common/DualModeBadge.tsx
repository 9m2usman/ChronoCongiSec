import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { CheckCircle2, ShieldAlert } from 'lucide-react';

export const DualModeBadge: React.FC = () => {
  const { apiMode, setApiMode } = useWorkstationStore();
  const isLive = apiMode === 'LIVE_CONNECTED';

  return (
    <div
      onClick={() => setApiMode(isLive ? 'SCHEMA_FALLBACK' : 'LIVE_CONNECTED')}
      className={`group relative flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border cursor-pointer select-none transition-all duration-150 ${
        isLive
          ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/60'
          : 'bg-amber-950/60 border-amber-500/40 text-amber-300 hover:bg-amber-900/60'
      }`}
      title="Click to toggle API mode between Live Backend and Schema-Compliant Fallback"
    >
      <span className="relative flex h-2 w-2">
        <span
          className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
            isLive ? 'bg-emerald-400' : 'bg-amber-400'
          }`}
        />
        <span
          className={`relative inline-flex rounded-full h-2 w-2 ${
            isLive ? 'bg-emerald-500' : 'bg-amber-500'
          }`}
        />
      </span>
      <span className="font-semibold tracking-wider">
        {isLive ? 'LIVE API: CONNECTED' : 'CONTRACT FALLBACK'}
      </span>
      {isLive ? (
        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
      ) : (
        <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
      )}

      {/* Tooltip on hover */}
      <div className="absolute top-8 left-1/2 -translate-x-1/2 w-64 p-2 bg-slate-900 border border-slate-700 rounded shadow-xl text-[10px] text-slate-300 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-50">
        <p className="font-bold text-slate-100 mb-0.5">
          {isLive ? 'Direct FastAPI Mode' : 'Contract Mock Fallback Active'}
        </p>
        <p>
          {isLive
            ? 'Making live REST calls to http://localhost:8000/api/v1. Failures will gracefully fallback.'
            : 'Unimplemented upstream endpoints use synthetic schemas from Document 05.'}
        </p>
      </div>
    </div>
  );
};
