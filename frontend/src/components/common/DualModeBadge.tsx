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
          ? 'bg-status-trustedBg border-status-trusted/40 text-status-trusted hover:opacity-90'
          : 'bg-status-warningBg border-status-warning/40 text-status-warning hover:opacity-90'
      }`}
      title="Click to toggle API mode between Live Backend and Schema-Compliant Fallback"
    >
      <span className="relative flex h-2 w-2">
        <span
          className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
            isLive ? 'bg-status-trusted' : 'bg-status-warning'
          }`}
        />
        <span
          className={`relative inline-flex rounded-full h-2 w-2 ${
            isLive ? 'bg-status-trusted' : 'bg-status-warning'
          }`}
        />
      </span>
      <span className="font-semibold tracking-wider">
        {isLive ? 'LIVE API: CONNECTED' : 'CONTRACT FALLBACK'}
      </span>
      {isLive ? (
        <CheckCircle2 className="w-3.5 h-3.5 text-status-trusted" />
      ) : (
        <ShieldAlert className="w-3.5 h-3.5 text-status-warning" />
      )}

      {/* Tooltip on hover */}
      <div className="absolute top-8 left-1/2 -translate-x-1/2 w-64 p-2.5 bg-surface border border-borderc rounded shadow-xl text-[10px] text-ink-muted pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-50">
        <p className="font-bold text-ink mb-0.5">
          {isLive ? 'Direct FastAPI Mode' : 'Contract Mock Fallback Active'}
        </p>
        <p>
          {isLive
            ? 'Making live REST calls to /api/v1. Failures will explicitly report backend state.'
            : 'Unimplemented upstream endpoints use deterministic schemas from Document 05.'}
        </p>
      </div>
    </div>
  );
};
