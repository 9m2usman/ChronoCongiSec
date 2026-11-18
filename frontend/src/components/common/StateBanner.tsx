import React from 'react';
import { AlertTriangle, ShieldX, ServerOff, Loader2, Inbox } from 'lucide-react';

interface StateBannerProps {
  type: 'loading' | 'empty' | 'unauthorized' | 'unavailable' | 'error';
  title?: string;
  message?: string;
  statusCode?: number;
  actionText?: string;
  onAction?: () => void;
}

export const StateBanner: React.FC<StateBannerProps> = ({
  type,
  title,
  message,
  statusCode,
  actionText,
  onAction,
}) => {
  if (type === 'loading') {
    return (
      <div className="flex flex-col items-center justify-center p-8 bg-slate-900/60 border border-slate-800 rounded-lg text-center" role="status" aria-live="polite">
        <Loader2 className="w-6 h-6 text-blue-400 animate-spin mb-2" />
        <span className="text-xs font-semibold text-slate-300">{title || 'Loading security telemetry...'}</span>
        {message && <p className="text-[11px] text-slate-500 mt-1">{message}</p>}
      </div>
    );
  }

  if (type === 'empty') {
    return (
      <div className="flex flex-col items-center justify-center p-8 bg-slate-900/40 border border-slate-800/80 rounded-lg text-center" role="region" aria-label="Empty State">
        <Inbox className="w-8 h-8 text-slate-600 mb-2" />
        <span className="text-xs font-semibold text-slate-300">{title || 'No Records Found'}</span>
        <p className="text-[11px] text-slate-500 mt-1 max-w-md">{message || 'No telemetry or records available for this query.'}</p>
        {actionText && onAction && (
          <button
            onClick={onAction}
            className="mt-3 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 rounded border border-slate-700"
          >
            {actionText}
          </button>
        )}
      </div>
    );
  }

  if (type === 'unauthorized') {
    return (
      <div className="p-4 bg-red-950/40 border border-red-500/50 rounded-lg text-left" role="alert">
        <div className="flex items-start gap-3">
          <ShieldX className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="text-xs font-bold text-red-200 flex items-center gap-2">
              <span>{title || 'Authorization Required'}</span>
              <span className="px-1.5 py-0.2 bg-red-900/80 text-red-300 text-[10px] rounded font-mono">
                HTTP {statusCode || 403}
              </span>
            </div>
            <p className="text-[11px] text-red-300/80">
              {message || 'Your current identity or role does not have permission to view or mutate this resource.'}
            </p>
            {actionText && onAction && (
              <button
                onClick={onAction}
                className="mt-2 px-2.5 py-1 bg-red-900/80 hover:bg-red-800 text-xs text-red-100 rounded border border-red-700 font-semibold"
              >
                {actionText}
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (type === 'unavailable') {
    return (
      <div className="p-4 bg-amber-950/40 border border-amber-500/50 rounded-lg text-left" role="alert">
        <div className="flex items-start gap-3">
          <ServerOff className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="text-xs font-bold text-amber-200 flex items-center gap-2">
              <span>{title || 'Upstream Backend Capability Unavailable'}</span>
              {statusCode && (
                <span className="px-1.5 py-0.2 bg-amber-900/80 text-amber-300 text-[10px] rounded font-mono">
                  HTTP {statusCode}
                </span>
              )}
            </div>
            <p className="text-[11px] text-amber-300/80">
              {message || 'This endpoint is pending deployment on the API server. Displaying schema-compliant fallback fixtures.'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 bg-red-950/40 border border-red-500/40 rounded-lg text-left" role="alert">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="text-xs font-bold text-red-200">{title || 'Telemetry Fault'}</div>
          <p className="text-[11px] text-red-300/80">{message || 'An unexpected error occurred while fetching security data.'}</p>
        </div>
      </div>
    </div>
  );
};
