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
      <div
        className="flex flex-col items-center justify-center p-8 bg-surface border border-borderc rounded-lg text-center"
        role="status"
        aria-live="polite"
      >
        <Loader2 className="w-6 h-6 text-brand animate-spin mb-2" />
        <span className="text-xs font-semibold text-ink">{title || 'Loading security telemetry...'}</span>
        {message && <p className="text-[11px] text-ink-muted mt-1">{message}</p>}
      </div>
    );
  }

  if (type === 'empty') {
    return (
      <div
        className="flex flex-col items-center justify-center p-8 bg-surface border border-borderc rounded-lg text-center"
        role="region"
        aria-label="Empty State"
      >
        <Inbox className="w-8 h-8 text-ink-muted mb-2" />
        <span className="text-xs font-semibold text-ink">{title || 'No Records Found'}</span>
        <p className="text-[11px] text-ink-muted mt-1 max-w-md">
          {message || 'No telemetry or records available for this query.'}
        </p>
        {actionText && onAction && (
          <button
            onClick={onAction}
            className="mt-3 px-3 py-1 bg-elevated hover:bg-brand-tint text-xs text-ink rounded border border-borderc transition-colors"
          >
            {actionText}
          </button>
        )}
      </div>
    );
  }

  if (type === 'unauthorized') {
    return (
      <div className="p-4 bg-status-criticalBg border border-status-critical/40 rounded-lg text-left" role="alert">
        <div className="flex items-start gap-3">
          <ShieldX className="w-5 h-5 text-status-critical shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="text-xs font-bold text-status-critical flex items-center gap-2">
              <span>{title || 'Authorization Required'}</span>
              <span className="px-1.5 py-0.5 bg-surface text-status-critical border border-status-critical/30 text-[10px] rounded font-mono">
                HTTP {statusCode || 403}
              </span>
            </div>
            <p className="text-[11px] text-ink">
              {message || 'Your current identity or role does not have permission to view or mutate this resource.'}
            </p>
            {actionText && onAction && (
              <button
                onClick={onAction}
                className="mt-2 px-2.5 py-1 bg-surface hover:bg-elevated text-xs text-status-critical rounded border border-status-critical/40 font-semibold transition-colors"
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
      <div className="p-4 bg-status-warningBg border border-status-warning/40 rounded-lg text-left" role="alert">
        <div className="flex items-start gap-3">
          <ServerOff className="w-5 h-5 text-status-warning shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="text-xs font-bold text-status-warning flex items-center gap-2">
              <span>{title || 'Upstream Backend Capability Unavailable'}</span>
              {statusCode && (
                <span className="px-1.5 py-0.5 bg-surface text-status-warning border border-status-warning/30 text-[10px] rounded font-mono">
                  HTTP {statusCode}
                </span>
              )}
            </div>
            <p className="text-[11px] text-ink">
              {message || 'This endpoint is pending deployment on the API server. Displaying schema-compliant fallback fixtures.'}
            </p>
            {actionText && onAction && (
              <button
                type="button"
                onClick={onAction}
                className="mt-2 px-2.5 py-1 bg-surface hover:bg-elevated text-xs text-status-warning rounded border border-status-warning/40 font-semibold transition-colors"
              >
                {actionText}
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 bg-status-criticalBg border border-status-critical/40 rounded-lg text-left" role="alert">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-status-critical shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="text-xs font-bold text-status-critical">{title || 'Telemetry Fault'}</div>
          <p className="text-[11px] text-ink">
            {message || 'An unexpected error occurred while fetching security data.'}
          </p>
        </div>
      </div>
    </div>
  );
};
