import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useQuarantineMutation } from '@/hooks';
import { StatusBadge } from '@/components/common/StatusBadge';
import { X, Copy, ExternalLink, Check, Ban, Loader2, AlertTriangle } from 'lucide-react';

export const InspectorDrawer: React.FC = () => {
  const { inspectorOpen, inspectorPayload, closeInspector, openInspector } = useWorkstationStore();
  const [copied, setCopied] = useState(false);
  const quarantineMutation = useQuarantineMutation();
  const navigate = useNavigate();

  useEffect(() => {
    if (!inspectorOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        closeInspector();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [inspectorOpen, closeInspector]);

  if (!inspectorOpen || !inspectorPayload) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleQuarantine = () => {
    quarantineMutation.mutate(
      {
        recordId: inspectorPayload.id,
        payload: {
          reason: 'Emergency operator quarantine triggered via Workstation Inspector Drawer',
          analyst_notes: 'Threat confirmed during analyst investigation',
        },
      },
      {
        onSuccess: (data) => {
          openInspector({
            ...inspectorPayload,
            trustState: 'QUARANTINED',
            details: {
              ...inspectorPayload.details,
              trust_state: 'QUARANTINED',
              quarantine_note: data.message,
            },
          });
        },
      }
    );
  };

  return (
    <div
      className="fixed inset-y-0 right-0 z-40 w-96 max-w-full bg-surface border-l border-borderc shadow-2xl flex flex-col font-mono text-xs text-ink"
      role="dialog"
      aria-modal="true"
      aria-label="Forensic Inspector Drawer"
    >
      {/* Drawer Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-elevated border-b border-borderc">
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-brand-tint border border-brand/40 text-brand">
            {inspectorPayload.type}
          </span>
          <span className="font-semibold text-ink truncate max-w-[180px]">
            {inspectorPayload.title}
          </span>
        </div>
        <button
          onClick={closeInspector}
          className="p-1 rounded hover:bg-canvas text-ink-muted hover:text-ink transition-colors"
          aria-label="Close Inspector"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Drawer Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Identifier & Status */}
        <div className="p-3 bg-canvas rounded border border-borderc">
          <div className="text-[10px] text-ink-muted mb-1">Entity ID:</div>
          <div className="flex items-center justify-between font-bold text-ink">
            <span className="truncate">{inspectorPayload.id}</span>
            <button
              onClick={() => handleCopy(inspectorPayload.id)}
              className="p-1 hover:text-brand text-ink-muted transition-colors"
              title="Copy ID"
              aria-label="Copy Entity ID"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-status-trusted" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          {inspectorPayload.trustState && (
            <div className="mt-2 flex items-center gap-1.5">
              <span className="text-[10px] text-ink-muted">Trust State:</span>
              <StatusBadge status={inspectorPayload.trustState} />
            </div>
          )}
        </div>

        {/* Cryptographic SHA-256 Checksum */}
        {inspectorPayload.sha256 && (
          <div className="p-3 bg-canvas rounded border border-borderc">
            <div className="text-[10px] text-ink-muted mb-1">Cryptographic Checksum (SHA-256):</div>
            <div className="text-[10px] text-status-trusted break-all bg-surface p-2 rounded border border-borderc">
              {inspectorPayload.sha256}
            </div>
          </div>
        )}

        {/* Forensic Metadata & Details */}
        <div className="p-3 bg-canvas rounded border border-borderc">
          <div className="text-[10px] text-ink-muted mb-1">Raw Forensic Payload:</div>
          <pre className="text-[10px] text-ink bg-surface p-2 rounded max-h-56 overflow-y-auto border border-borderc">
            {JSON.stringify(inspectorPayload.details, null, 2)}
          </pre>
        </div>

        {/* Quarantine Mutation Error (Fail-Closed Reporting) */}
        {quarantineMutation.isError && (
          <div className="p-2.5 bg-status-criticalBg border border-status-critical/40 rounded text-[11px] text-status-critical flex items-start gap-2" role="alert">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{(quarantineMutation.error as Error)?.message || 'Quarantine request rejected by server.'}</span>
          </div>
        )}

        {/* Forensic Action Triggers */}
        <div className="space-y-2 pt-2 border-t border-borderc">
          {inspectorPayload.trustState !== 'QUARANTINED' && (
            <button
              onClick={handleQuarantine}
              disabled={quarantineMutation.isPending}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-status-criticalBg hover:opacity-90 text-status-critical border border-status-critical/40 rounded font-semibold text-xs transition-opacity disabled:opacity-50"
            >
              {quarantineMutation.isPending ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Ban className="w-3.5 h-3.5" />
              )}
              Quarantine Entity (SEC-004)
            </button>
          )}

          <button
            onClick={() => {
              closeInspector();
              navigate('/chronimem');
            }}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-elevated hover:bg-brand-tint text-ink border border-borderc rounded font-semibold text-xs transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" /> Trace Lineage in ChroniMem
          </button>
        </div>
      </div>
    </div>
  );
};
