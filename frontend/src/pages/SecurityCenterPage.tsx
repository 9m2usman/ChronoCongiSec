import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useSecurityIncidents, useQuarantineMutation, useTraces, useKnowledgeGraph } from '@/hooks';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import { StateBanner } from '@/components/common/StateBanner';
import {
  ShieldAlert,
  ArrowUpRight,
  Ban,
  RotateCcw,
  AlertTriangle,
  Zap,
  TrendingDown,
  ShieldCheck,
  CheckCircle2,
  FileText,
  AlertCircle,
} from 'lucide-react';

export const SecurityCenterPage: React.FC = () => {
  const navigate = useNavigate();
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: incidents, isLoading, error } = useSecurityIncidents();
  const { data: traceList } = useTraces();
  const { data: graphData } = useKnowledgeGraph(2);
  const quarantineMutation = useQuarantineMutation();

  const [quarantinedIds, setQuarantinedIds] = useState<Record<string, boolean>>({});
  const [quarantineError, setQuarantineError] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

  // 4 Kill-Chain Stages
  const KILL_CHAIN_STAGES = [
    {
      id: 'INGEST_POISONING',
      title: '1. Ingest Poisoning',
      subtitle: 'External untrusted input ingestion',
      icon: FileText,
      accentColor: 'text-status-warning',
      borderColor: 'border-status-warning/40',
      bgHeader: 'bg-status-warningBg',
    },
    {
      id: 'DRIFT_SPIKE',
      title: '2. Semantic Drift Spike',
      subtitle: 'Vector divergence from policy',
      icon: TrendingDown,
      accentColor: 'text-brand',
      borderColor: 'border-brand/40',
      bgHeader: 'bg-brand-tint',
    },
    {
      id: 'INJECTION_DETECTED',
      title: '3. Prompt Injection',
      subtitle: 'Autonomous agent hijack directive',
      icon: Zap,
      accentColor: 'text-status-warning',
      borderColor: 'border-status-warning/40',
      bgHeader: 'bg-status-warningBg',
    },
    {
      id: 'GATEWAY_BLOCKED',
      title: '4. Fail-Closed Gate',
      subtitle: 'Server-side SEC-004 interception',
      icon: ShieldCheck,
      accentColor: 'text-status-critical',
      borderColor: 'border-status-critical/40',
      bgHeader: 'bg-status-criticalBg',
    },
  ];

  const handleQuarantine = (chunkId: string) => {
    setQuarantineError(null);
    quarantineMutation.mutate(
      {
        recordId: chunkId,
        payload: {
          reason: 'Emergency operator quarantine triggered from Kill-Chain Alert Triage Board',
          analyst_notes: 'Adversary memory poisoning confirmed',
        },
      },
      {
        onSuccess: () => {
          setQuarantinedIds((prev) => ({ ...prev, [chunkId]: true }));
        },
        onError: (err: any) => {
          setQuarantineError(err.message || 'Quarantine mutation failed on server. Memory NOT isolated.');
        },
      }
    );
  };

  const handleEscalateToRewind = (incidentId: string, chunkId: string) => {
    navigate(`/rewind?incident=${incidentId}&chunk=${chunkId}`);
  };

  return (
    <ForensicErrorBoundary fallbackTitle="Security Center Fault">
      <div className="space-y-6 font-mono text-ink">
        {/* Title Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-borderc gap-3">
          <div>
            <h1 className="text-xl font-bold text-ink flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-status-critical" />
              Security Center & Kill-Chain Triage
            </h1>
            <p className="text-xs text-ink-muted mt-0.5">
              Multi-stage kill-chain incident triage, one-click quarantine, and rapid rollback escalation for{' '}
              <span className="text-brand font-bold">{activeTenant.name}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            {isLoading ? (
              <span className="px-2.5 py-1 rounded bg-surface border border-borderc text-ink-muted text-xs font-bold">
                Evaluating Incidents...
              </span>
            ) : error ? (
              <span className="px-2.5 py-1 rounded bg-status-criticalBg border border-status-critical/40 text-status-critical text-xs font-bold flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" /> Incident Stream Error
              </span>
            ) : !incidents || incidents.length === 0 ? (
              <span className="px-2.5 py-1 rounded bg-status-trustedBg border border-status-trusted/40 text-status-trusted text-xs font-bold flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" /> 0 Active Incidents
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded bg-status-criticalBg border border-status-critical/40 text-status-critical text-xs font-bold flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" /> {incidents.length} Active Incident{incidents.length === 1 ? '' : 's'}
              </span>
            )}
          </div>
        </div>

        {/* Quarantine Error Alert */}
        {quarantineError && (
          <div className="p-3 bg-status-criticalBg border border-status-critical rounded-lg text-xs text-status-critical flex items-center justify-between" role="alert">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{quarantineError}</span>
            </div>
            <button
              onClick={() => setQuarantineError(null)}
              className="px-2 py-0.5 rounded bg-surface hover:bg-elevated text-[10px] text-status-critical border border-status-critical/40"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Kill-Chain Alert Triage Board (4 Columns) */}
        {isLoading ? (
          <StateBanner type="loading" title="Loading Kill-Chain Threat Telemetry..." message="Evaluating multi-stage poisoning and injection campaigns..." />
        ) : error ? (
          <StateBanner type="error" title="Failed to Load Security Incidents" statusCode={(error as any)?.status} message={(error as Error).message || 'Unable to query /security/incidents.'} />
        ) : !incidents || incidents.length === 0 ? (
          <StateBanner type="empty" title="No Security Incidents Reported" message={`No active kill-chain incidents have been recorded for ${activeTenant.name}.`} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {KILL_CHAIN_STAGES.map((stage) => {
              const StageIcon = stage.icon;
              const incidentsList = incidents.map((inc, idx) => ({
                id: inc.id,
                stage: inc.classification || KILL_CHAIN_STAGES[idx % KILL_CHAIN_STAGES.length].id,
                threat_type: inc.threat_type || inc.title,
                severity: inc.severity,
                target_agent_name: inc.target_agent_name || 'Unassigned Agent',
                tainted_chunk_id: inc.tainted_chunk_id || '',
                evidence_summary: inc.evidence_summary,
                created_at: inc.created_at || 'Just now',
              }));

              const stageIncidents = incidentsList.filter((i) => i.stage === stage.id);

              return (
                <div
                  key={stage.id}
                  className={`flex flex-col bg-surface border ${stage.borderColor} rounded-lg overflow-hidden shadow-sm`}
                >
                  {/* Column Header */}
                  <div className={`p-3 border-b border-borderc ${stage.bgHeader}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <StageIcon className={`w-4 h-4 ${stage.accentColor}`} />
                        <span className="text-xs font-bold text-ink">{stage.title}</span>
                      </div>
                      <span className="px-1.5 py-0.5 rounded bg-surface border border-borderc text-[10px] font-bold text-ink-muted">
                        {stageIncidents.length}
                      </span>
                    </div>
                    <p className="text-[10px] text-ink-muted mt-1">{stage.subtitle}</p>
                  </div>

                  {/* Incident Cards */}
                  <div className="p-3 space-y-3 flex-1 overflow-y-auto">
                    {stageIncidents.map((inc) => {
                      const isQuarantined =
                        quarantinedIds[inc.tainted_chunk_id] || inc.stage === 'GATEWAY_BLOCKED';

                      return (
                        <div
                          key={inc.id}
                          className="p-3 bg-canvas rounded border border-borderc hover:border-brand/40 transition-colors space-y-2.5"
                        >
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="font-bold text-ink">{inc.id}</span>
                            <span
                              className={`px-1.5 py-0.5 rounded font-bold border ${
                                inc.severity === 'CRITICAL'
                                  ? 'bg-status-criticalBg border-status-critical/40 text-status-critical'
                                  : 'bg-status-warningBg border-status-warning/40 text-status-warning'
                              }`}
                            >
                              {inc.severity}
                            </span>
                          </div>

                          <div className="text-xs font-semibold text-ink leading-tight">
                            {inc.threat_type}
                          </div>

                          <p className="text-[11px] text-ink-muted leading-relaxed font-sans">
                            {inc.evidence_summary}
                          </p>

                          <div className="p-2 bg-surface rounded border border-borderc text-[10px] space-y-1">
                            <div className="text-ink-muted flex items-center justify-between">
                              <span>Target Agent:</span>
                              <strong className="text-ink">{inc.target_agent_name}</strong>
                            </div>
                            <div className="text-ink-muted flex items-center justify-between">
                              <span>Cited Memory:</span>
                              <button
                                onClick={() =>
                                  openInspector({
                                    title: `Cited Memory: ${inc.tainted_chunk_id}`,
                                    type: 'RECORD',
                                    id: inc.tainted_chunk_id,
                                    sha256: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
                                    trustState: isQuarantined ? 'QUARANTINED' : 'SUSPICIOUS',
                                    details: inc,
                                  })
                                }
                                className="text-brand-teal hover:underline font-mono"
                              >
                                {inc.tainted_chunk_id}
                              </button>
                            </div>
                          </div>

                          {/* Action Triggers */}
                          <div className="flex flex-col gap-1.5 pt-1 border-t border-borderc">
                            <div className="flex items-center gap-1.5">
                              {/* One-click Quarantine */}
                              <button
                                onClick={() => handleQuarantine(inc.tainted_chunk_id)}
                                disabled={isQuarantined || quarantineMutation.isPending}
                                className={`flex-1 flex items-center justify-center gap-1 px-2 py-1 rounded text-[10px] font-bold transition-colors ${
                                  isQuarantined
                                    ? 'bg-status-criticalBg text-status-critical border border-status-critical/30 cursor-default'
                                    : 'bg-status-criticalBg hover:opacity-90 text-status-critical border border-status-critical/50'
                                }`}
                                title="Enforce immediate quarantine exclusion under SEC-004"
                              >
                                {isQuarantined ? (
                                  <>
                                    <CheckCircle2 className="w-3 h-3" /> Quarantined
                                  </>
                                ) : (
                                  <>
                                    <Ban className="w-3 h-3" /> Quarantine
                                  </>
                                )}
                              </button>

                              {/* Escalate to Rewind */}
                              <button
                                onClick={() => handleEscalateToRewind(inc.id, inc.tainted_chunk_id)}
                                className="flex-1 flex items-center justify-center gap-1 px-2 py-1 bg-status-warningBg hover:opacity-90 text-status-warning border border-status-warning/50 rounded text-[10px] font-bold transition-opacity"
                                title="Escalate to Screen 09 for atomic blast-radius rollback"
                              >
                                <RotateCcw className="w-3 h-3" /> Rewind →
                              </button>
                            </div>

                            {/* Deep Inspect in Drawer & Relationship View */}
                            <div className="flex items-center gap-1.5">
                              <button
                                onClick={() => setSelectedIncidentId(inc.id === selectedIncidentId ? null : inc.id)}
                                className="flex-1 flex items-center justify-center gap-1 py-1 text-[10px] text-brand-teal hover:bg-elevated rounded transition-colors border border-borderc"
                              >
                                <span>Relationships</span>
                              </button>
                              <button
                                onClick={() =>
                                  openInspector({
                                    title: `Incident Case: ${inc.id}`,
                                    type: 'INCIDENT',
                                    id: inc.id,
                                    trustState: isQuarantined ? 'QUARANTINED' : 'SUSPICIOUS',
                                    details: inc,
                                  })
                                }
                                className="flex-1 flex items-center justify-center gap-1 py-1 text-[10px] text-ink-muted hover:text-ink hover:bg-elevated rounded transition-colors"
                              >
                                <span>Dossier</span>
                                <ArrowUpRight className="w-3 h-3" />
                              </button>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Investigation Relationship View for Selected Incident */}
        {(() => {
          const activeInc = (incidents || []).find((i) => i.id === selectedIncidentId) || (incidents || [])[0];
          if (!activeInc) return null;
          const relatedTraces = (traceList?.items || []).filter(
            (t) => activeInc.target_agent_id && t.agent_id === activeInc.target_agent_id
          );
          const provenanceEdges = (graphData?.edges || []).filter(
            (e) =>
              activeInc.tainted_chunk_id &&
              (e.from_record_id === activeInc.tainted_chunk_id || e.to_record_id === activeInc.tainted_chunk_id)
          );
          return (
            <div className="p-4 bg-surface border border-borderc rounded-lg space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-borderc gap-2">
                <div className="text-xs font-bold text-ink">
                  Incident Investigation Relationship Map — <span className="text-brand">{activeInc.id}</span>
                </div>
                <span className="text-[10px] text-ink-muted">
                  Confirmed backend links vs. unavailable fields labeled explicitly
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                <div className="p-3 bg-canvas border border-borderc rounded">
                  <div className="text-[10px] text-ink-muted uppercase">Confirmed Incident</div>
                  <div className="font-bold text-ink mt-0.5 truncate">{activeInc.title}</div>
                  <div className="text-[10px] text-status-critical mt-0.5">{activeInc.severity} • {activeInc.status}</div>
                </div>
                <div className="p-3 bg-canvas border border-borderc rounded">
                  <div className="text-[10px] text-ink-muted uppercase">Affected Agent</div>
                  <div className="font-bold text-ink mt-0.5 truncate">
                    {activeInc.target_agent_name || activeInc.target_agent_id || 'Not linked in incident payload'}
                  </div>
                </div>
                <div className="p-3 bg-canvas border border-borderc rounded">
                  <div className="text-[10px] text-ink-muted uppercase">Affected Memory</div>
                  <div className="font-bold text-brand-teal mt-0.5 truncate">
                    {activeInc.tainted_chunk_id || 'Not linked in incident payload'}
                  </div>
                </div>
                <div className="p-3 bg-canvas border border-borderc rounded">
                  <div className="text-[10px] text-ink-muted uppercase">Traces &amp; Provenance</div>
                  <div className="text-[11px] text-ink mt-0.5">
                    {relatedTraces.length} trace(s) • {provenanceEdges.length} graph edge(s)
                  </div>
                </div>
              </div>
            </div>
          );
        })()}
      </div>
    </ForensicErrorBoundary>
  );
};
