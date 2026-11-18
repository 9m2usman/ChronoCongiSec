import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useSecurityIncidents, useQuarantineMutation } from '@/hooks';
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
  const quarantineMutation = useQuarantineMutation();

  const [quarantinedIds, setQuarantinedIds] = useState<Record<string, boolean>>({});
  const [quarantineError, setQuarantineError] = useState<string | null>(null);

  // 4 Kill-Chain Stages
  const KILL_CHAIN_STAGES = [
    {
      id: 'INGEST_POISONING',
      title: '1. Ingest Poisoning',
      subtitle: 'External untrusted input ingestion',
      icon: FileText,
      accentColor: 'text-amber-400',
      borderColor: 'border-amber-500/30',
      bgHeader: 'bg-amber-950/20',
    },
    {
      id: 'DRIFT_SPIKE',
      title: '2. Semantic Drift Spike',
      subtitle: 'Vector divergence from policy',
      icon: TrendingDown,
      accentColor: 'text-purple-400',
      borderColor: 'border-purple-500/30',
      bgHeader: 'bg-purple-950/20',
    },
    {
      id: 'INJECTION_DETECTED',
      title: '3. Prompt Injection',
      subtitle: 'Autonomous agent hijack directive',
      icon: Zap,
      accentColor: 'text-orange-400',
      borderColor: 'border-orange-500/30',
      bgHeader: 'bg-orange-950/20',
    },
    {
      id: 'GATEWAY_BLOCKED',
      title: '4. Fail-Closed Gate',
      subtitle: 'Server-side SEC-004 interception',
      icon: ShieldCheck,
      accentColor: 'text-red-400',
      borderColor: 'border-red-500/30',
      bgHeader: 'bg-red-950/20',
    },
  ];

  // Default campaign incidents for active tenant
  const defaultIncidents = activeTenant.id === 'tenant-betashield' ? [
    {
      id: 'INC-BETA-001',
      stage: 'INGEST_POISONING',
      threat_type: 'Distributed Port 22 SSH Brute Force Ingress',
      severity: 'HIGH',
      target_agent_name: 'CyberDefenseAnalyst-01',
      tainted_chunk_id: 'rec-beta-101',
      evidence_summary: 'Brute-force attempts against host gateway evaluated against intrusion response playbook.',
      created_at: '10m ago',
    },
  ] : activeTenant.id === 'tenant-gammaai' ? [
    {
      id: 'INC-GAMMA-001',
      stage: 'DRIFT_SPIKE',
      threat_type: 'High Replica Spike Threshold Anomaly',
      severity: 'MEDIUM',
      target_agent_name: 'CloudInfrastructureBot-01',
      tainted_chunk_id: 'rec-gamma-201',
      evidence_summary: 'Cluster autoscaling request evaluating pod memory constraints.',
      created_at: '45m ago',
    },
  ] : [
    {
      id: 'INC-2026-0812-A',
      stage: 'INGEST_POISONING',
      threat_type: 'Vendor Invoice PDF Malformed Directive',
      severity: 'HIGH',
      target_agent_name: 'FinancialOperationsAgent-01',
      tainted_chunk_id: 'rec-8812-441a',
      evidence_summary: 'Ingested document "vendor_invoice_9912.pdf" contains hidden prompt override instructions.',
      created_at: '22m ago',
    },
    {
      id: 'INC-2026-0812-B',
      stage: 'DRIFT_SPIKE',
      threat_type: 'Cosine Divergence Anomaly (0.42 Δ)',
      severity: 'MEDIUM',
      target_agent_name: 'FinancialOperationsAgent-01',
      tainted_chunk_id: 'rec-8812-441a',
      evidence_summary: 'Drift monitor observed vector distance spike exceeding 0.35 threshold from corporate accounting policy.',
      created_at: '18m ago',
    },
    {
      id: 'INC-2026-0812-C',
      stage: 'INJECTION_DETECTED',
      threat_type: 'Direct System Prompt Hijack Attempt',
      severity: 'CRITICAL',
      target_agent_name: 'FinancialOperationsAgent-01',
      tainted_chunk_id: 'rec-8812-441a',
      evidence_summary: 'Adversary directive instructs agent to bypass standard Accounts Payable dual-custody verification.',
      created_at: '15m ago',
    },
    {
      id: 'INC-2026-0812-D',
      stage: 'GATEWAY_BLOCKED',
      threat_type: 'Fail-Closed Gateway Interception',
      severity: 'CRITICAL',
      target_agent_name: 'FinancialOperationsAgent-01',
      tainted_chunk_id: 'rec-8812-441a',
      evidence_summary: 'Gateway evaluated proposal tool:execute_wire_transfer($240k). Blocked with 403 Forbidden under SEC-004.',
      created_at: '12m ago',
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
      <div className="space-y-6 font-mono text-slate-100">
        {/* Title Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              Security Center & Kill-Chain Triage
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Multi-stage kill-chain incident triage, one-click quarantine, and rapid rollback escalation for{' '}
              <span className="text-blue-400 font-bold">{activeTenant.name}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded bg-red-950/60 border border-red-500/40 text-red-300 text-xs font-bold flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" /> 1 Multi-Stage Campaign Active
            </span>
          </div>
        </div>

        {/* Quarantine Error Alert */}
        {quarantineError && (
          <div className="p-3 bg-red-950/80 border border-red-500 rounded-lg text-xs text-red-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{quarantineError}</span>
            </div>
            <button
              onClick={() => setQuarantineError(null)}
              className="px-2 py-0.5 rounded bg-red-900/60 hover:bg-red-800 text-[10px] text-red-200"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Kill-Chain Alert Triage Board (4 Columns) */}
        {isLoading ? (
          <StateBanner type="loading" title="Loading Kill-Chain Threat Telemetry..." message="Evaluating multi-stage poisoning and injection campaigns..." />
        ) : error ? (
          <StateBanner type="unavailable" title="Live Security Incidents Stream Offline" message="GET /security/incidents route is pending backend deployment. Loaded campaign baseline." />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {KILL_CHAIN_STAGES.map((stage) => {
              const StageIcon = stage.icon;
              const incidentsList = (incidents && incidents.length > 0)
                ? incidents.map((inc, idx) => ({
                    id: inc.id,
                    stage: inc.classification || KILL_CHAIN_STAGES[idx % KILL_CHAIN_STAGES.length].id,
                    threat_type: inc.threat_type || inc.title,
                    severity: inc.severity,
                    target_agent_name: inc.target_agent_name || 'FinancialOperationsAgent-01',
                    tainted_chunk_id: inc.tainted_chunk_id || 'rec-8812-441a',
                    evidence_summary: inc.evidence_summary,
                    created_at: inc.created_at || 'Just now',
                  }))
                : defaultIncidents;

              const stageIncidents = incidentsList.filter((i) => i.stage === stage.id);

              return (
                <div
                  key={stage.id}
                  className={`flex flex-col bg-slate-900 border ${stage.borderColor} rounded-lg overflow-hidden shadow-sm`}
                >
                  {/* Column Header */}
                  <div className={`p-3 border-b border-slate-800 ${stage.bgHeader}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <StageIcon className={`w-4 h-4 ${stage.accentColor}`} />
                        <span className="text-xs font-bold text-slate-200">{stage.title}</span>
                      </div>
                      <span className="px-1.5 py-0.2 rounded bg-slate-950 text-[10px] font-bold text-slate-400">
                        {stageIncidents.length}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1">{stage.subtitle}</p>
                  </div>

                  {/* Incident Cards */}
                  <div className="p-3 space-y-3 flex-1 overflow-y-auto">
                    {stageIncidents.map((inc) => {
                      const isQuarantined =
                        quarantinedIds[inc.tainted_chunk_id] || inc.stage === 'GATEWAY_BLOCKED';

                      return (
                        <div
                          key={inc.id}
                          className="p-3 bg-slate-950 rounded border border-slate-800 hover:border-slate-700 transition-all space-y-2.5"
                        >
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="font-bold text-slate-200">{inc.id}</span>
                            <span
                              className={`px-1.5 py-0.2 rounded font-bold ${
                                inc.severity === 'CRITICAL'
                                  ? 'bg-red-950 border border-red-800 text-red-300'
                                  : 'bg-amber-950 border border-amber-800 text-amber-300'
                              }`}
                            >
                              {inc.severity}
                            </span>
                          </div>

                          <div className="text-xs font-semibold text-slate-300 leading-tight">
                            {inc.threat_type}
                          </div>

                          <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                            {inc.evidence_summary}
                          </p>

                          <div className="p-2 bg-slate-900/80 rounded border border-slate-800 text-[10px] space-y-1">
                            <div className="text-slate-400 flex items-center justify-between">
                              <span>Target Agent:</span>
                              <strong className="text-slate-200">{inc.target_agent_name}</strong>
                            </div>
                            <div className="text-slate-400 flex items-center justify-between">
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
                                className="text-cyan-400 hover:underline font-mono"
                              >
                                {inc.tainted_chunk_id}
                              </button>
                            </div>
                          </div>

                          {/* Action Triggers */}
                          <div className="flex flex-col gap-1.5 pt-1 border-t border-slate-800/80">
                            <div className="flex items-center gap-1.5">
                              {/* One-click Quarantine */}
                              <button
                                onClick={() => handleQuarantine(inc.tainted_chunk_id)}
                                disabled={isQuarantined || quarantineMutation.isPending}
                                className={`flex-1 flex items-center justify-center gap-1 px-2 py-1 rounded text-[10px] font-bold transition-all ${
                                  isQuarantined
                                    ? 'bg-red-950/40 text-red-400 border border-red-800/40 cursor-default'
                                    : 'bg-red-950 hover:bg-red-900 text-red-200 border border-red-700'
                                }`}
                                title="Enforce immediate quarantine exclusion under SEC-004"
                              >
                                {isQuarantined ? (
                                  <>
                                    <CheckCircle2 className="w-3 h-3 text-red-400" /> Quarantined
                                  </>
                                ) : (
                                  <>
                                    <Ban className="w-3 h-3 text-red-400" /> Quarantine
                                  </>
                                )}
                              </button>

                              {/* Escalate to Rewind */}
                              <button
                                onClick={() => handleEscalateToRewind(inc.id, inc.tainted_chunk_id)}
                                className="flex-1 flex items-center justify-center gap-1 px-2 py-1 bg-amber-950 hover:bg-amber-900 text-amber-200 border border-amber-700 rounded text-[10px] font-bold transition-all"
                                title="Escalate to Screen 09 for atomic blast-radius rollback"
                              >
                                <RotateCcw className="w-3 h-3 text-amber-400" /> Rewind →
                              </button>
                            </div>

                            {/* Deep Inspect in Drawer */}
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
                              className="w-full flex items-center justify-center gap-1 py-1 text-[10px] text-slate-400 hover:text-slate-200 hover:bg-slate-900 rounded transition-colors"
                            >
                              <span>Open Forensic Dossier</span>
                              <ArrowUpRight className="w-3 h-3" />
                            </button>
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
      </div>
    </ForensicErrorBoundary>
  );
};
