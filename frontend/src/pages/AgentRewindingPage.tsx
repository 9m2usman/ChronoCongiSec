import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useAtomicRewindMutation, usePreviewRecoveryMutation } from '@/hooks';
import type { RecoveryExecuteResponse, RecoveryPlanPreviewResponse } from '@/types';
import { ApiError } from '@/services/apiClient';
import { HybridGraphViewer } from '@/components/graph/HybridGraphViewer';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import {
  RotateCcw,
  ShieldCheck,
  CheckCircle2,
  Loader2,
  AlertTriangle,
  Terminal,
  ArrowRight,
  Lock,
} from 'lucide-react';

export const AgentRewindingPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const [activeStep, setActiveStep] = useState<number>(1);
  const [targetIncident, setTargetIncident] = useState<string>('INC-2026-0812');
  const [rollbackComplete, setRollbackComplete] = useState<boolean>(false);
  const [rollbackLogs, setRollbackLogs] = useState<string[]>([]);
  const rewindMutation = useAtomicRewindMutation();
  const previewMutation = usePreviewRecoveryMutation();
  const [preview, setPreview] = useState<RecoveryPlanPreviewResponse | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<RecoveryExecuteResponse | null>(null);

  // DEVELOPMENT FIXTURE: demo incident targets and checkpoint ids. There is no checkpoint listing
  // endpoint yet (M3 checkpoint reader pending), so a preview only succeeds when the backend holds
  // matching records. Nothing below is presented as production data.
  const INCIDENT_TARGETS = [
    {
      id: 'INC-2026-0812',
      label: 'INC-2026-0812: Invoice Ingress Prompt Hijack',
      targetMemory: 'rec-8812-441a',
      checkpointId: 'cp-baseline-alpha-001',
      taintedTime: '2026-11-16 10:30 UTC',
      targetCheckpoint: 'CHK-2026-T15M (v2 Verified Baseline)',
      affectedAgents: ['FinancialOperationsAgent-01'],
      affectedDerived: ['rec-8812-derived (AP Batch Cache)'],
      severity: 'CRITICAL',
    },
    {
      id: 'INC-2026-0799',
      label: 'INC-2026-0799: CRM Escalation Vector Poisoning',
      targetMemory: 'rec-crm-2041',
      checkpointId: 'cp-crm-v1',
      taintedTime: '2026-11-15 16:12 UTC',
      targetCheckpoint: 'CHK-2026-CRM-V1 (Baseline)',
      affectedAgents: ['CustomerSupportAgent-02'],
      affectedDerived: ['rec-crm-cache-01'],
      severity: 'MEDIUM',
    },
  ];

  const currentIncident = INCIDENT_TARGETS.find((i) => i.id === targetIncident) || INCIDENT_TARGETS[0];

  const handlePreview = () => {
    setPreview(null);
    setPreviewError(null);
    setOutcome(null);
    setRollbackComplete(false);
    previewMutation.mutate(
      { checkpointId: currentIncident.checkpointId, targetRecordId: currentIncident.targetMemory },
      {
        onSuccess: (res) => {
          setPreview(res);
          setActiveStep(2);
        },
        onError: (err: unknown) => {
          setPreviewError(err instanceof Error ? err.message : 'Recovery preview failed.');
        },
      }
    );
  };

  const handleExecuteRewind = () => {
    if (!preview) return;
    setOutcome(null);
    setRollbackLogs([`[REQUEST] Executing recovery plan ${preview.plan_id} (server-side snapshot, containment, rollback, audit)...`]);

    const describe = (res: Partial<RecoveryExecuteResponse>): string[] => [
      `[STATUS] ${res.status ?? 'UNKNOWN'}${res.reason_codes?.length ? ` (${res.reason_codes.join(', ')})` : ''}`,
      `[RESTORED] ${res.restored_records_count ?? 0} record(s); trust state after recovery: ${res.restored_records_trust_state ?? 'not changed'}`,
      `[QUARANTINED] ${(res.quarantined_intermediary_ids ?? []).length} intermediary record(s)`,
      `[EXTERNAL] ${res.irreversible_external_actions ?? 0} irreversible external action(s) require human compensation`,
      `[AUDIT] ${res.audit_event_id ? `event ${res.audit_event_id}` : 'no audit event id returned'}`,
      res.message ?? '',
    ];

    rewindMutation.mutate(
      { planId: preview.plan_id },
      {
        onSuccess: (res) => {
          setOutcome(res);
          setRollbackLogs((prev) => [...prev, ...describe(res), res.success ? '[SUCCESS] Recovery verified by the server.' : '']);
          setRollbackComplete(res.success);
          setActiveStep(4);
        },
        onError: (err: unknown) => {
          const details = err instanceof ApiError ? (err.details as Partial<RecoveryExecuteResponse> | undefined) : undefined;
          setRollbackLogs((prev) => [
            ...prev,
            ...(details ? describe(details) : []),
            `[SERVER ERROR] ${err instanceof Error ? err.message : 'Recovery request failed.'}`,
          ]);
          if (details?.status) setOutcome(details as RecoveryExecuteResponse);
          setActiveStep(4);
        },
      }
    );
  };

  return (
    <ForensicErrorBoundary fallbackTitle="Agent Rewind Engine Fault">
      <div className="space-y-6 font-mono text-slate-100">
        {/* Title & Tenant Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <RotateCcw className="w-5 h-5 text-amber-400" />
              Agent Rewinding & Blast-Radius Recovery
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Surgical state rollback with mandatory SEC-007 pre-recovery snapshots for{' '}
              <span className="text-blue-400 font-bold">{activeTenant.name}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-xs font-bold flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" /> SEC-007 Snapshot Preservation Active
            </span>
          </div>
        </div>

        {/* 4-Step Recovery Wizard Progress Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
          {[
            { step: 1, title: '1. Incident Target', desc: 'Select tainted record' },
            { step: 2, title: '2. Blast Radius', desc: 'Preview affected entities' },
            { step: 3, title: '3. Pre-Snapshot', desc: 'SEC-007 state guarantee' },
            { step: 4, title: '4. Atomic Execution', desc: 'Rollback & audit event' },
          ].map((s) => {
            const isActive = activeStep === s.step;
            const isDone = activeStep > s.step || rollbackComplete;

            return (
              <button
                key={s.step}
                onClick={() => setActiveStep(s.step)}
                className={`p-3 rounded-lg border text-left transition-all ${
                  isActive
                    ? 'bg-blue-950/40 border-blue-500 shadow-md ring-1 ring-blue-500/30'
                    : isDone
                    ? 'bg-slate-900/90 border-emerald-500/40 text-slate-300'
                    : 'bg-slate-950/60 border-slate-800 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className={`text-xs font-bold ${isActive ? 'text-blue-400' : isDone ? 'text-emerald-400' : 'text-slate-400'}`}>
                    {s.title}
                  </span>
                  {isDone ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <span className="w-2 h-2 rounded-full bg-slate-700"></span>
                  )}
                </div>
                <div className="text-[10px] text-slate-400 mt-1">{s.desc}</div>
              </button>
            );
          })}
        </div>

        {/* Active Wizard Step Panel */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-5 shadow-lg">
          {activeStep === 1 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div>
                  <h2 className="text-sm font-bold text-slate-200">Step 1: Select Tainted Checkpoint / Incident Target</h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Choose which security incident or corrupted memory node requires rollback
                  </p>
                </div>
                <span className="text-[10px] text-amber-400 font-mono">Development fixture targets</span>
              </div>

              <div className="space-y-3">
                {INCIDENT_TARGETS.map((inc) => (
                  <label
                    key={inc.id}
                    className={`block p-4 rounded-lg border cursor-pointer transition-all ${
                      targetIncident === inc.id
                        ? 'bg-blue-950/30 border-blue-500 ring-1 ring-blue-500/40'
                        : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <input
                          type="radio"
                          name="targetIncident"
                          checked={targetIncident === inc.id}
                          onChange={() => setTargetIncident(inc.id)}
                          className="w-4 h-4 text-blue-600 bg-slate-900 border-slate-700"
                        />
                        <div>
                          <div className="font-bold text-xs text-slate-100">{inc.label}</div>
                          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-2">
                            <span>Target Memory: <strong className="text-red-400">{inc.targetMemory}</strong></span>
                            <span>•</span>
                            <span>Tainted At: {inc.taintedTime}</span>
                          </div>
                        </div>
                      </div>

                      <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 text-[10px] font-bold border border-red-500/40">
                        {inc.severity}
                      </span>
                    </div>
                  </label>
                ))}
              </div>

              {previewError && (
                <div role="alert" className="p-3 bg-red-950/30 border border-red-500/40 rounded text-xs text-red-300">
                  Preview failed: {previewError}. No recovery plan exists, so nothing can be executed.
                </div>
              )}

              <div className="flex justify-end pt-3">
                <button
                  onClick={handlePreview}
                  disabled={previewMutation.isPending}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors disabled:opacity-50"
                >
                  {previewMutation.isPending ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" /> Requesting server preview...
                    </>
                  ) : (
                    <>
                      Request Blast Radius Preview <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </div>
            </div>
          )}

          {activeStep === 2 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div>
                  <h2 className="text-sm font-bold text-slate-200">Step 2: Downstream Blast Radius Dependency Preview</h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Analyzing direct and derived state mutations triggered by {currentIncident.targetMemory}
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-500/40 text-[10px] font-bold">
                  {preview ? `${preview.preview.affected_records_count} record(s) · risk ${preview.preview.risk_level}` : 'No preview'}
                </span>
              </div>

              {preview ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div className="p-3 bg-slate-950 rounded border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase">Plan</div>
                      <div className="font-bold text-cyan-400 mt-1 text-xs break-all">{preview.plan_id}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">Status: {preview.status}</div>
                    </div>
                    <div className="p-3 bg-slate-950 rounded border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase">Checkpoint</div>
                      <div className="font-bold text-emerald-400 mt-1 text-xs break-all">
                        {preview.preview.checkpoint_name || preview.preview.checkpoint_id}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5">Integrity verified by the server</div>
                    </div>
                    <div className="p-3 bg-slate-950 rounded border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase">Irreversible External Actions</div>
                      <div className="font-bold text-red-400 mt-1 text-xs">{preview.preview.irreversible_external_actions}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">Recorded; require human compensation</div>
                    </div>
                  </div>
                  <table className="w-full text-[11px] text-left border border-slate-800">
                    <thead className="bg-slate-950 text-slate-500 uppercase text-[10px]">
                      <tr>
                        <th className="p-2">Record</th>
                        <th className="p-2">Planned action</th>
                        <th className="p-2">Checkpoint version</th>
                        <th className="p-2">Current trust state</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.preview.affected_records.map((rec) => (
                        <tr key={rec.record_id} className="border-t border-slate-800">
                          <td className="p-2 font-mono break-all">{rec.record_id}</td>
                          <td className="p-2">{rec.action}</td>
                          <td className="p-2">{rec.checkpoint_version ?? '-'}</td>
                          <td className="p-2">{rec.current_trust_state ?? '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p className="text-[11px] text-slate-400">
                    Restored records become <strong>UNVERIFIED</strong> and must be re-validated before any agent may use them.
                  </p>
                </div>
              ) : (
                <div className="p-3 bg-slate-950 border border-slate-800 rounded text-xs text-slate-400">
                  No server preview yet. Go back and request one.
                </div>
              )}

              {/* 2D/3D Hybrid Visualizer */}
              <HybridGraphViewer
                title="Blast Radius Cascade Topology (illustrative)"
                subtitle="Illustrative development topology; the table above is the server's actual plan"
              />

              <div className="flex justify-between items-center pt-3 border-t border-slate-800">
                <button
                  onClick={() => setActiveStep(1)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Back
                </button>
                <button
                  onClick={() => setActiveStep(3)}
                  disabled={!preview}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors disabled:opacity-50"
                >
                  Verify Pre-Recovery Snapshot <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {activeStep === 3 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div>
                  <h2 className="text-sm font-bold text-slate-200">Step 3: SEC-007 Pre-Recovery Snapshot Guarantee</h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Ensures an immutable copy of current corrupted state is preserved for forensic compliance prior to overwrite
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px] font-bold flex items-center gap-1">
                  <Lock className="w-3 h-3" /> Captured server-side on execution
                </span>
              </div>

              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Recovery Plan:</span>
                  <span className="font-mono text-cyan-400 font-bold break-all">{preview?.plan_id ?? 'none'}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Target Checkpoint:</span>
                  <span className="font-mono text-emerald-400 font-bold break-all">
                    {preview?.preview.checkpoint_name || preview?.preview.checkpoint_id || 'none'}
                  </span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Tenant:</span>
                  <span className="font-mono text-blue-400 font-bold">{activeTenant.id}</span>
                </div>
                <div className="text-[11px] text-slate-400">
                  The server commits the pre-recovery snapshot before changing anything; its hash is recorded in the
                  recovery audit event.
                </div>
              </div>

              <div className="p-3 bg-amber-950/30 border border-amber-500/40 rounded text-xs text-amber-300 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <strong>Fail-Closed Rollback Protocol:</strong> affected records are quarantined first, then restored
                  to the checkpoint content as a new version. Restored records end UNVERIFIED (never TRUSTED);
                  intermediaries stay QUARANTINED. If any step fails, the server reports it and no success is shown.
                </div>
              </div>

              <div className="flex justify-between items-center pt-3 border-t border-slate-800">
                <button
                  onClick={() => setActiveStep(2)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Back
                </button>
                <button
                  onClick={handleExecuteRewind}
                  disabled={rewindMutation.isPending || !preview}
                  className="flex items-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-bold transition-colors shadow-lg disabled:opacity-50"
                >
                  {rewindMutation.isPending ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Executing Atomic Rewind...
                    </>
                  ) : (
                    <>
                      <RotateCcw className="w-4 h-4" />
                      Execute Atomic Rewind (SEC-007)
                    </>
                  )}
                </button>
              </div>
            </div>
          )}

          {activeStep === 4 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div>
                  <h2 className="text-sm font-bold text-slate-200">Step 4: Atomic Execution & Recovery Verification</h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Live execution log and post-recovery cryptographic validation
                  </p>
                </div>
                {outcome && (
                  <span
                    className={`px-2.5 py-0.5 rounded text-xs font-bold flex items-center gap-1.5 border ${
                      outcome.success
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                        : 'bg-red-950 text-red-300 border-red-500/40'
                    }`}
                  >
                    {outcome.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                    {outcome.status}
                  </span>
                )}
              </div>

              {/* Terminal Execution Log */}
              <div className="p-4 bg-black rounded-lg border border-slate-800 font-mono text-xs text-slate-300 space-y-1.5 max-h-64 overflow-y-auto">
                <div className="text-slate-500 flex items-center gap-1.5 pb-1 border-b border-slate-900">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>AMSC Forensic Rewind Execution Engine v1.0.0</span>
                </div>
                {rollbackLogs.map((log, idx) => (
                  <div
                    key={idx}
                    className={
                      log.includes('SUCCESS')
                        ? 'text-emerald-400 font-bold'
                        : log.includes('SNAPSHOT')
                        ? 'text-cyan-400'
                        : log.includes('AUDIT')
                        ? 'text-purple-400'
                        : 'text-slate-300'
                    }
                  >
                    {log}
                  </div>
                ))}
              </div>

              {rollbackComplete && outcome && (
                <div className="p-4 bg-emerald-950/20 border border-emerald-500/40 rounded-lg flex items-center justify-between text-xs">
                  <div>
                    <div className="font-bold text-emerald-400 flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4" /> {outcome.restored_records_count} record(s) restored to{' '}
                      {preview?.preview.checkpoint_name || preview?.preview.checkpoint_id}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      Restored records are UNVERIFIED until re-validated. Audit event: {outcome.audit_event_id ?? 'not returned'}.
                    </div>
                  </div>

                  <button
                    onClick={() =>
                      openInspector({
                        title: `Recovery Plan: ${outcome.plan_id}`,
                        type: 'INCIDENT',
                        id: outcome.plan_id,
                        trustState: 'UNVERIFIED',
                        details: {
                          plan_id: outcome.plan_id,
                          status: outcome.status,
                          executed_at: outcome.executed_at,
                          restored_records: outcome.restored_records,
                          quarantined_intermediaries: outcome.quarantined_intermediary_ids,
                          irreversible_external_actions: outcome.irreversible_external_actions,
                          audit_event_id: outcome.audit_event_id,
                          reason_codes: outcome.reason_codes,
                        },
                      })
                    }
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded text-xs transition-colors"
                  >
                    Inspect Recovery Audit
                  </button>
                </div>
              )}

              <div className="flex justify-between items-center pt-3 border-t border-slate-800">
                <button
                  onClick={() => {
                    setActiveStep(1);
                    setRollbackComplete(false);
                    setRollbackLogs([]);
                    setPreview(null);
                    setOutcome(null);
                    setPreviewError(null);
                  }}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Start New Rewind Workflow
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </ForensicErrorBoundary>
  );
};
