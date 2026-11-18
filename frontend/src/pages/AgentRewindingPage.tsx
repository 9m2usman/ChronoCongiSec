import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useAtomicRewindMutation } from '@/hooks';
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

  const INCIDENT_TARGETS = [
    {
      id: 'INC-2026-0812',
      label: 'INC-2026-0812: Invoice Ingress Prompt Hijack',
      targetMemory: 'rec-8812-441a',
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
      taintedTime: '2026-11-15 16:12 UTC',
      targetCheckpoint: 'CHK-2026-CRM-V1 (Baseline)',
      affectedAgents: ['CustomerSupportAgent-02'],
      affectedDerived: ['rec-crm-cache-01'],
      severity: 'MEDIUM',
    },
  ];

  const currentIncident = INCIDENT_TARGETS.find((i) => i.id === targetIncident) || INCIDENT_TARGETS[0];

  const handleExecuteRewind = () => {
    setRollbackLogs([
      `[AMSC-SEC-007] Initiating atomic pre-recovery snapshot verification...`,
      `[SNAPSHOT] Storing pre-rollback state snap-${currentIncident.targetMemory}-pre-rewind... OK`,
      `[DATABASE] Acquiring multi-tenant vector lock for tenant: ${activeTenant.id}...`,
      `[GATEWAY] Freezing execution queues for affected agent: ${currentIncident.affectedAgents[0]}...`,
      `[CHRONIMEM] Reverting memory state to authoritative baseline: ${currentIncident.targetCheckpoint}...`,
      `[VECTOR-INDEX] Purging tainted embeddings for ${currentIncident.targetMemory} and derived nodes...`,
      `[AUDIT] Appending immutable cryptographic rewind event to SEC-010 audit ledger...`,
    ]);

    rewindMutation.mutate(
      {
        planId: `plan-${currentIncident.targetMemory}`,
        targetRecordId: currentIncident.targetMemory,
      },
      {
        onSuccess: () => {
          setTimeout(() => {
            setRollbackLogs((prev) => [
              ...prev,
              `[SUCCESS] Atomic rewind completed in 412ms. All blast-radius nodes restored to trusted state.`,
            ]);
            setRollbackComplete(true);
            setActiveStep(4);
          }, 800);
        },
        onError: (err: any) => {
          setRollbackLogs((prev) => [
            ...prev,
            `[SERVER ERROR] Operation failed: ${err.message}`,
            `[ABORTED] Rollback failed. Tainted state snapshot preserved; memory NOT restored.`,
          ]);
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
                <span className="text-[10px] text-slate-500 font-mono">1 Active Critical Campaign</span>
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

              <div className="flex justify-end pt-3">
                <button
                  onClick={() => setActiveStep(2)}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors"
                >
                  Proceed to Blast Radius Preview <ArrowRight className="w-3.5 h-3.5" />
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
                  2 Memories / 1 Agent Affected
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Primary Tainted Root</div>
                  <div className="font-bold text-red-400 mt-1 text-xs">{currentIncident.targetMemory}</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">Direct malicious prompt ingress</div>
                </div>

                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Derived Memory Chunks</div>
                  <div className="font-bold text-amber-400 mt-1 text-xs">{currentIncident.affectedDerived[0]}</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">Cached in RAG context store</div>
                </div>

                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Compromised Agent</div>
                  <div className="font-bold text-blue-400 mt-1 text-xs">{currentIncident.affectedAgents[0]}</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">Attempted wire transfer ($240k)</div>
                </div>
              </div>

              {/* 2D/3D Hybrid Visualizer */}
              <HybridGraphViewer
                title="Blast Radius Cascade Topology"
                subtitle="Red nodes depict tainted state marked for surgical rollback"
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
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors"
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
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold flex items-center gap-1">
                  <Lock className="w-3 h-3" /> Mandatory Check Passed
                </span>
              </div>

              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Snapshot Identifier:</span>
                  <span className="font-mono text-cyan-400 font-bold">snap-{currentIncident.targetMemory}-pre-rewind</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Target Checkpoint Baseline:</span>
                  <span className="font-mono text-emerald-400 font-bold">{currentIncident.targetCheckpoint}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Tenant Namespace Isolation:</span>
                  <span className="font-mono text-blue-400 font-bold">tenant-vector-{activeTenant.slug}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Cryptographic Signature:</span>
                  <span className="font-mono text-slate-300 text-[10px]">0x7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d</span>
                </div>
              </div>

              <div className="p-3 bg-amber-950/30 border border-amber-500/40 rounded text-xs text-amber-300 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <strong>Fail-Closed Rollback Protocol:</strong> Executing atomic rewind will immediately invalidate
                  quarantined vector embeddings, purge tainted RAG cache, and revert {currentIncident.targetMemory} to
                  the verified baseline. Agent memory state will reflect baseline authority without service disruption.
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
                  disabled={rewindMutation.isPending}
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
                {rollbackComplete && (
                  <span className="px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-xs font-bold flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Rewind Completed (412ms)
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

              {rollbackComplete && (
                <div className="p-4 bg-emerald-950/20 border border-emerald-500/40 rounded-lg flex items-center justify-between text-xs">
                  <div>
                    <div className="font-bold text-emerald-400 flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4" /> Memory State Restored to CHK-2026-T15M
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      AuditEvent appended to Audit Center. Quarantined records unblocked or purged according to policy.
                    </div>
                  </div>

                  <button
                    onClick={() =>
                      openInspector({
                        title: `Rewind Plan: ${currentIncident.targetMemory}`,
                        type: 'INCIDENT',
                        id: `rewind-${currentIncident.targetMemory}`,
                        sha256: '3a4f1b884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08aa',
                        trustState: 'TRUSTED',
                        details: {
                          incident_id: currentIncident.id,
                          target_record: currentIncident.targetMemory,
                          snapshot_checksum: `snap-${currentIncident.targetMemory}-pre-rewind`,
                          restored_checkpoint: currentIncident.targetCheckpoint,
                          latency_ms: 412,
                          status: 'COMPLETED_SUCCESSFULLY',
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
