import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { HybridGraphViewer } from '@/components/graph/HybridGraphViewer';
import { RotateCcw, ShieldCheck, CheckCircle2 } from 'lucide-react';

export const AgentRewindingPage: React.FC = () => {
  const { activeTenant } = useWorkstationStore();
  const [rollbackSuccess, setRollbackSuccess] = useState<boolean>(false);

  const handleRollback = () => {
    setRollbackSuccess(true);
    setTimeout(() => setRollbackSuccess(false), 5000);
  };

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <RotateCcw className="w-5 h-5 text-amber-400" />
            Agent Rewinding & Blast-Radius Recovery
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Surgical rollback to validated checkpoints with mandatory pre-recovery snapshot preservation for {activeTenant.name}
          </p>
        </div>
      </div>

      {/* Recovery Wizard Card */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
          <div>
            <h2 className="text-sm font-bold text-slate-200">Pending Recovery Action: INC-2026-0812</h2>
            <p className="text-xs text-slate-400 mt-0.5">Target Scope: rec-8812-441a and 1 downstream derived chunk</p>
          </div>
          <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-300 text-xs font-semibold flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" /> SEC-007 Snapshot Stored
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <div className="text-[10px] text-slate-500">Target Checkpoint</div>
            <div className="font-bold text-emerald-400 mt-1">CHK-2026-T15M (Baseline v1)</div>
          </div>
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <div className="text-[10px] text-slate-500">Blast Radius Scope</div>
            <div className="font-bold text-amber-400 mt-1">2 Memory Nodes / 1 Agent Affected</div>
          </div>
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <div className="text-[10px] text-slate-500">External Action Impact</div>
            <div className="font-bold text-emerald-400 mt-1">0 External Actions (100% Intercepted)</div>
          </div>
        </div>

        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-slate-400">
            Restores memory state prior to vendor injection while maintaining non-affected operations.
          </span>
          <button
            onClick={handleRollback}
            className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs rounded transition-colors"
          >
            <RotateCcw className="w-4 h-4" /> Execute Atomic Rollback
          </button>
        </div>

        {rollbackSuccess && (
          <div className="p-3 bg-emerald-950/60 border border-emerald-500 rounded text-xs text-emerald-200 flex items-center gap-2 animate-fade-in">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Rollback successfully committed! Memory state restored to validated checkpoint CHK-2026-T15M.</span>
          </div>
        )}
      </div>

      {/* 2D / 3D Blast Radius Hybrid Visualization */}
      <HybridGraphViewer
        title="3D Blast-Radius & Dependency Scope Explorer"
        subtitle="Forensic simulation of affected memory nodes and agent proposals prior to rollback"
      />
    </div>
  );
};
