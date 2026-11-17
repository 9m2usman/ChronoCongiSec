import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { Settings, Shield, Key } from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const { activeTenant } = useWorkstationStore();
  const [failClosed, setFailClosed] = useState<boolean>(true);
  const [quarantineRAGExclusion, setQuarantineRAGExclusion] = useState<boolean>(true);
  const [saved, setSaved] = useState<boolean>(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Settings className="w-5 h-5 text-slate-400" />
            Tenant Settings & Security Governance
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Security policy toggles, tenant keys, and fail-closed configurations for {activeTenant.name}
          </p>
        </div>
      </div>

      {/* Governance Settings Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Gateway Policy Toggles */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-200 pb-2 border-b border-slate-800">
            <Shield className="w-4 h-4 text-blue-400" />
            Authoritative Gateway Policies
          </div>

          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">Fail-Closed Default (SEC-004)</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Automatically block action if policy evaluation times out or encounters internal error.
              </div>
            </div>
            <input
              type="checkbox"
              checked={failClosed}
              onChange={(e) => setFailClosed(e.target.checked)}
              className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">Strict RAG Quarantine Exclusion (SEC-005)</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Automatically filter out memory chunks with trust_state = 'QUARANTINED' from retrieval queries.
              </div>
            </div>
            <input
              type="checkbox"
              checked={quarantineRAGExclusion}
              onChange={(e) => setQuarantineRAGExclusion(e.target.checked)}
              className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700"
            />
          </div>

          <div className="pt-2">
            <button
              onClick={handleSave}
              className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors"
            >
              Save Policy Rules
            </button>
            {saved && (
              <span className="ml-3 text-xs text-emerald-400">Settings saved successfully!</span>
            )}
          </div>
        </div>

        {/* Tenant API Credential & Identity */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-200 pb-2 border-b border-slate-800">
            <Key className="w-4 h-4 text-emerald-400" />
            Tenant Isolation Boundary & API Keys
          </div>

          <div>
            <div className="text-xs font-bold text-slate-200 mb-1">Active Tenant ID:</div>
            <div className="text-xs text-slate-300 bg-slate-950 p-2.5 rounded border border-slate-800">
              {activeTenant.id}
            </div>
          </div>

          <div>
            <div className="text-xs font-bold text-slate-200 mb-1">Tenant Secret API Key:</div>
            <div className="text-xs text-slate-300 bg-slate-950 p-2.5 rounded border border-slate-800 flex items-center justify-between">
              <span className="font-mono">amsc_live_sec_****************************</span>
              <button
                onClick={() => alert('Rotating Tenant API Key')}
                className="text-[10px] text-blue-400 hover:underline"
              >
                Rotate Key
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
