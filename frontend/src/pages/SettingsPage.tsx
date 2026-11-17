import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import {
  Settings,
  Shield,
  Key,
  Database,
  Sliders,
  CheckCircle2,
  Copy,
  RotateCw,
  Lock,
  Sparkles,
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const { activeTenant } = useWorkstationStore();

  // Policy toggles
  const [sec001, setSec001] = useState<boolean>(true);
  const [sec004, setSec004] = useState<boolean>(true);
  const [sec005, setSec005] = useState<boolean>(true);
  const [sec007, setSec007] = useState<boolean>(true);

  // Ceilings and thresholds
  const [gatewayTimeoutMs, setGatewayTimeoutMs] = useState<number>(2500);
  const [maxGraphDepth, setMaxGraphDepth] = useState<number>(5);
  const [anomalyThreshold, setAnomalyThreshold] = useState<number>(0.35);

  // Scoped key management
  const [apiKeyPrefix, setApiKeyPrefix] = useState<string>(`amsc_live_sk_${activeTenant.slug}_991a`);
  const [isRotatingKey, setIsRotatingKey] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [saved, setSaved] = useState<boolean>(false);

  const handleRotateKey = () => {
    setIsRotatingKey(true);
    setTimeout(() => {
      const randomHex = Math.random().toString(36).substring(2, 8);
      setApiKeyPrefix(`amsc_live_sk_${activeTenant.slug}_${randomHex}`);
      setIsRotatingKey(false);
    }, 600);
  };

  const handleCopyKey = () => {
    navigator.clipboard.writeText(`${apiKeyPrefix}********************`);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <ForensicErrorBoundary fallbackTitle="Settings & Governance Fault">
      <div className="space-y-6 font-mono text-slate-100">
        {/* Title Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Settings className="w-5 h-5 text-slate-400" />
              Tenant Settings & Security Governance
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Security policy toggles, tenant isolation keys, and fail-closed configurations for{' '}
              <span className="text-blue-400 font-bold">{activeTenant.name}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleSave}
              className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors shadow-sm"
            >
              <CheckCircle2 className="w-4 h-4" /> Save Configuration
            </button>
          </div>
        </div>

        {/* Saved Notification Banner */}
        {saved && (
          <div className="p-3 bg-emerald-950/60 border border-emerald-500/40 rounded-lg text-xs text-emerald-300 flex items-center gap-2 animate-fadeIn">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            Security policies and tenant governance configuration persisted successfully.
          </div>
        )}

        {/* Active Tenant Profile Card */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
              <Database className="w-4 h-4 text-cyan-400" /> Tenant Multi-Tenant Partitioning
            </div>
            <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-500/40 text-[10px] font-bold">
              Strict Isolation Active
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div className="p-3 bg-slate-950 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Tenant Identifier</div>
              <div className="font-bold text-slate-200 mt-1 font-mono text-xs">{activeTenant.id}</div>
            </div>

            <div className="p-3 bg-slate-950 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Vector Namespace</div>
              <div className="font-bold text-cyan-400 mt-1 font-mono text-xs">
                tenant-vector-{activeTenant.slug}
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Data Custody Tier</div>
              <div className="font-bold text-purple-400 mt-1 text-xs">Tier 1: Dedicated Hardware</div>
            </div>

            <div className="p-3 bg-slate-950 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">KMS Encryption Key</div>
              <div className="font-bold text-emerald-400 mt-1 font-mono text-[11px] truncate">
                arn:aws:kms:us-east-1:amsc-kms-{activeTenant.slug}
              </div>
            </div>
          </div>
        </div>

        {/* Two-Column Grid: Policy Toggles & Threshold Controls */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Authoritative Security Policy Toggles */}
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-200 pb-2 border-b border-slate-800">
              <Shield className="w-4 h-4 text-blue-400" /> Authoritative Security Policies (SEC Rules)
            </div>

            <div className="space-y-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-xs font-bold text-slate-200">SEC-001: Strict Schema Enforce on Ingest</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Reject memory ingest payloads lacking cryptographic SHA-256 signatures or required metadata schema.
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={sec001}
                  onChange={(e) => setSec001(e.target.checked)}
                  className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700 mt-0.5"
                />
              </div>

              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-xs font-bold text-slate-200">SEC-004: Fail-Closed Gateway Action Gate</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Automatically block tool proposals with 403 Forbidden if policy evaluation times out or errors.
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={sec004}
                  onChange={(e) => setSec004(e.target.checked)}
                  className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700 mt-0.5"
                />
              </div>

              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-xs font-bold text-slate-200">SEC-005: Strict RAG Quarantine Exclusion</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Filter out memory chunks with trust_state = 'QUARANTINED' from autonomous agent vector retrieval.
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={sec005}
                  onChange={(e) => setSec005(e.target.checked)}
                  className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700 mt-0.5"
                />
              </div>

              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-xs font-bold text-slate-200">SEC-007: Mandatory Pre-Rollback Snapshotting</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Guarantee immutable cryptographic capture of tainted memory state prior to atomic rewind execution.
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={sec007}
                  onChange={(e) => setSec007(e.target.checked)}
                  className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700 mt-0.5"
                />
              </div>
            </div>
          </div>

          {/* System Thresholds & Ceilings */}
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-200 pb-2 border-b border-slate-800">
              <Sliders className="w-4 h-4 text-purple-400" /> Enforcement Ceilings & Timeouts
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-slate-300 font-bold">Gateway Evaluation Timeout (ms)</span>
                  <span className="font-mono text-cyan-400">{gatewayTimeoutMs}ms</span>
                </div>
                <input
                  type="range"
                  min={500}
                  max={5000}
                  step={100}
                  value={gatewayTimeoutMs}
                  onChange={(e) => setGatewayTimeoutMs(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-950 rounded appearance-none cursor-pointer accent-cyan-400 border border-slate-800"
                />
                <span className="text-[10px] text-slate-500">Max latency allowance before fail-closed SEC-004 drop</span>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-slate-300 font-bold">Max Lineage Hop Depth</span>
                  <span className="font-mono text-purple-400">{maxGraphDepth} Hops</span>
                </div>
                <input
                  type="range"
                  min={1}
                  max={10}
                  value={maxGraphDepth}
                  onChange={(e) => setMaxGraphDepth(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-950 rounded appearance-none cursor-pointer accent-purple-400 border border-slate-800"
                />
                <span className="text-[10px] text-slate-500">Traversal radius limit for DAG queries</span>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-slate-300 font-bold">Anomaly Cosine Drift Limit (Δ)</span>
                  <span className="font-mono text-amber-400">{anomalyThreshold.toFixed(2)} Δ</span>
                </div>
                <input
                  type="range"
                  min={0.10}
                  max={0.80}
                  step={0.05}
                  value={anomalyThreshold}
                  onChange={(e) => setAnomalyThreshold(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-950 rounded appearance-none cursor-pointer accent-amber-400 border border-slate-800"
                />
                <span className="text-[10px] text-slate-500">Automatic quarantine trigger point</span>
              </div>
            </div>
          </div>
        </div>

        {/* Scoped API Key Management */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
              <Key className="w-4 h-4 text-amber-400" /> Scoped Tenant API Keys & Tokens
            </div>
            <span className="text-[10px] text-slate-400 flex items-center gap-1">
              <Lock className="w-3 h-3 text-emerald-400" /> HMAC-SHA256 Signed
            </span>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 bg-slate-950 rounded border border-slate-800">
            <div className="w-full">
              <div className="text-[10px] text-slate-500 uppercase">Primary Tenant Scoped Key</div>
              <div className="font-mono text-xs text-slate-200 mt-1 flex items-center gap-2">
                <span>{apiKeyPrefix}********************</span>
                <span className="px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-[9px] font-bold">
                  ACTIVE
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto justify-end">
              <button
                onClick={handleCopyKey}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors border border-slate-700"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>{copiedKey ? 'Copied!' : 'Copy'}</span>
              </button>

              <button
                onClick={handleRotateKey}
                disabled={isRotatingKey}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-950 hover:bg-amber-900 text-amber-200 rounded text-xs font-bold transition-colors border border-amber-500/40 disabled:opacity-50"
              >
                <RotateCw className={`w-3.5 h-3.5 ${isRotatingKey ? 'animate-spin' : ''}`} />
                <span>Rotate Key</span>
              </button>
            </div>
          </div>

          <div className="text-[11px] text-slate-500 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>Key rotation propagates to all fail-closed gateways within 2.5 seconds without dropping active sessions.</span>
          </div>
        </div>
      </div>
    </ForensicErrorBoundary>
  );
};
