import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { HybridGraphViewer } from '@/components/graph/HybridGraphViewer';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import {
  GitBranch,
  ShieldAlert,
  ShieldCheck,
  Filter,
  Sliders,
  Layers,
  Sparkles,
  Lock,
} from 'lucide-react';

export const KnowledgeGraphPage: React.FC = () => {
  const { activeTenant } = useWorkstationStore();
  const [nodeFilter, setNodeFilter] = useState<'ALL' | 'SOURCES' | 'MEMORIES' | 'AGENTS' | 'GATEWAY_TOOLS'>('ALL');
  const [trustFilter, setTrustFilter] = useState<'ALL' | 'TRUSTED' | 'QUARANTINED' | 'TAINTED'>('ALL');
  const [hopDepth, setHopDepth] = useState<number>(3);

  return (
    <ForensicErrorBoundary fallbackTitle="Knowledge Graph Render Failure">
      <div className="space-y-6 font-mono text-slate-100">
        {/* Title & Tenant Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-cyan-400" />
              Knowledge & Memory Lineage Graph
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Cryptographic DAG and 3D blast-radius topology of knowledge entities for{' '}
              <span className="text-blue-400 font-bold">{activeTenant.name}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              Integrity: <span className="font-mono text-cyan-400">SHA-256 Verified DAG</span>
            </span>
          </div>
        </div>

        {/* Graph Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <Layers className="w-3 h-3 text-cyan-400" /> Total Graph Entities
            </div>
            <div className="text-lg font-bold text-slate-100 mt-1">6 Active Nodes</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Sources, Chunks, Agents, Tools</div>
          </div>

          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <Sliders className="w-3 h-3 text-purple-400" /> Blast-Radius Depth
            </div>
            <div className="text-lg font-bold text-purple-400 mt-1">{hopDepth} Hop Horizon</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Max propagation boundary</div>
          </div>

          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-red-400" /> Tainted Scope
            </div>
            <div className="text-lg font-bold text-red-400 mt-1">2 Nodes Quarantined</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Excluded from Vector RAG</div>
          </div>

          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <ShieldCheck className="w-3 h-3 text-emerald-400" /> Lineage Authority
            </div>
            <div className="text-lg font-bold text-emerald-400 mt-1">SHA-256 Hashed</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Content-addressed provenance</div>
          </div>
        </div>

        {/* Filter Controls & Depth Scrubber */}
        <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg flex flex-col md:flex-row items-center justify-between gap-4 text-xs">
          {/* Node Type Filter */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] text-slate-400 flex items-center gap-1">
              <Filter className="w-3.5 h-3.5 text-cyan-400" /> Entity Type:
            </span>
            {(['ALL', 'SOURCES', 'MEMORIES', 'AGENTS', 'GATEWAY_TOOLS'] as const).map((type) => (
              <button
                key={type}
                onClick={() => setNodeFilter(type)}
                className={`px-2 py-1 rounded text-[11px] font-semibold transition-all ${
                  nodeFilter === type
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {type}
              </button>
            ))}
          </div>

          {/* Trust Filter */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] text-slate-400">Trust State:</span>
            {(['ALL', 'TRUSTED', 'QUARANTINED', 'TAINTED'] as const).map((trust) => (
              <button
                key={trust}
                onClick={() => setTrustFilter(trust)}
                className={`px-2 py-1 rounded text-[11px] font-semibold transition-all ${
                  trustFilter === trust
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {trust}
              </button>
            ))}
          </div>

          {/* Hop Depth Range */}
          <div className="flex items-center gap-2 min-w-[180px]">
            <span className="text-[11px] text-slate-400 shrink-0">Hops:</span>
            <input
              type="range"
              min={1}
              max={5}
              value={hopDepth}
              onChange={(e) => setHopDepth(Number(e.target.value))}
              className="w-24 h-1.5 bg-slate-950 rounded appearance-none cursor-pointer accent-cyan-400 border border-slate-800"
            />
            <span className="text-[11px] font-bold text-cyan-400">{hopDepth}</span>
          </div>
        </div>

        {/* Hybrid 2D/3D Viewer */}
        <HybridGraphViewer
          title="Interactive Lineage & Blast-Radius Topology"
          subtitle="Click any node to open the Inspector Drawer and review SHA-256 signatures, citations, and trust states"
        />

        {/* Security & Lineage Legend */}
        <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg flex flex-wrap items-center justify-between text-[11px] text-slate-400 gap-2">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Verified Trusted Policy
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Quarantined / Tainted Ingress
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span> Autonomous Agent Node
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> Fail-Closed Gateway Action
            </span>
          </div>
          <span className="text-slate-500 flex items-center gap-1">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" /> SEC-005 Auto-Exclusion Active
          </span>
        </div>
      </div>
    </ForensicErrorBoundary>
  );
};
