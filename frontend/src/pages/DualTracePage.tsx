import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { Activity, Clock, CornerDownRight } from 'lucide-react';

export const DualTracePage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const [selectedSpan, setSelectedSpan] = useState<string>('span-wire-proposal');

  const EXECUTION_SPANS = [
    {
      id: 'span-ingress-msg',
      time: '10:41:00',
      label: 'Agent Prompt Ingress',
      agent: 'FinOps-01',
      action: 'Process vendor invoice batch #9912',
      memoryRef: 'rec-1044-991b',
      status: 'OK',
    },
    {
      id: 'span-mem-query',
      time: '10:41:01',
      label: 'RAG Retrieval Execution',
      agent: 'FinOps-01',
      action: 'Query: "wiring instructions for vendor ACME Corp"',
      memoryRef: 'rec-8812-441a',
      status: 'TAINTED',
    },
    {
      id: 'span-wire-proposal',
      time: '10:41:02',
      label: 'Protected Tool Proposal',
      agent: 'FinOps-01',
      action: 'tool:execute_wire_transfer($240,000, SWIFT: ATTK-9912)',
      memoryRef: 'rec-8812-441a',
      status: 'BLOCKED',
    },
    {
      id: 'span-gateway-log',
      time: '10:41:03',
      label: 'Security Gateway Interception',
      agent: 'AMSC Gateway',
      action: 'Enforce SEC-002: Tainted memory chunk detected. Returning 403 Forbidden.',
      memoryRef: 'rec-8812-441a',
      status: 'INTERCEPTED',
    },
  ];

  const MEMORY_SPANS = [
    {
      id: 'rec-1044-991b',
      time: 'T - 1d',
      label: 'Corporate Accounting Policy',
      trust: 'TRUSTED',
      hash: '9f86d081884c...',
      status: 'VERIFIED',
    },
    {
      id: 'rec-8812-441a',
      time: 'T - 15m',
      label: 'Vendor Ticket Injection (#9912)',
      trust: 'QUARANTINED',
      hash: '7f83b1657ff1...',
      status: 'COMPROMISED',
    },
  ];

  const activeExecution = EXECUTION_SPANS.find((s) => s.id === selectedSpan) || EXECUTION_SPANS[2];

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Dual Trace Observability Scrubber
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Synchronized correlation between Agent Execution Spans and Memory Retrieval Events for {activeTenant.name}
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
            Trace Context: trace-w3c-4bf92f3577b34da6a3ce929d0e0e4736
          </span>
        </div>
      </div>

      {/* Top Scrubber: Execution Timeline */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
          <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-blue-400" /> Track 1: Agent Execution Timeline
          </span>
          <span className="text-[10px] text-slate-500">Click any span to cross-correlate memory</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
          {EXECUTION_SPANS.map((span) => (
            <div
              key={span.id}
              onClick={() => setSelectedSpan(span.id)}
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                selectedSpan === span.id
                  ? 'bg-blue-950/40 border-blue-500 shadow-md ring-1 ring-blue-500/50'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-[10px] mb-1">
                <span className="text-slate-400 font-semibold">{span.time}</span>
                <span
                  className={`px-1.5 py-0.2 rounded font-bold ${
                    span.status === 'OK'
                      ? 'text-emerald-400'
                      : span.status === 'TAINTED'
                      ? 'text-amber-400'
                      : 'text-red-400 font-extrabold'
                  }`}
                >
                  {span.status}
                </span>
              </div>
              <div className="text-xs font-bold text-slate-100 truncate">{span.label}</div>
              <div className="text-[10px] text-slate-400 mt-1 truncate">{span.action}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Synchronized Bridge Indicator */}
      <div className="flex items-center justify-center">
        <div className="flex items-center gap-2 px-3 py-1 bg-slate-950 border border-slate-800 rounded-full text-[11px] text-cyan-300">
          <CornerDownRight className="w-3.5 h-3.5 text-cyan-400" />
          <span>Synchronized Memory Correlation Link:</span>
          <span className="font-bold text-slate-200">{activeExecution.memoryRef}</span>
        </div>
      </div>

      {/* Bottom Scrubber: Memory Retrieval Timeline */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
          <span className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-emerald-400" /> Track 2: Memory Retrieval & Version Lineage
          </span>
          <span className="text-[10px] text-slate-500">Correlated memory sources</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {MEMORY_SPANS.map((mem) => {
            const isCorrelated = activeExecution.memoryRef === mem.id;
            return (
              <div
                key={mem.id}
                className={`p-4 rounded-lg border transition-all ${
                  isCorrelated
                    ? 'bg-cyan-950/20 border-cyan-500/80 ring-1 ring-cyan-500/50'
                    : 'bg-slate-950 border-slate-800 opacity-60'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-200">{mem.id}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      mem.trust === 'TRUSTED'
                        ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                        : 'bg-red-950/40 border-red-500/50 text-red-300'
                    }`}
                  >
                    {mem.trust}
                  </span>
                </div>
                <div className="text-xs text-slate-300 mb-1">{mem.label}</div>
                <div className="text-[10px] text-slate-500 font-mono">SHA-256: {mem.hash}</div>
                {isCorrelated && (
                  <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px]">
                    <span className="text-cyan-400 font-semibold">Active Ingress Link Verified</span>
                    <button
                      onClick={() =>
                        openInspector({
                          title: `Correlated Memory: ${mem.id}`,
                          type: 'SPAN',
                          id: mem.id,
                          trustState: mem.trust as any,
                          details: { ...mem, correlatedExecutionSpan: activeExecution.id },
                        })
                      }
                      className="text-blue-400 hover:underline"
                    >
                      Inspect in Drawer →
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
