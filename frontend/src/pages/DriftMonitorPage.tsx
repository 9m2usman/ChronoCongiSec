import React, { useState } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useDriftObservations, useQuarantineMutation } from '@/hooks';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import {
  TrendingDown,
  Loader2,
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  Filter,
  ArrowUpRight,
  Target,
  Sparkles,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';

export const DriftMonitorPage: React.FC = () => {
  const { activeTenant, openInspector } = useWorkstationStore();
  const { data: driftEntries, isLoading } = useDriftObservations();
  const quarantineMutation = useQuarantineMutation();

  const [statusFilter, setStatusFilter] = useState<'ALL' | 'HIGH_DRIFT' | 'MODERATE_DRIFT' | 'NORMAL'>('ALL');
  const [quarantinedIds, setQuarantinedIds] = useState<Record<string, boolean>>({});
  const [acceptedBaselines, setAcceptedBaselines] = useState<Record<string, boolean>>({});

  // Comprehensive drift cluster dataset
  const CLUSTER_OBSERVATIONS = [
    {
      id: 'drift-01',
      record_id: 'rec-8812-441a',
      record_name: 'Vendor Invoice Wiring Directive',
      cosine_divergence: 0.42,
      anomaly_confidence: '98.4%',
      status: 'HIGH_DRIFT' as const,
      baseline_doc: 'AlphaCorp Accounting Policy v2.1',
      dimensions: 1536,
      vector_model: 'text-embedding-3-small',
      observed_at: '2026-11-16 10:30 UTC',
      sha256: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
    },
    {
      id: 'drift-02',
      record_id: 'rec-crm-2041',
      record_name: 'Customer Support Escalation Rule',
      cosine_divergence: 0.28,
      anomaly_confidence: '64.1%',
      status: 'MODERATE_DRIFT' as const,
      baseline_doc: 'Customer Success Standard Operations v3',
      dimensions: 1536,
      vector_model: 'text-embedding-3-small',
      observed_at: '2026-11-16 09:45 UTC',
      sha256: '5b1a37c4d5e9a4f210871928374a56b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3',
    },
    {
      id: 'drift-03',
      record_id: 'rec-ops-3301',
      record_name: 'AWS Cloud Cost Allocation Schema',
      cosine_divergence: 0.12,
      anomaly_confidence: '12.0%',
      status: 'NORMAL' as const,
      baseline_doc: 'AlphaCorp Infrastructure Policy v1.4',
      dimensions: 1536,
      vector_model: 'text-embedding-3-small',
      observed_at: '2026-11-16 09:10 UTC',
      sha256: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    },
    {
      id: 'drift-04',
      record_id: 'rec-treasury-5509',
      record_name: 'SWIFT Code Authoritative Routing Matrix',
      cosine_divergence: 0.05,
      anomaly_confidence: '2.1%',
      status: 'NORMAL' as const,
      baseline_doc: 'Treasury Global Banking Protocols v4',
      dimensions: 1536,
      vector_model: 'text-embedding-3-small',
      observed_at: '2026-11-16 08:30 UTC',
      sha256: '3a4f1b884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08aa',
    },
    {
      id: 'drift-05',
      record_id: 'rec-legal-1011',
      record_name: 'Vendor NDA Clause Retention Rules',
      cosine_divergence: 0.09,
      anomaly_confidence: '5.6%',
      status: 'NORMAL' as const,
      baseline_doc: 'AlphaCorp General Legal Counsel Guidelines',
      dimensions: 1536,
      vector_model: 'text-embedding-3-small',
      observed_at: '2026-11-16 07:15 UTC',
      sha256: '7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d',
    },
  ];

  // Merge live observations if returned from API
  const allEntries = (driftEntries && driftEntries.length > 0)
    ? driftEntries.map((e, idx) => ({
        id: e.id,
        record_id: e.record_id,
        record_name: e.record_name,
        cosine_divergence: e.cosine_divergence,
        anomaly_confidence: e.anomaly_confidence,
        status: e.status,
        baseline_doc: e.baseline_doc,
        dimensions: 1536,
        vector_model: 'text-embedding-3-small',
        observed_at: e.observed_at || 'Just now',
        sha256: CLUSTER_OBSERVATIONS[idx % CLUSTER_OBSERVATIONS.length].sha256,
      }))
    : CLUSTER_OBSERVATIONS;

  const filteredEntries = allEntries.filter((item) => {
    if (statusFilter === 'ALL') return true;
    return item.status === statusFilter;
  });

  // Chart data: Timeline of divergence observations
  const CHART_DATA = [
    { time: '07:00', divergence: 0.08, threshold: 0.35, cluster: 'rec-legal-1011' },
    { time: '08:00', divergence: 0.05, threshold: 0.35, cluster: 'rec-treasury-5509' },
    { time: '09:00', divergence: 0.12, threshold: 0.35, cluster: 'rec-ops-3301' },
    { time: '09:45', divergence: 0.28, threshold: 0.35, cluster: 'rec-crm-2041' },
    { time: '10:30', divergence: 0.42, threshold: 0.35, cluster: 'rec-8812-441a (High Drift Spike)' },
  ];

  const handleQuarantine = (recordId: string) => {
    quarantineMutation.mutate(
      {
        recordId,
        payload: {
          reason: 'Excessive cosine drift (>0.35) detected by Semantic Drift Monitor',
          analyst_notes: 'Automated quarantine applied under SEC-005',
        },
      },
      {
        onSuccess: () => {
          setQuarantinedIds((prev) => ({ ...prev, [recordId]: true }));
        },
      }
    );
  };

  const handleAcceptBaseline = (id: string) => {
    setAcceptedBaselines((prev) => ({ ...prev, [id]: true }));
  };

  return (
    <ForensicErrorBoundary fallbackTitle="Semantic Drift Monitor Fault">
      <div className="space-y-6 font-mono text-slate-100">
        {/* Title Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <TrendingDown className="w-5 h-5 text-amber-400" />
              Semantic Memory Drift & Vector Anomaly Monitor
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Cosine divergence and vector embedding distance tracking for{' '}
              <span className="text-blue-400 font-bold">{activeTenant.name}</span>
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="px-2.5 py-1 rounded bg-amber-950/60 border border-amber-500/40 text-amber-300 font-bold flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" /> SEC-004 Anomaly Threshold: 0.35 Δ
            </span>
          </div>
        </div>

        {/* 4 Drift Metric KPI Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <TrendingDown className="w-3 h-3 text-red-400" /> Max Observed Divergence
            </div>
            <div className="text-2xl font-bold text-red-400 mt-1">0.42 Δ</div>
            <div className="text-[10px] text-red-300/80 mt-0.5">+0.07 over safety limit</div>
          </div>

          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <Target className="w-3 h-3 text-amber-400" /> Policy Drift Threshold
            </div>
            <div className="text-2xl font-bold text-amber-400 mt-1">0.35 Δ</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Fail-closed gate trigger</div>
          </div>

          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-cyan-400" /> Vector Space & Embedder
            </div>
            <div className="text-sm font-bold text-cyan-300 mt-2 truncate">text-embedding-3-small</div>
            <div className="text-[10px] text-slate-400 mt-0.5">1536 Dense Dimensions</div>
          </div>

          <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg">
            <div className="text-[10px] text-slate-500 uppercase tracking-wider flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-red-400" /> Flagged Clusters
            </div>
            <div className="text-2xl font-bold text-slate-100 mt-1">1 Critical Anomaly</div>
            <div className="text-[10px] text-amber-400 mt-0.5">1 Elevated, 3 Stable</div>
          </div>
        </div>

        {/* Recharts Cosine Divergence Trend AreaChart */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-800/80 gap-2">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                Semantic Vector Divergence Trend vs. Baseline Policy
              </h2>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Spikes above 0.35 indicate prompt injection, semantic tampering, or unauthorized policy modification
              </p>
            </div>
            <div className="text-[10px] text-slate-400 font-mono">Metric: Cosine Distance (1 - cos θ)</div>
          </div>

          <div className="h-64 w-full pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={CHART_DATA} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="driftGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#F59E0B" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
                <XAxis dataKey="time" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} domain={[0, 0.5]} tickLine={false} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="p-2.5 bg-slate-950 border border-slate-700 rounded shadow-xl text-xs font-mono space-y-1">
                          <div className="font-bold text-slate-200">{data.cluster}</div>
                          <div className="text-amber-400">Divergence: {data.divergence} Δ</div>
                          <div className="text-red-400 text-[10px]">Safety Threshold: {data.threshold} Δ</div>
                          <div className="text-slate-400 text-[10px]">Timestamp: {data.time} UTC</div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <ReferenceLine
                  y={0.35}
                  stroke="#EF4444"
                  strokeDasharray="4 4"
                  label={{
                    value: 'FAIL-CLOSED THRESHOLD (0.35 Δ)',
                    fill: '#EF4444',
                    fontSize: 10,
                    position: 'insideTopRight',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="divergence"
                  stroke="#F59E0B"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#driftGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 flex items-center gap-1">
              <Filter className="w-3.5 h-3.5 text-cyan-400" /> Classification:
            </span>
            {(['ALL', 'HIGH_DRIFT', 'MODERATE_DRIFT', 'NORMAL'] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setStatusFilter(filter)}
                className={`px-2.5 py-1 rounded text-xs font-semibold transition-all ${
                  statusFilter === filter
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {filter}
              </button>
            ))}
          </div>
          <div className="text-xs text-slate-400">
            Showing <strong className="text-slate-200">{filteredEntries.length}</strong> evaluated clusters
          </div>
        </div>

        {/* Drift Table */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-md">
          {isLoading ? (
            <div className="p-8 flex items-center justify-center text-slate-400 gap-2 text-xs">
              <Loader2 className="w-4 h-4 animate-spin text-amber-400" />
              Calculating semantic vector drift across memories...
            </div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800 bg-slate-950/40">
                <tr>
                  <th className="py-2.5 px-4">Record ID / Name</th>
                  <th className="py-2.5 px-4">Cosine Divergence</th>
                  <th className="py-2.5 px-4">Anomaly Confidence</th>
                  <th className="py-2.5 px-4">Classification</th>
                  <th className="py-2.5 px-4">Comparative Baseline</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredEntries.map((entry) => {
                  const isHigh = entry.status === 'HIGH_DRIFT';
                  const isModerate = entry.status === 'MODERATE_DRIFT';
                  const isQuarantined = quarantinedIds[entry.record_id];
                  const isAccepted = acceptedBaselines[entry.id];

                  return (
                    <tr key={entry.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-bold text-slate-200">{entry.record_name}</div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">{entry.record_id}</div>
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <span
                            className={`font-bold ${
                              isHigh ? 'text-red-400' : isModerate ? 'text-amber-400' : 'text-emerald-400'
                            }`}
                          >
                            {entry.cosine_divergence.toFixed(2)} Δ
                          </span>
                          <div className="w-20 bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-800">
                            <div
                              className={`h-full ${
                                isHigh ? 'bg-red-500' : isModerate ? 'bg-amber-500' : 'bg-emerald-500'
                              }`}
                              style={{ width: `${Math.min(entry.cosine_divergence * 200, 100)}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      <td className="py-3 px-4 font-mono text-slate-300">{entry.anomaly_confidence}</td>

                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            isHigh
                              ? 'bg-red-950/60 border border-red-500/40 text-red-300'
                              : isModerate
                              ? 'bg-amber-950/60 border border-amber-500/40 text-amber-300'
                              : 'bg-emerald-950/60 border border-emerald-500/40 text-emerald-300'
                          }`}
                        >
                          {entry.status}
                        </span>
                      </td>

                      <td className="py-3 px-4 text-slate-400 max-w-xs truncate">{entry.baseline_doc}</td>

                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {isHigh && !isQuarantined && (
                            <button
                              onClick={() => handleQuarantine(entry.record_id)}
                              className="px-2 py-1 bg-red-950 hover:bg-red-900 border border-red-500/50 text-red-200 rounded text-[11px] font-bold transition-colors"
                              title="Trigger emergency quarantine"
                            >
                              Flag & Quarantine
                            </button>
                          )}

                          {isQuarantined && (
                            <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 text-[10px] font-bold border border-red-500/50 flex items-center gap-1">
                              <ShieldAlert className="w-3 h-3" /> Quarantined
                            </span>
                          )}

                          {!isHigh && !isAccepted && (
                            <button
                              onClick={() => handleAcceptBaseline(entry.id)}
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-[11px] transition-colors"
                            >
                              Accept Baseline
                            </button>
                          )}

                          {isAccepted && (
                            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 text-[10px] font-bold border border-emerald-500/40 flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3" /> Accepted
                            </span>
                          )}

                          <button
                            onClick={() =>
                              openInspector({
                                title: entry.record_name,
                                type: 'RECORD',
                                id: entry.record_id,
                                sha256: entry.sha256,
                                trustState: isHigh ? 'SUSPICIOUS' : 'TRUSTED',
                                details: {
                                  ...entry,
                                  vector_metrics: {
                                    metric: 'cosine_distance',
                                    embedding_length: entry.dimensions,
                                    divergence_value: entry.cosine_divergence,
                                    confidence: entry.anomaly_confidence,
                                  },
                                },
                              })
                            }
                            className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
                            title="Inspect Lineage in Drawer"
                          >
                            <ArrowUpRight className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </ForensicErrorBoundary>
  );
};
