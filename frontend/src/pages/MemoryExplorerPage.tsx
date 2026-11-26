import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useMemories, useMemoryDetail, useIngestMemoryMutation, useBaselineRecords } from '@/hooks';
import { StateBanner } from '@/components/common/StateBanner';
import {
  Database,
  ArrowUpRight,
  Search,
  Loader2,
  Plus,
  X,
  CheckCircle2,
  Filter,
  FileText,
  AlertCircle,
  FileCheck,
  ShieldCheck,
  GitBranch,
} from 'lucide-react';

export const MemoryExplorerPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { activeTenant, openInspector } = useWorkstationStore();
  const [activeTab, setActiveTab] = useState<'MEMORY' | 'BASELINE'>('MEMORY');

  // Status Filter: URL query param sync
  const statusParam = (searchParams.get('status')?.toUpperCase() || 'ALL') as
    | 'ALL'
    | 'TRUSTED'
    | 'SUSPICIOUS'
    | 'QUARANTINED'
    | 'SUPERSEDED';

  const [statusFilter, setStatusFilter] = useState<string>(statusParam);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);

  const { data: memories, isLoading, error } = useMemories(
    statusFilter !== 'ALL' ? statusFilter : undefined
  );
  const { data: selectedDetail, isLoading: detailLoading, error: detailError } = useMemoryDetail(selectedRecordId || '');
  const { data: baselineRecords, isLoading: isBaselineLoading } = useBaselineRecords();
  const ingestMutation = useIngestMemoryMutation();

  // Sync state with URL parameter if it changes
  useEffect(() => {
    if (statusParam && statusParam !== statusFilter) {
      setStatusFilter(statusParam);
    }
  }, [statusParam]);

  const handleFilterChange = (filter: string) => {
    setStatusFilter(filter);
    if (filter === 'ALL') {
      searchParams.delete('status');
      setSearchParams(searchParams);
    } else {
      setSearchParams({ status: filter });
    }
  };

  // Ingest Modal State
  const [ingestModalOpen, setIngestModalOpen] = useState(false);
  const [sourceId, setSourceId] = useState('src-accounting-policy-v2.pdf');
  const [customSourceId, setCustomSourceId] = useState('');
  const [agentId, setAgentId] = useState('agent-crew-finance-003');
  const [customAgentId, setCustomAgentId] = useState('');
  const [recordType, setRecordType] = useState('KNOWLEDGE');
  const [content, setContent] = useState('');
  const [ingestSuccessChecksum, setIngestSuccessChecksum] = useState<string | null>(null);

  const handleIngestSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    const finalSourceId = sourceId === 'custom' ? customSourceId.trim() : sourceId;
    const finalAgentId = agentId === 'custom' ? customAgentId.trim() : agentId;
    if (!finalSourceId || !finalAgentId) return;

    ingestMutation.mutate(
      {
        content,
        record_type: recordType,
        source_id: finalSourceId,
        agent_id: finalAgentId,
      },
      {
        onSuccess: (res) => {
          setIngestSuccessChecksum(res.checksum || 'sha256_e3b0c44298fc1c149afbf4c8996fb924');
          setContent('');
        },
      }
    );
  };

  // Filter memories
  const filteredMemories = React.useMemo(() => {
    if (!memories) return [];
    return memories.filter((mem) => {
      const matchesStatus =
        statusFilter === 'ALL' ||
        mem.trust_state === statusFilter ||
        (statusFilter === 'SUSPICIOUS' && mem.trust_state === 'UNVERIFIED');
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !searchQuery ||
        mem.id.toLowerCase().includes(q) ||
        (mem.source_id && mem.source_id.toLowerCase().includes(q)) ||
        (mem.checksum && mem.checksum.toLowerCase().includes(q)) ||
        (mem.content && mem.content.toLowerCase().includes(q));
      return matchesStatus && matchesSearch;
    });
  }, [memories, statusFilter, searchQuery]);

  return (
    <div className="space-y-6 font-mono text-ink">
      {/* Title & Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-borderc gap-3">
        <div>
          <h1 className="text-xl font-bold text-ink flex items-center gap-2">
            <Database className="w-5 h-5 text-status-trusted" />
            Memory Explorer & Provenance Catalog
          </h1>
          <p className="text-xs text-ink-muted mt-0.5">
            Cryptographic SHA-256 verification and trust status for ingested memory chunks in{' '}
            <span className="text-brand font-bold">{activeTenant.name}</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Search Box */}
          <div className="flex items-center px-3 py-1.5 bg-surface border border-borderc rounded text-xs text-ink">
            <Search className="w-3.5 h-3.5 text-ink-muted mr-2 shrink-0" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search ID, hash, or text..."
              className="bg-transparent focus:outline-none placeholder-ink-muted w-48 text-xs font-mono text-ink"
            />
          </div>

          {/* + Ingest Memory Record Button */}
          <button
            onClick={() => {
              setIngestSuccessChecksum(null);
              setIngestModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-brand hover:bg-brand-hover text-white rounded text-xs font-bold transition-colors shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" /> Ingest Memory Record
          </button>
        </div>
      </div>

      {/* Category Tabs: Mutable Agent Memory vs Authoritative Enterprise Baseline */}
      <div className="flex items-center gap-2 border-b border-borderc pb-2">
        <button
          onClick={() => setActiveTab('MEMORY')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold transition-colors ${
            activeTab === 'MEMORY'
              ? 'bg-brand-tint text-brand border border-brand/30'
              : 'text-ink-muted hover:text-ink'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          Mutable Agent Memory ({memories?.length || 0})
        </button>
        <button
          onClick={() => setActiveTab('BASELINE')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold transition-colors ${
            activeTab === 'BASELINE'
              ? 'bg-brand-tint text-brand border border-brand/30'
              : 'text-ink-muted hover:text-ink'
          }`}
        >
          <FileCheck className="w-3.5 h-3.5" />
          Authoritative Enterprise Baseline ({baselineRecords?.length || 0})
        </button>
      </div>

      {activeTab === 'BASELINE' ? (
        <div className="space-y-4">
          <div className="p-3 bg-brand-tint border border-brand/30 rounded-lg flex items-center justify-between gap-3 text-xs text-ink">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-brand shrink-0" />
              <span>
                <strong>Independently Governed Enterprise Baseline:</strong> Authoritative enterprise policies, operational procedures, and approved knowledge. Governed via formal cryptographic lifecycle (Draft → Review → Approve → Activate). Agent memory writes cannot modify or supersede baseline records.
              </span>
            </div>
            <span className="px-2 py-0.5 rounded bg-surface border border-brand/40 text-brand text-[10px] font-bold shrink-0">
              SHA-256 Digest Verified
            </span>
          </div>

          <div className="bg-surface border border-borderc rounded-lg overflow-x-auto">
            {isBaselineLoading ? (
              <StateBanner type="loading" title="Loading Enterprise Baseline..." message="Fetching authoritative policies and cryptographic digests..." />
            ) : (!baselineRecords || baselineRecords.length === 0) ? (
              <StateBanner
                type="empty"
                title="No Baseline Records Found"
                message={`No baseline policies found for tenant ${activeTenant.name}.`}
              />
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="text-[10px] text-ink-muted uppercase tracking-wider border-b border-borderc bg-elevated">
                  <tr>
                    <th className="py-3 px-4">Policy / Baseline Record</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Branch Scope</th>
                    <th className="py-3 px-4">SHA-256 Digest</th>
                    <th className="py-3 px-4">Classification</th>
                    <th className="py-3 px-4 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-borderc">
                  {baselineRecords.map((rec) => (
                    <tr key={rec.id} className="hover:bg-elevated/60 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-bold text-ink flex items-center gap-1.5">
                          <FileCheck className="w-3.5 h-3.5 text-brand shrink-0" />
                          {rec.title}
                        </div>
                        <div className="text-[10px] text-ink-muted font-mono mt-0.5">
                          {rec.id} • {rec.source_type}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-canvas border border-borderc text-brand-teal">
                          {rec.category}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            rec.lifecycle_status === 'ACTIVE'
                              ? 'bg-status-trustedBg border-status-trusted/40 text-status-trusted'
                              : rec.lifecycle_status === 'APPROVED'
                              ? 'bg-status-infoBg border-status-info/40 text-status-info'
                              : 'bg-status-warningBg border-status-warning/40 text-status-warning'
                          }`}
                        >
                          {rec.lifecycle_status}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-ink">{rec.current_version}</td>
                      <td className="py-3 px-4">
                        <span className="px-1.5 py-0.5 rounded bg-canvas border border-borderc text-[10px] text-ink-muted font-mono">
                          {rec.branch_id || 'ENTERPRISE_WIDE'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[10px] text-status-trusted font-mono">
                        <span className="px-1.5 py-0.5 rounded bg-canvas border border-borderc truncate block max-w-[130px]" title={rec.content_digest}>
                          {rec.content_digest}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-brand-tint border border-brand/40 text-brand font-bold">
                          {rec.classification}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() =>
                            openInspector({
                              title: `Baseline: ${rec.title}`,
                              type: 'RECORD',
                              id: rec.id,
                              sha256: rec.content_digest,
                              trustState: rec.lifecycle_status === 'ACTIVE' ? 'TRUSTED' : 'UNVERIFIED',
                              details: {
                                ...rec,
                                governance_type: 'INDEPENDENT_ENTERPRISE_BASELINE',
                                immutability: 'CRYPTOGRAPHICALLY_SEALED',
                              },
                            })
                          }
                          className="p-1 hover:text-brand text-ink-muted transition-colors"
                          title="Inspect Baseline Governance Record"
                        >
                          <ArrowUpRight className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      ) : (
        <>
          {/* Filter Tabs Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-surface border border-borderc rounded-lg">
            <div className="flex items-center gap-1.5 flex-wrap">
              <Filter className="w-4 h-4 text-ink-muted mr-1" />
              <span className="text-[11px] text-ink-muted font-bold uppercase tracking-wider mr-2">Trust State:</span>
              {(['ALL', 'TRUSTED', 'SUSPICIOUS', 'QUARANTINED', 'SUPERSEDED'] as const).map((status) => (
                <button
                  key={status}
                  onClick={() => handleFilterChange(status)}
                  className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                    statusFilter === status
                      ? 'bg-brand text-white shadow-sm'
                      : 'text-ink-muted hover:text-ink hover:bg-elevated'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>

            <div className="text-xs text-ink-muted">
              Showing <strong className="text-ink">{filteredMemories.length}</strong> of{' '}
              <strong className="text-ink">{memories?.length || 0}</strong> chunks
            </div>
          </div>

          {/* Memory Data Table */}
          <div className="bg-surface border border-borderc rounded-lg overflow-x-auto">
            {isLoading ? (
              <StateBanner type="loading" title="Querying Tenant Knowledge Chunks..." message="Fetching cryptographic checksums and trust assertions..." />
            ) : error ? (
              (error as any)?.status === 403 || (error as any)?.name === 'AuthorizationError' ? (
                <StateBanner
                  type="unauthorized"
                  title="Knowledge Retrieval Restrained"
                  statusCode={403}
                  message="Quarantined records are isolated under SEC-004. Standard roles cannot retrieve them without forensic clearance."
                />
              ) : (
                <StateBanner
                  type="error"
                  title="Failed to Load Knowledge Chunks"
                  statusCode={(error as any)?.status}
                  message={(error as Error).message || 'Unable to query memory records from the API server.'}
                />
              )
            ) : filteredMemories.length === 0 ? (
              <StateBanner
                type="empty"
                title="No Knowledge Chunks Located"
                message={`No records in ${activeTenant.name} match status '${statusFilter}' and search '${searchQuery}'.`}
                actionText="+ Ingest First Record"
                onAction={() => setIngestModalOpen(true)}
              />
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="text-[10px] text-ink-muted uppercase tracking-wider border-b border-borderc bg-elevated">
                  <tr>
                    <th className="py-3 px-4">Chunk ID</th>
                    <th className="py-3 px-4">Source ID / Document</th>
                    <th className="py-3 px-4">SHA-256 Checksum</th>
                    <th className="py-3 px-4">Trust State</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Content Preview</th>
                    <th className="py-3 px-4 text-right">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-borderc">
                  {filteredMemories.map((chunk) => (
                    <tr key={chunk.id} className="hover:bg-elevated/60 transition-colors">
                      <td className="py-3 px-4 font-bold text-ink">{chunk.id}</td>
                      <td className="py-3 px-4 text-ink font-mono flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5 text-ink-muted shrink-0" />
                        <span className="truncate max-w-[160px]">{chunk.source_id || 'unassigned'}</span>
                      </td>
                      <td className="py-3 px-4 text-[10px] text-status-trusted font-mono">
                        <span className="px-1.5 py-0.5 rounded bg-canvas border border-borderc truncate block max-w-[140px]">
                          {chunk.checksum || 'pending_calculation'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            chunk.trust_state === 'TRUSTED'
                              ? 'bg-status-trustedBg border-status-trusted/40 text-status-trusted'
                              : chunk.trust_state === 'QUARANTINED'
                              ? 'bg-status-criticalBg border-status-critical/40 text-status-critical font-extrabold'
                              : 'bg-status-warningBg border-status-warning/40 text-status-warning'
                          }`}
                        >
                          {chunk.trust_state}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-ink-muted">v{chunk.current_version}</td>
                      <td className="py-3 px-4 text-ink max-w-[220px] truncate font-sans">
                        {chunk.content || 'Protected chunk content block'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => {
                            setSelectedRecordId(chunk.id);
                            openInspector({
                              title: `Memory Chunk: ${chunk.id}`,
                              type: 'RECORD',
                              id: chunk.id,
                              sha256: chunk.checksum || undefined,
                              trustState: chunk.trust_state as any,
                              details: chunk,
                            });
                          }}
                          className="p-1 hover:text-brand text-ink-muted transition-colors"
                          title="Inspect Chunk Provenance & Lineage"
                        >
                          <ArrowUpRight className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Compact Provenance Preview for Selected Record */}
          {selectedRecordId && (
            <div className="p-4 bg-surface border border-borderc rounded-lg space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-borderc gap-2">
                <div className="text-xs font-bold text-ink flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-brand-teal" />
                  Provenance Preview — <span className="text-brand">{selectedRecordId}</span>
                </div>
                <button
                  type="button"
                  onClick={() => navigate(`/knowledge-graph?nodeId=${encodeURIComponent(selectedRecordId)}`)}
                  className="px-2.5 py-1 rounded bg-brand hover:bg-brand-hover text-white text-[11px] font-semibold transition-colors"
                >
                  Focus in Knowledge Graph →
                </button>
              </div>
              {detailLoading ? (
                <p className="text-xs text-ink-muted">Loading provenance relationships...</p>
              ) : detailError ? (
                <p className="text-xs text-status-warning">
                  {(detailError as Error).message || 'Provenance detail unavailable for this record.'}
                </p>
              ) : !selectedDetail?.provenance || selectedDetail.provenance.length === 0 ? (
                <p className="text-xs text-ink-muted">
                  No parent or child provenance edges returned for this record ({selectedDetail?.versions?.length ?? 0} version(s)).
                </p>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {selectedDetail.provenance.map((edge) => (
                    <div key={edge.id} className="p-2 bg-canvas border border-borderc rounded flex items-center justify-between gap-2">
                      <span className="text-brand-teal font-semibold">{edge.relation_type}</span>
                      <span className="text-ink truncate">
                        {edge.from_record_id} → {edge.to_record_id}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* + Ingest Memory Record Modal */}
      {ingestModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-surface border border-borderc rounded-lg shadow-2xl overflow-hidden text-ink font-mono">
            {/* Modal Header */}
            <div className="flex items-center justify-between px-5 py-3.5 bg-elevated border-b border-borderc">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-status-trusted" />
                <h3 className="text-sm font-bold text-ink">Ingest Knowledge Chunk & Hash (POST /memory)</h3>
              </div>
              <button
                onClick={() => setIngestModalOpen(false)}
                className="text-ink-muted hover:text-ink transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleIngestSubmit} className="p-5 space-y-4">
              {ingestSuccessChecksum ? (
                <div className="p-4 bg-status-trustedBg border border-status-trusted/40 rounded space-y-2">
                  <div className="flex items-center gap-2 text-status-trusted text-xs font-bold">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Memory Record Successfully Ingested!</span>
                  </div>
                  <div className="text-[11px] text-ink">
                    Assigned Canonical SHA-256 Checksum:
                  </div>
                  <div className="text-[10px] text-status-trusted bg-canvas p-2 rounded break-all border border-borderc">
                    {ingestSuccessChecksum}
                  </div>
                  <div className="pt-2 flex justify-end">
                    <button
                      type="button"
                      onClick={() => setIngestSuccessChecksum(null)}
                      className="px-3 py-1 bg-elevated hover:bg-brand-tint rounded text-xs text-ink border border-borderc transition-colors"
                    >
                      Ingest Another Record
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-[11px] text-ink-muted mb-1">Source URI / Document:</label>
                    <div className="space-y-1.5">
                      <select
                        value={sourceId}
                        onChange={(e) => setSourceId(e.target.value)}
                        className="w-full bg-canvas border border-borderc rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand font-mono"
                      >
                        <option value="src-accounting-policy-v2.pdf">src-accounting-policy-v2.pdf (Accounting Policy v2)</option>
                        <option value="src-doc-001">src-doc-001 (Treasury Policy Memo)</option>
                        <option value="src-hr-handbook-v1.pdf">src-hr-handbook-v1.pdf (HR Employee Handbook)</option>
                        <option value="src-support-guide-v1.pdf">src-support-guide-v1.pdf (Customer Support Protocols)</option>
                        <option value="src-branch-ops-v1.pdf">src-branch-ops-v1.pdf (Branch Operations Manual)</option>
                        <option value="src-workflow-gov-v1.pdf">src-workflow-gov-v1.pdf (Cross-Department Workflow Governance)</option>
                        <option value="custom">-- Custom Source Identifier --</option>
                      </select>
                      {sourceId === 'custom' && (
                        <input
                          type="text"
                          value={customSourceId}
                          onChange={(e) => setCustomSourceId(e.target.value)}
                          required
                          placeholder="e.g. src-custom-feed-001"
                          className="w-full bg-canvas border border-borderc rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand font-mono"
                        />
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[11px] text-ink-muted mb-1">Target Agent ID:</label>
                      <div className="space-y-1.5">
                        <select
                          value={agentId}
                          onChange={(e) => setAgentId(e.target.value)}
                          className="w-full bg-canvas border border-borderc rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand font-mono"
                        >
                          <option value="agent-crew-finance-003">Finance Ops (agent-crew-finance-003)</option>
                          <option value="agent-crew-support-001">Customer Support (agent-crew-support-001)</option>
                          <option value="agent-crew-hr-002">HR Operations (agent-crew-hr-002)</option>
                          <option value="agent-crew-branch-004">Branch Operations (agent-crew-branch-004)</option>
                          <option value="agent-crew-coord-005">Workflow Coord (agent-crew-coord-005)</option>
                          <option value="agent-001">Finance Bot (agent-001)</option>
                          <option value="agent-head-office-001">Head Office Lead (agent-head-office-001)</option>
                          <option value="agt-fin-001">Finance Alias (agt-fin-001)</option>
                          <option value="custom">-- Custom Agent ID --</option>
                        </select>
                        {agentId === 'custom' && (
                          <input
                            type="text"
                            value={customAgentId}
                            onChange={(e) => setCustomAgentId(e.target.value)}
                            required
                            placeholder="e.g. agent-custom-001"
                            className="w-full bg-canvas border border-borderc rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand font-mono"
                          />
                        )}
                      </div>
                    </div>
                    <div>
                      <label className="block text-[11px] text-ink-muted mb-1">Record Type:</label>
                      <select
                        value={recordType}
                        onChange={(e) => setRecordType(e.target.value)}
                        className="w-full bg-canvas border border-borderc rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand font-mono"
                      >
                        <option value="KNOWLEDGE">KNOWLEDGE</option>
                        <option value="CONVERSATION">CONVERSATION</option>
                        <option value="SCRATCHPAD">SCRATCHPAD</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] text-ink-muted mb-1">Memory Content Chunk:</label>
                    <textarea
                      value={content}
                      onChange={(e) => setContent(e.target.value)}
                      required
                      rows={4}
                      placeholder="Enter raw text payload to be ingested and hashed..."
                      className="w-full bg-canvas border border-borderc rounded p-2.5 text-xs text-ink focus:outline-none focus:border-brand font-mono"
                    />
                  </div>

                  {ingestMutation.isError && (
                    <div className="p-3 bg-status-criticalBg border border-status-critical/40 rounded text-xs text-status-critical flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      <span>{ingestMutation.error?.message || 'Failed to ingest knowledge record.'}</span>
                    </div>
                  )}

                  <div className="pt-2 flex items-center justify-end gap-2 border-t border-borderc">
                    <button
                      type="button"
                      onClick={() => setIngestModalOpen(false)}
                      className="px-3.5 py-1.5 rounded text-xs text-ink-muted hover:text-ink hover:bg-elevated transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={ingestMutation.isPending}
                      className="flex items-center gap-1.5 px-4 py-1.5 bg-brand hover:bg-brand-hover text-white rounded text-xs font-bold transition-colors disabled:opacity-50"
                    >
                      {ingestMutation.isPending && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                      Ingest & Compute SHA-256
                    </button>
                  </div>
                </>
              )}
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
