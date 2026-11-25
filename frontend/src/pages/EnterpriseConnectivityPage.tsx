import React, { useState } from 'react';
import {
  Database,
  FolderTree,
  RefreshCw,
  ShieldCheck,
  AlertTriangle,
  Plus,
  Play,
  Pause,
  Ban,
  Search,
  FileText,
  GitMerge,
  Activity,
} from 'lucide-react';
import {
  useEnterpriseConnectors,
  useEnterpriseResources,
  useEnterpriseSyncJobs,
  useEnterpriseClaims,
  useEnterpriseMemoryProvenance,
  useEnterpriseAuditLogs,
  useEnterpriseActions,
} from '@/hooks/useAmscQueries';
import { apiClient } from '@/services/apiClient';
import { ConnectorType, ImpactTrace } from '@/types';

type TabKey = 'connectors' | 'resources' | 'sync' | 'knowledge' | 'provenance' | 'audit';

export const EnterpriseConnectivityPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('connectors');
  const [showOnboard, setShowOnboard] = useState(false);
  const [connName, setConnName] = useState('');
  const [connType, setConnType] = useState<ConnectorType>('FILESYSTEM');
  const [configPath, setConfigPath] = useState('');
  const [maxClass, setMaxClass] = useState<'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED'>('CONFIDENTIAL');
  const [actionError, setActionError] = useState<string | null>(null);
  const [impactTrace, setImpactTrace] = useState<ImpactTrace | null>(null);
  const [resourceFilter, setResourceFilter] = useState('');

  const { data: connectors = [], isLoading: loadingConns } = useEnterpriseConnectors();
  const { data: resources = [] } = useEnterpriseResources();
  const { data: syncJobs = [] } = useEnterpriseSyncJobs();
  const { data: claims = [] } = useEnterpriseClaims();
  const { data: memoryLinks = [] } = useEnterpriseMemoryProvenance();
  const { data: auditLogs = [] } = useEnterpriseAuditLogs();
  const actions = useEnterpriseActions();

  const handleOnboard = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionError(null);
    try {
      const config =
        connType === 'DATABASE'
          ? { db_path: configPath }
          : connType === 'FILESYSTEM' || connType === 'DOCUMENT_REPO' || connType === 'KNOWLEDGE_BASE'
          ? { root_path: configPath }
          : { endpoint: configPath };
      await actions.createConnector.mutateAsync({
        name: connName,
        connector_type: connType,
        auth_mode: 'LOCAL_SCOPED',
        config,
        scope: {
          allowed_operations: ['READ', 'DISCOVER'],
          max_classification: maxClass,
        },
      });
      setConnName('');
      setConfigPath('');
      setShowOnboard(false);
    } catch (err: any) {
      setActionError(err?.message || 'Failed to create connector');
    }
  };

  const handleTraceImpact = async (targetId: string) => {
    setActionError(null);
    try {
      const res = await apiClient.traceEnterpriseImpact(targetId);
      setImpactTrace(res);
      setActiveTab('provenance');
    } catch (err: any) {
      setActionError(err?.message || 'Impact trace failed');
    }
  };

  const statusBadge = (status: string) => {
    const map: Record<string, string> = {
      AUTHORIZED: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      SYNCED: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      COMPLETED: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      CURRENT: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      PENDING_AUTH: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      CHANGED: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      CONFLICTING: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      PAUSED: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
      UNAVAILABLE: 'bg-slate-600/30 text-slate-400 border-slate-600/50',
      REVOKED: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
      QUARANTINED: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
      FAILED: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
      ERROR: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
      INACCESSIBLE: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    };
    const cls = map[status] || 'bg-slate-700/40 text-slate-300 border-slate-600';
    return (
      <span className={`px-2 py-0.5 text-[11px] font-mono rounded border ${cls}`}>
        {status}
      </span>
    );
  };

  const filteredResources = resources.filter(
    (r) =>
      !resourceFilter ||
      r.name.toLowerCase().includes(resourceFilter.toLowerCase()) ||
      r.external_id.toLowerCase().includes(resourceFilter.toLowerCase()) ||
      r.classification.toLowerCase().includes(resourceFilter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <Database className="w-6 h-6 text-blue-400" />
            Enterprise Connectivity &amp; Knowledge Governance
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Authorized data source onboarding, automatic discovery, continuous synchronization, and organizational knowledge intelligence.
          </p>
        </div>
        <button
          onClick={() => setShowOnboard((v) => !v)}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium"
        >
          <Plus className="w-4 h-4" />
          Connect Enterprise Source
        </button>
      </div>

      {actionError && (
        <div className="p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-rose-200 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {actionError}
        </div>
      )}

      {/* Summary KPIs from live backend state */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400 uppercase">Connectors</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{connectors.length}</div>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400 uppercase">Discovered Resources</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{resources.length}</div>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400 uppercase">Sync Jobs</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{syncJobs.length}</div>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400 uppercase">Knowledge Claims</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{claims.length}</div>
        </div>
        <div className="p-4 rounded-xl bg-[#111827] border border-slate-800">
          <div className="text-xs text-slate-400 uppercase">Memory Links</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{memoryLinks.length}</div>
        </div>
      </div>

      {showOnboard && (
        <form onSubmit={handleOnboard} className="p-5 rounded-xl bg-[#111827] border border-slate-700 space-y-4">
          <h2 className="text-base font-semibold text-slate-100">Onboard Enterprise Data Source</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Connector Name</label>
              <input
                required
                value={connName}
                onChange={(e) => setConnName(e.target.value)}
                placeholder="e.g. Acme ERP SQLite"
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-sm text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Connector Type</label>
              <select
                value={connType}
                onChange={(e) => setConnType(e.target.value as ConnectorType)}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-sm text-slate-100"
              >
                <option value="FILESYSTEM">FILESYSTEM</option>
                <option value="DATABASE">DATABASE</option>
                <option value="DOCUMENT_REPO">DOCUMENT_REPO</option>
                <option value="KNOWLEDGE_BASE">KNOWLEDGE_BASE</option>
                <option value="AGENT_FRAMEWORK">AGENT_FRAMEWORK</option>
                <option value="CLOUD_STORAGE">CLOUD_STORAGE</option>
                <option value="INTERNAL_API">INTERNAL_API</option>
                <option value="ENTERPRISE_APP">ENTERPRISE_APP</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Scoped Path / Endpoint</label>
              <input
                value={configPath}
                onChange={(e) => setConfigPath(e.target.value)}
                placeholder="/path/to/db_or_root"
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-sm text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Max Classification Ceiling</label>
              <select
                value={maxClass}
                onChange={(e) => setMaxClass(e.target.value as any)}
                className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-sm text-slate-100"
              >
                <option value="PUBLIC">PUBLIC</option>
                <option value="INTERNAL">INTERNAL</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                <option value="RESTRICTED">RESTRICTED</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowOnboard(false)}
              className="px-3 py-1.5 rounded bg-slate-800 text-slate-300 text-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={actions.createConnector.isPending}
              className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium"
            >
              Create Connector
            </button>
          </div>
        </form>
      )}

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2">
        {(
          [
            ['connectors', 'Connectors & Health'],
            ['resources', 'Discovered Inventory'],
            ['sync', 'Sync Jobs & Failures'],
            ['knowledge', 'Knowledge & Conflicts'],
            ['provenance', 'Memory Provenance & Impact'],
            ['audit', 'Integration Audit'],
          ] as [TabKey, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${
              activeTab === key
                ? 'bg-blue-600/20 text-blue-300 border border-blue-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'connectors' && (
        <div className="space-y-3">
          {loadingConns && <div className="text-sm text-slate-400">Loading connectors...</div>}
          {!loadingConns && connectors.length === 0 && (
            <div className="p-8 text-center rounded-xl bg-[#111827] border border-slate-800 text-slate-400 text-sm">
              No enterprise connectors configured yet. Click &ldquo;Connect Enterprise Source&rdquo; to authorize a database, filesystem, or agent framework.
            </div>
          )}
          {connectors.map((c) => (
            <div key={c.id} className="p-4 rounded-xl bg-[#111827] border border-slate-800 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-100">{c.name}</span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {c.connector_type}
                    </span>
                    {statusBadge(c.status)}
                  </div>
                  <div className="text-xs text-slate-400 mt-1 font-mono">
                    ID: {c.id} | Scope Ceiling: {c.scope_json?.max_classification || 'CONFIDENTIAL'} | Last Sync:{' '}
                    {c.last_sync_at ? new Date(c.last_sync_at).toLocaleString() : 'Never'}
                  </div>
                  {c.last_error && (
                    <div className="text-xs text-rose-300 mt-1">Error: {c.last_error}</div>
                  )}
                </div>
                <div className="flex flex-wrap gap-2">
                  {c.status === 'PENDING_AUTH' && (
                    <button
                      onClick={() => actions.authorizeConnector.mutate({ id: c.id })}
                      className="px-2.5 py-1 rounded bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-1"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" /> Authorize
                    </button>
                  )}
                  {c.status === 'AUTHORIZED' && (
                    <>
                      <button
                        onClick={() => actions.discoverResources.mutate(c.id)}
                        className="px-2.5 py-1 rounded bg-blue-600/20 border border-blue-500/40 text-blue-300 text-xs flex items-center gap-1"
                      >
                        <FolderTree className="w-3.5 h-3.5" /> Discover
                      </button>
                      <button
                        onClick={() => actions.syncConnector.mutate({ id: c.id, strategy: 'INCREMENTAL' })}
                        className="px-2.5 py-1 rounded bg-indigo-600/20 border border-indigo-500/40 text-indigo-300 text-xs flex items-center gap-1"
                      >
                        <RefreshCw className="w-3.5 h-3.5" /> Sync
                      </button>
                      <button
                        onClick={() => actions.lifecycleAction.mutate({ id: c.id, action: 'pause' })}
                        className="px-2.5 py-1 rounded bg-slate-700 text-slate-200 text-xs flex items-center gap-1"
                      >
                        <Pause className="w-3.5 h-3.5" /> Pause
                      </button>
                    </>
                  )}
                  {c.status === 'PAUSED' && (
                    <button
                      onClick={() => actions.lifecycleAction.mutate({ id: c.id, action: 'resume' })}
                      className="px-2.5 py-1 rounded bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-1"
                    >
                      <Play className="w-3.5 h-3.5" /> Resume
                    </button>
                  )}
                  {c.status !== 'REVOKED' && (
                    <button
                      onClick={() => actions.lifecycleAction.mutate({ id: c.id, action: 'revoke' })}
                      className="px-2.5 py-1 rounded bg-rose-600/20 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-1"
                    >
                      <Ban className="w-3.5 h-3.5" /> Revoke
                    </button>
                  )}
                </div>
              </div>
              <div className="text-xs text-slate-400 border-t border-slate-800 pt-2 flex flex-wrap gap-4">
                <span>Observed: {(c.monitoring_coverage_json?.observed_events || []).join(', ') || 'None'}</span>
                <span>Inferred: {(c.monitoring_coverage_json?.inferred_events || []).join(', ') || 'None'}</span>
                <span>Unsupported: {(c.monitoring_coverage_json?.unsupported_events || []).join(', ') || 'None'}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'resources' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-slate-400" />
            <input
              value={resourceFilter}
              onChange={(e) => setResourceFilter(e.target.value)}
              placeholder="Filter resources by name, URI, or classification..."
              className="w-full max-w-md px-3 py-1.5 rounded bg-slate-900 border border-slate-700 text-sm text-slate-100"
            />
          </div>
          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#111827]">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/70 text-slate-400 uppercase">
                <tr>
                  <th className="p-3">Resource</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Classification</th>
                  <th className="p-3">Sync Status</th>
                  <th className="p-3">Version</th>
                  <th className="p-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredResources.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/30">
                    <td className="p-3">
                      <div className="font-medium text-slate-200">{r.name}</div>
                      <div className="text-[11px] font-mono text-slate-500">{r.external_id}</div>
                    </td>
                    <td className="p-3 font-mono text-slate-300">{r.resource_type}</td>
                    <td className="p-3">{statusBadge(r.classification)}</td>
                    <td className="p-3">{statusBadge(r.sync_status)}</td>
                    <td className="p-3 font-mono text-slate-400">{r.source_version || '-'}</td>
                    <td className="p-3 flex gap-2">
                      <button
                        onClick={() => actions.extractMemory.mutate({ resourceId: r.id })}
                        className="px-2 py-1 rounded bg-blue-600/20 text-blue-300 border border-blue-500/30"
                      >
                        Extract Memory
                      </button>
                      <button
                        onClick={() => handleTraceImpact(r.id)}
                        className="px-2 py-1 rounded bg-amber-600/20 text-amber-300 border border-amber-500/30"
                      >
                        Trace Impact
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredResources.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-6 text-center text-slate-500">
                      No discovered resources found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'sync' && (
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#111827]">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/70 text-slate-400 uppercase">
              <tr>
                <th className="p-3">Job ID</th>
                <th className="p-3">Strategy</th>
                <th className="p-3">Status</th>
                <th className="p-3">Discovered / Synced / Changed / Deleted</th>
                <th className="p-3">Started</th>
                <th className="p-3">Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {syncJobs.map((j) => (
                <tr key={j.id}>
                  <td className="p-3 font-mono text-slate-300">{j.id.slice(0, 8)}</td>
                  <td className="p-3 font-mono text-slate-300">{j.strategy}</td>
                  <td className="p-3">{statusBadge(j.status)}</td>
                  <td className="p-3 font-mono text-slate-300">
                    {j.resources_discovered} / {j.resources_synced} / {j.resources_changed} / {j.resources_deleted}
                  </td>
                  <td className="p-3 text-slate-400">{new Date(j.started_at).toLocaleString()}</td>
                  <td className="p-3 text-rose-300">{j.error_message || '-'}</td>
                </tr>
              ))}
              {syncJobs.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-6 text-center text-slate-500">
                    No synchronization jobs executed yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'knowledge' && (
        <div className="space-y-3">
          {claims.map((cl) => (
            <div key={cl.id} className="p-4 rounded-xl bg-[#111827] border border-slate-800 flex flex-wrap justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-blue-400" />
                  <span className="font-semibold text-slate-100">{cl.subject}</span>
                  <span className="text-xs font-mono text-slate-400">[{cl.predicate}]</span>
                  {statusBadge(cl.trust_state)}
                </div>
                <div className="text-sm text-slate-300 mt-1">{cl.object_value}</div>
                <div className="text-xs text-slate-500 mt-1 font-mono">
                  Source: {cl.provenance_json?.external_id} | Version: {cl.provenance_json?.source_version} | Confidence: {cl.confidence}
                  {cl.conflict_group_id ? ` | Conflict Group: ${cl.conflict_group_id.slice(0, 8)}` : ''}
                </div>
              </div>
              <button
                onClick={() => handleTraceImpact(cl.id)}
                className="self-start px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center gap-1"
              >
                <GitMerge className="w-3.5 h-3.5" /> Trace
              </button>
            </div>
          ))}
          {claims.length === 0 && (
            <div className="p-6 text-center rounded-xl bg-[#111827] border border-slate-800 text-slate-500 text-sm">
              No knowledge claims extracted yet. Run synchronization on an authorized connector.
            </div>
          )}
        </div>
      )}

      {activeTab === 'provenance' && (
        <div className="space-y-4">
          {impactTrace && (
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-amber-200">
                  Incident Impact Trace for {impactTrace.target_id}
                </h3>
                <button
                  onClick={() => setImpactTrace(null)}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Dismiss
                </button>
              </div>
              <div className="text-xs text-slate-300">
                Resources: {impactTrace.source_resources.length} | Claims: {impactTrace.affected_claims.length} | Dependent Memories:{' '}
                {impactTrace.dependent_memories.length} | Affected Agents: {impactTrace.affected_agent_ids.join(', ') || 'None'}
              </div>
              <div className="text-xs font-mono text-amber-300">
                Recommended: {impactTrace.recommended_actions.join(', ')}
              </div>
            </div>
          )}

          <div className="space-y-3">
            {memoryLinks.map((m) => (
              <div key={m.id} className="p-4 rounded-xl bg-[#111827] border border-slate-800 flex flex-wrap justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm text-slate-100">Memory {m.memory_record_id}</span>
                    {statusBadge(m.freshness_status)}
                  </div>
                  <div className="text-xs text-slate-400 mt-1 font-mono">
                    Resource: {m.resource_id} | Source Ver: {m.source_version} | Agent: {m.agent_id || 'N/A'} | Snapshot: {m.snapshot_checksum.slice(0, 12)}
                  </div>
                </div>
                <button
                  onClick={() => handleTraceImpact(m.memory_record_id)}
                  className="self-start px-2.5 py-1 rounded bg-blue-600/20 border border-blue-500/40 text-blue-300 text-xs"
                >
                  Trace Impact
                </button>
              </div>
            ))}
            {memoryLinks.length === 0 && (
              <div className="p-6 text-center rounded-xl bg-[#111827] border border-slate-800 text-slate-500 text-sm">
                No enterprise memory provenance links recorded yet.
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'audit' && (
        <div className="space-y-2">
          {auditLogs.map((a) => (
            <div key={a.id} className="p-3 rounded-lg bg-[#111827] border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-slate-400" />
                <span className="font-mono text-slate-200">{a.action}</span>
                {statusBadge(a.status)}
                <span className="text-slate-400">by {a.actor_id}</span>
              </div>
              <span className="text-slate-500 font-mono">{new Date(a.created_at).toLocaleString()}</span>
            </div>
          ))}
          {auditLogs.length === 0 && (
            <div className="p-6 text-center rounded-xl bg-[#111827] border border-slate-800 text-slate-500 text-sm">
              No integration audit events recorded yet.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
