import React, { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { useKnowledgeGraph } from '@/hooks';
import { HybridGraphViewer } from '@/components/graph/HybridGraphViewer';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import { StatusBadge } from '@/components/common/StatusBadge';
import { HighlightMode } from '@/components/graph/Graph2DView';
import {
  ClusterMode,
  computeGraphClusters,
  computeTopologyStats,
} from '@/utils/graphClustering';
import { KnowledgeGraphNode } from '@/types';
import {
  GitBranch,
  Filter,
  Search,
  RotateCcw,
  Lock,
  ExternalLink,
  History,
  Database,
  ArrowRight,
  Info,
  Layers,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

type EntityFilter = 'ALL' | 'SOURCES' | 'MEMORIES' | 'AGENTS';
type TrustFilter = 'ALL' | 'TRUSTED' | 'UNVERIFIED' | 'SUSPICIOUS' | 'QUARANTINED' | 'SUPERSEDED';

export const KnowledgeGraphPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { activeTenant } = useWorkstationStore();
  const [nodeFilter, setNodeFilter] = useState<EntityFilter>('ALL');
  const [trustFilter, setTrustFilter] = useState<TrustFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [hopDepth, setHopDepth] = useState<number>(3);
  const urlNodeId = searchParams.get('nodeId');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(() => urlNodeId);
  const [fitViewSignal, setFitViewSignal] = useState<number>(0);
  const [clusterMode, setClusterMode] = useState<ClusterMode>('NONE');
  const [highlightMode, setHighlightMode] = useState<HighlightMode>('NONE');
  const [focusedClusterId, setFocusedClusterId] = useState<string | null>(null);
  const [collapsedClusterIds, setCollapsedClusterIds] = useState<Set<string>>(new Set());
  const prevTenantIdRef = useRef(activeTenant.id);

  const { data: graphData, isLoading, error } = useKnowledgeGraph(hopDepth);

  const selectNode = useCallback(
    (nodeId: string | null) => {
      setSelectedNodeId(nodeId);
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (nodeId) next.set('nodeId', nodeId);
          else next.delete('nodeId');
          return next;
        },
        { replace: true }
      );
    },
    [setSearchParams]
  );

  // Sync from URL ?nodeId= changes without overriding initial mount
  useEffect(() => {
    if (urlNodeId !== selectedNodeId) {
      setSelectedNodeId(urlNodeId);
    }
  }, [urlNodeId]);

  // Clear selection on Escape
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        selectNode(null);
        setFocusedClusterId(null);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [selectNode]);

  // Reset selection & cluster state ONLY when tenant actually switches (preserving initial ?nodeId= mount)
  useEffect(() => {
    if (prevTenantIdRef.current !== activeTenant.id) {
      prevTenantIdRef.current = activeTenant.id;
      selectNode(null);
      setFocusedClusterId(null);
      setCollapsedClusterIds(new Set());
    }
  }, [activeTenant.id, selectNode]);

  const filteredGraph = useMemo(() => {
    if (!graphData) return undefined;
    const q = searchQuery.trim().toLowerCase();
    const filteredNodes = graphData.nodes.filter((node) => {
      const rt = (node.record_type || '').toUpperCase();
      const ts = (node.trust_state || '').toUpperCase();
      const matchesType =
        nodeFilter === 'ALL' ||
        (nodeFilter === 'SOURCES' && (rt.includes('SOURCE') || rt.includes('DOCUMENT'))) ||
        (nodeFilter === 'MEMORIES' && !rt.includes('AGENT') && !rt.includes('SOURCE') && !rt.includes('DOCUMENT')) ||
        (nodeFilter === 'AGENTS' && (Boolean(node.agent_id) || rt.includes('AGENT')));
      const matchesTrust = trustFilter === 'ALL' || ts === trustFilter;
      const matchesSearch =
        !q ||
        node.id.toLowerCase().includes(q) ||
        rt.toLowerCase().includes(q) ||
        ts.toLowerCase().includes(q) ||
        (node.agent_id && node.agent_id.toLowerCase().includes(q));
      return matchesType && matchesTrust && matchesSearch;
    });
    const allowedIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = graphData.edges.filter(
      (e) => allowedIds.has(e.from_record_id) && allowedIds.has(e.to_record_id)
    );
    return {
      ...graphData,
      nodes: filteredNodes,
      edges: filteredEdges,
    };
  }, [graphData, nodeFilter, trustFilter, searchQuery]);

  const selectedNode: KnowledgeGraphNode | null = useMemo(() => {
    if (!selectedNodeId || !filteredGraph) return null;
    return filteredGraph.nodes.find((n) => n.id === selectedNodeId) || null;
  }, [selectedNodeId, filteredGraph]);

  const connectedRelationships = useMemo(() => {
    if (!selectedNode || !filteredGraph) return [];
    const nodeMap = new Map(filteredGraph.nodes.map((n) => [n.id, n]));
    return filteredGraph.edges
      .filter((e) => e.from_record_id === selectedNode.id || e.to_record_id === selectedNode.id)
      .map((e) => {
        const isOutgoing = e.from_record_id === selectedNode.id;
        const peerId = isOutgoing ? e.to_record_id : e.from_record_id;
        return {
          edge: e,
          direction: isOutgoing ? ('OUTGOING' as const) : ('INCOMING' as const),
          peer: nodeMap.get(peerId) || null,
          peerId,
        };
      });
  }, [selectedNode, filteredGraph]);

  const topologyStats = useMemo(
    () => computeTopologyStats(filteredGraph?.nodes || [], filteredGraph?.edges || []),
    [filteredGraph]
  );

  const { clusters, nodeToClusterId } = useMemo(
    () => computeGraphClusters(filteredGraph, clusterMode),
    [filteredGraph, clusterMode]
  );

  const focusedCluster = useMemo(
    () => (focusedClusterId ? clusters.find((c) => c.id === focusedClusterId) || null : null),
    [focusedClusterId, clusters]
  );

  const totalNodeCount = filteredGraph?.nodes.length ?? 0;
  const totalEdgeCount = filteredGraph?.edges.length ?? 0;
  const quarantinedNodeCount = (filteredGraph?.nodes || []).filter(
    (n) => n.trust_state === 'QUARANTINED'
  ).length;

  const toggleClusterCollapse = (clusterId: string) => {
    setCollapsedClusterIds((prev) => {
      const next = new Set(prev);
      if (next.has(clusterId)) next.delete(clusterId);
      else next.add(clusterId);
      return next;
    });
  };

  const handleReturnToFullGraph = () => {
    setClusterMode('NONE');
    setHighlightMode('NONE');
    setFocusedClusterId(null);
    setCollapsedClusterIds(new Set());
    selectNode(null);
    setFitViewSignal((s) => s + 1);
  };

  const handleResetAll = () => {
    setNodeFilter('ALL');
    setTrustFilter('ALL');
    setSearchQuery('');
    setHopDepth(3);
    handleReturnToFullGraph();
  };

  return (
    <ForensicErrorBoundary fallbackTitle="Knowledge Graph Render Failure">
      <div className="space-y-4 font-mono text-ink">
        {/* Compact Top Investigation Toolbar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-3 border-b border-borderc gap-3">
          <div>
            <h1 className="text-xl font-bold text-ink flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-brand-teal shrink-0" />
              Knowledge &amp; Memory Lineage Graph
            </h1>
            <p className="text-xs text-ink-muted mt-0.5">
              Interactive provenance DAG for <span className="text-brand font-bold">{activeTenant.name}</span>
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search Node Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-ink-muted absolute left-2.5 top-2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search node ID, type, agent..."
                aria-label="Search graph nodes"
                className="w-56 bg-surface border border-borderc rounded pl-8 pr-3 py-1.5 text-xs text-ink placeholder-ink-muted focus:outline-none focus:border-brand"
              />
            </div>

            <button
              type="button"
              onClick={handleResetAll}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-surface border border-borderc hover:border-brand text-xs text-ink transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5 text-brand" /> Reset
            </button>

            <span className="px-2.5 py-1.5 rounded bg-surface border border-borderc text-[11px] text-ink flex items-center gap-1.5">
              <Lock className="w-3 h-3 text-status-trusted shrink-0" />
              {graphData && !graphData.complete
                ? `Truncated${graphData.truncated_reason ? `: ${graphData.truncated_reason}` : ''}`
                : 'Complete Provenance Projection'}
            </span>
          </div>
        </div>

        {/* 3-Pane Workstation Grid: Left Controls | Center Graph | Right Inspector */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Left Filter & Metrics Rail */}
          <aside className="lg:col-span-3 bg-surface border border-borderc rounded-lg p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-borderc pb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-ink flex items-center gap-1.5">
                <Filter className="w-3.5 h-3.5 text-brand-teal" /> Graph Controls
              </span>
              <span className="text-[10px] text-ink-muted">{hopDepth} Hop{hopDepth === 1 ? '' : 's'}</span>
            </div>

            {/* Summary Counts */}
            <div className="grid grid-cols-3 gap-1.5 text-center">
              <div className="p-1.5 bg-canvas border border-borderc rounded min-w-0">
                <div className="text-sm font-bold text-ink">{isLoading ? '—' : totalNodeCount}</div>
                <div className="text-[10px] text-ink-muted">Nodes</div>
              </div>
              <div className="p-1.5 bg-canvas border border-borderc rounded min-w-0">
                <div className="text-sm font-bold text-brand-teal">{isLoading ? '—' : totalEdgeCount}</div>
                <div className="text-[10px] text-ink-muted">Edges</div>
              </div>
              <div className="p-1.5 bg-canvas border border-borderc rounded min-w-0">
                <div className="text-sm font-bold text-status-critical">{isLoading ? '—' : quarantinedNodeCount}</div>
                <div className="text-[9px] text-ink-muted whitespace-nowrap">Quarantined</div>
              </div>
            </div>

            {/* Entity Type Filter */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-bold uppercase tracking-wider text-ink-muted">Entity Type</div>
              <div className="flex flex-wrap gap-1.5">
                {(['ALL', 'SOURCES', 'MEMORIES', 'AGENTS'] as const).map((type) => (
                  <button
                    key={type}
                    type="button"
                    onClick={() => setNodeFilter(type)}
                    className={`px-2 py-1 rounded text-[11px] font-semibold transition-colors ${
                      nodeFilter === type
                        ? 'bg-brand text-white shadow-sm'
                        : 'bg-canvas border border-borderc text-ink-muted hover:text-ink'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            {/* Trust State Filter */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-bold uppercase tracking-wider text-ink-muted">Trust State</div>
              <div className="flex flex-wrap gap-1.5">
                {(['ALL', 'TRUSTED', 'UNVERIFIED', 'SUSPICIOUS', 'QUARANTINED', 'SUPERSEDED'] as const).map((trust) => (
                  <button
                    key={trust}
                    type="button"
                    onClick={() => setTrustFilter(trust)}
                    className={`px-2 py-1 rounded text-[11px] font-semibold transition-colors ${
                      trustFilter === trust
                        ? 'bg-brand-teal text-white shadow-sm'
                        : 'bg-canvas border border-borderc text-ink-muted hover:text-ink'
                    }`}
                  >
                    {trust}
                  </button>
                ))}
              </div>
            </div>

            {/* Hop Depth Slider */}
            <div className="space-y-1.5 pt-1 border-t border-borderc">
              <div className="flex items-center justify-between text-[11px]">
                <span className="font-bold uppercase tracking-wider text-ink-muted">Blast-Radius Depth</span>
                <span className="font-bold text-brand-teal">{hopDepth} Hops</span>
              </div>
              <input
                type="range"
                min={1}
                max={5}
                value={hopDepth}
                aria-label="Graph Hop Depth"
                onChange={(e) => setHopDepth(Number(e.target.value))}
                className="w-full h-1.5 bg-canvas rounded appearance-none cursor-pointer accent-brand-teal border border-borderc"
              />
            </div>

            {/* Clustering & Topology Analysis */}
            <div className="space-y-2 pt-2 border-t border-borderc">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase tracking-wider text-ink-muted flex items-center gap-1">
                  <Layers className="w-3 h-3 text-brand" /> Clustering
                </span>
                {(clusterMode !== 'NONE' || highlightMode !== 'NONE' || focusedClusterId) && (
                  <button
                    type="button"
                    onClick={handleReturnToFullGraph}
                    className="text-[10px] text-brand-teal hover:underline"
                  >
                    Full Graph
                  </button>
                )}
              </div>

              <div className="grid grid-cols-2 gap-1.5">
                {([
                  { id: 'NONE', label: 'None' },
                  { id: 'CONNECTED_COMPONENTS', label: 'Components' },
                  { id: 'ENTITY_TYPE', label: 'Entity Type' },
                  { id: 'TRUST_STATE', label: 'Trust State' },
                ] as const).map((mode) => (
                  <button
                    key={mode.id}
                    type="button"
                    onClick={() => {
                      setClusterMode(mode.id);
                      setFocusedClusterId(null);
                      setCollapsedClusterIds(new Set());
                    }}
                    className={`px-2 py-1 rounded text-[11px] font-semibold transition-colors ${
                      clusterMode === mode.id
                        ? 'bg-brand text-white shadow-sm'
                        : 'bg-canvas border border-borderc text-ink-muted hover:text-ink'
                    }`}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>

              {/* Analytical Highlighting */}
              <div className="text-[10px] font-bold uppercase tracking-wider text-ink-muted pt-1">
                Topology Highlights
              </div>
              <div className="flex flex-wrap gap-1">
                {([
                  { id: 'NONE', label: 'All' },
                  { id: 'ISOLATED', label: `Isolated (${topologyStats.isolatedNodeIds.size})` },
                  { id: 'HUBS', label: `Hubs (${topologyStats.hubNodeIds.size})` },
                  { id: 'FLAGGED', label: 'Flagged' },
                ] as const).map((hl) => (
                  <button
                    key={hl.id}
                    type="button"
                    onClick={() => setHighlightMode(hl.id)}
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-colors ${
                      highlightMode === hl.id
                        ? 'bg-brand-teal text-white'
                        : 'bg-canvas border border-borderc text-ink-muted hover:text-ink'
                    }`}
                  >
                    {hl.label}
                  </button>
                ))}
              </div>

              {/* Cluster List (Focus / Expand & Collapse) */}
              {clusterMode !== 'NONE' && clusters.length > 0 && (
                <div className="space-y-1.5 pt-1 max-h-48 overflow-y-auto pr-1">
                  <div className="text-[10px] text-ink-muted">
                    Analytical Groups ({clusters.length}) — not security verdicts
                  </div>
                  {clusters.map((c) => {
                    const isFocused = focusedClusterId === c.id;
                    const isCollapsed = collapsedClusterIds.has(c.id);
                    return (
                      <div
                        key={c.id}
                        className={`p-2 rounded border text-[11px] flex items-center justify-between gap-1 ${
                          isFocused
                            ? 'bg-brand-tint border-brand'
                            : 'bg-canvas border-borderc'
                        }`}
                      >
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedNodeId(null);
                            setFocusedClusterId(isFocused ? null : c.id);
                          }}
                          className="min-w-0 flex-1 text-left"
                        >
                          <div className="font-semibold text-ink truncate" title={c.label}>
                            {c.label}
                          </div>
                          <div className="text-[9px] text-ink-muted flex items-center gap-1.5">
                            <span>{c.members.length} nodes</span>
                            {c.crossBoundaryEdgeCount > 0 && (
                              <span className="text-brand-teal">{c.crossBoundaryEdgeCount} cross</span>
                            )}
                            {c.hasFlaggedTrust && (
                              <span className="text-status-warning font-bold">flagged</span>
                            )}
                          </div>
                        </button>
                        <button
                          type="button"
                          onClick={() => toggleClusterCollapse(c.id)}
                          className="p-1 rounded hover:bg-elevated text-ink-muted hover:text-ink shrink-0"
                          title={isCollapsed ? 'Expand cluster nodes' : 'Collapse cluster'}
                          aria-label={isCollapsed ? `Expand ${c.label}` : `Collapse ${c.label}`}
                        >
                          {isCollapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Compact Legend */}
            <div className="pt-2 border-t border-borderc space-y-1.5 text-[10px] text-ink-muted">
              <div className="font-bold uppercase tracking-wider">Node Shapes &amp; Trust</div>
              <div>• Document / Source: Left-bordered block</div>
              <div>• Memory Record: Rounded card</div>
              <div>• Agent Attribution: Pill badge</div>
              <div className="flex flex-wrap gap-2 pt-1">
                <span className="text-status-trusted">■ TRUSTED</span>
                <span className="text-status-warning">■ SUSPICIOUS</span>
                <span className="text-status-critical">■ QUARANTINED</span>
              </div>
            </div>
          </aside>

          {/* Center Graph Canvas */}
          <section className="lg:col-span-6 min-w-0">
            <HybridGraphViewer
              title="Provenance & Blast-Radius Topology"
              subtitle="Pan, zoom, drag nodes, or click a node/cluster to highlight connected lineage"
              graphData={filteredGraph}
              isLoading={isLoading}
              error={error}
              selectedNodeId={selectedNodeId}
              onSelectNode={(node) => selectNode(node?.id ?? null)}
              fitViewSignal={fitViewSignal}
              onFitView={() => setFitViewSignal((s) => s + 1)}
              clusterMode={clusterMode}
              clusters={clusters}
              nodeToClusterId={nodeToClusterId}
              collapsedClusterIds={collapsedClusterIds}
              focusedClusterId={focusedClusterId}
              onSelectCluster={(cluster) => setFocusedClusterId(cluster?.id ?? null)}
              highlightMode={highlightMode}
              topologyStats={topologyStats}
            />
          </section>

          {/* Right Contextual Inspector */}
          <aside className="lg:col-span-3 bg-surface border border-borderc rounded-lg p-4 space-y-4" aria-label="Node Inspector">
            <div className="flex items-center justify-between border-b border-borderc pb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-ink flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-brand" />{' '}
                {selectedNode ? 'Node Inspector' : focusedCluster ? 'Cluster Inspector' : 'Node Inspector'}
              </span>
              {(selectedNode || focusedCluster || selectedNodeId) && (
                <button
                  type="button"
                  onClick={() => {
                    if (selectedNode || selectedNodeId) selectNode(null);
                    else setFocusedClusterId(null);
                  }}
                  className="text-[10px] text-ink-muted hover:text-ink"
                >
                  Clear
                </button>
              )}
            </div>

            {!selectedNode && focusedCluster ? (
              <div className="space-y-3 text-xs">
                <div className="p-2 rounded bg-canvas border border-borderc text-[10px] text-ink-muted">
                  Analytical grouping only — not a security verdict. Confirmed trust states are shown per member below.
                </div>

                <div>
                  <div className="text-[10px] text-ink-muted uppercase">Cluster Label</div>
                  <div className="font-bold text-ink mt-0.5">{focusedCluster.label}</div>
                </div>

                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="p-2 bg-canvas border border-borderc rounded">
                    <div className="font-bold text-ink">{focusedCluster.members.length}</div>
                    <div className="text-[9px] text-ink-muted">Members</div>
                  </div>
                  <div className="p-2 bg-canvas border border-borderc rounded">
                    <div className="font-bold text-ink">{focusedCluster.internalEdgeCount}</div>
                    <div className="text-[9px] text-ink-muted">Internal</div>
                  </div>
                  <div className="p-2 bg-canvas border border-borderc rounded">
                    <div className="font-bold text-brand-teal">{focusedCluster.crossBoundaryEdgeCount}</div>
                    <div className="text-[9px] text-ink-muted">Cross-Edge</div>
                  </div>
                </div>

                <div>
                  <div className="text-[10px] text-ink-muted uppercase mb-1">Entity-Type Distribution</div>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(focusedCluster.entityTypeCounts).map(([rt, count]) => (
                      <span key={rt} className="px-2 py-0.5 rounded bg-canvas border border-borderc text-[10px] text-ink">
                        {rt}: {count}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="text-[10px] text-ink-muted uppercase mb-1">Trust-State Distribution</div>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(focusedCluster.trustStateCounts).map(([ts, count]) => (
                      <span key={ts} className="px-2 py-0.5 rounded bg-canvas border border-borderc text-[10px] text-ink">
                        {ts}: {count}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => toggleClusterCollapse(focusedCluster.id)}
                    className="flex-1 px-2.5 py-1.5 rounded bg-canvas border border-borderc hover:border-brand text-[11px] font-semibold text-ink"
                  >
                    {collapsedClusterIds.has(focusedCluster.id) ? 'Expand to Nodes' : 'Collapse Group'}
                  </button>
                  <button
                    type="button"
                    onClick={handleReturnToFullGraph}
                    className="flex-1 px-2.5 py-1.5 rounded bg-brand text-[11px] font-semibold text-white"
                  >
                    Full Graph
                  </button>
                </div>

                <div className="pt-2 border-t border-borderc">
                  <div className="text-[10px] text-ink-muted uppercase mb-1.5">
                    Cluster Members ({focusedCluster.members.length})
                  </div>
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    {focusedCluster.members.map((m) => (
                      <button
                        key={m.id}
                        type="button"
                        onClick={() => setSelectedNodeId(m.id)}
                        className="w-full text-left p-2 bg-canvas border border-borderc hover:border-brand rounded flex items-center justify-between gap-2"
                      >
                        <span className="truncate text-[11px] text-ink font-semibold">{m.id}</span>
                        <StatusBadge status={m.trust_state} />
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : !selectedNode ? (
              <div className="py-8 text-center text-xs text-ink-muted space-y-2">
                <Database className="w-6 h-6 mx-auto text-ink-muted opacity-60" />
                {selectedNodeId && !isLoading && graphData ? (
                  <p className="text-status-warning">
                    Node <span className="font-mono font-bold">{selectedNodeId}</span> is not present in the current graph view.
                  </p>
                ) : (
                  <p>Select any node or cluster in the graph to inspect its trust state, distribution, and provenance edges.</p>
                )}
              </div>
            ) : (
              <div className="space-y-3 text-xs">
                <div>
                  <div className="text-[10px] text-ink-muted uppercase">Identifier</div>
                  <div className="font-bold text-ink break-all mt-0.5">{selectedNode.id}</div>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2 bg-canvas border border-borderc rounded">
                    <div className="text-[10px] text-ink-muted uppercase">Entity Type</div>
                    <div className="font-semibold text-ink mt-0.5">{selectedNode.record_type}</div>
                  </div>
                  <div className="p-2 bg-canvas border border-borderc rounded">
                    <div className="text-[10px] text-ink-muted uppercase">Version</div>
                    <div className="font-semibold text-ink mt-0.5">v{selectedNode.current_version}</div>
                  </div>
                </div>

                <div>
                  <div className="text-[10px] text-ink-muted uppercase mb-1">Trust State</div>
                  <StatusBadge status={selectedNode.trust_state} />
                </div>

                {selectedNode.agent_id && (
                  <div>
                    <div className="text-[10px] text-ink-muted uppercase">Attributed Agent</div>
                    <div className="font-mono text-ink mt-0.5">{selectedNode.agent_id}</div>
                  </div>
                )}

                <div>
                  <div className="text-[10px] text-ink-muted uppercase">Checksum</div>
                  <div className="text-[11px] text-ink-muted mt-0.5">
                    Not included in graph projection (inspect in Memory Explorer or ChroniMem)
                  </div>
                </div>

                <div className="pt-2 border-t border-borderc">
                  <div className="text-[10px] text-ink-muted uppercase mb-1.5">
                    Connected Relationships ({connectedRelationships.length})
                  </div>
                  {connectedRelationships.length === 0 ? (
                    <p className="text-[11px] text-ink-muted">No connected edges in current view.</p>
                  ) : (
                    <div className="space-y-1.5 max-h-44 overflow-y-auto pr-1">
                      {connectedRelationships.map(({ edge, direction, peer, peerId }) => (
                        <button
                          key={edge.id}
                          type="button"
                          onClick={() => peer && setSelectedNodeId(peer.id)}
                          className="w-full text-left p-2 bg-canvas border border-borderc hover:border-brand rounded transition-colors"
                        >
                          <div className="flex items-center justify-between text-[10px] text-brand-teal font-semibold">
                            <span>{edge.relation_type}</span>
                            <span className="text-ink-muted">{direction}</span>
                          </div>
                          <div className="flex items-center gap-1 text-[11px] text-ink truncate mt-0.5">
                            <ArrowRight className="w-3 h-3 shrink-0 text-ink-muted" />
                            <span className="truncate">{peerId}</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                <div className="pt-2 border-t border-borderc space-y-2">
                  <button
                    type="button"
                    onClick={() => navigate('/memory')}
                    className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded bg-canvas border border-borderc hover:border-brand text-xs text-ink font-semibold transition-colors"
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-brand-teal" /> Open Memory Explorer
                  </button>
                  <button
                    type="button"
                    onClick={() => navigate(`/chronimem?recordId=${encodeURIComponent(selectedNode.id)}`)}
                    className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded bg-brand hover:bg-brand-hover text-xs text-white font-semibold transition-colors"
                  >
                    <History className="w-3.5 h-3.5" /> View in ChroniMem
                  </button>
                </div>
              </div>
            )}
          </aside>
        </div>
      </div>
    </ForensicErrorBoundary>
  );
};
