import React, { useMemo, useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  MiniMap,
  Background,
  BackgroundVariant,
  MarkerType,
  Handle,
  Position,
  Node,
  Edge,
  NodeProps,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { getThemeTokens } from '@/styles/tokens';
import { KnowledgeGraphNode, KnowledgeGraphResponse } from '@/types';
import {
  ClusterMode,
  GraphCluster,
  GraphTopologyStats,
} from '@/utils/graphClustering';
import {
  Database,
  FileText,
  Bot,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Clock,
  History,
  Layers,
} from 'lucide-react';

export type HighlightMode = 'NONE' | 'ISOLATED' | 'HUBS' | 'FLAGGED';

interface AmscNodeData extends Record<string, unknown> {
  rawNode: KnowledgeGraphNode;
  isSelected: boolean;
  isDimmed: boolean;
  isConnected: boolean;
  degree?: number;
}

interface ClusterNodeData extends Record<string, unknown> {
  cluster: GraphCluster;
  isFocused: boolean;
  isDimmed: boolean;
}

const AmscGraphNode: React.FC<NodeProps> = ({ data }) => {
  const nodeData = data as AmscNodeData;
  const { rawNode, isSelected, isDimmed } = nodeData;
  const trust = (rawNode.trust_state || 'UNVERIFIED').toUpperCase();
  const recordType = (rawNode.record_type || 'KNOWLEDGE').toUpperCase();

  const isSource = recordType.includes('SOURCE') || recordType.includes('DOCUMENT');
  const isAgent = recordType.includes('AGENT');

  const shapeClass = isAgent
    ? 'rounded-full px-4 py-2'
    : isSource
    ? 'rounded-none border-l-4 px-3 py-2'
    : 'rounded-lg px-3 py-2';

  const trustStyles: Record<string, { border: string; badge: string; Icon: React.FC<{ className?: string }> }> = {
    TRUSTED: {
      border: 'border-status-trusted bg-surface text-ink',
      badge: 'bg-status-trustedBg text-status-trusted border-status-trusted/40',
      Icon: ShieldCheck,
    },
    QUARANTINED: {
      border: 'border-2 border-status-critical bg-surface text-ink',
      badge: 'bg-status-criticalBg text-status-critical border-status-critical/50',
      Icon: ShieldAlert,
    },
    SUSPICIOUS: {
      border: 'border-dashed border-2 border-status-warning bg-surface text-ink',
      badge: 'bg-status-warningBg text-status-warning border-status-warning/50',
      Icon: AlertTriangle,
    },
    SUPERSEDED: {
      border: 'border-dashed border-brand bg-surface text-ink',
      badge: 'bg-brand-tint text-brand border-brand/40',
      Icon: History,
    },
    REJECTED: {
      border: 'border-status-critical bg-surface text-ink',
      badge: 'bg-status-criticalBg text-status-critical border-status-critical/40',
      Icon: ShieldAlert,
    },
    UNVERIFIED: {
      border: 'border-dotted border-borderc-strong bg-surface text-ink',
      badge: 'bg-elevated text-ink-muted border-borderc',
      Icon: Clock,
    },
  };

  const styleCfg = trustStyles[trust] || trustStyles.UNVERIFIED;
  const TrustIcon = styleCfg.Icon;
  const EntityIcon = isAgent ? Bot : isSource ? FileText : Database;

  return (
    <div
      className={`min-w-[200px] max-w-[240px] border font-mono text-[11px] shadow-sm transition-opacity ${shapeClass} ${styleCfg.border} ${
        isSelected ? 'ring-2 ring-brand shadow-md' : ''
      } ${isDimmed ? 'opacity-25' : 'opacity-100'}`}
      aria-label={`${recordType} ${rawNode.id} ${trust}`}
    >
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-brand-teal !border-surface" />

      <div className="flex items-center justify-between gap-2 mb-1">
        <span className="flex items-center gap-1 text-[10px] font-bold text-ink-muted uppercase truncate">
          <EntityIcon className="w-3 h-3 shrink-0 text-brand-teal" />
          {recordType}
        </span>
        <span className="text-[10px] text-ink-muted shrink-0">v{rawNode.current_version}</span>
      </div>

      <div className="font-bold text-ink truncate" title={rawNode.id}>
        {rawNode.id}
      </div>

      <div className="mt-1.5 flex items-center justify-between gap-1.5">
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[9px] font-bold ${styleCfg.badge}`}
        >
          <TrustIcon className="w-2.5 h-2.5 shrink-0" />
          {trust}
        </span>
        {rawNode.agent_id && (
          <span className="text-[9px] text-ink-muted truncate max-w-[90px]" title={rawNode.agent_id}>
            {rawNode.agent_id}
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-brand !border-surface" />
    </div>
  );
};

const ClusterSummaryNode: React.FC<NodeProps> = ({ data }) => {
  const { cluster, isFocused, isDimmed } = data as ClusterNodeData;
  return (
    <div
      className={`min-w-[220px] max-w-[260px] rounded-lg border-2 px-3 py-2.5 font-mono text-[11px] shadow-sm transition-opacity bg-elevated text-ink ${
        cluster.hasFlaggedTrust ? 'border-status-warning' : 'border-brand'
      } ${isFocused ? 'ring-2 ring-brand-teal shadow-md' : ''} ${isDimmed ? 'opacity-25' : 'opacity-100'}`}
      aria-label={`Cluster ${cluster.label} (${cluster.members.length} members)`}
    >
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-brand-teal !border-surface" />
      <div className="flex items-center justify-between gap-2 mb-1">
        <span className="flex items-center gap-1 text-[10px] font-bold uppercase text-brand-teal">
          <Layers className="w-3 h-3 shrink-0" />
          Cluster Group
        </span>
        <span className="px-1.5 py-0.5 rounded bg-surface border border-borderc text-[9px] font-bold">
          {cluster.members.length} nodes
        </span>
      </div>
      <div className="font-bold text-ink truncate" title={cluster.label}>
        {cluster.label}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-1 text-[9px]">
        {Object.entries(cluster.trustStateCounts).map(([ts, count]) => (
          <span key={ts} className="px-1 py-0.5 rounded bg-surface border border-borderc text-ink-muted">
            {ts}: {count}
          </span>
        ))}
      </div>
      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-brand !border-surface" />
    </div>
  );
};

const NODE_TYPES = { amscNode: AmscGraphNode, clusterNode: ClusterSummaryNode };

function computeDagPositions(
  nodes: KnowledgeGraphNode[],
  edges: KnowledgeGraphResponse['edges']
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  if (nodes.length === 0) return positions;

  const nodeIds = new Set(nodes.map((n) => n.id));
  const inDegree = new Map<string, number>();
  const children = new Map<string, string[]>();

  for (const n of nodes) {
    inDegree.set(n.id, 0);
    children.set(n.id, []);
  }

  for (const e of edges) {
    if (nodeIds.has(e.from_record_id) && nodeIds.has(e.to_record_id)) {
      children.get(e.from_record_id)!.push(e.to_record_id);
      inDegree.set(e.to_record_id, (inDegree.get(e.to_record_id) || 0) + 1);
    }
  }

  const level = new Map<string, number>();
  const queue: string[] = [];
  for (const n of nodes) {
    if ((inDegree.get(n.id) || 0) === 0) {
      level.set(n.id, 0);
      queue.push(n.id);
    }
  }

  // BFS longest-layer assignment with cycle guard
  const visitCount = new Map<string, number>();
  while (queue.length > 0) {
    const curr = queue.shift()!;
    const currLvl = level.get(curr) || 0;
    for (const next of children.get(curr) || []) {
      const seen = (visitCount.get(next) || 0) + 1;
      visitCount.set(next, seen);
      if (seen > nodes.length) continue;
      if ((level.get(next) ?? -1) < currLvl + 1) {
        level.set(next, currLvl + 1);
        queue.push(next);
      }
    }
  }

  // Assign any remaining cyclic/unvisited nodes
  for (const n of nodes) {
    if (!level.has(n.id)) level.set(n.id, 0);
  }

  const buckets = new Map<number, KnowledgeGraphNode[]>();
  for (const n of nodes) {
    const lvl = level.get(n.id) || 0;
    if (!buckets.has(lvl)) buckets.set(lvl, []);
    buckets.get(lvl)!.push(n);
  }

  const colWidth = 300;
  const rowHeight = 125;
  for (const [lvl, list] of buckets.entries()) {
    list.forEach((n, idx) => {
      positions.set(n.id, { x: 40 + lvl * colWidth, y: 40 + idx * rowHeight });
    });
  }

  return positions;
}

interface Graph2DViewProps {
  graphData?: KnowledgeGraphResponse;
  selectedNodeId?: string | null;
  onSelectNode?: (node: KnowledgeGraphNode | null) => void;
  fitViewSignal?: number;
  clusterMode?: ClusterMode;
  clusters?: GraphCluster[];
  nodeToClusterId?: Map<string, string>;
  collapsedClusterIds?: Set<string>;
  focusedClusterId?: string | null;
  onSelectCluster?: (cluster: GraphCluster | null) => void;
  highlightMode?: HighlightMode;
  topologyStats?: GraphTopologyStats;
}

const Graph2DInner: React.FC<Graph2DViewProps> = ({
  graphData,
  selectedNodeId = null,
  onSelectNode,
  fitViewSignal = 0,
  clusterMode = 'NONE',
  clusters = [],
  nodeToClusterId,
  collapsedClusterIds,
  focusedClusterId = null,
  onSelectCluster,
  highlightMode = 'NONE',
  topologyStats,
}) => {
  const { openInspector, theme } = useWorkstationStore();
  const tokens = useMemo(() => getThemeTokens(theme), [theme]);
  const { fitView } = useReactFlow();

  const connectedNodeIds = useMemo(() => {
    const connected = new Set<string>();
    if (!selectedNodeId || !graphData) return connected;
    connected.add(selectedNodeId);
    for (const e of graphData.edges) {
      if (e.from_record_id === selectedNodeId) connected.add(e.to_record_id);
      if (e.to_record_id === selectedNodeId) connected.add(e.from_record_id);
    }
    return connected;
  }, [selectedNodeId, graphData]);

  const rawNodes = graphData?.nodes || [];
  const rawEdges = graphData?.edges || [];

  const positions = useMemo(() => computeDagPositions(rawNodes, rawEdges), [rawNodes, rawEdges]);

  const collapsedSet = collapsedClusterIds || new Set<string>();
  const clusterById = useMemo(() => new Map(clusters.map((c) => [c.id, c])), [clusters]);

  const flaggedClusterIds = useMemo(() => {
    const ids = new Set<string>();
    for (const c of clusters) {
      if (c.hasFlaggedTrust) ids.add(c.id);
    }
    return ids;
  }, [clusters]);

  const flowNodes = useMemo<Node[]>(() => {
    const result: Node[] = [];
    const addedCollapsed = new Set<string>();

    rawNodes.forEach((node, idx) => {
      const cid = nodeToClusterId?.get(node.id);
      if (clusterMode !== 'NONE' && cid && collapsedSet.has(cid)) {
        if (addedCollapsed.has(cid)) return;
        addedCollapsed.add(cid);
        const cluster = clusterById.get(cid);
        if (!cluster) return;
        const firstPos = positions.get(cluster.members[0]?.id || node.id) || { x: 40 + idx * 40, y: 40 };
        const isDimmed =
          (Boolean(focusedClusterId) && focusedClusterId !== cid) ||
          (highlightMode === 'FLAGGED' && !cluster.hasFlaggedTrust) ||
          (highlightMode === 'ISOLATED' && !cluster.isIsolated);
        result.push({
          id: `cluster:${cid}`,
          type: 'clusterNode',
          position: firstPos,
          data: {
            cluster,
            isFocused: focusedClusterId === cid,
            isDimmed,
          } satisfies ClusterNodeData,
        });
        return;
      }

      const isSelected = selectedNodeId === node.id;
      const isConnected = connectedNodeIds.has(node.id);
      const inFocusedCluster = !focusedClusterId || cid === focusedClusterId;
      const matchesHighlight =
        highlightMode === 'NONE' ||
        (highlightMode === 'ISOLATED' && Boolean(topologyStats?.isolatedNodeIds.has(node.id))) ||
        (highlightMode === 'HUBS' && Boolean(topologyStats?.hubNodeIds.has(node.id))) ||
        (highlightMode === 'FLAGGED' &&
          (node.trust_state === 'QUARANTINED' ||
            node.trust_state === 'SUSPICIOUS' ||
            (cid ? flaggedClusterIds.has(cid) : false)));

      const isDimmed =
        (Boolean(selectedNodeId) && !isConnected) ||
        (!selectedNodeId && !inFocusedCluster) ||
        (!selectedNodeId && highlightMode !== 'NONE' && !matchesHighlight);

      result.push({
        id: node.id,
        type: 'amscNode',
        position: positions.get(node.id) || { x: 40, y: 40 },
        data: {
          rawNode: node,
          isSelected,
          isConnected,
          isDimmed,
          degree: topologyStats?.degrees.get(node.id) ?? 0,
        } satisfies AmscNodeData,
      });
    });

    return result;
  }, [
    rawNodes,
    positions,
    selectedNodeId,
    connectedNodeIds,
    clusterMode,
    nodeToClusterId,
    collapsedSet,
    clusterById,
    focusedClusterId,
    highlightMode,
    topologyStats,
    flaggedClusterIds,
  ]);

  const flowEdges = useMemo<Edge[]>(() => {
    const nodeMap = new Map(rawNodes.map((n) => [n.id, n]));
    const mappedEdges: Edge[] = [];
    const seenCollapsedEdges = new Set<string>();

    for (const edge of rawEdges) {
      if (!nodeMap.has(edge.from_record_id) || !nodeMap.has(edge.to_record_id)) continue;
      const cFrom = nodeToClusterId?.get(edge.from_record_id);
      const cTo = nodeToClusterId?.get(edge.to_record_id);
      const source =
        clusterMode !== 'NONE' && cFrom && collapsedSet.has(cFrom)
          ? `cluster:${cFrom}`
          : edge.from_record_id;
      const target =
        clusterMode !== 'NONE' && cTo && collapsedSet.has(cTo)
          ? `cluster:${cTo}`
          : edge.to_record_id;

      if (source === target) continue;
      const dedupeKey = `${source}->${target}:${edge.relation_type}`;
      if ((source.startsWith('cluster:') || target.startsWith('cluster:')) && seenCollapsedEdges.has(dedupeKey)) {
        continue;
      }
      seenCollapsedEdges.add(dedupeKey);

      const isCrossCluster = clusterMode !== 'NONE' && Boolean(cFrom && cTo && cFrom !== cTo);
      const targetTrust = (nodeMap.get(edge.to_record_id)?.trust_state || '').toUpperCase();
      const isEdgeConnected =
        !selectedNodeId ||
        edge.from_record_id === selectedNodeId ||
        edge.to_record_id === selectedNodeId;
      const stroke = isCrossCluster
        ? tokens.brand.teal
        : targetTrust === 'QUARANTINED'
        ? tokens.status.critical
        : targetTrust === 'SUSPICIOUS'
        ? tokens.status.warning
        : tokens.status.trusted;

      mappedEdges.push({
        id: edge.id,
        source,
        target,
        label: isCrossCluster ? `${edge.relation_type} [CROSS]` : edge.relation_type,
        animated: (targetTrust === 'QUARANTINED' || isCrossCluster) && isEdgeConnected,
        markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
        style: {
          stroke,
          strokeDasharray: isCrossCluster ? '5 3' : undefined,
          strokeWidth: selectedNodeId && isEdgeConnected ? 2.5 : isCrossCluster ? 2 : 1.5,
          opacity: isEdgeConnected ? 1 : 0.15,
        },
        labelStyle: {
          fill: tokens.textPrimary,
          fontSize: 10,
          fontFamily: 'monospace',
          fontWeight: 600,
          opacity: isEdgeConnected ? 1 : 0.2,
        },
        labelBgStyle: {
          fill: tokens.surface,
          fillOpacity: 0.9,
        },
        labelBgPadding: [4, 2] as [number, number],
      });
    }

    return mappedEdges;
  }, [rawNodes, rawEdges, tokens, selectedNodeId, clusterMode, nodeToClusterId, collapsedSet]);

  const [nodes, setNodes, onNodesChange] = useNodesState(flowNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(flowEdges);

  useEffect(() => {
    setNodes(flowNodes);
    setEdges(flowEdges);
  }, [flowNodes, flowEdges, setNodes, setEdges]);

  useEffect(() => {
    if (fitViewSignal > 0) {
      fitView({ padding: 0.2, duration: 250 });
    }
  }, [fitViewSignal, fitView]);

  const handleNodeClick = (_event: React.MouseEvent, node: Node) => {
    if (node.type === 'clusterNode') {
      const cluster = (node.data as ClusterNodeData)?.cluster;
      if (cluster && onSelectCluster) {
        onSelectNode?.(null);
        onSelectCluster(cluster);
      }
      return;
    }
    const rawNode = (node.data as AmscNodeData)?.rawNode;
    if (!rawNode) return;
    if (onSelectNode) {
      onSelectNode(rawNode);
    } else {
      openInspector({
        title: `${rawNode.record_type}: ${rawNode.id}`,
        type: 'RECORD',
        id: rawNode.id,
        trustState: rawNode.trust_state as any,
        details: {
          ...rawNode,
          connected_edges: edges.filter((e) => e.source === node.id || e.target === node.id).map((e) => e.id),
        },
      });
    }
  };

  return (
    <div className="w-full h-[560px] bg-canvas rounded-lg border border-borderc overflow-hidden relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        onPaneClick={() => onSelectNode?.(null)}
        nodesDraggable
        nodesFocusable
        fitView
        fitViewOptions={{ padding: 0.2 }}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color={tokens.border} />
        <Controls className="bg-surface border border-borderc text-ink" />
        {nodes.length >= 4 && (
          <MiniMap
            className="!bg-surface !border !border-borderc rounded"
            maskColor={theme === 'dark' ? 'rgba(13, 19, 33, 0.7)' : 'rgba(244, 247, 251, 0.7)'}
            nodeColor={(n) => {
              if (n.type === 'clusterNode') return tokens.brand.teal;
              const t = ((n.data as AmscNodeData)?.rawNode?.trust_state || '').toUpperCase();
              if (t === 'QUARANTINED') return tokens.status.critical;
              if (t === 'SUSPICIOUS') return tokens.status.warning;
              if (t === 'TRUSTED') return tokens.status.trusted;
              return tokens.brand.primary;
            }}
          />
        )}
      </ReactFlow>

      {rawNodes.length > 0 && rawEdges.length === 0 && (
        <div className="absolute top-3 left-3 px-3 py-1.5 bg-surface/95 border border-borderc rounded text-[11px] font-mono text-ink-muted pointer-events-none">
          No relationship edges are currently available for these records.
        </div>
      )}

      <div className="hidden sm:flex absolute bottom-3 left-14 max-w-[calc(100%-15rem)] px-3 py-1 bg-surface/90 border border-borderc rounded text-[11px] font-mono text-ink-muted pointer-events-none items-center gap-2 whitespace-nowrap overflow-hidden">
        <span className="shrink-0">Mode: 2D Lineage DAG</span>
        <span className="text-borderc shrink-0">|</span>
        <span className="text-brand-teal truncate">Click node to highlight lineage &amp; inspect</span>
      </div>
    </div>
  );
};

export const Graph2DView: React.FC<Graph2DViewProps> = (props) => (
  <ReactFlowProvider>
    <Graph2DInner {...props} />
  </ReactFlowProvider>
);
