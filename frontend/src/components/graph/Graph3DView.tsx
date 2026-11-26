import React, { useMemo, useRef, useState, useEffect, useCallback } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { getThemeTokens } from '@/styles/tokens';
import { isWebGLAvailable } from '@/components/common/ForensicErrorBoundary';
import { StateBanner } from '@/components/common/StateBanner';
import { KnowledgeGraphNode, KnowledgeGraphResponse } from '@/types';

interface GraphNode3D {
  id: string;
  name: string;
  val: number;
  color: string;
  group: string;
  trustState: string;
  rawNode: KnowledgeGraphNode;
  x?: number;
  y?: number;
  z?: number;
}

interface GraphLink3D {
  source: string;
  target: string;
  relationType: string;
  color: string;
}

interface Graph3DViewProps {
  graphData?: KnowledgeGraphResponse;
  selectedNodeId?: string | null;
  onSelectNode?: (node: KnowledgeGraphNode | null) => void;
  onFallbackTo2D?: () => void;
}

export const Graph3DView: React.FC<Graph3DViewProps> = ({
  graphData,
  selectedNodeId = null,
  onSelectNode,
  onFallbackTo2D,
}) => {
  const { openInspector, theme } = useWorkstationStore();
  const tokens = useMemo(() => getThemeTokens(theme), [theme]);
  const containerRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<any>(null);
  const [dimensions, setDimensions] = useState({ width: 900, height: 560 });
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const webGlReady = useMemo(() => isWebGLAvailable(), []);

  useEffect(() => {
    const onWindowError = (event: ErrorEvent) => {
      const msg = event?.message || '';
      if (
        msg.includes('intersectsFrustum') ||
        msg.toLowerCase().includes('webgl') ||
        msg.toLowerCase().includes('three')
      ) {
        setRuntimeError(msg);
      }
    };
    window.addEventListener('error', onWindowError);
    return () => window.removeEventListener('error', onWindowError);
  }, []);

  const prefersReducedMotion = useMemo(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const updateSize = () => {
      if (el.clientWidth > 0) {
        setDimensions({ width: el.clientWidth, height: 560 });
      }
    };
    updateSize();
    if (typeof ResizeObserver !== 'undefined') {
      const observer = new ResizeObserver(updateSize);
      observer.observe(el);
      return () => observer.disconnect();
    }
  }, []);

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

  const data = useMemo(() => {
    const rawNodes = graphData?.nodes || [];
    const rawEdges = graphData?.edges || [];
    const nodeIds = new Set(rawNodes.map((n) => n.id));

    const nodes: GraphNode3D[] = rawNodes.map((n) => {
      const trust = (n.trust_state || 'UNVERIFIED').toUpperCase();
      const baseColor =
        trust === 'QUARANTINED' || trust === 'REJECTED'
          ? tokens.status.critical
          : trust === 'SUSPICIOUS'
          ? tokens.status.warning
          : trust === 'TRUSTED'
          ? tokens.status.trusted
          : trust === 'SUPERSEDED'
          ? tokens.brand.primary
          : tokens.textMuted;

      const isDimmed = Boolean(selectedNodeId) && !connectedNodeIds.has(n.id);
      return {
        id: n.id,
        name: `${n.record_type}: ${n.id} [${trust} • v${n.current_version}]`,
        val: selectedNodeId === n.id ? 20 : trust === 'QUARANTINED' ? 16 : 11,
        color: isDimmed ? (theme === 'dark' ? '#334155' : '#cbd5e1') : baseColor,
        group: n.record_type,
        trustState: trust,
        rawNode: n,
      };
    });

    const links: GraphLink3D[] = rawEdges
      .filter((e) => nodeIds.has(e.from_record_id) && nodeIds.has(e.to_record_id))
      .map((e) => {
        const isEdgeConnected =
          !selectedNodeId ||
          e.from_record_id === selectedNodeId ||
          e.to_record_id === selectedNodeId;
        return {
          source: e.from_record_id,
          target: e.to_record_id,
          relationType: e.relation_type,
          color: isEdgeConnected ? tokens.brand.teal : theme === 'dark' ? '#1e293b' : '#e2e8f0',
        };
      });

    return { nodes, links };
  }, [graphData, tokens, theme, selectedNodeId, connectedNodeIds]);

  // Focus camera gently on selected node when selection changes
  useEffect(() => {
    if (!selectedNodeId || !fgRef.current) return;
    const node = data.nodes.find((n) => n.id === selectedNodeId);
    if (node && typeof node.x === 'number' && typeof node.y === 'number' && typeof node.z === 'number') {
      const distance = 140;
      const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z || 1);
      fgRef.current.cameraPosition(
        { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
        { x: node.x, y: node.y, z: node.z },
        prefersReducedMotion ? 0 : 450
      );
    }
  }, [selectedNodeId, data.nodes, prefersReducedMotion]);

  const handleNodeClick = useCallback(
    (node: any) => {
      const rawNode = (node as GraphNode3D)?.rawNode;
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
            topology: '3D WebGL Force Directed',
          },
        });
      }
    },
    [onSelectNode, openInspector]
  );

  if (!webGlReady || runtimeError) {
    return (
      <StateBanner
        type="unavailable"
        title={runtimeError ? '3D WebGL Renderer Unavailable' : 'WebGL Unavailable for 3D Graph'}
        message={
          runtimeError
            ? `3D WebGL rendering encountered an error (${runtimeError}). Switch back to 2D Graph to continue investigating.`
            : 'This browser environment does not support WebGL rendering. Switch back to 2D Graph to continue investigating.'
        }
        actionText={onFallbackTo2D ? 'Switch to 2D Graph' : undefined}
        onAction={onFallbackTo2D}
      />
    );
  }

  return (
    <div ref={containerRef} className="w-full h-[560px] bg-canvas rounded-lg border border-borderc overflow-hidden relative">
      <ForceGraph3D
        ref={fgRef}
        graphData={data}
        nodeLabel={(node: any) => node.name}
        nodeColor={(node: any) => node.color}
        nodeVal={(node: any) => node.val}
        linkLabel={(link: any) => link.relationType}
        linkColor={(link: any) => link.color}
        linkDirectionalArrowLength={3.5}
        linkDirectionalArrowRelPos={1}
        linkDirectionalParticles={prefersReducedMotion ? 0 : 1}
        linkDirectionalParticleSpeed={0.005}
        cooldownTicks={prefersReducedMotion ? 40 : 80}
        onNodeClick={handleNodeClick}
        onBackgroundClick={() => onSelectNode?.(null)}
        backgroundColor={tokens.canvas}
        width={dimensions.width}
        height={dimensions.height}
      />

      {data.nodes.length > 0 && data.links.length === 0 && (
        <div className="absolute top-3 left-3 px-3 py-1.5 bg-surface/95 border border-borderc rounded text-[11px] font-mono text-ink-muted pointer-events-none">
          No relationship edges are currently available for these records.
        </div>
      )}

      <div className="hidden sm:flex absolute bottom-3 left-3 max-w-[calc(100%-1.5rem)] px-3 py-1 bg-surface/90 border border-borderc rounded text-[11px] font-mono text-ink-muted pointer-events-none items-center gap-2 whitespace-nowrap overflow-hidden">
        <span className="text-brand-teal font-semibold shrink-0">Mode: 3D Graph (WebGL)</span>
        <span className="text-borderc shrink-0">|</span>
        <span className="truncate">Drag to rotate • Scroll to zoom • Click node to focus &amp; inspect</span>
      </div>
    </div>
  );
};

export default Graph3DView;
