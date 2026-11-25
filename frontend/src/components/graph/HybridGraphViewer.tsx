import React, { useState, Suspense, lazy } from 'react';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import { StateBanner } from '@/components/common/StateBanner';
import { KnowledgeGraphNode, KnowledgeGraphResponse } from '@/types';
import { Graph2DView, HighlightMode } from './Graph2DView';
import { ClusterMode, GraphCluster, GraphTopologyStats } from '@/utils/graphClustering';
import { Layers, Box, Loader2, Maximize2, RotateCcw } from 'lucide-react';

const LazyGraph3DView = lazy(() => import('./Graph3DView'));

interface Props {
  title?: string;
  subtitle?: string;
  graphData?: KnowledgeGraphResponse;
  isLoading?: boolean;
  error?: unknown;
  selectedNodeId?: string | null;
  onSelectNode?: (node: KnowledgeGraphNode | null) => void;
  fitViewSignal?: number;
  onFitView?: () => void;
  clusterMode?: ClusterMode;
  clusters?: GraphCluster[];
  nodeToClusterId?: Map<string, string>;
  collapsedClusterIds?: Set<string>;
  focusedClusterId?: string | null;
  onSelectCluster?: (cluster: GraphCluster | null) => void;
  highlightMode?: HighlightMode;
  topologyStats?: GraphTopologyStats;
}

export const HybridGraphViewer: React.FC<Props> = ({
  title = 'Forensic Topological & Lineage Graph',
  subtitle = 'Interactive correlation between sources, memory chunks, and agent records',
  graphData,
  isLoading,
  error,
  selectedNodeId = null,
  onSelectNode,
  fitViewSignal = 0,
  onFitView,
  clusterMode = 'NONE',
  clusters = [],
  nodeToClusterId,
  collapsedClusterIds,
  focusedClusterId = null,
  onSelectCluster,
  highlightMode = 'NONE',
  topologyStats,
}) => {
  const [viewMode, setViewMode] = useState<'2D' | '3D'>('2D');

  return (
    <div className="bg-surface border border-borderc rounded-lg p-3 sm:p-4 font-mono">
      {/* Viewer Header with Fit View & 2D / 3D Switch */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 mb-3 border-b border-borderc gap-2">
        <div className="min-w-0">
          <h2 className="text-xs sm:text-sm font-bold text-ink flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-brand-teal shrink-0"></span>
            <span className="truncate">{title}</span>
          </h2>
          <p className="text-[11px] text-ink-muted mt-0.5 truncate">{subtitle}</p>
        </div>

        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          {viewMode === '2D' && onFitView && (
            <button
              type="button"
              onClick={onFitView}
              className="flex items-center gap-1 px-2.5 py-1 rounded border border-borderc bg-canvas hover:border-brand text-[11px] text-ink transition-colors"
              title="Fit graph to viewport"
            >
              <Maximize2 className="w-3 h-3 text-brand-teal" /> Fit View
            </button>
          )}
          {selectedNodeId && onSelectNode && (
            <button
              type="button"
              onClick={() => onSelectNode(null)}
              className="flex items-center gap-1 px-2.5 py-1 rounded border border-borderc bg-canvas hover:border-brand text-[11px] text-ink transition-colors"
              title="Clear selected node"
            >
              <RotateCcw className="w-3 h-3 text-brand" /> Clear Selection
            </button>
          )}

          {/* 2D / 3D Toggle */}
          <div className="flex items-center bg-canvas p-1 rounded-md border border-borderc" role="group" aria-label="Graph View Mode">
            <button
              type="button"
              onClick={() => setViewMode('2D')}
              aria-pressed={viewMode === '2D'}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
                viewMode === '2D'
                  ? 'bg-brand text-white shadow-sm'
                  : 'text-ink-muted hover:text-ink'
              }`}
            >
              <Layers className="w-3.5 h-3.5" /> 2D Graph
            </button>
            <button
              type="button"
              onClick={() => setViewMode('3D')}
              aria-pressed={viewMode === '3D'}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
                viewMode === '3D'
                  ? 'bg-brand text-white shadow-sm'
                  : 'text-ink-muted hover:text-ink'
              }`}
            >
              <Box className="w-3.5 h-3.5" /> 3D Graph
            </button>
          </div>
        </div>
      </div>

      {/* Canvas Viewport wrapped in Forensic Error Boundary */}
      <ForensicErrorBoundary is3dView={viewMode === '3D'}>
        {isLoading ? (
          <StateBanner
            type="loading"
            title="Loading Knowledge Lineage Graph..."
            message="Querying cryptographic provenance nodes and edges..."
          />
        ) : error ? (
          <StateBanner
            type="error"
            title="Knowledge Graph Unavailable"
            statusCode={(error as any)?.status}
            message={(error as Error)?.message || 'Failed to load knowledge graph from the API server.'}
          />
        ) : graphData && graphData.nodes.length === 0 ? (
          <StateBanner
            type="empty"
            title="No Graph Entities Match Filter"
            message="No knowledge graph nodes were returned for the selected tenant, depth, or filter criteria."
          />
        ) : viewMode === '2D' ? (
          <Graph2DView
            graphData={graphData}
            selectedNodeId={selectedNodeId}
            onSelectNode={onSelectNode}
            fitViewSignal={fitViewSignal}
            clusterMode={clusterMode}
            clusters={clusters}
            nodeToClusterId={nodeToClusterId}
            collapsedClusterIds={collapsedClusterIds}
            focusedClusterId={focusedClusterId}
            onSelectCluster={onSelectCluster}
            highlightMode={highlightMode}
            topologyStats={topologyStats}
          />
        ) : (
          <Suspense
            fallback={
              <div className="w-full h-[560px] flex flex-col items-center justify-center bg-canvas border border-borderc rounded-lg text-ink-muted">
                <Loader2 className="w-8 h-8 animate-spin text-brand mb-2" />
                <span className="text-xs">Initializing WebGL 3D Blast-Radius Graph...</span>
              </div>
            }
          >
            <LazyGraph3DView
              graphData={graphData}
              selectedNodeId={selectedNodeId}
              onSelectNode={onSelectNode}
              onFallbackTo2D={() => setViewMode('2D')}
            />
          </Suspense>
        )}
      </ForensicErrorBoundary>
    </div>
  );
};
