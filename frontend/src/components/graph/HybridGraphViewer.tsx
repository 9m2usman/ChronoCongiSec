import React, { useState, Suspense, lazy } from 'react';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import { Graph2DView } from './Graph2DView';
import { Layers, Box, Loader2 } from 'lucide-react';

const LazyGraph3DView = lazy(() => import('./Graph3DView'));

interface Props {
  title?: string;
  subtitle?: string;
}

export const HybridGraphViewer: React.FC<Props> = ({
  title = 'Forensic Topological & Lineage Graph',
  subtitle = 'Interactive correlation between sources, memory chunks, and agent decisions',
}) => {
  const [viewMode, setViewMode] = useState<'2D' | '3D'>('2D');

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono">
      {/* Viewer Header with 2D / 3D Switch */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-4 border-b border-slate-800 gap-3">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            {title}
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">{subtitle}</p>
        </div>

        {/* 2D / 3D Toggle */}
        <div className="flex items-center bg-slate-950 p-1 rounded-md border border-slate-800 shrink-0">
          <button
            onClick={() => setViewMode('2D')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold transition-all ${
              viewMode === '2D'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" /> 2D DAG
          </button>
          <button
            onClick={() => setViewMode('3D')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold transition-all ${
              viewMode === '3D'
                ? 'bg-amber-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Box className="w-3.5 h-3.5" /> 3D Blast Radius
          </button>
        </div>
      </div>

      {/* Canvas Viewport wrapped in Forensic Error Boundary */}
      <ForensicErrorBoundary is3dView={viewMode === '3D'}>
        {viewMode === '2D' ? (
          <Graph2DView />
        ) : (
          <Suspense
            fallback={
              <div className="w-full h-[550px] flex flex-col items-center justify-center bg-[#070A10] border border-slate-800 rounded-lg text-slate-400">
                <Loader2 className="w-8 h-8 animate-spin text-amber-500 mb-2" />
                <span className="text-xs">Initializing WebGL 3D Blast-Radius Graph...</span>
              </div>
            }
          >
            <LazyGraph3DView />
          </Suspense>
        )}
      </ForensicErrorBoundary>
    </div>
  );
};
