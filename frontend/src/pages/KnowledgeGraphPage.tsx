import React from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { HybridGraphViewer } from '@/components/graph/HybridGraphViewer';
import { GitBranch } from 'lucide-react';

export const KnowledgeGraphPage: React.FC = () => {
  const { activeTenant } = useWorkstationStore();

  return (
    <div className="space-y-6 font-mono">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-cyan-400" />
            Knowledge & Memory Lineage Graph
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic DAG and 3D blast-radius topology of knowledge entities for {activeTenant.name}
          </p>
        </div>
      </div>

      {/* Hybrid 2D/3D Viewer */}
      <HybridGraphViewer
        title="Knowledge Provenance & Agent Dependency Graph"
        subtitle="Toggle between 2D React Flow DAG and 3D Force-Directed Blast-Radius topology"
      />
    </div>
  );
};
