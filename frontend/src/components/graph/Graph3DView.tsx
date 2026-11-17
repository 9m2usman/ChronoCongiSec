import React, { useMemo } from 'react';
import ForceGraph3D from 'react-force-graph-3d';

interface GraphNode {
  id: string;
  name: string;
  val: number;
  color: string;
  group: string;
}

interface GraphLink {
  source: string;
  target: string;
  color: string;
}

export const Graph3DView: React.FC = () => {
  const data = useMemo(() => {
    const nodes: GraphNode[] = [
      { id: 'PoisonRoot', name: 'Root Ingress: TKT-9912', val: 20, color: '#EF4444', group: 'POISON' },
      { id: 'Chunk_A', name: 'Memory: rec-8812-441a (Tainted)', val: 14, color: '#EF4444', group: 'POISON' },
      { id: 'Chunk_B', name: 'Derived Chunk: rec-8812-derived', val: 10, color: '#F87171', group: 'POISON' },
      { id: 'Agent_1', name: 'Agent: FinOps-01', val: 16, color: '#3B82F6', group: 'AGENT' },
      { id: 'Agent_2', name: 'Agent: AuditBot-9', val: 12, color: '#3B82F6', group: 'AGENT' },
      { id: 'WireProposal', name: 'Tool: execute_wire ($240k)', val: 18, color: '#F59E0B', group: 'PROPOSAL' },
      { id: 'CheckpointT0', name: 'Trusted Checkpoint (T-15m)', val: 22, color: '#10B981', group: 'RECOVERY' },
    ];

    const links: GraphLink[] = [
      { source: 'PoisonRoot', target: 'Chunk_A', color: '#EF4444' },
      { source: 'Chunk_A', target: 'Chunk_B', color: '#EF4444' },
      { source: 'Chunk_A', target: 'Agent_1', color: '#EF4444' },
      { source: 'Chunk_B', target: 'Agent_2', color: '#F87171' },
      { source: 'Agent_1', target: 'WireProposal', color: '#F59E0B' },
      { source: 'CheckpointT0', target: 'Chunk_A', color: '#10B981' },
    ];

    return { nodes, links };
  }, []);

  return (
    <div className="w-full h-[550px] bg-[#070A10] rounded-lg border border-slate-800 overflow-hidden relative">
      <ForceGraph3D
        graphData={data}
        nodeLabel={(node: any) => `${node.name} (${node.group})`}
        nodeColor={(node: any) => node.color}
        nodeVal={(node: any) => node.val}
        linkColor={(link: any) => link.color}
        linkDirectionalParticles={2}
        linkDirectionalParticleSpeed={0.008}
        backgroundColor="#070A10"
        width={900}
        height={550}
      />
      <div className="absolute bottom-3 left-3 px-3 py-1 bg-slate-900/80 border border-slate-700 rounded text-[11px] font-mono text-amber-400 pointer-events-none">
        Mode: 3D Force-Directed Blast-Radius & Topological WebGL
      </div>
    </div>
  );
};

export default Graph3DView;
