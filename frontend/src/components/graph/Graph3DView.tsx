import React, { useMemo } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import { useWorkstationStore } from '@/stores/useWorkstationStore';

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
  const { openInspector } = useWorkstationStore();

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

  const handleNodeClick = (node: any) => {
    const isPoison = node.group === 'POISON';
    openInspector({
      title: node.name,
      type: node.group === 'AGENT' ? 'AGENT' : node.group === 'POISON' ? 'INCIDENT' : 'RECORD',
      id: node.id,
      sha256: isPoison
        ? '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4'
        : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      trustState: isPoison ? 'QUARANTINED' : 'TRUSTED',
      details: {
        node_id: node.id,
        group: node.group,
        relative_mass: node.val,
        topology: '3D WebGL Force Directed',
        state: isPoison ? 'QUARANTINED / ISOLATED' : 'STABLE',
      },
    });
  };

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
        onNodeClick={handleNodeClick}
        backgroundColor="#070A10"
        width={900}
        height={550}
      />
      <div className="absolute bottom-3 left-3 px-3 py-1 bg-slate-900/80 border border-slate-700 rounded text-[11px] font-mono text-amber-400 pointer-events-none flex items-center gap-2">
        <span>Mode: 3D Blast-Radius WebGL</span>
        <span className="text-slate-600">|</span>
        <span className="text-slate-300">Click node to inspect forensic lineage</span>
      </div>
    </div>
  );
};

export default Graph3DView;
