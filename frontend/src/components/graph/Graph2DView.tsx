import React from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  BackgroundVariant,
  Node,
  Edge,
  useNodesState,
  useEdgesState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useWorkstationStore } from '@/stores/useWorkstationStore';

const INITIAL_NODES: Node[] = [
  {
    id: 'src-vendor-tkt',
    position: { x: 50, y: 150 },
    data: { label: 'Source: Vendor Ticket #9912\n[UNTRUSTED INGRESS]' },
    style: { background: '#1E293B', color: '#F1F5F9', border: '1px solid #64748B', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' },
  },
  {
    id: 'mem-8812',
    position: { x: 300, y: 100 },
    data: { label: 'Memory Chunk: rec-8812-441a\n[QUARANTINED]' },
    style: { background: '#450A0A', color: '#FCA5A5', border: '1px solid #DC2626', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' },
  },
  {
    id: 'mem-9912',
    position: { x: 300, y: 220 },
    data: { label: 'Memory Chunk: rec-9912-b1\n[TRUSTED POLICY]' },
    style: { background: '#064E3B', color: '#A7F3D0', border: '1px solid #059669', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' },
  },
  {
    id: 'mem-derived-8813',
    position: { x: 540, y: 60 },
    data: { label: 'Derived Chunk: rec-8813-cache\n[TAINTED CACHE]' },
    style: { background: '#450A0A', color: '#F87171', border: '1px dashed #EF4444', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' },
  },
  {
    id: 'agt-fin-01',
    position: { x: 580, y: 170 },
    data: { label: 'Agent: FinOps-01\n[ACTION INTERCEPTED]' },
    style: { background: '#1E293B', color: '#93C5FD', border: '1px solid #3B82F6', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' },
  },
  {
    id: 'tool-wire',
    position: { x: 840, y: 170 },
    data: { label: 'Gateway Tool: execute_wire\n[BLOCKED SEC-004]' },
    style: { background: '#450A0A', color: '#FCA5A5', border: '1px solid #EF4444', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' },
  },
];

const INITIAL_EDGES: Edge[] = [
  { id: 'e1', source: 'src-vendor-tkt', target: 'mem-8812', animated: true, style: { stroke: '#EF4444' } },
  { id: 'e2', source: 'src-vendor-tkt', target: 'mem-9912', style: { stroke: '#059669' } },
  { id: 'e-deriv', source: 'mem-8812', target: 'mem-derived-8813', animated: true, style: { stroke: '#EF4444', strokeDasharray: '4 4' } },
  { id: 'e3', source: 'mem-8812', target: 'agt-fin-01', animated: true, style: { stroke: '#EF4444' } },
  { id: 'e4', source: 'mem-9912', target: 'agt-fin-01', style: { stroke: '#059669' } },
  { id: 'e5', source: 'agt-fin-01', target: 'tool-wire', animated: true, style: { stroke: '#EF4444', strokeWidth: 2 } },
];

export const Graph2DView: React.FC = () => {
  const { openInspector } = useWorkstationStore();
  const [nodes, , onNodesChange] = useNodesState(INITIAL_NODES);
  const [edges, , onEdgesChange] = useEdgesState(INITIAL_EDGES);

  const handleNodeClick = (_event: React.MouseEvent, node: Node) => {
    const rawLabel = typeof node.data?.label === 'string' ? node.data.label : 'Node';
    const title = rawLabel.split('\n')[0];
    const isQuarantined = node.id === 'mem-8812' || node.id === 'mem-derived-8813';
    
    openInspector({
      title,
      type: node.id.startsWith('mem') ? 'RECORD' : node.id.startsWith('agt') ? 'AGENT' : 'INCIDENT',
      id: node.id,
      sha256: isQuarantined
        ? '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4'
        : '3a4f1b884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08aa',
      trustState: isQuarantined ? 'QUARANTINED' : 'TRUSTED',
      details: {
        node_id: node.id,
        entity_label: rawLabel,
        blast_radius_depth: 3,
        connected_edges: edges.filter((e) => e.source === node.id || e.target === node.id).map((e) => e.id),
        security_policy: isQuarantined ? 'SEC-005 Vector Exclusion Active' : 'Compliant',
      },
    });
  };

  return (
    <div className="w-full h-[550px] bg-[#0B0F19] rounded-lg border border-slate-800 overflow-hidden relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        fitView
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#334155" />
        <Controls className="bg-slate-900 border border-slate-700 text-slate-200 fill-slate-200" />
      </ReactFlow>
      <div className="absolute bottom-3 left-3 px-3 py-1 bg-slate-900/80 border border-slate-700 rounded text-[11px] font-mono text-slate-400 pointer-events-none flex items-center gap-2">
        <span>Mode: 2D DAG</span>
        <span className="text-slate-500">|</span>
        <span className="text-cyan-400">Click any node to inspect cryptographic lineage</span>
      </div>
    </div>
  );
};
