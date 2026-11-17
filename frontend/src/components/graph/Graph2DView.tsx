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
    id: 'agt-fin-01',
    position: { x: 580, y: 150 },
    data: { label: 'Agent: FinOps-01\n[ACTION INTERCEPTED]' },
    style: { background: '#1E293B', color: '#93C5FD', border: '1px solid #3B82F6', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' },
  },
  {
    id: 'tool-wire',
    position: { x: 820, y: 150 },
    data: { label: 'Gateway Tool: execute_wire\n[BLOCKED]' },
    style: { background: '#450A0A', color: '#FCA5A5', border: '1px solid #EF4444', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' },
  },
];

const INITIAL_EDGES: Edge[] = [
  { id: 'e1', source: 'src-vendor-tkt', target: 'mem-8812', animated: true, style: { stroke: '#EF4444' } },
  { id: 'e2', source: 'src-vendor-tkt', target: 'mem-9912', style: { stroke: '#059669' } },
  { id: 'e3', source: 'mem-8812', target: 'agt-fin-01', animated: true, style: { stroke: '#EF4444' } },
  { id: 'e4', source: 'mem-9912', target: 'agt-fin-01', style: { stroke: '#059669' } },
  { id: 'e5', source: 'agt-fin-01', target: 'tool-wire', animated: true, style: { stroke: '#EF4444', strokeWidth: 2 } },
];

export const Graph2DView: React.FC = () => {
  const [nodes, , onNodesChange] = useNodesState(INITIAL_NODES);
  const [edges, , onEdgesChange] = useEdgesState(INITIAL_EDGES);

  return (
    <div className="w-full h-[550px] bg-[#0B0F19] rounded-lg border border-slate-800 overflow-hidden relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#334155" />
        <Controls className="bg-slate-900 border border-slate-700 text-slate-200 fill-slate-200" />
      </ReactFlow>
      <div className="absolute bottom-3 left-3 px-3 py-1 bg-slate-900/80 border border-slate-700 rounded text-[11px] font-mono text-slate-400 pointer-events-none">
        Mode: 2D DAG (Directed Acyclic Lineage Graph)
      </div>
    </div>
  );
};
