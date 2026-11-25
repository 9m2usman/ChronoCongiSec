import { KnowledgeGraphEdge, KnowledgeGraphNode, KnowledgeGraphResponse } from '@/types';

export type ClusterMode = 'NONE' | 'CONNECTED_COMPONENTS' | 'ENTITY_TYPE' | 'TRUST_STATE';

export interface GraphCluster {
  id: string;
  label: string;
  mode: ClusterMode;
  memberIds: string[];
  members: KnowledgeGraphNode[];
  entityTypeCounts: Record<string, number>;
  trustStateCounts: Record<string, number>;
  isIsolated: boolean;
  hasFlaggedTrust: boolean;
  internalEdgeCount: number;
  crossBoundaryEdgeCount: number;
}

export interface GraphTopologyStats {
  degrees: Map<string, number>;
  isolatedNodeIds: Set<string>;
  hubNodeIds: Set<string>;
  maxDegree: number;
}

/**
 * Computes node degrees, isolated nodes (degree 0), and hub nodes (degree >= 2 and highest connectivity).
 */
export function computeTopologyStats(
  nodes: KnowledgeGraphNode[],
  edges: KnowledgeGraphEdge[]
): GraphTopologyStats {
  const nodeIds = new Set(nodes.map((n) => n.id));
  const degrees = new Map<string, number>();
  for (const n of nodes) degrees.set(n.id, 0);

  for (const e of edges) {
    if (nodeIds.has(e.from_record_id) && nodeIds.has(e.to_record_id)) {
      degrees.set(e.from_record_id, (degrees.get(e.from_record_id) || 0) + 1);
      degrees.set(e.to_record_id, (degrees.get(e.to_record_id) || 0) + 1);
    }
  }

  let maxDegree = 0;
  const isolatedNodeIds = new Set<string>();
  for (const [id, deg] of degrees.entries()) {
    if (deg === 0) isolatedNodeIds.add(id);
    if (deg > maxDegree) maxDegree = deg;
  }

  const hubThreshold = Math.max(2, Math.ceil(maxDegree * 0.6));
  const hubNodeIds = new Set<string>();
  if (maxDegree >= 2) {
    for (const [id, deg] of degrees.entries()) {
      if (deg >= hubThreshold) hubNodeIds.add(id);
    }
  }

  return { degrees, isolatedNodeIds, hubNodeIds, maxDegree };
}

/**
 * Groups nodes using connected components (BFS on undirected projection), entity type, or trust state.
 * Analytical grouping only — never modifies or infers security verdicts.
 */
export function computeGraphClusters(
  graph: KnowledgeGraphResponse | undefined,
  mode: ClusterMode
): { clusters: GraphCluster[]; nodeToClusterId: Map<string, string> } {
  if (!graph || mode === 'NONE' || graph.nodes.length === 0) {
    return { clusters: [], nodeToClusterId: new Map() };
  }

  const nodes = graph.nodes;
  const edges = graph.edges;
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const rawGroups = new Map<string, { label: string; members: KnowledgeGraphNode[] }>();

  if (mode === 'CONNECTED_COMPONENTS') {
    const adj = new Map<string, string[]>();
    for (const n of nodes) adj.set(n.id, []);
    for (const e of edges) {
      if (nodeMap.has(e.from_record_id) && nodeMap.has(e.to_record_id)) {
        adj.get(e.from_record_id)!.push(e.to_record_id);
        adj.get(e.to_record_id)!.push(e.from_record_id);
      }
    }

    const visited = new Set<string>();
    let compIndex = 1;
    for (const n of nodes) {
      if (visited.has(n.id)) continue;
      const queue = [n.id];
      visited.add(n.id);
      const members: KnowledgeGraphNode[] = [];
      while (queue.length > 0) {
        const curr = queue.shift()!;
        const nodeObj = nodeMap.get(curr);
        if (nodeObj) members.push(nodeObj);
        for (const neighbor of adj.get(curr) || []) {
          if (!visited.has(neighbor)) {
            visited.add(neighbor);
            queue.push(neighbor);
          }
        }
      }
      const isIsolated = members.length === 1 && (adj.get(members[0].id)?.length || 0) === 0;
      const id = `comp-${compIndex}`;
      const label = isIsolated ? `Isolated: ${members[0].id}` : `Component #${compIndex}`;
      rawGroups.set(id, { label, members });
      compIndex += 1;
    }
  } else if (mode === 'ENTITY_TYPE') {
    for (const n of nodes) {
      const key = (n.record_type || 'UNKNOWN').toUpperCase();
      const id = `type-${key}`;
      if (!rawGroups.has(id)) rawGroups.set(id, { label: key, members: [] });
      rawGroups.get(id)!.members.push(n);
    }
  } else if (mode === 'TRUST_STATE') {
    for (const n of nodes) {
      const key = (n.trust_state || 'UNVERIFIED').toUpperCase();
      const id = `trust-${key}`;
      if (!rawGroups.has(id)) rawGroups.set(id, { label: key, members: [] });
      rawGroups.get(id)!.members.push(n);
    }
  }

  const nodeToClusterId = new Map<string, string>();
  for (const [cid, group] of rawGroups.entries()) {
    for (const m of group.members) {
      nodeToClusterId.set(m.id, cid);
    }
  }

  const clusters: GraphCluster[] = [];
  for (const [cid, group] of rawGroups.entries()) {
    const entityTypeCounts: Record<string, number> = {};
    const trustStateCounts: Record<string, number> = {};
    let hasFlaggedTrust = false;

    for (const m of group.members) {
      const rt = (m.record_type || 'UNKNOWN').toUpperCase();
      const ts = (m.trust_state || 'UNVERIFIED').toUpperCase();
      entityTypeCounts[rt] = (entityTypeCounts[rt] || 0) + 1;
      trustStateCounts[ts] = (trustStateCounts[ts] || 0) + 1;
      if (ts === 'QUARANTINED' || ts === 'SUSPICIOUS') {
        hasFlaggedTrust = true;
      }
    }

    let internalEdgeCount = 0;
    let crossBoundaryEdgeCount = 0;
    for (const e of edges) {
      const cFrom = nodeToClusterId.get(e.from_record_id);
      const cTo = nodeToClusterId.get(e.to_record_id);
      if (!cFrom || !cTo) continue;
      if (cFrom === cid && cTo === cid) {
        internalEdgeCount += 1;
      } else if (cFrom === cid || cTo === cid) {
        crossBoundaryEdgeCount += 1;
      }
    }

    clusters.push({
      id: cid,
      label: group.label,
      mode,
      memberIds: group.members.map((m) => m.id),
      members: group.members,
      entityTypeCounts,
      trustStateCounts,
      isIsolated: group.members.length === 1 && internalEdgeCount === 0 && crossBoundaryEdgeCount === 0,
      hasFlaggedTrust,
      internalEdgeCount,
      crossBoundaryEdgeCount,
    });
  }

  return { clusters, nodeToClusterId };
}
