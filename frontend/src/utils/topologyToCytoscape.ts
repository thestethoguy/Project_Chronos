import type { NetworkTopologyFile, NodeStatus } from "../types/topology.types";

/** Pure function, trivially unit-testable (Guide 6.4 Step 3). device.id is the canonical id end-to-end. */
export function topologyToCytoscapeElements(
  topology: NetworkTopologyFile,
  statuses: Record<string, NodeStatus> = {}
) {
  const nodes = topology.devices.map((d) => ({
    data: {
      id: d.id,
      label: d.name,
      subnet: d.subnet,
      status: statuses[d.id] ?? "default",
    },
  }));
  const edges = topology.connections.map((c) => ({
    data: {
      id: `${c.source}->${c.target}`,
      source: c.source,
      target: c.target,
      type: c.type,
    },
  }));
  return [...nodes, ...edges];
}
