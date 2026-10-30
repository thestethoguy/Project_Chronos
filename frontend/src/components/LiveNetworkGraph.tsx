import { useEffect, useMemo, useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type { NetworkTopologyFile, NodeStatus } from "../types/topology.types";
import { fetchTopology, isMockMode } from "../services/topologyApi";
import { topologyToCytoscapeElements } from "../utils/topologyToCytoscape";

interface Props {
  /** Incremented by App.tsx after each successful upload to trigger a refetch. */
  refreshSignal: number;
  /** device id -> status, derived from your existing /simulation_status polling. */
  nodeStatuses?: Record<string, NodeStatus>;
  /** Your existing mock fixture elements (data/mockData.ts) - used only in mock mode. */
  mockElements?: Array<Record<string, unknown>>;
}

const stylesheet = [
  { selector: "node", style: { label: "data(label)", "background-color": "#4b8bf5", color: "#222", "font-size": 10, "text-valign": "bottom", "text-margin-y": 4 } },
  { selector: 'node[subnet = "public_dmz"]', style: { "background-color": "#f5a623" } },
  { selector: 'node[status = "compromised"]', style: { "background-color": "#d0021b", "border-width": 3, "border-color": "#7a0010" } },
  { selector: 'node[status = "isolated"]', style: { "background-color": "#9b9b9b", "border-style": "dashed", "border-width": 2 } },
  { selector: "edge", style: { width: 2, "line-color": "#bbb", "target-arrow-color": "#bbb", "target-arrow-shape": "triangle", "curve-style": "bezier" } },
];

export function LiveNetworkGraph({ refreshSignal, nodeStatuses = {}, mockElements = [] }: Props) {
  const [topology, setTopology] = useState<NetworkTopologyFile | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [retryTick, setRetryTick] = useState(0);

  useEffect(() => {
    if (isMockMode) return; // mock path untouched
    let cancelled = false;
    setLoading(true);
    setLoadError("");
    fetchTopology()
      .then((t) => !cancelled && setTopology(t))
      .catch(() => !cancelled && setLoadError("Could not load live network topology."))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [refreshSignal, retryTick]);

  const elements = useMemo(
    () => (isMockMode ? mockElements : topology ? topologyToCytoscapeElements(topology, nodeStatuses) : []),
    [topology, nodeStatuses, mockElements]
  );

  if (!isMockMode) {
    if (loading) return <p>Loading network topology...</p>;
    if (loadError)
      return (
        <div role="alert">
          <p>{loadError}</p>
          <button onClick={() => setRetryTick((n) => n + 1)}>Retry</button>
        </div>
      );
    if (!topology || topology.devices.length === 0)
      return <p>No network topology loaded yet — upload a network_topology.json file to begin.</p>;
  }

  // key forces a fresh layout whenever the node set changes (new upload)
  const layoutKey = isMockMode ? "mock" : topology!.devices.map((d) => d.id).join("|");

  return (
    <CytoscapeComponent
      key={layoutKey}
      elements={elements}
      stylesheet={stylesheet}
      layout={{ name: "cose", animate: false } as any}
      style={{ width: "100%", height: "520px" }}
    />
  );
}
