import { useEffect, useMemo, useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type { LayoutOptions, Stylesheet } from "cytoscape";
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

const stylesheet: Stylesheet[] = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      "background-color": "#4b8bf5",
      color: "#eaf2ff",
      "font-size": 10,
      "text-valign": "bottom",
      "text-margin-y": 4,
    },
  },
  {
    selector: 'node[subnet = "public_dmz"]',
    style: { "background-color": "#f5a623" },
  },
  {
    selector: 'node[status = "compromised"]',
    style: {
      "background-color": "#d0021b",
      "border-width": 3,
      "border-color": "#7a0010",
    },
  },
  {
    selector: 'node[status = "isolated"]',
    style: {
      "background-color": "#2dd4bf",
      "border-style": "dashed",
      "border-width": 2,
    },
  },
  {
    selector: "edge",
    style: {
      width: 2,
      "line-color": "#356892",
      "target-arrow-color": "#356892",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
    },
  },
];

export function LiveNetworkGraph({
  refreshSignal,
  nodeStatuses = {},
  mockElements = [],
}: Props) {
  const [topology, setTopology] = useState<NetworkTopologyFile | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [retryTick, setRetryTick] = useState(0);

  useEffect(() => {
    if (isMockMode) return;
    let cancelled = false;
    setLoading(true);
    setLoadError("");
    fetchTopology()
      .then((t) => {
        if (!cancelled) setTopology(t);
      })
      .catch(() => {
        if (!cancelled) setLoadError("Could not load live network topology.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshSignal, retryTick]);

  const elements = useMemo(
    () =>
      isMockMode
        ? mockElements
        : topology
        ? topologyToCytoscapeElements(topology, nodeStatuses)
        : [],
    [topology, nodeStatuses, mockElements]
  );

  const layoutKey = isMockMode
    ? "mock"
    : topology
    ? topology.devices.map((d) => d.id).join("|")
    : "empty";

  const layoutConfig = useMemo<LayoutOptions>(
    () => ({ name: "breadthfirst", animate: false }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [layoutKey]
  );

  if (!isMockMode) {
    if (loading) return <p>Loading network topology...</p>;
    if (loadError)
      return (
        <div role="alert">
          <p>{loadError}</p>
          <button type="button" onClick={() => setRetryTick((n) => n + 1)}>
            Retry
          </button>
        </div>
      );
    if (!topology || topology.devices.length === 0)
      return (
        <p>
          No network topology loaded yet — upload a network_topology.json file
          to begin.
        </p>
      );
  }

  return (
    <CytoscapeComponent
      key={layoutKey}
      elements={elements}
      stylesheet={stylesheet}
      layout={layoutConfig}
      minZoom={0.45}
      maxZoom={1.75}
      wheelSensitivity={0.15}
      userZoomingEnabled={false}
      style={{ width: "100%", height: "520px" }}
    />
  );
}
