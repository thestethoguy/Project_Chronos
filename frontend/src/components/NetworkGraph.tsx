import { useEffect, useMemo, useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type { Core } from "cytoscape";
import { fetchTopology, useMockData } from "../services/api";
import type {
  NetworkEdge,
  NetworkNode,
  NetworkTopologyFile,
  NodeStatus,
  PendingAction,
  SimulationStatus,
} from "../types/simulation";

interface NetworkGraphProps {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  selectedNodeId?: string;
  onNodeSelect: (nodeId: string) => void;
  refreshSignal?: number;
  compromisedNode?: string | null;
  pendingAction?: PendingAction | null;
  simulationStatus?: SimulationStatus;
  actionTaken?: string | null;
}

export function NetworkGraph({
  nodes,
  edges,
  selectedNodeId,
  onNodeSelect,
  refreshSignal = 0,
  compromisedNode,
  pendingAction,
  simulationStatus = "idle",
  actionTaken,
}: NetworkGraphProps) {
  const [liveTopology, setLiveTopology] = useState<NetworkTopologyFile | null>(
    null
  );
  const [loading, setLoading] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string>("");
  const [retryTick, setRetryTick] = useState<number>(0);

  useEffect(() => {
    if (useMockData) return;
    let cancelled = false;
    setLoading(true);
    setLoadError("");
    fetchTopology()
      .then((t) => {
        if (!cancelled) {
          setLiveTopology(t);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setLoadError("Could not load live network topology.");
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [refreshSignal, retryTick]);

  const effectiveGraph = useMemo(() => {
    if (useMockData || !liveTopology) {
      return { nodes, edges };
    }

    const matchesNode = (
      id: string,
      label: string,
      target: string | null | undefined
    ): boolean => {
      if (!target) return false;
      return (
        id === target ||
        id.includes(target) ||
        target.includes(id) ||
        label.toLowerCase().includes(target.toLowerCase())
      );
    };

    const statusFromPropMap = new Map<string, NodeStatus>(
      nodes.map((n) => [n.id, n.status])
    );

    const mappedNodes: NetworkNode[] = liveTopology.devices.map((d) => {
      let status: NodeStatus = statusFromPropMap.get(d.id) ?? "default";
      if (simulationStatus !== "idle") {
        const hit =
          matchesNode(d.id, d.name, compromisedNode) ||
          matchesNode(d.id, d.name, pendingAction?.target) ||
          matchesNode(d.id, d.name, pendingAction?.source);
        if (hit) {
          const wasSevered =
            simulationStatus === "completed" &&
            (!actionTaken || !actionTaken.toLowerCase().includes("rejected"));
          status = wasSevered ? "isolated" : "compromised";
        }
      } else {
        status = "default";
      }

      const isCritical =
        d.subnet === "internal_core" ||
        /auth|dc|db|sql|secret|classified/i.test(`${d.id} ${d.name}`);

      return {
        id: d.id,
        label: d.name || d.id,
        type: d.subnet,
        subnet: d.subnet,
        status,
        ipAddress: d.ip,
        operatingSystem: d.os,
        riskScore: isCritical ? 80 : 45,
        vulnerabilities: [],
        knownCves: d.cves ?? [],
        openPorts: d.ports ?? [],
        isCriticalService: isCritical,
      };
    });

    const mappedEdges: NetworkEdge[] = liveTopology.connections.map(
      (c, index) => ({
        id: `${c.source}->${c.target}-${index}`,
        source: c.source,
        target: c.target,
        type: c.type,
        active:
          simulationStatus !== "idle" &&
          Boolean(
            pendingAction &&
              pendingAction.source === c.source &&
              pendingAction.target === c.target
          ),
      })
    );

    return { nodes: mappedNodes, edges: mappedEdges };
  }, [
    nodes,
    edges,
    liveTopology,
    compromisedNode,
    pendingAction,
    simulationStatus,
    actionTaken,
  ]);

  const elements = useMemo(
    () => [
      ...effectiveGraph.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.label,
          status: node.status,
          type: node.type,
          subnet: node.subnet ?? "internal_core",
          critical: node.isCriticalService ? "true" : "false",
        },
        selected: node.id === selectedNodeId,
      })),

      ...effectiveGraph.edges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          active: edge.active ? "true" : "false",
        },
      })),
    ],
    [effectiveGraph, selectedNodeId]
  );

  const layoutKey = useMemo(
    () => effectiveGraph.nodes.map((n) => n.id).join("|") || "empty",
    [effectiveGraph.nodes]
  );

  return (
    <section className="panel graph-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">LIVE TOPOLOGY</p>
          <h2>Infrastructure Digital Twin</h2>
        </div>

        <div className="legend">
          <span>
            <i className="legend-default" />
            Normal
          </span>

          <span>
            <i className="legend-compromised" />
            Compromised
          </span>

          <span>
            <i className="legend-isolated" />
            Isolated
          </span>

          <span>
            <i className="legend-attack-path" />
            Attack Path
          </span>
        </div>
      </div>

      <div className="graph-container">
        {!useMockData && loading && !liveTopology ? (
          <div className="graph-state-overlay">
            <p>Loading network topology...</p>
          </div>
        ) : !useMockData && loadError && !liveTopology ? (
          <div className="graph-state-overlay" role="alert">
            <p>{loadError}</p>
            <button
              type="button"
              className="button button-primary"
              onClick={() => setRetryTick((n) => n + 1)}
            >
              Retry
            </button>
          </div>
        ) : effectiveGraph.nodes.length === 0 ? (
          <div className="graph-state-overlay">
            <p>
              No network topology loaded yet — upload a network_topology.json
              file to begin.
            </p>
          </div>
        ) : (
          <CytoscapeComponent
            key={layoutKey}
            elements={elements}
            layout={{
              name: "breadthfirst",
              directed: true,
              padding: 40,
              spacingFactor: 1.5,
              animate: true,
            }}
            style={{
              width: "100%",
              height: "100%",
            }}
            cy={(cy: Core) => {
              cy.removeAllListeners();

              cy.on("tap", (event) => {
                const target = event.target;

                if (target && target.isNode?.()) {
                  onNodeSelect(target.id());
                }
              });
            }}
            stylesheet={[
              {
                selector: "node",
                style: {
                  "background-color": "#102b47",
                  "border-color": "#63adff",
                  "border-width": 3,
                  width: 62,
                  height: 62,
                  color: "#edf5ff",
                  label: "data(label)",
                  "font-size": 11,
                  "font-weight": 700,
                  "text-valign": "bottom",
                  "text-margin-y": 10,
                  "text-outline-color": "#07111f",
                  "text-outline-width": 2,
                },
              },
              {
                selector: 'node[critical = "true"]',
                style: {
                  "border-color": "#ffbd5e",
                  "border-width": 4,
                },
              },
              {
                selector: 'node[status = "compromised"]',
                style: {
                  "background-color": "#651b2a",
                  "border-color": "#ff5c74",
                  "border-width": 5,
                },
              },
              {
                selector: 'node[status = "isolated"]',
                style: {
                  "background-color": "#123451",
                  "border-color": "#53d6ff",
                  "border-style": "dashed",
                  "border-width": 5,
                  opacity: 0.82,
                },
              },
              {
                selector: "node:selected",
                style: {
                  "overlay-color": "#ffffff",
                  "overlay-opacity": 0.12,
                  "overlay-padding": 12,
                  "border-color": "#ffffff",
                },
              },
              {
                selector: "edge",
                style: {
                  width: 2,
                  "line-color": "#2a5375",
                  "target-arrow-color": "#2a5375",
                  "target-arrow-shape": "triangle",
                  "curve-style": "bezier",
                  opacity: 0.8,
                },
              },
              {
                selector: 'edge[active = "true"]',
                style: {
                  width: 6,
                  "line-color": "#ff5c74",
                  "target-arrow-color": "#ff5c74",
                  opacity: 1,
                },
              },
            ]}
          />
        )}
      </div>
    </section>
  );
}
