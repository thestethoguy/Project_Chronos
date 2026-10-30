import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type { Core, Stylesheet } from "cytoscape";
import {
  FiLock,
  FiMaximize2,
  FiMinus,
  FiPlus,
  FiUnlock,
} from "react-icons/fi";
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

const MIN_ZOOM = 0.45;
const MAX_ZOOM = 1.75;

/**
 * Assigns every node in the topology to one of 5 architectural columns (0..4)
 * and spaces nodes evenly so the graph fills the canvas horizontally at 100% zoom.
 */
function computeTieredPositions(
  nodes: NetworkNode[],
  edges: NetworkEdge[]
): Record<string, { x: number; y: number }> {
  const incomingCount = new Map<string, number>();
  const outgoingCount = new Map<string, number>();
  for (const n of nodes) {
    incomingCount.set(n.id, 0);
    outgoingCount.set(n.id, 0);
  }
  for (const e of edges) {
    incomingCount.set(e.target, (incomingCount.get(e.target) ?? 0) + 1);
    outgoingCount.set(e.source, (outgoingCount.get(e.source) ?? 0) + 1);
  }

  const columns: NetworkNode[][] = [[], [], [], [], []];

  for (const node of nodes) {
    const idLower = `${node.id} ${node.label}`.toLowerCase();
    const isDmz =
      node.subnet === "public_dmz" ||
      node.type === "public_dmz" ||
      node.type === "dmz-asset" ||
      /proxy|web|mail|dns|vpn|internet|dmz/i.test(idLower);

    if (isDmz) {
      const inDeg = incomingCount.get(node.id) ?? 0;
      const outDeg = outgoingCount.get(node.id) ?? 0;
      // Ingress gateways / proxies with no inbound edges sit in Tier 0 (far left)
      if (inDeg === 0 && outDeg > 0) {
        columns[0].push(node);
      } else {
        columns[1].push(node);
      }
      continue;
    }

    // Internal Core categorization into Tiers 2, 3, and 4
    if (/db|sql|vault|backup|file_share|siem|classified|secret/i.test(idLower)) {
      columns[4].push(node);
    } else if (/auth|dc-|domain|app_internal|dhcp|controller/i.test(idLower)) {
      columns[3].push(node);
    } else {
      columns[2].push(node);
    }
  }

  // Collapse empty columns so small custom topologies (e.g. 6 nodes) also spread nicely
  const nonEmptyCols = columns.filter((col) => col.length > 0);
  const positions: Record<string, { x: number; y: number }> = {};

  const totalCols = Math.max(1, nonEmptyCols.length);
  const xSpan = totalCols <= 3 ? 680 : 1040;
  const xStep = totalCols > 1 ? xSpan / (totalCols - 1) : 0;
  const startX = -xSpan / 2;

  nonEmptyCols.forEach((colNodes, colIndex) => {
    const x = Math.round(startX + colIndex * xStep);
    const count = colNodes.length;
    const yStep = count <= 3 ? 138 : count <= 5 ? 112 : 92;
    const totalHeight = (count - 1) * yStep;
    const startY = -totalHeight / 2;

    colNodes.forEach((node, rowIndex) => {
      positions[node.id] = {
        x,
        y: Math.round(startY + rowIndex * yStep),
      };
    });
  });

  return positions;
}

const GRAPH_STYLESHEET: Stylesheet[] = [
  {
    selector: "node",
    style: {
      "background-color": "#0d2640",
      "border-color": "#4da3ff",
      "border-width": 2.5,
      width: 52,
      height: 52,
      color: "#e6f2ff",
      label: "data(displayLabel)",
      "font-size": 10,
      "font-weight": 600,
      "text-wrap": "wrap",
      "text-max-width": "132px",
      "text-valign": "bottom",
      "text-margin-y": 8,
      "text-outline-color": "#050d18",
      "text-outline-width": 2.5,
      "overlay-padding": 8,
    },
  },
  {
    selector: 'node[subnet = "public_dmz"]',
    style: {
      "background-color": "#132c47",
      "border-color": "#38bdf8",
      shape: "round-octagon",
    },
  },
  {
    selector: 'node[critical = "true"]',
    style: {
      "border-color": "#f59e0b",
      "border-width": 3.5,
    },
  },
  {
    selector: 'node[status = "compromised"]',
    style: {
      "background-color": "#691426",
      "border-color": "#ff3b5c",
      "border-width": 5,
      width: 58,
      height: 58,
      "overlay-color": "#ff3b5c",
      "overlay-opacity": 0.18,
    },
  },
  {
    selector: 'node[hitlTarget = "true"]',
    style: {
      "background-color": "#5c3409",
      "border-color": "#fbbf24",
      "border-width": 5,
      "border-style": "double",
      width: 60,
      height: 60,
      "overlay-color": "#fbbf24",
      "overlay-opacity": 0.22,
    },
  },
  {
    selector: 'node[status = "isolated"]',
    style: {
      "background-color": "#0c3b38",
      "border-color": "#2dd4bf",
      "border-style": "dashed",
      "border-width": 4.5,
      "overlay-color": "#2dd4bf",
      "overlay-opacity": 0.14,
    },
  },
  {
    selector: "node:selected",
    style: {
      "border-color": "#ffffff",
      "border-width": 4.5,
      "overlay-color": "#60a5fa",
      "overlay-opacity": 0.24,
    },
  },
  {
    selector: "edge",
    style: {
      width: 2,
      "line-color": "#264e70",
      "target-arrow-color": "#356892",
      "target-arrow-shape": "triangle",
      "arrow-scale": 0.95,
      "curve-style": "bezier",
      label: "data(edgeLabel)",
      "font-size": 8,
      color: "#6d90b0",
      "text-rotation": "autorotate",
      "text-margin-y": -7,
      "text-outline-color": "#06101c",
      "text-outline-width": 2,
      opacity: 0.84,
    },
  },
  {
    selector: 'edge[active = "true"]',
    style: {
      width: 4.5,
      "line-color": "#ff3b5c",
      "target-arrow-color": "#ff3b5c",
      "line-style": "dashed",
      "line-dash-pattern": [10, 5],
      "line-dash-offset": 0,
      color: "#ff9ebb",
      "font-size": 9,
      "font-weight": 700,
      opacity: 1,
    },
  },
];

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
  const cyRef = useRef<Core | null>(null);
  const [liveTopology, setLiveTopology] = useState<NetworkTopologyFile | null>(
    null
  );
  const [loading, setLoading] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string>("");
  const [retryTick, setRetryTick] = useState<number>(0);

  // Scroll-wheel zoom is LOCKED by default so scrolling the dashboard never zooms the canvas
  const [zoomLocked, setZoomLocked] = useState<boolean>(true);
  const [zoomPercent, setZoomPercent] = useState<number>(100);
  const [baselineEdgeCount, setBaselineEdgeCount] = useState<number>(0);

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
        riskScore: isCritical ? 82 : 45,
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

  // Track max edge count for "Severed Paths" telemetry counter
  useEffect(() => {
    const count = effectiveGraph.edges.length;
    if (simulationStatus === "idle" || count > baselineEdgeCount) {
      setBaselineEdgeCount(count);
    }
  }, [effectiveGraph.edges.length, simulationStatus, baselineEdgeCount]);

  // Structural signature ONLY changes when nodes or edges are added/removed
  const topologySignature = useMemo(() => {
    const nodeKey = effectiveGraph.nodes.map((n) => n.id).join("|");
    const edgeKey = effectiveGraph.edges
      .map((e) => `${e.source}->${e.target}`)
      .join("|");
    return `${nodeKey}::${edgeKey}`;
  }, [effectiveGraph.nodes, effectiveGraph.edges]);

  // Structural elements + preset coordinates — recomputed ONLY when topologySignature changes
  const structuralElements = useMemo(() => {
    const posMap = computeTieredPositions(
      effectiveGraph.nodes,
      effectiveGraph.edges
    );

    return [
      ...effectiveGraph.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.label,
          displayLabel: `${node.label}\n[${node.ipAddress}]`,
          status: node.status,
          hitlTarget:
            simulationStatus === "awaiting_approval" &&
            pendingAction?.target === node.id
              ? "true"
              : "false",
          type: node.type,
          subnet: node.subnet ?? "internal_core",
          critical: node.isCriticalService ? "true" : "false",
        },
        position: posMap[node.id] ?? { x: 0, y: 0 },
      })),

      ...effectiveGraph.edges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          edgeLabel: edge.type ? edge.type.replace(/_/g, " ") : "",
          active: edge.active ? "true" : "false",
        },
      })),
    ];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topologySignature]);

  const presetLayout = useMemo(
    () => ({
      name: "preset",
      fit: true,
      padding: 46,
      animate: false,
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [topologySignature]
  );

  // Update node/edge status in-place without re-running layout or resetting camera zoom
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      for (const node of effectiveGraph.nodes) {
        const ele = cy.getElementById(node.id);
        if (ele && ele.length > 0) {
          ele.data("status", node.status);
          ele.data(
            "hitlTarget",
            simulationStatus === "awaiting_approval" &&
              pendingAction?.target === node.id
              ? "true"
              : "false"
          );
          if (node.id === selectedNodeId) {
            ele.select();
          } else {
            ele.unselect();
          }
        }
      }

      for (const edge of effectiveGraph.edges) {
        const ele = cy.getElementById(edge.id);
        if (ele && ele.length > 0) {
          ele.data("active", edge.active ? "true" : "false");
        }
      }
    });
  }, [effectiveGraph, selectedNodeId, simulationStatus, pendingAction]);

  // Keep userZoomingEnabled synchronized with zoomLocked state
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.userZoomingEnabled(!zoomLocked);
    cy.minZoom(MIN_ZOOM);
    cy.maxZoom(MAX_ZOOM);
  }, [zoomLocked]);

  // Animate malicious traffic packets flowing along active attack edges
  useEffect(() => {
    if (
      simulationStatus !== "running" &&
      simulationStatus !== "awaiting_approval"
    ) {
      return;
    }
    let offset = 0;
    const timer = window.setInterval(() => {
      const cy = cyRef.current;
      if (!cy) return;
      offset = (offset - 2) % 30;
      cy.edges('[active = "true"]').style("line-dash-offset", offset);
    }, 75);

    return () => {
      window.clearInterval(timer);
    };
  }, [simulationStatus]);

  const handleZoomIn = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const next = Math.min(MAX_ZOOM, cy.zoom() * 1.2);
    cy.zoom({
      level: next,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
    });
    setZoomPercent(Math.round(cy.zoom() * 100));
  }, []);

  const handleZoomOut = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const next = Math.max(MIN_ZOOM, cy.zoom() / 1.2);
    cy.zoom({
      level: next,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
    });
    setZoomPercent(Math.round(cy.zoom() * 100));
  }, []);

  const handleFitGraph = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.fit(undefined, 46);
    setZoomPercent(Math.round(cy.zoom() * 100));
  }, []);

  const dmzCount = effectiveGraph.nodes.filter(
    (n) => n.subnet === "public_dmz" || n.type === "public_dmz"
  ).length;
  const coreCount = effectiveGraph.nodes.length - dmzCount;
  const compromisedCount = effectiveGraph.nodes.filter(
    (n) => n.status === "compromised"
  ).length;
  const severedCount = Math.max(
    0,
    baselineEdgeCount - effectiveGraph.edges.length
  );

  return (
    <section className="panel graph-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">LIVE CYBER DIGITAL TWIN TOPOLOGY</p>
          <h2>Multi-Tier Enterprise Network Architecture</h2>
        </div>

        <div className="legend">
          <span>
            <i className="legend-dmz" />
            Public DMZ ({dmzCount})
          </span>

          <span>
            <i className="legend-default" />
            Internal Core ({coreCount})
          </span>

          <span>
            <i className="legend-compromised" />
            Compromised ({compromisedCount})
          </span>

          <span>
            <i className="legend-hitl" />
            HITL Target
          </span>

          <span>
            <i className="legend-isolated" />
            Quarantined
          </span>

          <span>
            <i className="legend-attack-path" />
            Packet Attack Flow
          </span>
        </div>
      </div>

      {/* Multi-Tier Subnet Architecture Header Bar */}
      <div className="graph-tier-banner">
        <div className="tier-pill tier-dmz">
          <span className="tier-dot" />
          TIER 1: PUBLIC DMZ INGRESS
        </div>
        <div className="tier-arrow">➔</div>
        <div className="tier-pill tier-bastion">
          <span className="tier-dot" />
          TIER 2: BASTION &amp; WORKSTATIONS
        </div>
        <div className="tier-arrow">➔</div>
        <div className="tier-pill tier-identity">
          <span className="tier-dot" />
          TIER 3: IDENTITY &amp; MICROSERVICES
        </div>
        <div className="tier-arrow">➔</div>
        <div className="tier-pill tier-vault">
          <span className="tier-dot" />
          TIER 4: CROWN-JEWEL DATA VAULTS
        </div>
      </div>

      <div className="graph-container">
        {/* Radar Sweep Visual Overlay */}
        <div
          className={`graph-radar-overlay ${
            simulationStatus === "running" ||
            simulationStatus === "awaiting_approval"
              ? "radar-active"
              : ""
          }`}
        />

        {/* On-Canvas Viewport HUD Control Bar */}
        <div className="graph-hud-controls" role="toolbar" aria-label="Graph Viewport Controls">
          <button
            type="button"
            className="hud-btn"
            onClick={handleZoomOut}
            title="Zoom Out"
          >
            <FiMinus />
          </button>
          <span className="hud-zoom-readout">{zoomPercent}%</span>
          <button
            type="button"
            className="hud-btn"
            onClick={handleZoomIn}
            title="Zoom In"
          >
            <FiPlus />
          </button>
          <button
            type="button"
            className="hud-btn"
            onClick={handleFitGraph}
            title="Fit Graph to Canvas"
          >
            <FiMaximize2 />
            <span>Fit</span>
          </button>
          <button
            type="button"
            className={`hud-btn ${zoomLocked ? "hud-btn-locked" : "hud-btn-unlocked"}`}
            onClick={() => setZoomLocked((prev) => !prev)}
            title="Toggle mouse-wheel zoom lock"
          >
            {zoomLocked ? <FiLock /> : <FiUnlock />}
            <span>{zoomLocked ? "Scroll Zoom: LOCKED" : "Scroll Zoom: UNLOCKED"}</span>
          </button>
        </div>

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
            key={topologySignature}
            elements={structuralElements}
            layout={presetLayout}
            minZoom={MIN_ZOOM}
            maxZoom={MAX_ZOOM}
            wheelSensitivity={0.15}
            userZoomingEnabled={!zoomLocked}
            userPanningEnabled={true}
            boxSelectionEnabled={false}
            autounselectify={false}
            style={{
              width: "100%",
              height: "100%",
            }}
            cy={(cy: Core) => {
              const isNewInstance = cyRef.current !== cy;
              cyRef.current = cy;

              cy.minZoom(MIN_ZOOM);
              cy.maxZoom(MAX_ZOOM);
              cy.userZoomingEnabled(!zoomLocked);

              if (isNewInstance) {
                cy.removeAllListeners();

                cy.on("tap", "node", (event) => {
                  const target = event.target;
                  if (target && target.isNode?.()) {
                    onNodeSelect(target.id());
                  }
                });

                cy.on("zoom", () => {
                  setZoomPercent(Math.round(cy.zoom() * 100));
                });

                cy.ready(() => {
                  cy.fit(undefined, 46);
                  setZoomPercent(Math.round(cy.zoom() * 100));
                });
              }
            }}
            stylesheet={GRAPH_STYLESHEET}
          />
        )}
      </div>

      {/* Live Graph Telemetry Footer Bar */}
      <div className="graph-telemetry-bar">
        <div className="telemetry-stat">
          <span>ACTIVE ASSETS</span>
          <strong>{effectiveGraph.nodes.length}</strong>
        </div>
        <div className="telemetry-stat">
          <span>ACTIVE ROUTES</span>
          <strong>{effectiveGraph.edges.length}</strong>
        </div>
        <div className="telemetry-stat">
          <span>SEVERED PATHS (SOAR)</span>
          <strong className={severedCount > 0 ? "telemetry-emerald" : ""}>
            {severedCount}
          </strong>
        </div>
        <div className="telemetry-stat">
          <span>ACTIVE ATTACK CORRIDOR</span>
          <strong className={pendingAction ? "telemetry-crimson" : ""}>
            {pendingAction
              ? `${pendingAction.source} ➔ ${pendingAction.target}`
              : simulationStatus === "completed" && actionTaken
              ? actionTaken
              : "None (Monitoring Baseline)"}
          </strong>
        </div>
      </div>
    </section>
  );
}
