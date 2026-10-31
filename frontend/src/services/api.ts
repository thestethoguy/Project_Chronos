import axios from "axios";

import type {
  AuditLog,
  NetworkEdge,
  NetworkNode,
  NetworkTopologyFile,
  PendingAction,
  PlaybookImpact,
  PlaybookRequest,
  SimulationData,
  SimulationStatus,
} from "../types/simulation";

import { initialMockData } from "../data/mockData";

import {
  buildRemediationItemsFromTopology,
  computeTopologyBaselineRisk,
  mockApproveAction,
  mockClearCustomTopology,
  mockFetchTopology,
  mockGetSimulation,
  mockLoadDemoTopology,
  mockPauseSimulation,
  mockRejectAction,
  mockResetSimulation,
  mockRunPlaybook,
  mockStartSimulation,
  mockUploadTopology,
  topologyFileToNodesAndEdges,
} from "./mockSimulation";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/**
 * VITE_USE_MOCK_DATA defaults to true unless explicitly set to "false".
 * Set VITE_USE_MOCK_DATA=false in .env to hit the real FastAPI backend.
 */
export const useMockData =
  import.meta.env.VITE_USE_MOCK_DATA !== "false";

export const api = axios.create({
  baseURL:
    import.meta.env.VITE_API_BASE_URL ||
    "http://localhost:8000",

  timeout: 10000,
});

// Cache the latest live topology so adaptBackendResponse overlays real device IDs
let cachedLiveTopology: NetworkTopologyFile | null = null;

// ---------------------------------------------------------------------------
// Backend response shape (as returned by FastAPI /simulation_status)
// ---------------------------------------------------------------------------
interface BackendSimulationState {
  session_id?: string;
  status: string;
  latest_event: string | null;
  action_taken: string | null;
  compromised_node: string | null;
  mitre_tactic: string | null;
  anomaly_score: number | null;
  red_report: string | null;
  blue_report: string | null;
  pending_action?: PendingAction | null;
  cycles_run: number;
  last_updated: string | null;
  error: string | null;
}

// ---------------------------------------------------------------------------
// Schema adapter — translates FastAPI snapshot → SimulationData
// ---------------------------------------------------------------------------

/** Maps backend status strings to the SimulationStatus union. */
function mapStatus(raw: string): SimulationStatus {
  const valid: SimulationStatus[] = [
    "idle",
    "running",
    "awaiting_approval",
    "paused",
    "completed",
    "error",
  ];
  return valid.includes(raw as SimulationStatus)
    ? (raw as SimulationStatus)
    : "idle";
}

/**
 * Derives a 0–100 risk score dynamically from the active topology baseline and backend ML telemetry.
 */
function deriveRiskScore(
  backend: BackendSimulationState,
  baselineRisk: number
): number {
  const anomaly =
    backend.anomaly_score ?? backend.pending_action?.anomaly_score ?? null;

  if (backend.status === "completed") {
    const wasRejected = backend.action_taken
      ?.toLowerCase()
      .includes("rejected");
    if (wasRejected) {
      return Math.min(
        98,
        Math.max(
          baselineRisk + 14,
          Math.round(baselineRisk * 0.42 + (anomaly ?? 0.75) * 58)
        )
      );
    }
    const reduction = Math.max(12, Math.round(baselineRisk * 0.45));
    return Math.max(8, baselineRisk - reduction);
  }

  if (backend.status === "awaiting_approval") {
    const effectiveAnomaly = anomaly ?? Math.min(0.95, 0.48 + baselineRisk / 160);
    return Math.min(
      98,
      Math.max(
        baselineRisk + 14,
        Math.round(baselineRisk * 0.42 + effectiveAnomaly * 58)
      )
    );
  }

  if (backend.status === "running") {
    const effectiveAnomaly = anomaly ?? Math.min(0.88, 0.42 + baselineRisk / 180);
    return Math.min(
      94,
      Math.max(
        baselineRisk + 10,
        Math.round(baselineRisk * 0.55 + effectiveAnomaly * 38)
      )
    );
  }

  if (backend.status === "error") {
    return Math.min(96, baselineRisk + 22);
  }

  return baselineRisk;
}

/** Maps backend status to a timeline step (0–6). */
function deriveStep(backend: BackendSimulationState): number {
  switch (backend.status) {
    case "running":
      return 2;
    case "awaiting_approval":
      return 4;
    case "completed":
      return 6;
    case "error":
      return 3;
    default:
      return 0;
  }
}

/**
 * Overlays node statuses based on compromised_node and pending_action.
 * Matches loosely so "web_server_01" hits "web-server" or exact IDs in the topology.
 */
function applyNodeOverrides(
  nodes: NetworkNode[],
  compromisedNode: string | null,
  pendingAction: PendingAction | null | undefined,
  simulationStatus: string,
  actionTaken: string | null
): NetworkNode[] {
  if (simulationStatus === "idle") {
    return nodes.map((n) => ({ ...n, status: "default" as const }));
  }

  return nodes.map((node) => {
    const matchesNode = (targetId: string | null | undefined): boolean => {
      if (!targetId) return false;
      return (
        node.id === targetId ||
        node.id.includes(targetId) ||
        targetId.includes(node.id) ||
        node.label.toLowerCase().includes(targetId.toLowerCase())
      );
    };

    const isCompromisedTarget =
      matchesNode(compromisedNode) ||
      matchesNode(pendingAction?.target) ||
      matchesNode(pendingAction?.source);

    if (isCompromisedTarget) {
      const wasSevered =
        simulationStatus === "completed" &&
        (!actionTaken || !actionTaken.toLowerCase().includes("rejected"));
      const nodeStatus = wasSevered ? "isolated" : "compromised";
      return { ...node, status: nodeStatus as const };
    }
    return { ...node, status: "default" as const };
  });
}

function applyEdgeOverrides(
  edges: NetworkEdge[],
  pendingAction: PendingAction | null | undefined,
  simulationStatus: string
): NetworkEdge[] {
  if (simulationStatus === "idle" || !pendingAction) {
    return edges.map((e) => ({ ...e, active: false }));
  }
  return edges.map((edge) => ({
    ...edge,
    active:
      edge.source === pendingAction.source &&
      edge.target === pendingAction.target,
  }));
}

/**
 * Builds a merged AuditLog list: the mock baseline plus live backend events.
 * Ensures the log feed is never empty on first render.
 */
function buildLogs(
  backend: BackendSimulationState,
  topo?: NetworkTopologyFile | null
): AuditLog[] {
  const assetCount = topo?.devices?.length ?? initialMockData.nodes.length;
  const connCount = topo?.connections?.length ?? initialMockData.edges.length;
  const logs: AuditLog[] = [
    {
      id: "log-1",
      timestamp: new Date().toLocaleTimeString(),
      message: `Project Chronos Cyber Digital Twin initialized — ${assetCount} network asset(s) and ${connCount} connection(s) online across Public DMZ & Internal Core.`,
      type: "system",
    },
  ];
  const eventTimestamp = backend.last_updated
    ? new Date(backend.last_updated).toLocaleTimeString()
    : initialMockData.logs[0]?.timestamp || "00:00:00";

  if (backend.latest_event) {
    logs.push({
      id: `be-event-${backend.session_id || "0"}-${backend.status}`,
      timestamp: eventTimestamp,
      message: backend.latest_event,
      type:
        backend.status === "error"
          ? "warning"
          : backend.status === "running"
          ? "attack"
          : backend.status === "awaiting_approval"
          ? "warning"
          : "system",
    });
  }

  if (backend.action_taken && backend.action_taken !== "None") {
    logs.push({
      id: `be-action-${backend.session_id || "0"}-${backend.action_taken.slice(0, 12)}`,
      timestamp: eventTimestamp,
      message: `Blue Agent: ${backend.action_taken}`,
      type: backend.status === "completed" ? "success" : "defence",
    });
  }

  if (backend.mitre_tactic) {
    logs.push({
      id: `be-tactic-${backend.session_id || "0"}`,
      timestamp: eventTimestamp,
      message: `MITRE ATT&CK — ${backend.mitre_tactic}`,
      type: "warning",
    });
  }

  if (backend.pending_action?.cited_incident) {
    logs.push({
      id: `be-rag-${backend.session_id || "0"}`,
      timestamp: eventTimestamp,
      message: `RAG Precedent Cited: ${backend.pending_action.cited_incident}`,
      type: "defence",
    });
  }

  if (backend.error) {
    logs.push({
      id: `be-error-${backend.session_id || "0"}`,
      timestamp: eventTimestamp,
      message: `Backend error: ${backend.error}`,
      type: "warning",
    });
  }

  return logs;
}

/**
 * Core adapter — merges the FastAPI snapshot into a complete SimulationData
 * object. Uses live topology nodes/edges when available, falling back to
 * initialMockData so the Cytoscape canvas is always populated.
 */
export function adaptBackendResponse(
  backend: BackendSimulationState,
  topologyOverride?: NetworkTopologyFile | null
): SimulationData {
  const status = mapStatus(backend.status);
  const topo = topologyOverride ?? cachedLiveTopology;
  const baseGraph = topo
    ? topologyFileToNodesAndEdges(topo)
    : { nodes: initialMockData.nodes, edges: initialMockData.edges };

  const validIds = new Set(baseGraph.nodes.map((n) => n.id));
  const validCompromised =
    backend.compromised_node && validIds.has(backend.compromised_node)
      ? backend.compromised_node
      : null;
  const validPendingAction =
    backend.pending_action &&
    validIds.has(backend.pending_action.source) &&
    validIds.has(backend.pending_action.target)
      ? backend.pending_action
      : null;

  const nodes = applyNodeOverrides(
    baseGraph.nodes,
    validCompromised,
    validPendingAction,
    backend.status,
    backend.action_taken
  );
  const edges = applyEdgeOverrides(
    baseGraph.edges,
    validPendingAction,
    backend.status
  );

  const baselineRisk = computeTopologyBaselineRisk(nodes, edges);
  const dynamicRiskScore = deriveRiskScore(backend, baselineRisk);

  const dynamicRemediations = topo
    ? buildRemediationItemsFromTopology(topo)
    : initialMockData.remediations;

  return {
    simulationId: backend.session_id
      ? `SIM-${backend.session_id.toUpperCase()}`
      : `SIM-${String(backend.cycles_run || 0).padStart(3, "0")}`,
    session_id: backend.session_id,
    status,
    riskScore: dynamicRiskScore,
    currentStep: deriveStep(backend),
    nodes,
    edges,
    logs: buildLogs(backend, topo),
    remediations: dynamicRemediations,
    pending_action: validPendingAction,
    red_report: backend.red_report,
    blue_report: backend.blue_report,
    compromised_node: validCompromised,
    mitre_tactic: backend.mitre_tactic,
    anomaly_score: backend.anomaly_score,
    latest_event: backend.latest_event,
    action_taken: backend.action_taken,
  };
}

// ---------------------------------------------------------------------------
// Exported API functions
// ---------------------------------------------------------------------------

export const clearCachedTopology = (): void => {
  cachedLiveTopology = null;
  mockClearCustomTopology();
};

export const fetchTopology = async (): Promise<NetworkTopologyFile> => {
  if (useMockData) {
    return mockFetchTopology();
  }
  const response = await api.get<NetworkTopologyFile>("/topology");
  cachedLiveTopology = response.data;
  return response.data;
};

export const loadDemoTopology = async (): Promise<{
  deviceCount: number;
  connectionCount: number;
}> => {
  const localDemo = await mockLoadDemoTopology();
  const demoTopo = await mockFetchTopology();
  cachedLiveTopology = demoTopo;
  if (useMockData) {
    return localDemo;
  }
  try {
    const response = await api.post<{
      deviceCount: number;
      connectionCount: number;
    }>("/load_demo_topology");
    await fetchTopology();
    return response.data;
  } catch {
    return localDemo;
  }
};

export const uploadTopology = async (
  file: File
): Promise<{ deviceCount: number; connectionCount: number }> => {
  // Always parse, validate, and store the user's custom topology locally first
  // so that `cachedLiveTopology` and `mockSimulation` reflect the exact uploaded file.
  const localCounts = await mockUploadTopology(file);
  const localTopo = await mockFetchTopology();
  cachedLiveTopology = localTopo;

  if (useMockData) {
    return localCounts;
  }
  try {
    const formData = new FormData();
    formData.append("topology_file", file);
    const response = await api.post<{
      deviceCount: number;
      connectionCount: number;
    }>("/upload_topology", formData);
    cachedLiveTopology = localTopo;
    return response.data;
  } catch (err: unknown) {
    if (axios.isAxiosError(err) && err.response) {
      throw err;
    }
    return localCounts;
  }
};

export const approveAction = async (): Promise<{
  status: string;
  action_taken: string;
}> => {
  if (useMockData) {
    return mockApproveAction();
  }
  const response = await api.post<{ status: string; action_taken: string }>(
    "/approve_action"
  );
  try {
    await fetchTopology();
  } catch {
    // ignore
  }
  return response.data;
};

export const rejectAction = async (): Promise<{
  status: string;
  action_taken: string;
}> => {
  if (useMockData) {
    return mockRejectAction();
  }
  const response = await api.post<{ status: string; action_taken: string }>(
    "/reject_action"
  );
  return response.data;
};

export const getSimulationStatus =
  async (): Promise<SimulationData> => {
    if (useMockData) {
      return mockGetSimulation();
    }

    if (!cachedLiveTopology) {
      try {
        await fetchTopology();
      } catch {
        // fallback to mock nodes if /topology is temporarily unreachable
      }
    }

    const response =
      await api.get<BackendSimulationState>("/simulation_status");

    return adaptBackendResponse(response.data);
  };

export const startSimulation =
  async (): Promise<SimulationData> => {
    if (useMockData) {
      return mockStartSimulation();
    }

    await api.post("/start_simulation");

    const status =
      await api.get<BackendSimulationState>("/simulation_status");

    return adaptBackendResponse(status.data);
  };

export const pauseSimulation =
  async (): Promise<SimulationData> => {
    if (useMockData) {
      return mockPauseSimulation();
    }

    const status =
      await api.get<BackendSimulationState>("/simulation_status");

    return {
      ...adaptBackendResponse(status.data),
      status: "paused",
    };
  };

export const resetSimulation =
  async (): Promise<SimulationData> => {
    if (useMockData) {
      return mockResetSimulation();
    }

    await api.post("/reset_simulation");
    try {
      await fetchTopology();
    } catch {
      // ignore
    }

    const status =
      await api.get<BackendSimulationState>("/simulation_status");
    return adaptBackendResponse(status.data);
  };

export const runPlaybook =
  async (request: PlaybookRequest): Promise<PlaybookImpact> => {
    if (useMockData) {
      return mockRunPlaybook(request);
    }

    return mockRunPlaybook(request);
  };
