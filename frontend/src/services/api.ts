import axios from "axios";

import type {
  AuditLog,
  NetworkNode,
  PlaybookImpact,
  PlaybookRequest,
  SimulationData,
  SimulationStatus,
} from "../types/simulation";

import { initialMockData } from "../data/mockData";

import {
  mockGetSimulation,
  mockPauseSimulation,
  mockResetSimulation,
  mockRunPlaybook,
  mockStartSimulation,
} from "./mockSimulation";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/**
 * VITE_USE_MOCK_DATA defaults to true unless explicitly set to "false".
 * Set VITE_USE_MOCK_DATA=false in .env to hit the real FastAPI backend.
 */
const useMockData =
  import.meta.env.VITE_USE_MOCK_DATA !== "false";

const api = axios.create({
  baseURL:
    import.meta.env.VITE_API_BASE_URL ||
    "http://localhost:8000",

  timeout: 10000,
});

// ---------------------------------------------------------------------------
// Backend response shape (as returned by FastAPI /simulation_status)
// ---------------------------------------------------------------------------
interface BackendSimulationState {
  status: string;
  latest_event: string | null;
  action_taken: string | null;
  compromised_node: string | null;
  mitre_tactic: string | null;
  anomaly_score: number | null;
  red_report: string | null;
  blue_report: string | null;
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
    "paused",
    "completed",
    "error",
  ];
  return valid.includes(raw as SimulationStatus)
    ? (raw as SimulationStatus)
    : "idle";
}

/**
 * Derives a 0–100 risk score from the backend state.
 * Uses anomaly_score (0–1) when available, otherwise infers from status.
 */
function deriveRiskScore(backend: BackendSimulationState): number {
  if (backend.anomaly_score != null) {
    return Math.round(backend.anomaly_score * 100);
  }
  switch (backend.status) {
    case "running":
      return 68;
    case "completed":
      return 35;
    case "error":
      return 90;
    default:
      return initialMockData.riskScore;
  }
}

/** Maps backend status to a timeline step (0–6). */
function deriveStep(backend: BackendSimulationState): number {
  switch (backend.status) {
    case "running":
      return 2;
    case "completed":
      return 6;
    case "error":
      return 3;
    default:
      return 0;
  }
}

/**
 * Overlays node statuses based on the compromised_node field.
 * Matches loosely so "web_server_01" hits "web-server" in the topology.
 */
function applyNodeOverrides(
  nodes: NetworkNode[],
  compromisedNode: string | null,
  simulationStatus: string
): NetworkNode[] {
  if (!compromisedNode || simulationStatus === "idle") {
    return nodes.map((n) => ({ ...n, status: "default" as const }));
  }
  return nodes.map((node) => {
    const hit =
      node.id.includes(compromisedNode) ||
      compromisedNode.includes(node.id) ||
      node.label.toLowerCase().includes(compromisedNode.toLowerCase());

    if (hit) {
      const nodeStatus =
        simulationStatus === "completed" ? "isolated" : "compromised";
      return { ...node, status: nodeStatus as const };
    }
    return { ...node, status: "default" as const };
  });
}

/**
 * Builds a merged AuditLog list: the mock baseline plus live backend events.
 * Ensures the log feed is never empty on first render.
 */
function buildLogs(backend: BackendSimulationState): AuditLog[] {
  const logs: AuditLog[] = [...initialMockData.logs];

  if (backend.latest_event) {
    logs.push({
      id: `be-event-${Date.now()}`,
      timestamp: backend.last_updated
        ? new Date(backend.last_updated).toLocaleTimeString()
        : new Date().toLocaleTimeString(),
      message: backend.latest_event,
      type:
        backend.status === "error"
          ? "warning"
          : backend.status === "running"
          ? "attack"
          : "system",
    });
  }

  if (backend.action_taken && backend.action_taken !== "None") {
    logs.push({
      id: `be-action-${Date.now() + 1}`,
      timestamp: new Date().toLocaleTimeString(),
      message: `Blue Agent: ${backend.action_taken}`,
      type: "defence",
    });
  }

  if (backend.mitre_tactic) {
    logs.push({
      id: `be-tactic-${Date.now() + 2}`,
      timestamp: new Date().toLocaleTimeString(),
      message: `MITRE ATT&CK — ${backend.mitre_tactic}`,
      type: "warning",
    });
  }

  if (backend.error) {
    logs.push({
      id: `be-error-${Date.now() + 3}`,
      timestamp: new Date().toLocaleTimeString(),
      message: `Backend error: ${backend.error}`,
      type: "warning",
    });
  }

  return logs;
}

/**
 * Core adapter — merges the FastAPI snapshot into a complete SimulationData
 * object. Topology nodes/edges are preserved from initialMockData so the
 * Cytoscape canvas is always populated; live fields overlay on top.
 */
function adaptBackendResponse(
  backend: BackendSimulationState
): SimulationData {
  const status = mapStatus(backend.status);
  const nodes = applyNodeOverrides(
    initialMockData.nodes,
    backend.compromised_node,
    backend.status
  );

  return {
    simulationId: `SIM-${String(backend.cycles_run).padStart(3, "0")}`,
    status,
    riskScore: deriveRiskScore(backend),
    currentStep: deriveStep(backend),
    nodes,
    edges: initialMockData.edges,
    logs: buildLogs(backend),
    remediations: initialMockData.remediations,
  };
}

// ---------------------------------------------------------------------------
// Exported API functions
// ---------------------------------------------------------------------------

export const getSimulationStatus =
  async (): Promise<SimulationData> => {
    if (useMockData) {
      return mockGetSimulation();
    }

    // ✅ Correct backend path: /simulation_status
    const response =
      await api.get<BackendSimulationState>("/simulation_status");

    return adaptBackendResponse(response.data);
  };

export const startSimulation =
  async (): Promise<SimulationData> => {
    if (useMockData) {
      return mockStartSimulation();
    }

    // ✅ Correct backend path: /start_simulation (POST returns 202 + message)
    await api.post("/start_simulation");

    // Fetch the updated state immediately so the UI reflects "running"
    const status =
      await api.get<BackendSimulationState>("/simulation_status");

    return adaptBackendResponse(status.data);
  };

export const pauseSimulation =
  async (): Promise<SimulationData> => {
    if (useMockData) {
      return mockPauseSimulation();
    }

    // Backend has no dedicated pause endpoint — return current state
    // with status overridden to "paused" so the control bar updates.
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

    // ✅ Correct backend path: /reset_simulation
    await api.post("/reset_simulation");

    // Return a clean idle snapshot seeded from mockData
    return {
      ...initialMockData,
      simulationId: "SIM-000",
      status: "idle",
      currentStep: 0,
      nodes: initialMockData.nodes.map((n) => ({
        ...n,
        status: "default" as const,
      })),
      logs: [
        {
          id: `reset-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          message: "Simulation state reset — system baseline normal.",
          type: "system",
        },
      ],
    };
  };

export const runPlaybook =
  async (request: PlaybookRequest): Promise<PlaybookImpact> => {
    if (useMockData) {
      return mockRunPlaybook(request);
    }

    // Backend has no /playbook/validate endpoint yet.
    // Delegate to the mock so the UI remains fully functional.
    return mockRunPlaybook(request);
  };