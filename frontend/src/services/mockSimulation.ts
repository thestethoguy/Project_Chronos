import { initialMockData } from "../data/mockData";
import type {
  NodeStatus,
  PlaybookImpact,
  PlaybookRequest,
  SimulationData,
} from "../types/simulation";

let state: SimulationData = structuredClone(initialMockData);
let step = 0;

const wait = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const addLog = (
  message: string,
  type: "attack" | "defence" | "system" | "warning" | "success"
): void => {
  state.logs = [
    ...state.logs,
    {
      id: crypto.randomUUID(),
      timestamp: new Date().toLocaleTimeString(),
      message,
      type,
    },
  ];
};

const updateNodeStatus = (
  nodeId: string,
  status: NodeStatus
): void => {
  state.nodes = state.nodes.map((node) =>
    node.id === nodeId
      ? {
          ...node,
          status,
        }
      : node
  );
};

const activateEdge = (
  edgeId: string,
  active: boolean
): void => {
  state.edges = state.edges.map((edge) =>
    edge.id === edgeId
      ? {
          ...edge,
          active,
        }
      : edge
  );
};

const applyNextStep = (): void => {
  if (state.status !== "running") {
    return;
  }

  step += 1;

  if (step === 1) {
    updateNodeStatus("web-server", "compromised");
    activateEdge("e1", true);

    state.riskScore = 60;

    addLog(
      "Red Agent compromised the Web Server.",
      "attack"
    );
  } else if (step === 2) {
    updateNodeStatus("app-server", "compromised");
    activateEdge("e2", true);

    state.riskScore = 75;

    addLog(
      "Red Agent moved to the Application Server.",
      "warning"
    );
  } else if (step === 3) {
    updateNodeStatus("web-server", "isolated");

    state.riskScore = 65;

    addLog(
      "Blue Agent isolated the Web Server.",
      "defence"
    );
  } else if (step === 4) {
    updateNodeStatus("app-server", "isolated");

    state.edges = state.edges.map((edge) => ({
      ...edge,
      active: false,
    }));

    state.riskScore = 40;
    state.status = "completed";

    addLog(
      "Blue Agent successfully contained the attack.",
      "success"
    );
  }
};

export const mockGetSimulation =
  async (): Promise<SimulationData> => {
    await wait(200);

    applyNextStep();

    return structuredClone(state);
  };

export const mockStartSimulation =
  async (): Promise<SimulationData> => {
    await wait(200);

    state.status = "running";
    step = 0;

    addLog("Simulation started.", "system");

    return structuredClone(state);
  };

export const mockPauseSimulation =
  async (): Promise<SimulationData> => {
    await wait(200);

    state.status = "paused";

    addLog("Simulation paused.", "system");

    return structuredClone(state);
  };

export const mockResetSimulation =
  async (): Promise<SimulationData> => {
    await wait(200);

    state = structuredClone(initialMockData);
    step = 0;

    state.logs = [
      {
        id: crypto.randomUUID(),
        timestamp: new Date().toLocaleTimeString(),
        message: "Simulation reset.",
        type: "system",
      },
    ];

    return structuredClone(state);
  };

export const mockRunPlaybook = async (
  _request: PlaybookRequest
): Promise<PlaybookImpact> => {
  await wait(300);

  const currentRisk = state.riskScore;
  const projectedRisk = Math.max(0, currentRisk - 15);

  return {
    previousRiskScore: currentRisk,
    projectedRiskScore: projectedRisk,
    mttdReduction: 12,
    mttrReduction: 8,
    criticalServicesOffline: 1,
    affectedServices: ["web-server", "app-server"],
    recommendation:
      "Isolate the affected node and patch the identified vulnerability before resuming normal operations.",
  };
};