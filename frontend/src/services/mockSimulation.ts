import { initialMockData } from "../data/mockData";
import type {
  NetworkEdge,
  NetworkNode,
  NetworkTopologyFile,
  NodeStatus,
  PendingAction,
  PlaybookImpact,
  PlaybookRequest,
  SimulationData,
  TopologyConnection,
  TopologyDevice,
} from "../types/simulation";

let state: SimulationData = structuredClone(initialMockData);
let step = 0;
let customTopology: NetworkTopologyFile | null = null;

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

export function topologyFileToNodesAndEdges(
  topo: NetworkTopologyFile
): { nodes: NetworkNode[]; edges: NetworkEdge[] } {
  const nodes: NetworkNode[] = topo.devices.map((d: TopologyDevice) => {
    const isCrit =
      d.subnet === "internal_core" ||
      /auth|dc|db|sql|secret|classified/i.test(`${d.id} ${d.name}`);
    const baseRisk =
      (d.cves?.length ?? 0) * 18 + (isCrit ? 48 : 28);
    return {
      id: d.id,
      label: d.name || d.id,
      type: d.subnet === "public_dmz" ? "dmz-asset" : "core-asset",
      subnet: d.subnet,
      status: "default",
      ipAddress: d.ip,
      operatingSystem: d.os,
      softwareName: d.subnet === "public_dmz" ? "Edge Service" : "Core Service",
      softwareVersion: "2.4",
      riskScore: Math.min(95, baseRisk),
      vulnerabilities:
        d.cves && d.cves.length > 0
          ? d.cves.map((c) => `Unpatched vulnerability (${c})`)
          : [],
      knownCves: d.cves ?? [],
      openPorts: d.ports ?? [],
      isCriticalService: isCrit,
      businessService:
        d.subnet === "internal_core" ? "Core Infrastructure" : "Public DMZ",
    };
  });

  const edges: NetworkEdge[] = topo.connections.map(
    (c: TopologyConnection, idx: number) => ({
      id: `${c.source}->${c.target}-${idx}`,
      source: c.source,
      target: c.target,
      type: c.type,
      active: false,
    })
  );

  return { nodes, edges };
}

function buildMockPendingAction(): PendingAction {
  const activeEdge =
    state.edges[1] ?? state.edges[0] ?? { source: "web-server", target: "app-server" };
  return {
    source: activeEdge.source,
    target: activeEdge.target,
    anomaly_score: 0.8742,
    mitre_tactic: "Lateral Movement (T1550.002 - Pass the Hash)",
    cited_incident:
      "Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth",
    justification: `Isolation Forest scored the event 0.8742 (ANOMALY): Activity outside normal office hours (06:00–22:00); Excessive data transfer (50,000 bytes); High failed-login count (20 attempts). Closest historical incident: 'Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth'. Severing ${activeEdge.source} -> ${activeEdge.target} cuts the lateral-movement path. Awaiting human approval.`,
    aws_remediation: {
      role_name: "DomainAdminRole",
      before: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: ["iam:PassRole", "sts:AssumeRole", "ec2:*"],
            Resource: "*",
          },
        ],
      },
      after: {
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: ["sts:AssumeRole", "ec2:*"],
            Resource: "*",
          },
        ],
      },
      change_summary:
        "Removed 'iam:PassRole' from the inspected policy of DomainAdminRole.",
      data_source: "mock",
      executed: false,
    },
    proposed_at: new Date().toISOString(),
  };
}

const applyNextStep = (): void => {
  if (state.status !== "running") {
    return;
  }

  step += 1;
  const firstNode = state.nodes[1]?.id ?? state.nodes[0]?.id ?? "web-server";
  const secondNode = state.nodes[2]?.id ?? state.nodes[1]?.id ?? "app-server";
  const firstEdge = state.edges[0]?.id ?? "e1";
  const secondEdge = state.edges[1]?.id ?? firstEdge;

  if (step === 1) {
    updateNodeStatus(firstNode, "compromised");
    activateEdge(firstEdge, true);

    state.riskScore = 62;
    state.currentStep = 1;
    state.compromised_node = firstNode;

    addLog(
      `Red Agent compromised ${firstNode} via initial foothold.`,
      "attack"
    );
  } else if (step === 2) {
    updateNodeStatus(secondNode, "compromised");
    activateEdge(secondEdge, true);

    state.riskScore = 82;
    state.currentStep = 2;
    state.compromised_node = secondNode;
    state.mitre_tactic = "Lateral Movement (T1550.002 - Pass the Hash)";

    addLog(
      `Red Agent moved laterally to ${secondNode} (T1550.002 Pass the Hash).`,
      "warning"
    );
  } else if (step >= 3) {
    const proposal = buildMockPendingAction();
    state.status = "awaiting_approval";
    state.currentStep = 4;
    state.riskScore = 87;
    state.anomaly_score = proposal.anomaly_score;
    state.pending_action = proposal;
    state.red_report =
      `THREAT ACTOR REPORT (tool-grounded)\n` +
      `a) Technique: T1550.002 — Pass the Hash (Lateral Movement)\n` +
      `b) Discovered path: ${proposal.source} -> ${proposal.target}\n` +
      `c) Objective: Escalate privileges on ${proposal.target}.`;
    state.blue_report =
      `INCIDENT RESPONSE PROPOSAL (awaiting human approval)\n` +
      `1) ML verdict: ANOMALY — anomaly_score ${proposal.anomaly_score}\n` +
      `2) Historical incident cited (RAG): ${proposal.cited_incident}\n` +
      `3) Proposed containment: sever ${proposal.source} -> ${proposal.target}.`;

    addLog(
      `Blue Agent proposes severing ${proposal.source} -> ${proposal.target} (ML score ${proposal.anomaly_score}) — awaiting human analyst approval.`,
      "defence"
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
    state.pending_action = null;
    state.currentStep = 1;
    step = 0;

    addLog("Simulation started — Red Agent scanning network topology.", "system");

    return structuredClone(state);
  };

export const mockPauseSimulation =
  async (): Promise<SimulationData> => {
    await wait(200);

    state.status = "paused";

    addLog("Simulation paused.", "system");

    return structuredClone(state);
  };

export const mockApproveAction =
  async (): Promise<{ status: string; action_taken: string }> => {
    await wait(200);

    const action = state.pending_action ?? buildMockPendingAction();
    updateNodeStatus(action.target, "isolated");
    if (action.source !== action.target) {
      updateNodeStatus(action.source, "isolated");
    }

    state.edges = state.edges
      .filter((e) => !(e.source === action.source && e.target === action.target))
      .map((e) => ({ ...e, active: false }));

    if (customTopology) {
      customTopology = {
        ...customTopology,
        connections: customTopology.connections.filter(
          (c) => !(c.source === action.source && c.target === action.target)
        ),
      };
    }

    const taken = `Severed ${action.source} -> ${action.target} (Approved by human-analyst)`;
    state.status = "completed";
    state.currentStep = 6;
    state.riskScore = 34;
    state.pending_action = null;
    state.action_taken = taken;

    addLog(`HITL APPROVED: ${taken}`, "success");
    return { status: "completed", action_taken: taken };
  };

export const mockRejectAction =
  async (): Promise<{ status: string; action_taken: string }> => {
    await wait(200);

    const taken = "No action taken (proposal rejected by analyst).";
    state.status = "completed";
    state.currentStep = 6;
    state.pending_action = null;
    state.action_taken = taken;

    addLog(`HITL REJECTED: ${taken}`, "warning");
    return { status: "completed", action_taken: taken };
  };

export const mockResetSimulation =
  async (): Promise<SimulationData> => {
    await wait(200);

    state = structuredClone(initialMockData);
    if (customTopology) {
      const converted = topologyFileToNodesAndEdges(customTopology);
      state.nodes = converted.nodes;
      state.edges = converted.edges;
    }
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

export const mockUploadTopology = async (
  file: File
): Promise<{ deviceCount: number; connectionCount: number }> => {
  await wait(150);
  const raw = JSON.parse(await file.text()) as NetworkTopologyFile;
  if (!raw || !Array.isArray(raw.devices) || !Array.isArray(raw.connections)) {
    throw new Error("Topology JSON must contain 'devices' and 'connections' arrays.");
  }
  const known = new Set(raw.devices.map((d) => d.id));
  for (const conn of raw.connections) {
    if (!known.has(conn.source) || !known.has(conn.target)) {
      throw new Error(
        `Connection references unknown device id: ${conn.source} -> ${conn.target}`
      );
    }
  }
  customTopology = raw;
  const converted = topologyFileToNodesAndEdges(raw);
  state.nodes = converted.nodes;
  state.edges = converted.edges;
  state.status = "idle";
  state.pending_action = null;
  state.currentStep = 0;
  step = 0;
  addLog(
    `Loaded custom topology (${raw.devices.length} devices, ${raw.connections.length} connections).`,
    "system"
  );
  return {
    deviceCount: raw.devices.length,
    connectionCount: raw.connections.length,
  };
};

export const mockFetchTopology = async (): Promise<NetworkTopologyFile> => {
  await wait(100);
  if (customTopology) {
    return structuredClone(customTopology);
  }
  return {
    devices: state.nodes.map((n, idx) => ({
      id: n.id,
      name: n.label,
      ip: n.ipAddress,
      subnet: idx < 2 ? "public_dmz" : "internal_core",
      ports: n.openPorts,
      os: n.operatingSystem ?? "Linux",
      cves: n.knownCves,
    })),
    connections: state.edges.map((e) => ({
      source: e.source,
      target: e.target,
      type: e.type ?? "NETWORK_LINK",
    })),
  };
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
