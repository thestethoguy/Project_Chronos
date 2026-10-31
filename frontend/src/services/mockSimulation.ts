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

export function computeTopologyBaselineRisk(
  nodes: NetworkNode[],
  edges: NetworkEdge[]
): number {
  if (nodes.length === 0) return 0;
  const totalCves = nodes.reduce(
    (sum, n) => sum + (n.knownCves?.length ?? 0),
    0
  );
  const critCount = nodes.filter(
    (n) => n.isCriticalService || n.riskScore >= 70
  ).length;
  const avgNodeRisk =
    nodes.reduce((sum, n) => sum + (n.riskScore ?? 35), 0) / nodes.length;
  const score = Math.round(
    avgNodeRisk * 0.55 +
      Math.min(28, totalCves * 4) +
      Math.min(18, critCount * 2 + Math.floor(edges.length / 3))
  );
  return Math.max(12, Math.min(92, score));
}

export function buildStandbySimulationData(): SimulationData {
  return {
    simulationId: "SIM-STANDBY",
    status: "idle",
    riskScore: 0,
    mttd: 0,
    mttr: 0,
    totalAssets: 0,
    vulnerableAssets: 0,
    compromisedAssets: 0,
    currentStep: 0,
    nodes: [],
    edges: [],
    remediations: [],
    pending_action: null,
    compromised_node: null,
    mitre_tactic: null,
    anomaly_score: 0,
    red_report:
      "[STANDBY] No topology blueprint loaded yet. Select 'Load 20-Node Enterprise Demo' or 'Upload Custom Topology (.json)' above to initialize the Digital Twin.",
    blue_report:
      "[STANDBY] Bounded-authority SOAR engine on standby. Select a topology mode above to compute baseline CVE posture and enable autonomous simulation.",
    logs: [
      {
        id: "standby-log-1",
        timestamp: new Date().toLocaleTimeString(),
        message:
          "System initialized in Dual-Mode Standby. Choose Pre-Structured Demo Mode or Upload Custom Topology (.json) to begin.",
        type: "system",
      },
    ],
  };
}

export function buildRemediationItemsFromTopology(topo: NetworkTopologyFile) {
  const withCves = topo.devices.filter((d) => d.cves && d.cves.length > 0);
  if (withCves.length === 0) {
    return topo.devices.slice(0, 3).map((d, idx) => ({
      id: `rem-custom-${idx + 1}`,
      priority: idx + 1,
      title: `Harden & segment ${d.name || d.id} (${d.subnet})`,
      affectedNode: d.id,
      riskReduction: 14,
      estimatedEffort: "Low" as const,
      recommendedAction: `Enforce strict firewall ACLs and MFA on ${d.id} (${d.ip}) running ${d.os}.`,
    }));
  }
  return withCves.map((d, idx) => ({
    id: `rem-cve-${idx + 1}`,
    priority: idx + 1,
    title: `Patch ${d.cves.join(", ")} on ${d.name || d.id}`,
    affectedNode: d.id,
    riskReduction: Math.min(30, 12 + d.cves.length * 8),
    estimatedEffort: (d.subnet === "internal_core" ? "Medium" : "Low") as
      | "Low"
      | "Medium"
      | "High",
    recommendedAction: `Apply vendor security updates for ${d.cves.join(", ")} on ${d.id} (${d.ip}, ${d.os}) and restrict lateral ports [${(d.ports ?? []).join(", ")}].`,
  }));
}

function buildMockPendingAction(): PendingAction {
  const coreIds = new Set(
    state.nodes
      .filter((n) => n.subnet === "internal_core" || n.isCriticalService)
      .map((n) => n.id)
  );
  const preferredEdge =
    state.edges.find(
      (e) =>
        (e.source === "web_server_01" && e.target === "db_secret_01") ||
        (e.source === "web_server_01" && e.target === "auth_controller") ||
        (e.source === "auth-ctl" && e.target === "dc-01")
    ) ??
    state.edges.find((e) => coreIds.has(e.target) && !coreIds.has(e.source)) ??
    state.edges.find((e) => coreIds.has(e.target)) ??
    state.edges[state.edges.length - 1] ??
    state.edges[0] ?? {
      source: "web_server_01",
      target: "db_secret_01",
    };
  return {
    source: preferredEdge.source,
    target: preferredEdge.target,
    anomaly_score: 0.8742,
    mitre_tactic: "Lateral Movement (T1550.002 - Pass the Hash)",
    cited_incident:
      "Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth",
    justification: `Isolation Forest scored the event 0.8742 (ANOMALY): Activity outside normal office hours (06:00–22:00); Excessive data transfer (50,000 bytes); High failed-login count (20 attempts). Closest historical incident: 'Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth'. Severing ${preferredEdge.source} -> ${preferredEdge.target} cuts the lateral-movement path. Awaiting human approval.`,
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
  const proposal = buildMockPendingAction();
  const entryNode =
    state.nodes.find((n) => n.id === "proxy_ingress")?.id ??
    state.edges.find((e) => e.target === proposal.source)?.source ??
    state.nodes.find((n) => n.subnet === "public_dmz")?.id ??
    state.nodes[0]?.id ??
    "proxy_ingress";
  const hopNode =
    proposal.source !== entryNode
      ? proposal.source
      : state.nodes.find((n) => n.id === "web_server_01")?.id ??
        state.nodes[1]?.id ??
        entryNode;
  const firstEdge =
    state.edges.find(
      (e) => e.source === entryNode && e.target === hopNode
    )?.id ??
    state.edges[0]?.id ??
    "e1";
  const secondEdge =
    state.edges.find(
      (e) => e.source === proposal.source && e.target === proposal.target
    )?.id ??
    state.edges[1]?.id ??
    firstEdge;

  if (step === 1) {
    updateNodeStatus(entryNode, "compromised");
    activateEdge(firstEdge, true);

    state.riskScore = 62;
    state.currentStep = 1;
    state.compromised_node = entryNode;
    state.latest_event = `Red Agent breached perimeter foothold '${entryNode}' and invoked graph_scan_neighbors('${entryNode}').`;

    addLog(
      `Red Agent compromised ${entryNode} via initial foothold.`,
      "attack"
    );
  } else if (step === 2) {
    updateNodeStatus(hopNode, "compromised");
    activateEdge(secondEdge, true);

    state.riskScore = 82;
    state.currentStep = 2;
    state.compromised_node = hopNode;
    state.mitre_tactic = "Lateral Movement (T1550.002 - Pass the Hash)";
    state.latest_event = `Red Agent pivoted to '${hopNode}' via NTLM credential replay (T1550.002), targeting '${proposal.target}'.`;

    addLog(
      `Red Agent moved laterally to ${hopNode} (T1550.002 Pass the Hash).`,
      "warning"
    );
  } else if (step >= 3) {
    updateNodeStatus(proposal.target, "compromised");
    activateEdge(secondEdge, true);
    state.status = "awaiting_approval";
    state.currentStep = 4;
    state.riskScore = 87;
    state.compromised_node = proposal.target;
    state.mitre_tactic = proposal.mitre_tactic;
    state.anomaly_score = proposal.anomaly_score;
    state.pending_action = proposal;
    state.latest_event = `Blue Agent proposes severing ${proposal.source} -> ${proposal.target} — awaiting human analyst approval.`;
    state.action_taken = "Pending human approval";
    state.red_report =
      `THREAT ACTOR REPORT (tool-grounded)\n` +
      `a) Technique: T1550.002 — Pass the Hash (Lateral Movement) via cached NTLM hash from ${entryNode}.\n` +
      `b) Discovered path (graph_scan_neighbors): ${entryNode} -> ${proposal.source} -> ${proposal.target}.\n` +
      `c) Tooling: Impacket (smbexec/psexec), CrackMapExec for credential replay.\n` +
      `d) OPSEC: after-hours activity (03:17 UTC), slow-and-low authentication attempts.\n` +
      `e) Next objective: reach ${proposal.target} and stage crown-jewel data for exfiltration.`;
    state.blue_report =
      `INCIDENT RESPONSE PROPOSAL (awaiting human approval)\n` +
      `1) ML verdict: ANOMALY — anomaly_score ${proposal.anomaly_score.toFixed(4)}.\n` +
      `2) Historical incident cited (RAG): ${proposal.cited_incident}.\n` +
      `3) AWS remediation draft (executed=False): ${proposal.aws_remediation?.change_summary ?? "Isolation group drafted"}.\n` +
      `4) Proposed containment: sever ${proposal.source} -> ${proposal.target} (${proposal.mitre_tactic}).`;

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
      state.riskScore = computeTopologyBaselineRisk(
        converted.nodes,
        converted.edges
      );
      state.remediations = buildRemediationItemsFromTopology(customTopology);
      state.totalAssets = converted.nodes.length;
      state.vulnerableAssets = converted.nodes.filter(
        (n) => (n.knownCves?.length ?? 0) > 0
      ).length;
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

export const mockLoadDemoTopology = async (): Promise<{
  deviceCount: number;
  connectionCount: number;
}> => {
  await wait(150);
  customTopology = null;
  state = structuredClone(initialMockData);
  step = 0;
  addLog(
    `Loaded Pre-Structured Enterprise Demo Topology (${state.nodes.length} devices, ${state.edges.length} connections).`,
    "system"
  );
  return {
    deviceCount: state.nodes.length,
    connectionCount: state.edges.length,
  };
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
  state.riskScore = computeTopologyBaselineRisk(
    converted.nodes,
    converted.edges
  );
  state.remediations = buildRemediationItemsFromTopology(raw);
  state.totalAssets = converted.nodes.length;
  state.vulnerableAssets = converted.nodes.filter(
    (n) => (n.knownCves?.length ?? 0) > 0
  ).length;
  state.status = "idle";
  state.pending_action = null;
  state.compromised_node = undefined;
  state.red_report = undefined;
  state.blue_report = undefined;
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

export const mockClearCustomTopology = (): void => {
  customTopology = null;
  step = 0;
};

export const getMockCustomTopology = (): NetworkTopologyFile | null => {
  return customTopology ? structuredClone(customTopology) : null;
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
      subnet: n.subnet ?? (idx < 5 ? "public_dmz" : "internal_core"),
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
