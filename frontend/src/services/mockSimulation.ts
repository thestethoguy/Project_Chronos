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

const HIGH_RISK_PORTS = new Set([
  21, 22, 23, 53, 80, 88, 135, 139, 389, 445, 1433, 1521, 3306, 3389, 5432,
  5985, 6379, 8080, 8443,
]);
const DB_DATA_PORTS = new Set([445, 1433, 1521, 3306, 5432, 6379, 9200, 27017]);
const AUTH_REMOTE_PORTS = new Set([22, 23, 88, 389, 445, 3389, 5985]);

function polyHash(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h = Math.imul(h ^ text.charCodeAt(i), 16777619) & 0x7fffffff;
  }
  return h;
}

function countDownstreamReach(edges: NetworkEdge[], startId: string): number {
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    const list = adj.get(e.source) ?? [];
    list.push(e.target);
    adj.set(e.source, list);
  }
  const visited = new Set<string>([startId]);
  const queue: string[] = [startId];
  while (queue.length > 0) {
    const curr = queue.shift()!;
    for (const nxt of adj.get(curr) ?? []) {
      if (!visited.has(nxt)) {
        visited.add(nxt);
        queue.push(nxt);
      }
    }
  }
  return visited.size;
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
  const vulnCount = nodes.filter((n) => (n.knownCves?.length ?? 0) > 0).length;
  const vulnRatio = vulnCount / nodes.length;

  let riskyPortCount = 0;
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  for (const n of nodes) {
    for (const p of n.openPorts ?? []) {
      if (HIGH_RISK_PORTS.has(p)) riskyPortCount += 1;
    }
  }

  let crossSubnetLinks = 0;
  for (const e of edges) {
    const sSub = nodeMap.get(e.source)?.subnet;
    const tSub = nodeMap.get(e.target)?.subnet;
    if (sSub && tSub && sSub !== tSub) {
      crossSubnetLinks += 1;
    }
  }

  const score = Math.round(
    14 +
      vulnRatio * 24 +
      Math.min(24, totalCves * 3.5) +
      Math.min(12, riskyPortCount * 1.2) +
      Math.min(10, crossSubnetLinks * 2.5)
  );
  return Math.max(14, Math.min(78, score));
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

interface CorridorProfile {
  source: string;
  target: string;
  hour_of_day: number;
  bytes_transferred: number;
  failed_login_attempts: number;
  anomaly_score: number;
  mitre_tactic: string;
  cited_incident: string;
  aws_remediation: NonNullable<PendingAction["aws_remediation"]>;
}

export function computeCorridorProfile(
  nodes: NetworkNode[],
  edges: NetworkEdge[]
): CorridorProfile {
  const coreIds = new Set(
    nodes
      .filter((n) => n.subnet === "internal_core" || n.isCriticalService)
      .map((n) => n.id)
  );
  const preferredEdge =
    edges.find(
      (e) =>
        (e.source === "web_server_01" && e.target === "db_secret_01") ||
        (e.source === "web_server_01" && e.target === "auth_controller") ||
        (e.source === "auth-ctl" && e.target === "dc-01")
    ) ??
    edges.find((e) => coreIds.has(e.target) && !coreIds.has(e.source)) ??
    edges.find((e) => coreIds.has(e.target)) ??
    edges[edges.length - 1] ??
    edges[0] ?? {
      id: "e0",
      source: nodes[0]?.id ?? "node_0",
      target: nodes[1]?.id ?? nodes[0]?.id ?? "node_1",
      active: false,
    };

  const srcId = preferredEdge.source;
  const tgtId = preferredEdge.target;
  const srcNode = nodes.find((n) => n.id === srcId);
  const tgtNode = nodes.find((n) => n.id === tgtId);

  const srcCves = srcNode?.vulnerabilities?.length ?? 0;
  const tgtCves = tgtNode?.vulnerabilities?.length ?? 0;
  const corridorCves = srcCves + tgtCves;
  const totalCves = nodes.reduce(
    (sum, n) => sum + (n.vulnerabilities?.length ?? 0),
    0
  );

  const tgtPorts = new Set(tgtNode?.openPorts ?? []);
  const srcPorts = new Set(srcNode?.openPorts ?? []);
  const combinedPorts = new Set([...srcPorts, ...tgtPorts]);

  let highRiskPortHits = 0;
  let dbPortHits = 0;
  let authPortHits = 0;
  for (const p of combinedPorts) {
    if (HIGH_RISK_PORTS.has(p)) highRiskPortHits += 1;
    if (DB_DATA_PORTS.has(p)) dbPortHits += 1;
    if (AUTH_REMOTE_PORTS.has(p)) authPortHits += 1;
  }

  const crossSubnet =
    (srcNode?.subnet ?? "public_dmz") !== (tgtNode?.subnet ?? "internal_core")
      ? 1
      : 0;
  const tgtCritical =
    tgtNode?.isCriticalService || tgtNode?.subnet === "internal_core" ? 1 : 0;
  const downstreamReach = countDownstreamReach(tgtId, edges);

  const topoSignature = `${nodes.map((n) => n.id).sort().join(",")}|${srcId}->${tgtId}|cves=${totalCves}:${corridorCves}|ports=${Array.from(combinedPorts).sort((a, b) => a - b).join(",")}`;
  const sigHash = polyHash(topoSignature);

  const hour_of_day =
    corridorCves > 0 || tgtCritical ? sigHash % 5 : 8 + (sigHash % 9);

  const baseBytes = 1400 + nodes.length * 420 + edges.length * 310;
  const cveBytes = corridorCves * 14500 + totalCves * 2800;
  const portBytes = dbPortHits * 26000 + highRiskPortHits * 6800;
  const reachBytes = downstreamReach * 4900 + crossSubnet * 9500;
  const jitterBytes = sigHash % 4300;
  const bytes_transferred = Math.min(
    250000,
    Math.max(950, baseBytes + cveBytes + portBytes + reachBytes + jitterBytes)
  );

  const failed_login_attempts = Math.min(
    65,
    Math.max(
      1,
      1 +
        corridorCves * 5 +
        authPortHits * 6 +
        highRiskPortHits * 2 +
        crossSubnet * 3 +
        (sigHash % 5)
    )
  );

  // Continuous mathematical anomaly score in [0.4200, 0.9850]
  const byteRatio = Math.min(1, bytes_transferred / 95000);
  const loginRatio = Math.min(1, failed_login_attempts / 32);
  const cveRatio = Math.min(1, (corridorCves * 2 + totalCves * 0.4) / 10);
  const portRatio = Math.min(1, (highRiskPortHits + dbPortHits * 1.5) / 6);
  const reachRatio = Math.min(
    1,
    (downstreamReach + crossSubnet * 2 + tgtCritical * 2) / 8
  );
  const microOffset = ((sigHash % 89) - 44) * 0.0003;

  const rawScore =
    0.38 +
    byteRatio * 0.19 +
    loginRatio * 0.15 +
    cveRatio * 0.12 +
    portRatio * 0.08 +
    reachRatio * 0.06 +
    microOffset;
  const anomaly_score = Number(
    Math.min(0.985, Math.max(0.42, rawScore)).toFixed(4)
  );

  const blob = `${srcId} ${tgtId} ${tgtNode?.label ?? ""} ${preferredEdge.edgeType ?? ""}`.toLowerCase();

  let mitre_tactic =
    "Lateral Movement (T1210 - Exploitation of Remote Services)";
  let cited_incident =
    "Incident 2024-09: DMZ Web Tier Remote Service Exploitation & Lateral Pivot";

  if (
    ["auth", "domain", "dc", "kerberos", "ldap", "controller"].some((k) =>
      blob.includes(k)
    ) ||
    tgtPorts.has(88) ||
    tgtPorts.has(389) ||
    tgtPorts.has(636)
  ) {
    mitre_tactic = "Lateral Movement (T1550.002 - Pass the Hash)";
    cited_incident =
      "Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth";
  } else if (
    ["db", "sql", "postgres", "mysql", "redis", "mongo", "vault", "ledger", "storage"].some(
      (k) => blob.includes(k)
    ) ||
    [1433, 1521, 3306, 5432, 6379, 27017].some((p) => tgtPorts.has(p))
  ) {
    mitre_tactic =
      "Collection & Exfiltration (T1213 - Automated Database Extraction)";
    cited_incident =
      "Incident 2024-11: Unauthorized SQL Bulk Extraction & Core Vault Staging";
  } else if (tgtPorts.has(445) || blob.includes("smb")) {
    mitre_tactic = "Lateral Movement (T1021.002 - SMB/Windows Admin Shares)";
    cited_incident =
      "Incident 2024-08: East-West SMB Admin Share Traversal & Worm Propagation";
  } else if (tgtPorts.has(22) || blob.includes("ssh")) {
    mitre_tactic = "Lateral Movement (T1021.004 - SSH Credential Hijacking)";
    cited_incident =
      "Incident 2025-01: Compromised Bastion SSH Key Replay Across Internal Subnets";
  } else if (tgtPorts.has(3389) || blob.includes("rdp")) {
    mitre_tactic = "Lateral Movement (T1021.001 - Remote Desktop Protocol)";
    cited_incident =
      "Incident 2024-10: Privileged RDP Session Hijacking into Core Subnet";
  } else if (tgtPorts.has(53) || blob.includes("dns")) {
    mitre_tactic = "Command and Control (T1071.004 - DNS Tunneling)";
    cited_incident =
      "Incident 2024-07: Internal DNS Resolver C2 Tunneling & Beacon Exfiltration";
  }

  const isAuthTarget = ["auth", "domain", "dc", "iam", "ldap", "controller"].some(
    (k) => blob.includes(k)
  );
  const roleName = isAuthTarget
    ? `ChronosRole-${tgtId.replace(/[^a-zA-Z0-9]/g, "")}`
    : `ChronosSG-${tgtId.replace(/[^a-zA-Z0-9]/g, "")}`;

  const aws_remediation: NonNullable<PendingAction["aws_remediation"]> =
    isAuthTarget
      ? {
          role_name: roleName,
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
                Action: ["sts:AssumeRole"],
                Resource: `arn:aws:iam::account:role/${roleName}`,
              },
            ],
          },
          change_summary: `Revoked wildcard 'iam:PassRole' and scoped 'sts:AssumeRole' on ${roleName} to block credential replay toward ${tgtId}.`,
          data_source: "mock",
          executed: false,
        }
      : {
          instance_id: tgtId,
          before_security_groups: [`sg-default-${tgtNode?.subnet ?? "core"}`],
          after_security_groups: [
            `sg-quarantine-deny-all-${tgtId.slice(0, 10)}`,
          ],
          ingress_rules: [],
          egress_rules: [],
          change_summary: `Drafted zero-ingress/zero-egress quarantine security group for ${tgtId} (${tgtNode?.ip ?? "10.0.1.x"}, ports [${Array.from(tgtPorts).join(", ") || "none"}]).`,
          data_source: "mock",
          executed: false,
        };

  return {
    source: srcId,
    target: tgtId,
    hour_of_day,
    bytes_transferred,
    failed_login_attempts,
    anomaly_score,
    mitre_tactic,
    cited_incident,
    aws_remediation,
  };
}

function buildMockPendingAction(): PendingAction {
  const profile = computeCorridorProfile(state.nodes, state.edges);
  return {
    source: profile.source,
    target: profile.target,
    anomaly_score: profile.anomaly_score,
    mitre_tactic: profile.mitre_tactic,
    cited_incident: profile.cited_incident,
    justification: `Isolation Forest scored telemetry on ${profile.source} -> ${profile.target} at ${profile.anomaly_score.toFixed(4)} (ANOMALY): Event at ${String(profile.hour_of_day).padStart(2, "0")}:17 UTC; ${profile.bytes_transferred.toLocaleString()} bytes transferred; ${profile.failed_login_attempts} failed authentication attempts. Closest historical precedent: '${profile.cited_incident}'. Severing ${profile.source} -> ${profile.target} cuts the active ${profile.mitre_tactic} path. Awaiting human approval.`,
    aws_remediation: profile.aws_remediation,
    proposed_at: new Date().toISOString(),
  };
}

const applyNextStep = (): void => {
  if (state.status !== "running") {
    return;
  }

  step += 1;
  const profile = computeCorridorProfile(state.nodes, state.edges);
  const proposal = buildMockPendingAction();
  const baselineRisk = computeTopologyBaselineRisk(state.nodes, state.edges);

  const entryNode =
    state.nodes.find((n) => n.id === "proxy_ingress")?.id ??
    state.edges.find((e) => e.target === proposal.source)?.source ??
    state.nodes.find((n) => n.subnet === "public_dmz")?.id ??
    state.nodes[0]?.id ??
    proposal.source;
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

  const entryCves =
    state.nodes.find((n) => n.id === entryNode)?.vulnerabilities?.length ?? 0;
  const hopCves =
    state.nodes.find((n) => n.id === hopNode)?.vulnerabilities?.length ?? 0;

  if (step === 1) {
    updateNodeStatus(entryNode, "compromised");
    activateEdge(firstEdge, true);

    state.riskScore = Math.min(
      92,
      Math.max(baselineRisk + 8, baselineRisk + 7 + entryCves * 5)
    );
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

    state.riskScore = Math.min(
      95,
      Math.max(
        baselineRisk + 16,
        Math.round(
          baselineRisk * 0.55 +
            profile.anomaly_score * 42 +
            (entryCves + hopCves) * 3
        )
      )
    );
    state.currentStep = 2;
    state.compromised_node = hopNode;
    state.mitre_tactic = proposal.mitre_tactic;
    state.latest_event = `Red Agent pivoted to '${hopNode}' via ${proposal.mitre_tactic}, targeting '${proposal.target}'.`;

    addLog(
      `Red Agent moved laterally to ${hopNode} (${proposal.mitre_tactic}).`,
      "warning"
    );
  } else if (step >= 3) {
    updateNodeStatus(proposal.target, "compromised");
    activateEdge(secondEdge, true);
    state.status = "awaiting_approval";
    state.currentStep = 4;
    state.riskScore = Math.min(
      98,
      Math.max(
        baselineRisk + 14,
        Math.round(baselineRisk * 0.42 + proposal.anomaly_score * 58)
      )
    );
    state.compromised_node = proposal.target;
    state.mitre_tactic = proposal.mitre_tactic;
    state.anomaly_score = proposal.anomaly_score;
    state.pending_action = proposal;
    state.latest_event = `Blue Agent proposes severing ${proposal.source} -> ${proposal.target} — awaiting human analyst approval.`;
    state.action_taken = "Pending human approval";
    state.red_report =
      `THREAT ACTOR REPORT (tool-grounded)\n` +
      `a) Technique: ${proposal.mitre_tactic} launched from ${entryNode}.\n` +
      `b) Discovered path (graph_scan_neighbors): ${entryNode} -> ${proposal.source} -> ${proposal.target}.\n` +
      `c) Telemetry footprint: ${profile.bytes_transferred.toLocaleString()} bytes staged across ${profile.failed_login_attempts} authentication attempts.\n` +
      `d) OPSEC: activity timestamped at ${String(profile.hour_of_day).padStart(2, "0")}:17 UTC.\n` +
      `e) Next objective: compromise ${proposal.target} and exfiltrate crown-jewel assets.`;
    state.blue_report =
      `INCIDENT RESPONSE PROPOSAL (awaiting human approval)\n` +
      `1) ML verdict: ANOMALY — anomaly_score ${proposal.anomaly_score.toFixed(4)} (${profile.bytes_transferred.toLocaleString()} bytes, ${profile.failed_login_attempts} failed logins, hour=${profile.hour_of_day}).\n` +
      `2) Historical incident cited (RAG): ${proposal.cited_incident}.\n` +
      `3) AWS remediation draft (executed=False): ${proposal.aws_remediation?.change_summary ?? "Isolation group drafted"}.\n` +
      `4) Proposed containment: sever ${proposal.source} -> ${proposal.target} (${proposal.mitre_tactic}).`;

    addLog(
      `Blue Agent proposes severing ${proposal.source} -> ${proposal.target} (ML score ${proposal.anomaly_score.toFixed(4)}) — awaiting human analyst approval.`,
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

    const baselineRisk = computeTopologyBaselineRisk(state.nodes, state.edges);
    const reduction = Math.max(12, Math.round(baselineRisk * 0.45));
    const taken = `Severed ${action.source} -> ${action.target} (Approved by human-analyst)`;
    state.status = "completed";
    state.currentStep = 6;
    state.riskScore = Math.max(8, baselineRisk - reduction);
    state.pending_action = null;
    state.action_taken = taken;

    addLog(`HITL APPROVED: ${taken}`, "success");
    return { status: "completed", action_taken: taken };
  };

export const mockRejectAction =
  async (): Promise<{ status: string; action_taken: string }> => {
    await wait(200);

    const baselineRisk = computeTopologyBaselineRisk(state.nodes, state.edges);
    const taken = "No action taken (proposal rejected by analyst).";
    state.status = "completed";
    state.currentStep = 6;
    state.riskScore = Math.min(98, Math.max(baselineRisk + 12, state.riskScore));
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
