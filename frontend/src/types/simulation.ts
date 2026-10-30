export type NodeStatus =
  | "default"
  | "compromised"
  | "isolated";

export type SimulationStatus =
  | "idle"
  | "running"
  | "awaiting_approval"
  | "paused"
  | "completed"
  | "error";

export type LogType =
  | "attack"
  | "defence"
  | "system"
  | "warning"
  | "success";

export type RemediationPriority =
  | "critical"
  | "high"
  | "medium"
  | "low";

export type PlaybookAction =
  | "isolate-node"
  | "block-port"
  | "patch-vulnerability"
  | "disable-connection";

export interface TopologyDevice {
  id: string;
  name: string;
  ip: string;
  subnet: "public_dmz" | "internal_core";
  ports: number[];
  os: string;
  cves: string[];
}

export interface TopologyConnection {
  source: string;
  target: string;
  type: string;
}

export interface NetworkTopologyFile {
  devices: TopologyDevice[];
  connections: TopologyConnection[];
}

export interface PendingAction {
  source: string;
  target: string;
  anomaly_score: number;
  mitre_tactic: string;
  justification: string;
  cited_incident?: string;
  aws_remediation?: Record<string, unknown> | null;
  proposed_at?: string;
}

export interface NetworkNode {
  id: string;
  label: string;
  type: string;
  status: NodeStatus;
  subnet?: "public_dmz" | "internal_core";

  ipAddress: string;
  operatingSystem?: string;

  softwareName?: string;
  softwareVersion?: string;

  riskScore: number;
  vulnerabilities: string[];
  knownCves: string[];
  openPorts: number[];

  isCriticalService: boolean;
  businessService?: string;
}

export interface NetworkEdge {
  id: string;
  source: string;
  target: string;
  type?: string;
  active?: boolean;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  message: string;
  type: LogType;
}

export interface Remediation {
  id: string;
  title: string;
  priority: RemediationPriority;

  affectedNodeId: string;
  affectedNodeLabel: string;

  cve?: string;
  exploitFrequency: number;
  riskReduction: number;
}

export interface PlaybookRequest {
  nodeId: string;
  action: PlaybookAction;
  port?: number;
  vulnerability?: string;
  edgeId?: string;
}

export interface PlaybookImpact {
  previousRiskScore: number;
  projectedRiskScore: number;

  mttdReduction: number;
  mttrReduction: number;

  criticalServicesOffline: number;
  affectedServices: string[];

  recommendation: string;
}

export interface SimulationData {
  simulationId: string;
  session_id?: string;
  status: SimulationStatus;
  riskScore: number;

  // Used by the timeline.
  // 0 = not started, 1–6 = simulation stages.
  currentStep: number;

  nodes: NetworkNode[];
  edges: NetworkEdge[];
  logs: AuditLog[];
  remediations: Remediation[];

  pending_action?: PendingAction | null;
  red_report?: string | null;
  blue_report?: string | null;
  compromised_node?: string | null;
  mitre_tactic?: string | null;
  anomaly_score?: number | null;
  latest_event?: string | null;
  action_taken?: string | null;

  latestPlaybookImpact?: PlaybookImpact;
}

export type SimulationSession = SimulationData;
