export type NodeStatus =
  | "default"
  | "compromised"
  | "isolated";

export type SimulationStatus =
  | "idle"
  | "running"
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

export interface NetworkNode {
  id: string;
  label: string;
  type: string;
  status: NodeStatus;

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
  status: SimulationStatus;
  riskScore: number;

  // Used by the timeline.
  // 0 = not started, 1–6 = simulation stages.
  currentStep: number;

  nodes: NetworkNode[];
  edges: NetworkEdge[];
  logs: AuditLog[];
  remediations: Remediation[];

  latestPlaybookImpact?: PlaybookImpact;
}