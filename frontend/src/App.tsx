import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  FiActivity,
  FiCpu,
  FiCrosshair,
  FiShield,
} from "react-icons/fi";

import { Header } from "./components/Header";
import { RiskSummary } from "./components/RiskSummary";
import { TopologyUploader } from "./components/TopologyUploader";
import { ApprovalPanel } from "./components/ApprovalPanel";
import { NetworkGraph } from "./components/NetworkGraph";
import { NodeDetails } from "./components/NodeDetails";
import { SOCCopilotChat } from "./components/SOCCopilotChat";
import { AuditLog } from "./components/AuditLog";
import { RemediationQueue } from "./components/RemediationQueue";
import { SimulationControls } from "./components/SimulationControls";
import { SimulationTimeline } from "./components/SimulationTimeline";
import { PlaybookModal } from "./components/PlaybookModal";

import {
  getSimulationStatus,
  pauseSimulation,
  resetSimulation,
  runPlaybook,
  startSimulation,
} from "./services/api";

import { initialMockData } from "./data/mockData";

import type {
  PlaybookImpact,
  PlaybookRequest,
  SimulationData,
} from "./types/simulation";

function App() {
  const [data, setData] =
    useState<SimulationData>(initialMockData);

  const [selectedNodeId, setSelectedNodeId] =
    useState<string | undefined>("web_server_01");

  const [refreshSignal, setRefreshSignal] =
    useState<number>(0);

  const [loading, setLoading] =
    useState<boolean>(false);

  const [error, setError] =
    useState<string | undefined>(undefined);

  const [playbookOpen, setPlaybookOpen] =
    useState<boolean>(false);

  const [playbookLoading, setPlaybookLoading] =
    useState<boolean>(false);

  const [
    playbookImpact,
    setPlaybookImpact,
  ] = useState<PlaybookImpact | undefined>(
    undefined
  );

  const pollingInterval = Number(
    import.meta.env.VITE_POLLING_INTERVAL ||
      1000
  );

  const selectedNode = useMemo(() => {
    return (
      data.nodes.find((node) => node.id === selectedNodeId) ??
      data.nodes[0]
    );
  }, [data.nodes, selectedNodeId]);

  const refreshSimulation =
    useCallback(async (): Promise<void> => {
      try {
        const response =
          await getSimulationStatus();

        setData(response);
        if (response.pending_action?.target) {
          setSelectedNodeId((prev) => prev ?? response.pending_action?.target);
        }
        setError(undefined);
      } catch (err) {
        console.error(
          "Could not retrieve simulation data:",
          err
        );

        setError(
          "Unable to retrieve simulation data."
        );
      }
    }, []);

  const refreshAll =
    useCallback(async (): Promise<void> => {
      setRefreshSignal((n) => n + 1);
      await refreshSimulation();
    }, [refreshSimulation]);

  useEffect(() => {
    void refreshSimulation();
  }, [refreshSimulation]);

  useEffect(() => {
    if (
      data.status !== "running" &&
      data.status !== "awaiting_approval"
    ) {
      return;
    }

    const intervalId =
      window.setInterval(() => {
        void refreshSimulation();
      }, pollingInterval);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [
    data.status,
    pollingInterval,
    refreshSimulation,
  ]);

  const runAction = async (
    action: () => Promise<SimulationData>
  ): Promise<void> => {
    try {
      setLoading(true);

      const response = await action();

      setData(response);
      setRefreshSignal((n) => n + 1);
      setError(undefined);
    } catch (err) {
      console.error(
        "Simulation action failed:",
        err
      );

      setError(
        "The requested simulation action failed."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleStart =
    async (): Promise<void> => {
      await runAction(startSimulation);
    };

  const handlePause =
    async (): Promise<void> => {
      await runAction(pauseSimulation);
    };

  const handleReset =
    async (): Promise<void> => {
      await runAction(resetSimulation);

      setSelectedNodeId(undefined);
      setPlaybookImpact(undefined);
    };

  const handleRunPlaybook = async (
    request: PlaybookRequest
  ): Promise<void> => {
    try {
      setPlaybookLoading(true);

      const impact =
        await runPlaybook(request);

      setPlaybookImpact(impact);
      setError(undefined);
    } catch (err) {
      console.error(
        "Playbook validation failed:",
        err
      );

      setError(
        "Unable to calculate the playbook impact."
      );
    } finally {
      setPlaybookLoading(false);
    }
  };

  const handleOpenPlaybook = (): void => {
    setPlaybookImpact(undefined);
    setPlaybookOpen(true);
  };

  const handleClosePlaybook = (): void => {
    setPlaybookOpen(false);
  };

  const anomalyPercent =
    data.anomaly_score != null
      ? Math.round(data.anomaly_score * 100)
      : data.pending_action?.anomaly_score != null
      ? Math.round(data.pending_action.anomaly_score * 100)
      : data.status === "idle"
      ? 12
      : 82;

  const citedIncident =
    data.pending_action?.cited_incident ||
    (data.status === "completed"
      ? "Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth"
      : "Standby — RAG vector search triggers on anomaly detection");

  const protocolStage =
    data.status === "idle"
      ? 0
      : data.status === "running"
      ? 2
      : data.status === "awaiting_approval"
      ? 3
      : 4;

  return (
    <main className="app-shell">
      <Header
        status={data.status}
        simulationId={data.simulationId}
      />

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      <RiskSummary data={data} />

      <TopologyUploader
        onUploaded={refreshAll}
      />

      <SimulationControls
        status={data.status}
        loading={loading}
        onStart={handleStart}
        onPause={handlePause}
        onReset={handleReset}
      />

      <ApprovalPanel
        status={data.status}
        pendingAction={data.pending_action}
        onActionResolved={refreshAll}
      />

      <div className="playbook-action-row">
        <button
          type="button"
          className="button playbook-open-button"
          onClick={handleOpenPlaybook}
        >
          <FiShield />
          Test Containment Strategy
        </button>
      </div>

      <SimulationTimeline
        currentStep={data.currentStep}
        status={data.status}
      />

      {/* Live Multi-Agent Reasoning & Telemetry Console */}
      <section className="agent-telemetry-grid">
        {/* RED AGENT CARD */}
        <article className="panel agent-card agent-card-red">
          <div className="agent-card-header">
            <div className="agent-title-group">
              <span className="agent-pulse-dot agent-pulse-red" />
              <div>
                <p className="eyebrow agent-eyebrow-red">
                  OFFENSIVE ADVERSARY EMULATION
                </p>
                <h2>
                  <FiCrosshair style={{ marginRight: 7, verticalAlign: "middle" }} />
                  Red Agent — APT29 / APT41 Simulator
                </h2>
              </div>
            </div>
            <span className="agent-badge agent-badge-red">
              {data.mitre_tactic || "T1550.002 Pass the Hash"}
            </span>
          </div>

          <div className="agent-metrics-row">
            <div className="agent-kv">
              <span>ENTRY FOOTHOLD</span>
              <strong className="mono-id">
                {data.nodes[0]?.id || "proxy_ingress"}
              </strong>
            </div>
            <div className="agent-kv">
              <span>DISCOVERED CORRIDOR</span>
              <strong className="mono-id">
                {data.pending_action
                  ? `${data.pending_action.source} ➔ ${data.pending_action.target}`
                  : data.compromised_node
                  ? `proxy_ingress ➔ ${data.compromised_node}`
                  : "Scanning DMZ neighbors..."}
              </strong>
            </div>
            <div className="agent-kv">
              <span>ACTIVE TOOL</span>
              <strong className="mono-id">graph_scan_neighbors()</strong>
            </div>
          </div>

          <pre className="agent-console-output">
            {data.red_report ||
              (data.status === "running"
                ? "[APT-SIM] Probing adjacent graph pathways via graph_scan_neighbors('proxy_ingress')...\n[APT-SIM] Replaying cached NTLM credentials across internal_core subnet..."
                : "[APT-SIM] Adversary simulator on standby. Click 'Start Simulation' to launch autonomous multi-hop lateral movement.")}
          </pre>
        </article>

        {/* BLUE AGENT CARD */}
        <article className="panel agent-card agent-card-blue">
          <div className="agent-card-header">
            <div className="agent-title-group">
              <span className="agent-pulse-dot agent-pulse-blue" />
              <div>
                <p className="eyebrow agent-eyebrow-blue">
                  BOUNDED-AUTHORITY SOAR DEFENSE
                </p>
                <h2>
                  <FiCpu style={{ marginRight: 7, verticalAlign: "middle" }} />
                  Blue Agent — ML + RAG + AWS Governance
                </h2>
              </div>
            </div>
            <span className="agent-badge agent-badge-blue">
              <FiActivity style={{ marginRight: 5 }} />
              ML Anomaly: {anomalyPercent}%
            </span>
          </div>

          {/* 4-Step Mandatory Protocol Stepper */}
          <div className="protocol-stepper">
            <span className={`protocol-pill ${protocolStage >= 1 ? "done" : ""}`}>
              1. Isolation Forest ML {protocolStage >= 1 ? "✓" : ""}
            </span>
            <span className={`protocol-pill ${protocolStage >= 2 ? "done" : ""}`}>
              2. RAG Incident Cite {protocolStage >= 2 ? "✓" : ""}
            </span>
            <span className={`protocol-pill ${protocolStage >= 3 ? "done" : ""}`}>
              3. AWS Draft (executed:false) {protocolStage >= 3 ? "✓" : ""}
            </span>
            <span
              className={`protocol-pill ${
                data.status === "awaiting_approval"
                  ? "pending"
                  : protocolStage >= 4
                  ? "done"
                  : ""
              }`}
            >
              4. HITL Analyst Gate{" "}
              {data.status === "awaiting_approval"
                ? "⏳"
                : protocolStage >= 4
                ? "✓"
                : ""}
            </span>
          </div>

          <div className="agent-rag-box">
            <span>RAG HISTORICAL PRECEDENT CITED:</span>
            <strong>{citedIncident}</strong>
          </div>

          <pre className="agent-console-output">
            {data.blue_report ||
              (data.status === "running"
                ? "[SOAR-AI] Scoring telemetry via ml_score_anomaly(hour=3, bytes=50000, failed_logins=20)...\n[SOAR-AI] Querying 768-dim incident vector store via rag_retrieve_incidents()..."
                : "[SOAR-AI] Bounded-authority defense active. Destructive actions (graph_cut_connection) require explicit human-analyst approval.")}
          </pre>
        </article>
      </section>

      <div className="dashboard-grid">
        <div className="main-column">
          <NetworkGraph
            nodes={data.nodes}
            edges={data.edges}
            selectedNodeId={selectedNodeId}
            onNodeSelect={setSelectedNodeId}
            refreshSignal={refreshSignal}
            compromisedNode={data.compromised_node}
            pendingAction={data.pending_action}
            simulationStatus={data.status}
            actionTaken={data.action_taken}
          />

          <RemediationQueue
            items={data.remediations}
          />
        </div>

        <aside className="side-column">
          <NodeDetails
            node={selectedNode}
            edges={data.edges}
          />

          <SOCCopilotChat />

          <AuditLog logs={data.logs} />
        </aside>
      </div>

      <PlaybookModal
        nodes={data.nodes}
        open={playbookOpen}
        loading={playbookLoading}
        impact={playbookImpact}
        onClose={handleClosePlaybook}
        onRun={handleRunPlaybook}
      />
    </main>
  );
}

export default App;
