import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  FiActivity,
  FiCpu,
  FiCrosshair,
  FiShield,
} from "react-icons/fi";

import { Header } from "./components/Header";
import { ChronosIntroSplash } from "./components/ChronosIntroSplash";
import { ChronosCornerHolograms } from "./components/ChronosCornerHolograms";
import { RiskSummary } from "./components/RiskSummary";
import {
  TopologyEntryMode,
  TopologyUploader,
} from "./components/TopologyUploader";
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
  clearCachedTopology,
  getSimulationStatus,
  loadDemoTopology,
  pauseSimulation,
  resetSimulation,
  runPlaybook,
  startSimulation,
} from "./services/api";

import { buildStandbySimulationData } from "./services/mockSimulation";

import type {
  PlaybookImpact,
  PlaybookRequest,
  SimulationData,
} from "./types/simulation";

function App() {
  const [introVisible, setIntroVisible] = useState<boolean>(true);
  const [topologyMode, setTopologyMode] =
    useState<TopologyEntryMode>("standby");
  const [activeTopologyLabel, setActiveTopologyLabel] = useState<string>(
    "Standby — No Blueprint Loaded"
  );
  const [topologySourceName, setTopologySourceName] = useState<string>(
    "Standby — No Blueprint Loaded"
  );
  const [topologyRefreshKey, setTopologyRefreshKey] = useState<number>(0);

  const [data, setData] = useState<SimulationData>(() =>
    buildStandbySimulationData()
  );
  const prevStatusRef = useRef(data.status);

  const [selectedNodeId, setSelectedNodeId] =
    useState<string | undefined>(undefined);

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

  const activeData = useMemo<SimulationData>(() => {
    if (topologyMode === "standby") {
      return buildStandbySimulationData();
    }
    return data;
  }, [topologyMode, data]);

  const selectedNode = useMemo(() => {
    return (
      activeData.nodes.find((node) => node.id === selectedNodeId) ??
      activeData.nodes[0]
    );
  }, [activeData.nodes, selectedNodeId]);

  const refreshSimulation =
    useCallback(async (): Promise<void> => {
      try {
        const response =
          await getSimulationStatus();

        prevStatusRef.current = response.status;
        setData(response);
        if (response.pending_action?.target) {
          setSelectedNodeId((prev) => prev ?? response.pending_action?.target);
        } else if (response.nodes.length > 0) {
          setSelectedNodeId((prev) =>
            prev && response.nodes.some((n) => n.id === prev)
              ? prev
              : response.nodes[0]?.id
          );
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

  const handleLaunchDemo = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      const counts = await loadDemoTopology();
      setTopologyMode("demo");
      setTopologySourceName("20-Node Enterprise Reference");
      setActiveTopologyLabel(
        `20-Node Enterprise Core (${counts.deviceCount} devices, ${counts.connectionCount} links)`
      );
      setTopologyRefreshKey((k) => k + 1);
      setRefreshSignal((n) => n + 1);
      await refreshSimulation();
      setError(undefined);
    } catch (err) {
      console.error("Failed to launch demo topology:", err);
      setError("Could not load the Enterprise Demo topology.");
    } finally {
      setLoading(false);
    }
  }, [refreshSimulation]);

  const handleCustomUploaded = useCallback(
    async (
      filename: string,
      counts: { deviceCount: number; connectionCount: number }
    ): Promise<void> => {
      setTopologyMode("custom");
      setTopologySourceName(filename);
      setActiveTopologyLabel(
        `${filename} (${counts.deviceCount} devices, ${counts.connectionCount} links)`
      );
      setSelectedNodeId(undefined);
      setPlaybookImpact(undefined);
      setTopologyRefreshKey((k) => k + 1);
      setRefreshSignal((n) => n + 1);
      await refreshSimulation();
    },
    [refreshSimulation]
  );

  const handleUnloadTopology = useCallback((): void => {
    clearCachedTopology();
    setTopologyMode("standby");
    setTopologySourceName("Standby — No Blueprint Loaded");
    setActiveTopologyLabel("Standby — No Blueprint Loaded");
    setData(buildStandbySimulationData());
    setSelectedNodeId(undefined);
    setPlaybookImpact(undefined);
    setTopologyRefreshKey((k) => k + 1);
    setError(undefined);
  }, []);

  useEffect(() => {
    if (topologyMode === "standby") {
      return;
    }
    if (
      activeData.status !== "running" &&
      activeData.status !== "awaiting_approval"
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
    topologyMode,
    activeData.status,
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
      if (topologyMode === "standby") {
        setError(
          "Choose Demo Mode above to explore the reference enterprise template, or Upload Custom JSON to simulate your own network."
        );
        return;
      }
      await runAction(startSimulation);
    };

  const handlePause =
    async (): Promise<void> => {
      if (topologyMode === "standby") return;
      await runAction(pauseSimulation);
    };

  const handleReset =
    async (): Promise<void> => {
      if (topologyMode === "standby") return;
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
    if (topologyMode === "standby") {
      setError(
        "Choose Demo Mode above or Upload Custom JSON before running a containment playbook."
      );
      return;
    }
    setPlaybookImpact(undefined);
    setPlaybookOpen(true);
  };

  const handleClosePlaybook = (): void => {
    setPlaybookOpen(false);
  };

  const anomalyPercent =
    topologyMode === "standby"
      ? 0
      : activeData.anomaly_score != null
      ? Math.round(activeData.anomaly_score * 100)
      : activeData.pending_action?.anomaly_score != null
      ? Math.round(activeData.pending_action.anomaly_score * 100)
      : activeData.status === "idle"
      ? 12
      : 82;

  const citedIncident =
    topologyMode === "standby"
      ? "Standby — Select Demo Mode or Upload Custom JSON to activate RAG vector store"
      : activeData.pending_action?.cited_incident ||
        (activeData.status === "completed"
          ? "Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth"
          : "Standby — RAG vector search triggers on anomaly detection");

  const protocolStage =
    topologyMode === "standby" || activeData.status === "idle"
      ? 0
      : activeData.status === "running"
      ? 2
      : activeData.status === "awaiting_approval"
      ? 3
      : 4;

  const entryFootholdId =
    topologyMode === "standby"
      ? "awaiting-blueprint"
      : activeData.nodes.find((n) => n.subnet === "public_dmz")?.id ||
        activeData.nodes[0]?.id ||
        "proxy_ingress";

  return (
    <main className="app-shell">
      <ChronosIntroSplash
        visible={introVisible}
        onComplete={() => setIntroVisible(false)}
      />

      <ChronosCornerHolograms />

      <Header
        status={activeData.status}
        simulationId={activeData.simulationId}
        onReplayIntro={() => setIntroVisible(true)}
      />

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      <TopologyUploader
        mode={topologyMode}
        activeLabel={activeTopologyLabel}
        onLaunchDemo={handleLaunchDemo}
        onCustomUploaded={handleCustomUploaded}
        onUnloadTopology={handleUnloadTopology}
      />

      <RiskSummary data={activeData} />

      <SimulationControls
        status={activeData.status}
        loading={loading}
        onStart={handleStart}
        onPause={handlePause}
        onReset={handleReset}
      />

      <ApprovalPanel
        status={activeData.status}
        pendingAction={activeData.pending_action}
        onActionResolved={refreshAll}
      />

      <div className="playbook-action-row">
        <button
          type="button"
          className="button playbook-open-button"
          onClick={handleOpenPlaybook}
          disabled={topologyMode === "standby"}
        >
          <FiShield />
          Test Containment Strategy
        </button>
      </div>

      <SimulationTimeline
        currentStep={activeData.currentStep}
        status={activeData.status}
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
              {topologyMode === "standby"
                ? "STANDBY"
                : activeData.mitre_tactic || "T1550.002 Pass the Hash"}
            </span>
          </div>

          <div className="agent-metrics-row">
            <div className="agent-kv">
              <span>ENTRY FOOTHOLD</span>
              <strong className="mono-id">
                {entryFootholdId}
              </strong>
            </div>
            <div className="agent-kv">
              <span>DISCOVERED CORRIDOR</span>
              <strong className="mono-id">
                {topologyMode === "standby"
                  ? "Awaiting topology selection..."
                  : activeData.pending_action
                  ? `${activeData.pending_action.source} ➔ ${activeData.pending_action.target}`
                  : activeData.compromised_node
                  ? `${entryFootholdId} ➔ ${activeData.compromised_node}`
                  : "Scanning DMZ neighbors..."}
              </strong>
            </div>
            <div className="agent-kv">
              <span>ACTIVE TOOL</span>
              <strong className="mono-id">graph_scan_neighbors()</strong>
            </div>
          </div>

          <pre className="agent-console-output">
            {activeData.red_report ||
              (activeData.status === "running"
                ? `[APT-SIM] Probing adjacent graph pathways via graph_scan_neighbors('${entryFootholdId}')...\n[APT-SIM] Replaying cached NTLM credentials across internal_core subnet...`
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
                activeData.status === "awaiting_approval"
                  ? "pending"
                  : protocolStage >= 4
                  ? "done"
                  : ""
              }`}
            >
              4. HITL Analyst Gate{" "}
              {activeData.status === "awaiting_approval"
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
            {activeData.blue_report ||
              (activeData.status === "running"
                ? "[SOAR-AI] Scoring telemetry via ml_score_anomaly(hour=3, bytes=50000, failed_logins=20)...\n[SOAR-AI] Querying 768-dim incident vector store via rag_retrieve_incidents()..."
                : "[SOAR-AI] Bounded-authority defense active. Destructive actions (graph_cut_connection) require explicit human-analyst approval.")}
          </pre>
        </article>
      </section>

      <div className="dashboard-grid">
        <div className="main-column">
          <NetworkGraph
            nodes={activeData.nodes}
            edges={activeData.edges}
            selectedNodeId={selectedNodeId}
            onNodeSelect={setSelectedNodeId}
            refreshSignal={refreshSignal}
            compromisedNode={activeData.compromised_node}
            pendingAction={activeData.pending_action}
            simulationStatus={activeData.status}
            actionTaken={activeData.action_taken}
            topologyMode={topologyMode}
            onLaunchDemo={() => void handleLaunchDemo()}
          />

          <RemediationQueue
            items={activeData.remediations}
          />
        </div>

        <aside className="side-column">
          <NodeDetails
            node={selectedNode}
            edges={activeData.edges}
          />

          <SOCCopilotChat
            simulationData={activeData}
            topologyMode={topologyMode}
            topologySourceName={topologySourceName}
            topologyRefreshKey={topologyRefreshKey}
            onLaunchDemo={() => void handleLaunchDemo()}
            onScrollToUploader={() => {
              document
                .getElementById("topology-uploader-section")
                ?.scrollIntoView({ behavior: "smooth", block: "start" });
            }}
          />

          <AuditLog logs={activeData.logs} />
        </aside>
      </div>

      <PlaybookModal
        nodes={activeData.nodes}
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
