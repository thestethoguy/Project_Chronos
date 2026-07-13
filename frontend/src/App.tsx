import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import { FiShield } from "react-icons/fi";

import { Header } from "./components/Header";
import { RiskSummary } from "./components/RiskSummary";
import { NetworkGraph } from "./components/NetworkGraph";
import { NodeDetails } from "./components/NodeDetails";
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
    useState<string | undefined>(undefined);

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
    return data.nodes.find(
      (node) => node.id === selectedNodeId
    );
  }, [data.nodes, selectedNodeId]);

  const refreshSimulation =
    useCallback(async (): Promise<void> => {
      try {
        const response =
          await getSimulationStatus();

        setData(response);
        setError(undefined);
      } catch (error) {
        console.error(
          "Could not retrieve simulation data:",
          error
        );

        setError(
          "Unable to retrieve simulation data."
        );
      }
    }, []);

  useEffect(() => {
    void refreshSimulation();
  }, [refreshSimulation]);

  useEffect(() => {
    if (data.status !== "running") {
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
      setError(undefined);
    } catch (error) {
      console.error(
        "Simulation action failed:",
        error
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
    } catch (error) {
      console.error(
        "Playbook validation failed:",
        error
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

      <SimulationControls
        status={data.status}
        loading={loading}
        onStart={handleStart}
        onPause={handlePause}
        onReset={handleReset}
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

      <div className="dashboard-grid">
        <div className="main-column">
          <NetworkGraph
            nodes={data.nodes}
            edges={data.edges}
            selectedNodeId={selectedNodeId}
            onNodeSelect={setSelectedNodeId}
          />

          <RemediationQueue
            items={data.remediations}
          />
        </div>

        <aside className="side-column">
          <NodeDetails node={selectedNode} />

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