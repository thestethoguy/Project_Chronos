import {
  FiPause,
  FiPlay,
  FiRotateCcw,
} from "react-icons/fi";

import type { SimulationStatus } from "../types/simulation";

interface SimulationControlsProps {
  status: SimulationStatus;
  loading: boolean;
  onStart: () => void;
  onPause: () => void;
  onReset: () => void;
}

export function SimulationControls({
  status,
  loading,
  onStart,
  onPause,
  onReset,
}: SimulationControlsProps) {
  const isRunning = status === "running";
  const isPaused = status === "paused";
  const isCompleted = status === "completed";

  const startButtonText = isPaused
    ? "Resume"
    : isCompleted
      ? "Start Again"
      : "Start Simulation";

  return (
    <section className="simulation-controls">
      <div className="control-information">
        <span className="control-label">
          Simulation Controls
        </span>

        <p>
          Run or manage the current cyberattack simulation.
        </p>
      </div>

      <div className="control-buttons">
        <button
          type="button"
          className="button button-primary"
          onClick={onStart}
          disabled={loading || isRunning}
        >
          <FiPlay />
          {startButtonText}
        </button>

        <button
          type="button"
          className="button"
          onClick={onPause}
          disabled={loading || !isRunning}
        >
          <FiPause />
          Pause
        </button>

        <button
          type="button"
          className="button button-reset"
          onClick={onReset}
          disabled={loading}
        >
          <FiRotateCcw />
          Reset
        </button>
      </div>
    </section>
  );
}