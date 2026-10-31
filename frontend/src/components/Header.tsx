import type { SimulationStatus } from "../types/simulation";
import { ChronosEmblem } from "./ChronosEmblem";

interface HeaderProps {
  status: SimulationStatus;
  simulationId: string;
  onReplayIntro?: () => void;
}

export function Header({
  status,
  simulationId,
  onReplayIntro,
}: HeaderProps) {
  const statusLabel = status.toUpperCase();

  return (
    <header className="app-header">
      <div className="brand-section">
        <div
          className="brand-emblem-container"
          title="Project Chronos — Autonomous Cyber-Resilience Digital Twin Emblem"
        >
          <ChronosEmblem size={58} animated={true} />
        </div>

        <div>
          <p className="eyebrow">
            CYBER RESILIENCE DIGITAL TWIN
          </p>

          <h1>Project Chronos</h1>

          <p className="header-description">
            Real-time cyberattack simulation and infrastructure
            monitoring.
          </p>
        </div>
      </div>

      <div className="header-status">
        {onReplayIntro && (
          <>
            <button
              type="button"
              className="copilot-chip chronos-replay-intro-btn"
              onClick={onReplayIntro}
              title="Replay the Project Chronos Holographic Initialization Sequence"
            >
              ⚡ Replay Intro
            </button>
            <div className="header-divider" />
          </>
        )}

        <div className="status-information">
          <span
            className={`status-dot status-${status}`}
          />

          <div>
            <span className="status-label">
              Simulation Status
            </span>

            <strong>{statusLabel}</strong>
          </div>
        </div>

        <div className="header-divider" />

        <div>
          <span className="status-label">
            Simulation ID
          </span>

          <strong>{simulationId}</strong>
        </div>
      </div>
    </header>
  );
}
