import type { SimulationStatus } from "../types/simulation";

interface HeaderProps {
  status: SimulationStatus;
  simulationId: string;
}

export function Header({
  status,
  simulationId,
}: HeaderProps) {
  const statusLabel = status.toUpperCase();

  return (
    <header className="app-header">
      <div className="brand-section">
        <div className="brand-icon">C</div>

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