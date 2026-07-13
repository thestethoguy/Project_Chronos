import type { SimulationStatus } from "../types/simulation";

interface SimulationTimelineProps {
  currentStep: number;
  status: SimulationStatus;
}

const stages = [
  "Initial Access",
  "Lateral Movement",
  "Database Compromise",
  "Containment",
  "Recovery",
  "Completed",
];

export function SimulationTimeline({
  currentStep,
  status,
}: SimulationTimelineProps) {
  return (
    <section className="panel timeline-panel">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">SIMULATION PROGRESS</p>
          <h2>Attack Timeline</h2>
        </div>

        <span className={`timeline-status timeline-status-${status}`}>
          {status.toUpperCase()}
        </span>
      </div>

      <div className="timeline">
        {stages.map((stage, index) => {
          const stageNumber = index + 1;
          const isCompleted = currentStep > stageNumber;
          const isActive =
            currentStep === stageNumber && status !== "completed";

          return (
            <div
              className={`timeline-item ${
                isCompleted ? "timeline-completed" : ""
              } ${isActive ? "timeline-active" : ""}`}
              key={stage}
            >
              <div className="timeline-marker">
                {isCompleted ? "✓" : stageNumber}
              </div>

              <span>{stage}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}