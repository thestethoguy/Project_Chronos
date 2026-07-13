import type { SimulationData } from "../types/simulation";

interface RiskSummaryProps {
  data: SimulationData;
}

export function RiskSummary({
  data,
}: RiskSummaryProps) {
  const compromised = data.nodes.filter(
    (node) => node.status === "compromised"
  ).length;

  const isolated = data.nodes.filter(
    (node) => node.status === "isolated"
  ).length;

  const critical = data.nodes.filter(
    (node) => node.riskScore >= 70
  ).length;

  const getRiskLevel = (): string => {
    if (data.riskScore >= 75) {
      return "Critical";
    }

    if (data.riskScore >= 50) {
      return "High";
    }

    if (data.riskScore >= 25) {
      return "Moderate";
    }

    return "Low";
  };

  return (
    <section className="risk-grid">
      <article className="risk-card risk-main-card">
        <div className="risk-card-header">
          <span>Overall Risk</span>

          <span className="risk-level">
            {getRiskLevel()}
          </span>
        </div>

        <strong>{data.riskScore}/100</strong>

        <div className="risk-progress">
          <div
            className="risk-progress-value"
            style={{
              width: `${data.riskScore}%`,
            }}
          />
        </div>
      </article>

      <article className="risk-card">
        <span>Critical Nodes</span>

        <strong>{critical}</strong>

        <p>Assets requiring immediate attention</p>
      </article>

      <article className="risk-card">
        <span>Compromised</span>

        <strong className="risk-danger">
          {compromised}
        </strong>

        <p>Assets accessed by the Red Agent</p>
      </article>

      <article className="risk-card">
        <span>Isolated</span>

        <strong className="risk-isolated">
          {isolated}
        </strong>

        <p>Assets secured by the Blue Agent</p>
      </article>
    </section>
  );
}