import type { Remediation } from "../types/simulation";

interface RemediationQueueProps {
  items: Remediation[];
}

export function RemediationQueue({ items }: RemediationQueueProps) {
  return (
    <section className="panel remediation-panel">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">PRIORITISED ACTIONS</p>
          <h2>Remediation Queue</h2>
        </div>
      </div>

      <div className="remediation-list">
        {items.map((item, index) => (
          <article className="remediation-item" key={item.id}>
            <span className={`priority priority-${item.priority}`}>{item.priority}</span>
            <div>
              <strong>{index + 1}. {item.title}</strong>
              <p>Estimated risk reduction: {item.riskReduction}%</p>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
