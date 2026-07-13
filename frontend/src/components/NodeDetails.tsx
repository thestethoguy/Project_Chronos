import type { NetworkNode } from "../types/simulation";

interface NodeDetailsProps {
  node?: NetworkNode;
}

export function NodeDetails({
  node,
}: NodeDetailsProps) {
  return (
    <section className="panel side-panel-section">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">
            SELECTED ASSET
          </p>

          <h2>Node Details</h2>
        </div>
      </div>

      {!node ? (
        <p className="empty-state">
          Select a node from the graph to inspect it.
        </p>
      ) : (
        <div className="details-list">
          <div>
            <span>Name</span>
            <strong>{node.label}</strong>
          </div>

          <div>
            <span>Type</span>
            <strong>{node.type}</strong>
          </div>

          <div>
            <span>Status</span>
            <strong
              className={`text-${node.status}`}
            >
              {node.status}
            </strong>
          </div>

          <div>
            <span>IP Address</span>
            <strong>{node.ipAddress}</strong>
          </div>

          <div>
            <span>Operating System</span>
            <strong>
              {node.operatingSystem || "Unknown"}
            </strong>
          </div>

          <div>
            <span>Software</span>
            <strong>
              {node.softwareName || "Unknown"}
            </strong>
          </div>

          <div>
            <span>Version</span>
            <strong>
              {node.softwareVersion || "Unknown"}
            </strong>
          </div>

          <div>
            <span>Risk Score</span>
            <strong>{node.riskScore}/100</strong>
          </div>

          <div>
            <span>Critical Service</span>
            <strong
              className={
                node.isCriticalService
                  ? "critical-service-text"
                  : ""
              }
            >
              {node.isCriticalService ? "Yes" : "No"}
            </strong>
          </div>

          {node.businessService && (
            <div>
              <span>Business Service</span>
              <strong>
                {node.businessService}
              </strong>
            </div>
          )}

          <div className="vulnerability-block">
            <span>Open Ports</span>

            {node.openPorts.length === 0 ? (
              <p>No open ports reported.</p>
            ) : (
              <div className="tag-list">
                {node.openPorts.map((port) => (
                  <span
                    className="detail-tag"
                    key={port}
                  >
                    {port}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="vulnerability-block">
            <span>Known CVEs</span>

            {node.knownCves.length === 0 ? (
              <p>No known CVEs.</p>
            ) : (
              <ul>
                {node.knownCves.map((cve) => (
                  <li key={cve}>
                    {cve}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="vulnerability-block">
            <span>Vulnerabilities</span>

            {node.vulnerabilities.length === 0 ? (
              <p>No known vulnerabilities.</p>
            ) : (
              <ul>
                {node.vulnerabilities.map(
                  (item) => (
                    <li key={item}>
                      {item}
                    </li>
                  )
                )}
              </ul>
            )}
          </div>
        </div>
      )}
    </section>
  );
}