import type { NetworkEdge, NetworkNode } from "../types/simulation";

interface NodeDetailsProps {
  node?: NetworkNode;
  edges?: NetworkEdge[];
}

export function NodeDetails({ node, edges = [] }: NodeDetailsProps) {
  const inboundEdges = node
    ? edges.filter((e) => e.target === node.id)
    : [];
  const outboundEdges = node
    ? edges.filter((e) => e.source === node.id)
    : [];

  const isDmz =
    node?.subnet === "public_dmz" ||
    node?.type === "public_dmz" ||
    node?.type === "dmz-asset";

  return (
    <section className="panel side-panel-section asset-inspector-panel">
      <div className="panel-heading compact">
        <div>
          <p className="eyebrow">SOC ASSET INSPECTOR</p>
          <h2>Node Telemetry &amp; Exposure</h2>
        </div>
        {node && (
          <span className={`asset-status-pill asset-status-${node.status}`}>
            {node.status.toUpperCase()}
          </span>
        )}
      </div>

      {!node ? (
        <div className="empty-state">
          <p style={{ marginBottom: 6, color: "#9eb8d0", fontWeight: 600 }}>
            No Asset Selected
          </p>
          <p style={{ margin: 0, fontSize: 12 }}>
            Click any node in the Digital Twin graph to inspect its IP, subnet
            tier, open ports, CVEs, and lateral-movement neighbors.
          </p>
        </div>
      ) : (
        <div className="details-list">
          <div>
            <span>Device ID</span>
            <strong className="mono-id">{node.id}</strong>
          </div>

          <div>
            <span>Display Name</span>
            <strong>{node.label}</strong>
          </div>

          <div>
            <span>Subnet Scope</span>
            <strong
              className={
                isDmz ? "subnet-badge-dmz" : "subnet-badge-core"
              }
            >
              {isDmz
                ? "PUBLIC DMZ (External)"
                : "INTERNAL CORE (Restricted)"}
            </strong>
          </div>

          <div>
            <span>IPv4 Address</span>
            <strong className="mono-id">{node.ipAddress}</strong>
          </div>

          <div>
            <span>Operating System</span>
            <strong>{node.operatingSystem || "Linux / Unknown"}</strong>
          </div>

          <div>
            <span>Risk Score</span>
            <strong>{node.riskScore}/100</strong>
          </div>

          <div>
            <span>Crown-Jewel / Critical</span>
            <strong
              className={
                node.isCriticalService ? "critical-service-text" : ""
              }
            >
              {node.isCriticalService ? "HIGH-VALUE TARGET" : "Standard Tier"}
            </strong>
          </div>

          <div className="vulnerability-block">
            <span>Open TCP/UDP Ports</span>
            {node.openPorts.length === 0 ? (
              <p className="muted-detail-note">No exposed ports reported.</p>
            ) : (
              <div className="tag-list">
                {node.openPorts.map((port) => (
                  <span className="detail-tag" key={port}>
                    PORT {port}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="vulnerability-block">
            <span>Known CVEs ({node.knownCves.length})</span>
            {node.knownCves.length === 0 ? (
              <p className="muted-detail-note">0 known CVEs on record.</p>
            ) : (
              <div className="tag-list">
                {node.knownCves.map((cve) => (
                  <span className="detail-tag cve-tag" key={cve}>
                    {cve}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="vulnerability-block">
            <span>
              Inbound Connections ({inboundEdges.length})
            </span>
            {inboundEdges.length === 0 ? (
              <p className="muted-detail-note">
                None (Perimeter Entry / Isolated)
              </p>
            ) : (
              <div className="neighbor-route-list">
                {inboundEdges.map((edge) => (
                  <div key={edge.id} className="neighbor-route-chip">
                    <span className="mono-id">{edge.source}</span>
                    <span className="route-arrow">➔</span>
                    <span className="mono-id">{node.id}</span>
                    {edge.type && (
                      <small className="route-type-badge">{edge.type}</small>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="vulnerability-block">
            <span>
              Outbound Lateral Routes ({outboundEdges.length})
            </span>
            {outboundEdges.length === 0 ? (
              <p className="muted-detail-note">
                None (Terminal Data Tier / Sink)
              </p>
            ) : (
              <div className="neighbor-route-list">
                {outboundEdges.map((edge) => (
                  <div key={edge.id} className="neighbor-route-chip">
                    <span className="mono-id">{node.id}</span>
                    <span className="route-arrow">➔</span>
                    <span className="mono-id">{edge.target}</span>
                    {edge.type && (
                      <small className="route-type-badge">{edge.type}</small>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
