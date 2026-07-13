import { useMemo, useState } from "react";
import { FiShield, FiX } from "react-icons/fi";

import type {
  NetworkNode,
  PlaybookAction,
  PlaybookImpact,
  PlaybookRequest,
} from "../types/simulation";

interface PlaybookModalProps {
  nodes: NetworkNode[];
  open: boolean;
  loading: boolean;
  impact?: PlaybookImpact;

  onClose: () => void;
  onRun: (
    request: PlaybookRequest
  ) => Promise<void>;
}

export function PlaybookModal({
  nodes,
  open,
  loading,
  impact,
  onClose,
  onRun,
}: PlaybookModalProps) {
  const selectableNodes = useMemo(
    () =>
      nodes.filter(
        (node) => node.id !== "internet"
      ),
    [nodes]
  );

  const [nodeId, setNodeId] = useState(
    selectableNodes[0]?.id || ""
  );

  const [action, setAction] =
    useState<PlaybookAction>("isolate-node");

  const [port, setPort] = useState("443");

  const selectedNode = selectableNodes.find(
    (node) => node.id === nodeId
  );

  if (!open) {
    return null;
  }

  const handleSubmit = async (
    event: React.FormEvent<HTMLFormElement>
  ) => {
    event.preventDefault();

    const request: PlaybookRequest = {
      nodeId,
      action,
    };

    if (action === "block-port") {
      request.port = Number(port);
    }

    if (
      action === "patch-vulnerability" &&
      selectedNode?.knownCves[0]
    ) {
      request.vulnerability =
        selectedNode.knownCves[0];
    }

    await onRun(request);
  };

  return (
    <div
      className="modal-backdrop"
      onMouseDown={onClose}
    >
      <section
        className="playbook-modal"
        onMouseDown={(event) =>
          event.stopPropagation()
        }
      >
        <div className="playbook-modal-header">
          <div>
            <p className="eyebrow">
              WHAT-IF ANALYSIS
            </p>

            <h2>
              <FiShield />
              Test Containment Strategy
            </h2>
          </div>

          <button
            type="button"
            className="modal-close-button"
            onClick={onClose}
            aria-label="Close playbook modal"
          >
            <FiX />
          </button>
        </div>

        <form
          className="playbook-form"
          onSubmit={handleSubmit}
        >
          <label>
            Asset

            <select
              value={nodeId}
              onChange={(event) =>
                setNodeId(event.target.value)
              }
            >
              {selectableNodes.map((node) => (
                <option
                  value={node.id}
                  key={node.id}
                >
                  {node.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            Containment action

            <select
              value={action}
              onChange={(event) =>
                setAction(
                  event.target
                    .value as PlaybookAction
                )
              }
            >
              <option value="isolate-node">
                Isolate node
              </option>

              <option value="block-port">
                Block port
              </option>

              <option value="patch-vulnerability">
                Patch vulnerability
              </option>

              <option value="disable-connection">
                Disable network connection
              </option>
            </select>
          </label>

          {action === "block-port" && (
            <label>
              Port

              <select
                value={port}
                onChange={(event) =>
                  setPort(event.target.value)
                }
              >
                {selectedNode?.openPorts.map(
                  (openPort) => (
                    <option
                      value={openPort}
                      key={openPort}
                    >
                      {openPort}
                    </option>
                  )
                )}
              </select>
            </label>
          )}

          {action ===
            "patch-vulnerability" && (
            <div className="playbook-selection-info">
              <span>Selected CVE</span>

              <strong>
                {selectedNode?.knownCves[0] ||
                  "No known CVE"}
              </strong>
            </div>
          )}

          {selectedNode?.isCriticalService && (
            <div className="critical-warning">
              This asset supports the critical
              service:{" "}
              <strong>
                {selectedNode.businessService}
              </strong>
            </div>
          )}

          <button
            type="submit"
            className="button button-primary playbook-submit"
            disabled={loading || !nodeId}
          >
            <FiShield />

            {loading
              ? "Calculating impact..."
              : "Run What-If Simulation"}
          </button>
        </form>

        {impact && (
          <div className="impact-assessment">
            <div className="impact-heading">
              <div>
                <p className="eyebrow">
                  PROJECTED RESULT
                </p>

                <h3>Impact Assessment</h3>
              </div>

              <span className="impact-ready">
                Complete
              </span>
            </div>

            <div className="impact-grid">
              <article>
                <span>Risk score</span>

                <strong>
                  {impact.previousRiskScore}
                  <small> → </small>
                  {impact.projectedRiskScore}
                </strong>
              </article>

              <article>
                <span>MTTD reduction</span>

                <strong>
                  {impact.mttdReduction}%
                </strong>
              </article>

              <article>
                <span>MTTR reduction</span>

                <strong>
                  {impact.mttrReduction}%
                </strong>
              </article>

              <article>
                <span>
                  Critical services offline
                </span>

                <strong
                  className={
                    impact.criticalServicesOffline >
                    0
                      ? "impact-danger"
                      : "impact-safe"
                  }
                >
                  {
                    impact.criticalServicesOffline
                  }
                </strong>
              </article>
            </div>

            {impact.affectedServices.length >
              0 && (
              <div className="affected-services">
                <span>Affected services</span>

                <p>
                  {impact.affectedServices.join(
                    ", "
                  )}
                </p>
              </div>
            )}

            <div className="impact-recommendation">
              <span>Recommendation</span>

              <p>{impact.recommendation}</p>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}