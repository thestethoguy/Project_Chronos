import { useState } from "react";
import { FiAlertTriangle, FiCheckCircle, FiCode, FiXCircle } from "react-icons/fi";
import { approveAction, rejectAction } from "../services/api";
import { extractErrorMessage } from "../services/topologyApi";
import type { PendingAction, SimulationStatus } from "../types/simulation";

interface ApprovalPanelProps {
  status: SimulationStatus;
  pendingAction?: PendingAction | null;
  onActionResolved: () => void | Promise<void>;
}

export function ApprovalPanel({
  status,
  pendingAction,
  onActionResolved,
}: ApprovalPanelProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [showAwsJson, setShowAwsJson] = useState(true);

  if (status !== "awaiting_approval" || !pendingAction) {
    return null;
  }

  const action = pendingAction;

  async function handleDecision(type: "approve" | "reject") {
    if (isSubmitting) return;
    setIsSubmitting(true);
    setErrorMsg("");
    try {
      if (type === "approve") {
        await approveAction();
      } else {
        await rejectAction();
      }
      await onActionResolved();
    } catch (err) {
      setErrorMsg(
        extractErrorMessage(
          err,
          `Failed to ${type} the proposed containment action.`
        )
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <section
      className="panel approval-panel"
      role="region"
      aria-label="Human-in-the-Loop Containment Approval"
    >
      <div className="panel-heading approval-panel-heading">
        <div>
          <p className="eyebrow approval-eyebrow">
            <FiAlertTriangle /> HUMAN-IN-THE-LOOP APPROVAL REQUIRED
          </p>
          <h2>Proposed SOAR Containment Action</h2>
        </div>

        <span className="approval-badge">AWAITING_APPROVAL</span>
      </div>

      <div className="approval-body">
        <div className="approval-grid">
          <div className="approval-metric-box">
            <span className="approval-metric-label">
              Proposed Containment Action
            </span>
            <strong className="approval-route">
              Sever Connection: {action.source} → {action.target}
            </strong>
          </div>

          <div className="approval-metric-box">
            <span className="approval-metric-label">
              ML Verification &amp; MITRE Classification
            </span>
            <strong>
              Anomaly Score: {Number(action.anomaly_score).toFixed(4)} | MITRE
              ATT&amp;CK: {action.mitre_tactic}
            </strong>
          </div>
        </div>

        {action.cited_incident && (
          <div className="approval-section">
            <span className="approval-metric-label">
              RAG Historical Precedent Cited
            </span>
            <p className="approval-incident-cite">{action.cited_incident}</p>
          </div>
        )}

        <div className="approval-section">
          <span className="approval-metric-label">Blue Agent Justification</span>
          <p className="approval-justification">{action.justification}</p>
        </div>

        {action.aws_remediation && (
          <div className="approval-section">
            <div className="approval-aws-header">
              <span className="approval-metric-label">
                <FiCode /> Drafted AWS Cloud Remediation (executed: false)
              </span>
              <button
                type="button"
                className="button button-small"
                onClick={() => setShowAwsJson((v) => !v)}
              >
                {showAwsJson ? "Hide JSON" : "Show JSON"}
              </button>
            </div>

            {showAwsJson && (
              <pre className="approval-code-block">
                {JSON.stringify(action.aws_remediation, null, 2)}
              </pre>
            )}
          </div>
        )}

        {errorMsg && (
          <div className="error-banner" role="alert">
            {errorMsg}
          </div>
        )}

        <div className="approval-actions">
          <button
            type="button"
            className="button button-approve"
            disabled={isSubmitting}
            onClick={() => handleDecision("approve")}
          >
            <FiCheckCircle />
            {isSubmitting
              ? "Processing Decision..."
              : "Approve & Execute Containment"}
          </button>

          <button
            type="button"
            className="button button-reject"
            disabled={isSubmitting}
            onClick={() => handleDecision("reject")}
          >
            <FiXCircle />
            {isSubmitting ? "Processing Decision..." : "Reject Proposal"}
          </button>
        </div>
      </div>
    </section>
  );
}

