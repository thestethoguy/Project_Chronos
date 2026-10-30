from datetime import datetime
from pathlib import Path
from typing import Optional


class DefenseLogger:
    """
    Writes human-readable audit logs for every defense action.
    This is useful because government/cybersecurity systems must be explainable.
    """

    def __init__(self, log_file: str = "audit.log") -> None:
        self.log_file = Path(log_file)

    def log_action(
        self,
        node_name: str,
        action: str,
        anomaly_score: float,
        reason: str,
        mitre_tactic: Optional[str] = "Initial Access",
        approved_by: str = "autonomous-soar",
    ) -> None:
        """Append one audit line.

        Phase 2 adds `approved_by` (who authorised the action; "human-analyst" for HITL decisions).
        Existing Phase-1 callers (5 positional/keyword args) keep working unchanged.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mitre_tactic = mitre_tactic or "Initial Access"

        log_message = (
            f"[{timestamp}] ACTION TAKEN: {action.upper()} {node_name}. "
            f"REASON: Anomaly score {anomaly_score:.4f} detected by ML Engine. "
            f"{reason}. MITRE ATT&CK tactic matches {mitre_tactic}. "
            f"APPROVED BY: {approved_by}.\n"
        )

        with self.log_file.open("a", encoding="utf-8") as file:
            file.write(log_message)

        print(log_message.strip())
