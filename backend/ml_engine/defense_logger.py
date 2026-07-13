from datetime import datetime
from pathlib import Path


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
        mitre_tactic: str = "Initial Access",
    ) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log_message = (
            f"[{timestamp}] ACTION TAKEN: {action.upper()} {node_name}. "
            f"REASON: Anomaly score {anomaly_score:.4f} detected by ML Engine. "
            f"{reason}. MITRE ATT&CK tactic matches {mitre_tactic}.\n"
        )

        with self.log_file.open("a", encoding="utf-8") as file:
            file.write(log_message)

        print(log_message.strip())
