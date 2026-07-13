import pandas as pd
import joblib
from pathlib import Path
from defense_logger import DefenseLogger

MODEL_FILE = Path("isolation_model.pkl")
FEATURE_COLUMNS = [
    "hour_of_day",
    "bytes_transferred",
    "failed_login_attempts",
]


def explain_reason(row: pd.Series) -> str:
    """
    Convert numbers into simple English explanation for the audit log.
    """
    reasons = []

    if row["hour_of_day"] < 6 or row["hour_of_day"] > 22:
        reasons.append("Unusual activity time outside normal office hours")

    if row["bytes_transferred"] > 1000:
        reasons.append("Very high data transfer detected")

    if row["failed_login_attempts"] > 5:
        reasons.append("Multiple failed login attempts detected")

    if not reasons:
        reasons.append("Mathematical behavior pattern is far from normal office activity")

    return "; ".join(reasons)


def detect_single_log(hour_of_day: int, bytes_transferred: float, failed_login_attempts: int) -> None:
    if not MODEL_FILE.exists():
        raise FileNotFoundError("isolation_model.pkl not found. Run train_model.py first.")

    model = joblib.load(MODEL_FILE)
    logger = DefenseLogger("audit.log")

    row = pd.DataFrame(
        [
            {
                "hour_of_day": hour_of_day,
                "bytes_transferred": bytes_transferred,
                "failed_login_attempts": failed_login_attempts,
            }
        ]
    )

    prediction = model.predict(row[FEATURE_COLUMNS])[0]
    anomaly_score = -model.score_samples(row[FEATURE_COLUMNS])[0]

    if prediction == -1:
        reason = explain_reason(row.iloc[0])
        logger.log_action(
            node_name="web_server_01",
            action="ISOLATED",
            anomaly_score=anomaly_score,
            reason=reason,
            mitre_tactic="Initial Access",
        )
    else:
        print("NORMAL: No action needed.")
        print(f"Anomaly score: {anomaly_score:.4f}")


def main() -> None:
    print("Testing one normal log:")
    detect_single_log(hour_of_day=11, bytes_transferred=25, failed_login_attempts=0)

    print("\nTesting one hacker/anomaly log:")
    detect_single_log(hour_of_day=3, bytes_transferred=50000, failed_login_attempts=20)


if __name__ == "__main__":
    main()
