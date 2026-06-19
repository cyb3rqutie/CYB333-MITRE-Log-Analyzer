"""
detector.py

Detects suspicious activity in log data.
"""


def detect_brute_force(logs):
    """
    Detect brute-force attempts based on failed logins.

    Event ID 4625 = Failed Login

    Args:
        logs (DataFrame)

    Returns:
        list
    """

    alerts = []

    failed_logins = logs[logs["EventID"] == 4625]

    if len(failed_logins) >= 5:
        alerts.append(
            "ALERT: Potential Brute Force Attack Detected"
        )

    return alerts
