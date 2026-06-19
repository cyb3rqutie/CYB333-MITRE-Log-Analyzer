"""
report.py

Generates a security report.
"""

import pandas as pd


def generate_report(logs, alerts):
    """
    Generate a security report.

    Args:
        logs (DataFrame)
        alerts (list)

    Returns:
        DataFrame
    """

    report = pd.DataFrame({
        "Total Events": [len(logs)],
        "Alerts Generated": [len(alerts)]
    })

    report.to_csv(
        "reports/security_report.csv",
        index=False
    )

    return report
