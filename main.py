"""
main.py

Main application entry point.
"""

from src.parser import load_logs
from src.detector import detect_brute_force
from src.report import generate_report


def main():

    logs = load_logs("data/sample_logs.csv")

    if logs is None:
        return

    alerts = detect_brute_force(logs)

    print("\n=== SECURITY ALERTS ===")

    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No alerts detected.")

    report = generate_report(logs, alerts)

    print("\n=== REPORT SUMMARY ===")
    print(report)


if __name__ == "__main__":
    main()
