"""
main.py

The central execution pipeline for the CYB333 MITRE Log Analyzer tool.
"""
import os
import pandas as pd
from src.detector import detect_brute_force
from src.report import generate_report

def main():
    # 1. Locate the log dataset safely
    log_file = os.path.join("data", "sample_logs.csv")
    if not os.path.exists(log_file):
        # Fallback if the data folder structure is flat
        log_file = "sample_logs.csv"

    if not os.path.exists(log_file):
        print(f"[!] ERROR: Target log file not found. Ensure sample_logs.csv is in your project directory.")
        return

    # 2. Ingest log data using pandas
    logs = pd.read_csv(log_file)

    # 3. Process logs through the MITRE detection rules engine
    alerts = detect_brute_force(logs)

    # 4. Display findings dynamically on the Security Console
    print("\n" + "="*24 + " SECURITY ALERTS " + "="*24)
    if alerts and not alerts[0].startswith("[!] ERROR"):
        for alert in alerts:
            print(alert)
    elif alerts:
        print(alerts[0]) # Print the diagnostic error message
    else:
        print("[+] Scan complete: No malicious indicators detected.")

    # 5. Compile and export the formal security intelligence document
    summary_text = generate_report(logs, alerts if not (alerts and alerts[0].startswith("[!] ERROR")) else [])
    
    print("\n" + "="*24 + " REPORT SUMMARY " + "="*24)
    print(summary_text)
    print("="*64 + "\n")

if __name__ == "__main__":
    main()
