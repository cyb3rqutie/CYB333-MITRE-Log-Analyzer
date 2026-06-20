"""
src/report.py

Generates structured security assessment summaries and writes an automated
Markdown report file for security operations analysis.
"""
import os
from datetime import datetime

def generate_report(df, alerts):
    """
    Compiles log metrics and alert structures, then automates the creation
    of a Markdown incident report artifact.
    """
    total_events = len(df) if df is not None else 0
    total_alerts = len(alerts)
    
    # Create the text summary for console printout
    summary = f"Total Log Events Analyzed: {total_events}\nTotal High Severity Alerts: {total_alerts}"
    
    # Automation: Define the paths to save the artifact
    report_dir = "reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
        
    report_filename = os.path.join(report_dir, "incident_response_report.md")
    
    # Build a formal security intelligence document
    with open(report_filename, "w") as f:
        f.write("# Cyber Attack Analytics & MITRE ATT&CK Mapping Report\n")
        f.write(f"**Generated On:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**System Status:** ACTION REQUIRED ({total_alerts} Active Threat Indicators)\n\n")
        
        f.write("## 1. Executive Log Analytics Summary\n")
        f.write(f"- **Total Events Audited:** {total_events}\n")
        f.write(f"- **Security Incidents Identified:** {total_alerts}\n\n")
        
        f.write("## 2. Active Security Indicators & Framework Context\n")
        if alerts:
            for alert in alerts:
                f.write(f"```text\n{alert}```\n\n")
        else:
            f.write("*No malicious attack signatures or frame anomalies were detected within this dataset.*\n\n")
            
        f.write("## 3. Recommended Remediation Blueprint\n")
        f.write("1. **IP Throttling/Blocking:** Immediately isolate the offending IP address(es) identified above at the perimeter firewall.\n")
        f.write("2. **Account Audit:** Check affected accounts for successful authentications immediately following the brute force cluster.\n")
        f.write("3. **Enforce MFA:** Ensure Multi-Factor Authentication is explicitly applied to all user profiles to degrade adversary technique viability.\n")

    return summary
