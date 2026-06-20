"""
src/detector.py

Analyzes logs to detect specific malicious behaviors and maps them
directly to the MITRE ATT&CK Framework.
"""

def detect_brute_force(df, threshold=3):
    """
    Scans a DataFrame of authentication logs and flags source IPs with failed
    login attempts exceeding the specified threshold. Maps alerts to MITRE ATT&CK.
    """
    if df is None or df.empty:
        return []

    alerts = []
    
    # Normalize column names to lowercase to prevent case-matching errors (e.g., Status vs status)
    df.columns = df.columns.str.lower()
    
    # Check if required columns exist after normalization
    if 'status' not in df.columns or 'source_ip' not in df.columns:
        return ["[!] ERROR: Log data missing required 'status' or 'source_ip' columns."]
    
    # Filter for failed login attempts
    failed_logins = df[df['status'].str.upper() == 'FAILED']
    
    # Count failures per Source IP
    failed_counts = failed_logins['source_ip'].value_counts()
    
    for ip, count in failed_counts.items():
        if count >= threshold:
            # MITRE ATT&CK Framework Mapping Details
            mitre_tactic = "Credential Access (TA0006)"
            mitre_technique = "Brute Force (T1110)"
            
            alert_msg = (
                f"[!] SECURITY ALERT: Potential Brute Force Detected from IP: {ip}\n"
                f"    - Failed Attempts: {count}\n"
                f"    - MITRE ATT&CK Tactic: {mitre_tactic}\n"
                f"    - MITRE ATT&CK Technique: {mitre_technique}\n"
            )
            alerts.append(alert_msg)
            
    return alerts
