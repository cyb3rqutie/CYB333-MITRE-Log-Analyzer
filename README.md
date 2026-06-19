# CYB333: MITRE ATT&CK Log Analyzer System

## Project Objective
This security automation tool acts as a localized Security Information and Event Management (SIEM) parsing engine. It is designed to automatically ingest unstructured system authentication logs, identify active malicious brute force patterns, map them to standardized industry threat frameworks, and auto-generate an interactive incident response report for security teams.

## Key Features
* **Automated Data Pipeline:** Utilizes the Python `pandas` library to ingest and normalize system logs directly from flat CSV structures.
* **Algorithmic Threat Detection:** Group-analyzes event logs dynamically per unique `source_ip` address to catch rapid, automated authentication spraying attacks instead of tracking simple global failure counts.
* **MITRE ATT&CK Framework Mapping:** Instantly tags caught security alerts with specialized industry indicators: **Tactic: Credential Access (TA0006)** and **Technique: Brute Force (T1110)**.
* **Automated Incident Response Asset Generation:** Independently validates file-system paths to generate a clean, executive-ready Markdown threat blueprint inside a `reports/` folder at runtime.
* **Defensive Code Architecture:** Uses automated header case-normalization (`.str.lower()`) and structural schema checks to cleanly block data execution errors without throwing system crashes.

## Prerequisites & Project Dependencies
This project runs entirely inside the Anaconda environment workspace using Python 3.
* **Pandas Library:** Used for high-speed log dataset structural tracking and mathematical aggregations.

## Installation & Environment Setup Instructions

### 1. Initialize Your Environment
Open your **Anaconda PowerShell Prompt** and install the required data management dependencies inside your base environment profile:
```bash
conda install pandas -y
