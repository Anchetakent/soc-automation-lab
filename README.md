
# SOC Automation Lab: Wazuh + Sysmon + Shuffle + VirusTotal + TheHive

## Overview

This project is an end-to-end SOC automation lab designed to simulate a basic security operations workflow.

The lab collects endpoint telemetry from a Windows virtual machine using Sysmon and the Wazuh Agent. Wazuh analyzes the telemetry and detects suspicious activity using a custom detection rule.

When the rule is triggered, the alert is forwarded to Shuffle SOAR, where the file hash is extracted and enriched using VirusTotal. Shuffle then automatically creates an alert in TheHive and sends an email notification to a SOC analyst.

The project demonstrates the complete security monitoring lifecycle:

**Detect → Enrich → Investigate → Notify**

---

## Architecture

```text
Windows 10 VM
    │
    │ Sysmon Telemetry
    ▼
Wazuh Agent
    │
    ▼
Wazuh Manager
    │
    │ Custom Detection Rule
    ▼
Shuffle SOAR
    │
    ├── SHA256 Extraction
    │
    ├── VirusTotal Enrichment
    │
    ▼
TheHive
    │
    │ Create Security Alert
    ▼
SOC Analyst Email Notification
