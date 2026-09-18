# SOC Automation Lab

End-to-end SOC automation lab integrating **Sysmon, Wazuh, Shuffle SOAR, VirusTotal, and TheHive** to detect suspicious Windows activity, enrich indicators, create security alerts, and notify a SOC analyst.

The project demonstrates a complete defensive workflow using a controlled **Mimikatz detection scenario** in an isolated Windows lab.

## Detection Pipeline

```text
Windows 10 + Sysmon
        ↓
    Wazuh Agent
        ↓
  Wazuh Manager
        ↓
Custom Detection Rule
        ↓
    Shuffle SOAR
        ↓
  SHA256 Extraction
        ↓
VirusTotal Enrichment
        ↓
   TheHive Alert
        ↓
 Email Notification
```

---

## Architecture

![SOC Automation Architecture](screenshots/00-architecture.png)

### Environment

- **Endpoint:** Windows 10 VM running Sysmon and Wazuh Agent
- **SIEM/XDR:** Wazuh hosted on Microsoft Azure
- **SOAR:** Shuffle
- **Threat Intelligence:** VirusTotal
- **Alert Management:** TheHive hosted on Microsoft Azure
- **Cloud Infrastructure:** Azure Ubuntu VMs
- **Virtualization:** Oracle VirtualBox

The completed workflow follows:

**Detect → Enrich → Investigate → Notify**

---

## What I Built

This project was designed to simulate a small SOC environment capable of:

- Collecting detailed Windows telemetry with Sysmon
- Forwarding endpoint events to Wazuh
- Searching and investigating raw security events
- Creating a custom Wazuh rule to detect Mimikatz
- Mapping the detection to MITRE ATT&CK
- Forwarding high-severity alerts to Shuffle
- Extracting SHA256 hashes from Wazuh events
- Enriching file hashes using VirusTotal
- Automatically creating alerts in TheHive
- Sending email notifications to a SOC analyst

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Wazuh | SIEM/XDR, log analysis, detection |
| Sysmon | Windows endpoint telemetry |
| Shuffle | SOAR workflow automation |
| VirusTotal | Threat intelligence enrichment |
| TheHive | Security alert management |
| Microsoft Azure | Cloud infrastructure |
| Windows 10 | Monitored endpoint |
| Ubuntu Server | Wazuh and TheHive servers |
| Filebeat | Event forwarding |
| Wazuh Indexer | Event indexing and search |
| Cassandra / Elasticsearch | TheHive backend services |
| MITRE ATT&CK | Detection mapping |

---

# Implementation

## 1. Windows Endpoint Monitoring

A Windows 10 virtual machine was configured with:

- Sysmon
- Wazuh Agent
- PowerShell
- Windows Event logging

The Wazuh Agent communicates with the Wazuh Manager hosted in Azure.

Azure Network Security Group rules were configured for Wazuh communication, including:

```text
TCP 1514 - Agent communication
TCP 1515 - Agent enrollment
TCP 443  - Wazuh Dashboard
```

### Wazuh Agent Connected

![Wazuh Agent Active](screenshots/01-wazuh-agent-active.png)

---

## 2. Sysmon Telemetry Collection

Sysmon was used to provide detailed endpoint telemetry such as:

- Process creation
- Process access
- Image loading
- File creation
- Command-line arguments
- File hashes
- Parent process information

The Wazuh Agent was configured to collect the Sysmon Operational channel:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### Sysmon Telemetry in Wazuh

![Sysmon Telemetry](screenshots/02-sysmon-telemetry.png)

---

## 3. Wazuh Archive Logging

Raw event archiving was enabled so that events could still be investigated even when they did not trigger an alert.

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

Archived JSON events were stored in:

```text
/var/ossec/logs/archives/archives.json
```

Filebeat archive forwarding was enabled and events were indexed under:

```text
wazuh-archives-*
```

This allowed raw Sysmon events to be searched through Wazuh Discover.

---

## 4. Custom Mimikatz Detection

Mimikatz was executed inside the isolated Windows VM to generate controlled security telemetry.

Sysmon captured the process execution, including information such as:

```text
Image: mimikatz.exe
OriginalFileName: mimikatz.exe
Product: mimikatz
```

I created a custom Wazuh detection rule:

```xml
<group name="sysmon,mimikatz,">

  <rule id="100002" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
    <description>Mimikatz Usage Detected</description>

    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>

</group>
```

The rule:

- Monitors Sysmon Process Create events
- Checks the executable's original filename
- Uses case-insensitive matching
- Generates a **Level 15** Wazuh alert
- Maps the activity to **MITRE ATT&CK T1003 - OS Credential Dumping**

### Detection Result

![Mimikatz Detection](screenshots/03-mimikatz-detection.png)

The custom rule is available in:

```text
wazuh/local_rules.xml
```

---

## 5. Wazuh → Shuffle Integration

The custom Wazuh alert was forwarded to Shuffle using a webhook integration.

```xml
<integration>
  <name>shuffle</name>
  <hook_url>SHUFFLE_WEBHOOK_URL</hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Only events matching Rule `100002` were sent into this automation workflow.

The actual webhook URL is excluded from the repository.

---

## 6. Shuffle SOAR Automation

Shuffle orchestrates the automated workflow after receiving the Wazuh alert.

```text
Wazuh Alert
     ↓
Shuffle Webhook
     ↓
Extract SHA256
     ↓
VirusTotal Lookup
     ↓
Create TheHive Alert
     ↓
Notify SOC Analyst
```

### Workflow

![Shuffle Workflow](screenshots/04-shuffle-workflow.png)

---

## 7. SHA256 Extraction & VirusTotal Enrichment

The Wazuh event contained multiple file hashes.

Shuffle extracts the SHA256 value using:

```regex
SHA256=([0-9A-Fa-f]{64})
```

The extracted hash is then submitted to VirusTotal for threat intelligence enrichment.

A successful lookup returned:

```text
HTTP 200
```

### VirusTotal Result

![VirusTotal Enrichment](screenshots/05-virustotal-enrichment.png)

This allows the SOC workflow to automatically retrieve threat intelligence instead of requiring a manual hash lookup.

---

## 8. Automated TheHive Alert

TheHive was deployed on a separate Azure Ubuntu VM.

A dedicated SOAR service account and API key were configured so Shuffle could automatically create security alerts.

The successful API request returned:

```text
POST /api/v1/alert
HTTP 201 Created
```

The generated alert included:

```text
Title: Mimikatz Usage Detected
Severity: High
Source: WAZUH Alert
MITRE ATT&CK: T1003
Status: New
Host: windows
```

### TheHive Alert

![TheHive Alert](screenshots/06-thehive-alert.png)

---

## 9. SOC Analyst Notification

The final stage of the workflow sends an email notification to the SOC analyst.

This demonstrates that the detection is automatically escalated beyond the SIEM and brought to the analyst's attention.

### Email Notification

![SOC Analyst Email Notification](screenshots/07-email-notification.png)

---

# Key Troubleshooting & Lessons Learned

Building the lab required troubleshooting across multiple layers rather than only configuring security tools.

### Azure Networking

The Windows agent initially could not communicate with the Wazuh server because the required Azure NSG rules were not configured.

Connectivity was tested using:

```powershell
Test-NetConnection <WAZUH_SERVER> -Port 1514
Test-NetConnection <WAZUH_SERVER> -Port 1515
```

This helped isolate the problem to the network layer.

### Wazuh Search Troubleshooting

Mimikatz events were present in Wazuh's archive and indexer, but initially appeared as:

```text
No Results
```

in Discover.

The problem was the selected **time range**, not event ingestion.

This reinforced an important SIEM troubleshooting principle:

> No search results does not necessarily mean no logs were collected.

I verified the pipeline layer-by-layer:

```text
Sysmon
   ↓
Wazuh Agent
   ↓
Wazuh Manager
   ↓
archives.json
   ↓
Filebeat
   ↓
Wazuh Indexer
   ↓
Discover
```

### Shuffle Data Handling

The SHA256 regex action originally returned a structured object rather than a single hash.

Passing the entire object to VirusTotal caused the lookup to fail.

The workflow was corrected to pass only the extracted SHA256 value.

### Shuffle → TheHive Connectivity

TheHive TCP `9000` was initially restricted to my administrator IP.

Because Shuffle Cloud originated from another network, the API request timed out.

Once network connectivity was corrected, the response changed from:

```text
Timeout
```

to:

```text
HTTP 401
```

This confirmed that networking was fixed and authentication was the remaining problem.

After configuring the correct API authentication:

```text
HTTP 201 Created
```

confirmed successful alert creation.

This demonstrated the value of troubleshooting integrations layer-by-layer:

```text
Network → Authentication → API → Application
```

---

# Skills Demonstrated

### Security Operations
- SIEM monitoring
- Endpoint telemetry analysis
- Threat detection
- Threat hunting
- IOC enrichment
- Alert escalation
- SOAR automation

### Detection Engineering
- Sysmon
- Wazuh custom rules
- Windows Event Logs
- MITRE ATT&CK mapping
- Regex
- Detection validation

### Cloud & Networking
- Microsoft Azure
- Azure Network Security Groups
- TCP/IP troubleshooting
- Firewall rules
- Cloud virtual machines

### Systems Administration
- Windows 10
- Ubuntu Linux
- SSH
- systemd
- Linux file permissions
- Service troubleshooting

### Automation & Integration
- REST APIs
- JSON
- XML
- Webhooks
- API authentication
- Shuffle
- VirusTotal
- TheHive

---

# Security Considerations

This project was created for **defensive cybersecurity education and testing inside an isolated lab environment**.

Sensitive information is intentionally excluded from this repository.

The following should never be committed:

```text
API keys
Passwords
Webhook URLs
SSH private keys
Authentication tokens
Session cookies
Azure credentials
```

During testing, TheHive TCP `9000` was temporarily made publicly reachable so Shuffle Cloud could access the API.

This was a temporary lab configuration and should **not** be considered suitable for a production environment.

---

# Future Improvements

- Configure HTTPS for TheHive
- Place TheHive behind an Nginx reverse proxy
- Remove direct public exposure of TCP 9000
- Use more restrictive Azure NSG rules
- Implement secure secret management
- Add behavioral detection beyond filename matching
- Detect renamed credential-dumping tools
- Add additional MITRE ATT&CK detections
- Add observables automatically to TheHive
- Include VirusTotal enrichment data directly in TheHive alerts
- Add additional Windows endpoints
- Build additional Wazuh dashboards
- Implement controlled automated response actions

---

# Repository Structure

```text
soc-automation-lab/
│
├── README.md
├── LICENSE
│
├── docs/
│   └── architecture.md
│
├── screenshots/
│   ├── 00-architecture.png
│   ├── 01-wazuh-agent-active.png
│   ├── 02-sysmon-telemetry.png
│   ├── 03-mimikatz-detection.png
│   ├── 04-shuffle-workflow.png
│   ├── 05-virustotal-enrichment.png
│   ├── 06-thehive-alert.png
│   └── 07-email-notification.png
│
└── wazuh/
    └── local_rules.xml
```

More detailed architecture documentation is available in:

[`docs/architecture.md`](docs/architecture.md)

---

## Key Takeaway

This project demonstrates how endpoint telemetry, SIEM detection, threat intelligence, SOAR automation, and alert management can be integrated into a functional SOC pipeline.

Rather than configuring each technology independently, the lab connects them into an end-to-end workflow:

**Collect → Detect → Enrich → Investigate → Notify**

---

## Disclaimer

This project was performed in an isolated lab environment for cybersecurity education and defensive security testing.

All testing was performed against systems owned and controlled by the author.
