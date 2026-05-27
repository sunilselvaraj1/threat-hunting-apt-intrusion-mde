# Threat Hunting — Corporate Espionage Investigation
## Azuki Import/Export Trading Co. · Microsoft Defender for Endpoint · KQL

---

## Scenario Overview

A Japanese shipping logistics company suspected a competitor had obtained their confidential supplier contracts and pricing data — undercutting a 6-year contract by exactly 3%. The compromised data had appeared on underground forums.

**Environment:** 23-employee company, Japan/SE Asia operations  
**Compromised asset:** AZUKI-SL (IT admin workstation)  
**Evidence source:** Microsoft Defender for Endpoint logs  
**Investigation window:** 2025-11-19 to 2025-11-20  
**Threat actor:** JADE SPIDER (tracked threat group)

---

## Methodology

This investigation followed a hypothesis-driven threat hunting approach using the MITRE ATT&CK framework as a structured reference. Rather than waiting for alerts, the hunt was initiated based on a business anomaly — the precision of the competitor's knowledge suggested insider access or targeted intrusion.

Each stage of the investigation involved:
1. Forming a hypothesis about attacker behaviour at that phase of the kill chain
2. Writing targeted KQL queries against MDE tables to test the hypothesis
3. Correlating findings across tables to build a timeline
4. Mapping confirmed techniques to MITRE ATT&CK TTPs

---

## Attack Chain Summary

| Phase | MITRE Tactic | Technique | Finding |
|---|---|---|---|
| Initial Access | TA0001 | T1021.001 — Remote Desktop Protocol | External RDP from suspicious IP |
| Discovery | TA0007 | T1016 — System Network Configuration Discovery | Network enumeration post-access |
| Defence Evasion | TA0005 | T1562.001 — Impair Defenses | Windows Defender exclusions added |
| Defence Evasion | TA0005 | T1074.001 — Local Data Staging | Hidden staging directory created |
| Defence Evasion | TA0005 | T1197 — BITS Jobs / LOLBin abuse | Native binary abused for download |
| Persistence | TA0003 | T1053.005 — Scheduled Task | Task masquerading as Windows Update |
| Credential Access | TA0006 | T1003.001 — LSASS Memory | Mimikatz deployed for credential dump |
| Collection | TA0009 | T1560.001 — Archive via Utility | Data compressed for exfiltration |
| Exfiltration | TA0010 | T1567 — Exfiltration Over Web Service | Data sent via consumer cloud platform |
| Anti-Forensics | TA0005 | T1070.001 — Clear Windows Event Logs | Security and System logs wiped |
| Persistence | TA0003 | T1136.001 — Create Local Account | Hidden backdoor account added |
| Lateral Movement | TA0008 | T1021.001 — Remote Desktop Protocol | RDP pivot to secondary target |

---

## Investigation Highlights

### Initial Access — RDP from External Source

The investigation began by querying `DeviceLogonEvents` for remote interactive sessions originating from non-RFC1918 addresses during the incident window. A successful external RDP connection was identified, establishing the initial foothold and the compromised user account.

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive", "Network")
| where isnotempty(RemoteIP)
| where RemoteIP !startswith "10."
    and RemoteIP !startswith "192.168."
    and RemoteIP !startswith "172."
| project Timestamp, AccountName, LogonType, RemoteIP, RemotePort, Protocol
| order by Timestamp asc
```

---

### Defence Evasion — Defender Exclusions and Staging

After initial access, the attacker made targeted modifications to Windows Defender configuration via registry changes, adding both file extension exclusions and a folder path exclusion. A hidden staging directory was created under `C:\ProgramData\` to store tools and collected data — a common pattern for minimising filesystem noise.

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey has "Exclusions\\Extensions"
    or RegistryKey has "Exclusions\\Paths"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
```

---

### Persistence — Scheduled Task Masquerading

A scheduled task was created with a name designed to blend with legitimate Windows maintenance activity. The task executed a binary from the staging directory, ensuring persistence across reboots.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, ProcessCommandLine
```

---

### Credential Access — Mimikatz Deployment

The attacker used a LOLBin (`certutil.exe`) to download a credential dumping tool into the staging directory, then executed it with `sekurlsa::logonpasswords` to extract plaintext credentials from LSASS memory. The tool was renamed to evade signature-based detection.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("sekurlsa", "logonpasswords", "privilege::debug")
| project Timestamp, FileName, ProcessCommandLine
```

---

### Exfiltration — Data Staging and Cloud Upload

Collected data was compressed into a ZIP archive and exfiltrated via a consumer cloud/messaging platform — identified by querying `DeviceNetworkEvents` for outbound connections to known file-sharing and communication services.

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteUrl has_any ("dropbox", "mega.nz", "discord", "telegram",
    "onedrive", "drive.google", "slack", "pastebin",
    "anonfiles", "gofile", "wetransfer")
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName
```

---

### Anti-Forensics — Event Log Clearing

Near the end of the attack, `wevtutil.exe` was used to clear multiple Windows event logs in sequence, beginning with the Security log — a deliberate attempt to destroy forensic artefacts. MDE's telemetry captured these actions despite the log clearing.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

---

### Lateral Movement — RDP Pivot

Using credentials obtained via Mimikatz, the attacker used `cmdkey` to cache credentials and `mstsc.exe` to pivot laterally to a secondary internal target — demonstrating that the compromise extended beyond the initial workstation.

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mstsc", "cmdkey")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

---

## Key Takeaways

**Detection opportunities identified:**

- RDP exposure to the internet is a critical risk — NSG/firewall rules should restrict RDP to authorised IP ranges or require VPN
- Registry modifications to Windows Defender exclusions are high-fidelity indicators of compromise and should trigger immediate investigation
- LOLBin abuse (certutil for file download) is a well-documented evasion technique — process command line monitoring with alerts on certutil + URL patterns is effective
- Scheduled tasks with names mimicking Windows components warrant scrutiny — baselining legitimate scheduled tasks enables anomaly detection
- Even after event log clearing, MDE telemetry preserved the full attack chain — demonstrating the value of cloud-delivered EDR telemetry that attackers cannot easily tamper with

**Tools and platforms used:**
- Microsoft Defender for Endpoint (MDE)
- KQL (Kusto Query Language)
- MITRE ATT&CK Framework
- Microsoft Sentinel (for detection rule development based on findings)

---

## About This Investigation

This investigation was conducted as part of the **Cyber Range SOC Challenge** (Azuki Series, November 2025), designed by Mohammed A. to simulate real-world incident response artefacts. All analysis was performed using Microsoft Defender for Endpoint advanced hunting tables.

**Analyst:** Sunil Selvaraj  
**Certifications:** BTL1 | CompTIA Security+ (in progress)  
**Background:** MSc Cybersecurity — Distinction, Oxford Brookes University  
**LinkedIn:** [linkedin.com/in/sunilselvaraj](https://linkedin.com/in/sunilselvaraj)

