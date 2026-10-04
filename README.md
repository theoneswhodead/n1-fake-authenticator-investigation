# N1 - Fake Authenticator Website Investigation

## Overview

This project documents a network-based SOC investigation of a suspected malware infection.

The investigation was performed using a PCAP file and Wireshark. The analysis focused on identifying the affected host, suspicious DNS and HTTP activity, payload delivery, persistence mechanisms, and Command and Control (C2) communication.

## Scenario

The investigated host accessed a suspicious fake software website and subsequently communicated with external infrastructure.

The investigation identified:

- Suspicious communication with `authenticatoor.org`
- PowerShell payload delivery
- Download of `29842.ps1`
- Persistence through the Windows Startup folder
- Periodic HTTP callback communication
- Encrypted C2 communication with external infrastructure

## Affected Host

| Attribute | Value |
|---|---|
| IP Address | `10.1.17.215` |
| MAC Address | `00:d0:b7:26:4a:74` |
| Hostname | `DESKTOP-L8C5GSJ` |
| FQDN | `DESKTOP-L8C5GSJ.bluemoontuesday.com` |
| DNS Server | `10.1.17.2` |

## Investigation Methodology

The investigation was performed in several stages:

1. Host identification and network orientation
2. DNS traffic analysis
3. HTTP traffic and payload analysis
4. Encrypted C2 traffic analysis
5. Incident assessment and IOC extraction

## Key Findings

### Initial Access / Suspicious Website

The host communicated with:

- Domain: `authenticatoor.org`
- IP: `82.221.136.26`
- Protocol: TLS 1.3

The available PCAP confirms the communication but does not independently prove the exact user action that initiated it.

### PowerShell Payload

The host downloaded:

`29842.ps1`

from:

`http://5[.]252[.]153[.]241/api/file/get-file/29842.ps1`

The observed script used PowerShell functionality to retrieve and execute remote content.

### Persistence

Persistence was established using the Windows Startup folder.

Observed artifacts included:

- `C:\ProgramData\huo\TeamViewer.exe`
- `TeamViewer.lnk`

### Command and Control

The host communicated with external infrastructure exhibiting characteristics consistent with C2 activity.

Observed infrastructure included:

- `45.125.66.32:2917`
- `45.125.66.252:443`
- `5.252.153.241`

## Verdict

**Confirmed malicious activity**

**Confidence: High**

Multiple independent indicators support the assessment, including suspicious external infrastructure, PowerShell payload delivery and execution, persistence through the Startup folder, and periodic communication with external infrastructure consistent with C2 activity.

## MITRE ATT&CK

| Technique | Name |
|---|---|
| T1059.001 | PowerShell |
| T1105 | Ingress Tool Transfer |
| T1547.001 | Registry Run Keys / Startup Folder |
| T1071.001 | Web Protocols |
| T1573 | Encrypted Channel |

## Detailed Report

See [`incident-report.md`](incident-report.md) for the complete investigation timeline, findings, limitations, IOCs, recommendations, and MITRE ATT&CK mapping.

## Tools

- Wireshark
- PCAP analysis
- Network traffic analysis
