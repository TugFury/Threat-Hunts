
<img width="1536" height="1024" alt="Port of entry Image" src="https://github.com/user-attachments/assets/fcfd59d8-503c-45b0-8080-0df78134b07b" />
<h1>🛡️ Port of Entry – RDP Intrusion (2025)</h1>
Cyber Range Community Threat Hunt Case Study

This directory contains the complete investigation, forensic analysis, and incident response documentation for the Azuki Port of Entry  RDP Intrusion, a structured threat hunt challenge from the Cyber Range Community Threat Hunting Competition. 

I completed this hunt as part of a competitive blue-team event and achieved a 4th place finish, demonstrating strong threat-hunting speed, accuracy, and IR methodology.

The scenario simulated a targeted compromise against Azuki Import/Export, a logistics company in Japan/SE Asia.

During the intrusion, the attacker:
<ul>
    <li>Used RDP with stolen credentials</li>
    <li>Disabled security tools</li>
    <li>Established a hidden staging directory</li>
    <li>Dumped credentials from LSASS</li>
    <li>Archived and exfiltrated contract data</li>
    <li>Maintained persistence</li>
    <li>Attempted lateral movement</li>
</ul>




<h2>INCIDENT RESPONSE REPORT</h2>

On November 19th, 2025, Azuki Import/Export experienced a targeted intrusion involving credential compromise, remote access, credential dumping, data theft, and exfiltration to a Discord webhook. The attacker leveraged RDP using stolen credentials, established persistence, disabled security controls, stole internal contract data, and uploaded it via HTTPS. The intrusion lasted several hours and involved anti-forensics and attempted lateral movement.


Date of Report: [2025-12-01]

Severity Level:High

Status: Contained



Flag 1 Initial Access

Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

KQL Query:
DeviceLogonEvents 
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP, RemoteDeviceName
| order by Timestamp asc


<img width="1243" height="440" alt="Flag 1 Return" src="https://github.com/user-attachments/assets/da03a46f-6398-42ea-ac45-97c3a16ca7b9" />

