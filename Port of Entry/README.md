
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


Analysis of the command line for the credential dumping tool (mm.exe) shows it invoked the Mimikatz memory extraction module sekurlsa::logonpasswords, which is used to retrieve usernames and plaintext passwords, NTLM hashes, Kerberos tickets, and other authentication material directly from.

Resource used: <a href="https://github.com/gentilkiwi/mimikatz/wiki">Mimikatz</a>

🚩 Flag 13 - sekurlsa::logonpasswords
 
