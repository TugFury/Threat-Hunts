

<img width="740" height="1110" alt="Cargohold image" src="https://github.com/user-attachments/assets/c4e61910-e5e6-4213-862c-9c7784373ee5" />


<h1>🛡️ Port of Entry – RDP Intrusion (2025)</h1>
Part 2 of the 4 Part Threat Hunt Event at the Cyber Range.

SITUATION: After establishing initial access on November 19th, network monitoring detected the attacker returning approximately 72 hours later. Suspicious lateral movement and large data transfers were observed overnight on the file server.


<h3>Flag 1: Initial Access</h3>

Return Connection Source After establishing initial access, sophisticated attackers often wait hours or days (dwell time) before continuing operations. They may rotate infrastructure between sessions to avoid detection.

KQL Query

DeviceLogonEvents <br>
| where DeviceName contains "azuki" <br>
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType <br>
| order by TimeGenerated asc <br>



By querying successful logons and remote access activity on the Azuki beachhead VM, I identified a later successful connection back to the host from the external IP: 159.26.106.98

🚩 Flag 1 - 159.26.106.98

