LAB 7 — WebStrike | CyberDefenders | Network Forensics | Easy
Scenario

E-commerce web server (shoporoma.com) compromised through a file upload vulnerability, granting the attacker remote code execution via a reverse shell

Attack Chain

Attacker (117.11.88.124) performs recon via HTTP GET requests on shoporoma.com
Uploads malicious file image.jpg.php via /reviews/upload.php — double-extension bypass, Content-Type: application/x-php
Embedded PHP payload spawns a reverse shell (mkfifo + netcat) connecting out to 117.11.88.124:8080
MITRE ATT&CK: T1190 (Exploit Public-Facing Application) → T1105 (Ingress Tool Transfer)

Network Indicators

Attacker IP: 117.11.88.124
Compromised web server: shoporoma.com (Apache/2.4.52, Ubuntu)
Uploaded web shell: image.jpg.php
Reverse shell C2 port: 8080

Techniques Identified

Unrestricted file upload — double-extension bypass defeating naive extension-based filtering
Reverse shell — classic mkfifo/netcat one-liner for outbound interactive shell

Tools Used: Wireshark, display filters (http.request.method, tcp.stream)
Concepts Learned

HTTP upload vulnerability analysis
Multipart form-data inspection
Reverse shell payload deconstruction

LAB LOCATION: https://cyberdefenders.org/blueteam-ctf-challenges/webstrike/

LAB 8 — PacketDetective | CyberDefenders | Network Forensics | Easy
Scenario

SOC detected suspicious activity from a user device, flagged by unusual SMB protocol usage
Analysis indicated a possible compromise of a privileged account and remote access tool usage
Three PCAP files analyzed to reconstruct the attacker's methods, persistence tactics, and full timeline

Attack Chain

Attacker authenticates via SMB using compromised Administrator credentials
Accesses and exfiltrates the eventlog file
Clears Windows event logs at 2020-09-23 16:50 UTC to evade detection
Establishes lateral movement via DCOM/WMI (IWbemLoginClientID) and the atsvc named pipe (Task Scheduler service)
Maintains persistence using a non-standard backdoor username for follow-up NTLM requests
Executes remote processes using PSEXESVC.exe
MITRE ATT&CK: T1078 (Valid Accounts) → T1070.001 (Clear Windows Event Logs) → T1021.003 (Remote Services: DCOM) → T1569.002 (PsExec-style Service Execution)

Network Indicators

Compromised account: Administrator
File accessed: eventlog
Log-clearing timestamp: 2020-09-23 16:50 UTC
Named pipe / lateral movement service: atsvc
Communication duration between 172.16.66.1 and 172.16.66.36: 11.7247 seconds
Persistence username: backdoor
Remote execution binary: PSEXESVC.exe
Total SMB protocol bytes: 4406

Techniques Identified

Privileged account abuse — SMB authentication using compromised Administrator credentials
Anti-forensics — deliberate event log access/clearing to cover tracks
Lateral movement (dual technique) — DCOM/WMI session plus a classic atsvc (Task Scheduler) named pipe
Persistence — non-standard backdoor account used for follow-up authenticated requests
Remote execution — PSEXESVC.exe, the service binary PsExec drops to execute commands remotely

Tools Used: Wireshark, display filters (smb2, ntlmssp.auth.username, smb2.filename, dcerpc, frame contains)
Concepts Learned

SMB protocol byte-level analysis
NTLM authentication field extraction
Named pipe identification
DCOM/RPC interface UUID lookup
Event log tampering detection
PsExec artifact recognition
Multi-file timeline correlation across a single incident

LAB LOCATION: https://cyberdefenders.org/blueteam-ctf-challenges/packetdetective/
