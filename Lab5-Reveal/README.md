LAB 5 — Reveal | CyberDefenders | Memory Forensics | Easy
Scenario
SIEM flagged unusual activity on a financial institution workstation with access to sensitive data. Memory dump analyzed to identify breach and assess scope.
Attack Chain

wordpad.exe (PID 4120) launched powershell.exe (PID 3692) — initial infection vector
PowerShell downloaded second stage payload: 3435.dll
3435.dll executed via rundll32.exe — MITRE ATT&CK T1218.011

Network Indicators

Remote server: 45.9.74.32 port 8888
Shared directory: davwwwroot
Full path: \45.9.74.32@8888\davwwwroot\3435.dll
Delivery method: WebDAV — file loaded directly from network without touching disk (fileless)

Malware Family: StrelaStealer

Identified via VirusTotal IP lookup and community reports
Infostealer targeting email credentials — Outlook and Thunderbird
WebDAV delivery via davwwwroot on port 8888 is a StrelaStealer signature technique

Tools Used: Volatility 3, strings, VirusTotal, windows.pslist, windows.cmdline, windows.filescan
Concepts Learned: Multi-stage payload delivery, WebDAV fileless execution, MITRE ATT&CK mapping, threat intelligence correlation, infostealer malware family identification

LAB LOCATION: https://cyberdefenders.org/blueteam-ctf-challenges/reveal/
