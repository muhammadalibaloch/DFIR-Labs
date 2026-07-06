LAB 3 — Ramnit | CyberDefenders | Memory Forensics | Easy
Scenario
IDS alerted on suspicious behavior on a workstation indicating likely malware intrusion. A memory dump was taken for analysis. 
Task was to analyze the dump, trace malware actions, and report key findings.
Malware Identified: ChromeSetup.exe

Identified via windows.pslist — process name stood out as unusual on a corporate machine
Confirmed via windows.netstat — process PID 4628 was making outbound connection to 58.64.204.181 on port 5202 with state SYN_SENT
IP traced to Hong Kong via ipinfo.io
Disguised as a Chrome installer to avoid detection — classic Living off the Land technique

How the File Was Extracted From Memory

Ran windows.filescan and grepped for ChromeSetup to find its memory address
Used windows.dumpfiles --virtaddr to extract the actual executable from RAM
Calculated SHA1 hash using sha1sum: 280c9d36039f9432433893dee6126d72b9112ad2

VirusTotal Findings

65/70 security vendors flagged the file as malicious
Contacted domain: dnsnb8.net — command and control server
Contacted URLs all pointed to ddos.dnsnb8.net:799 — downloading additional payloads
Tags: persistence, spreader, checks-network-adapters — confirms it's a spreading malware

Key Forensic Artifacts

Process list revealed suspicious process name
Network connections revealed C2 communication attempt
PE header contained compilation timestamp
strings analysis revealed Microsoft.XMLHTTP — malware makes web requests programmatically

Tools Used: Volatility 3, sha1sum, strings, VirusTotal
Concepts Learned: Memory forensics, process analysis, network IOC extraction, file extraction from RAM, PE file analysis, 
hash-based threat intelligence, C2 domain identification

Location to File is https://cyberdefenders.org/blueteam-ctf-challenges/ramnit/
