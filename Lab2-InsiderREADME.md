LAB 2 — Insider | CyberDefenders | Disk Forensics | Easy
Scenario
Employee Karen at TAAUSAI suspected of illegal hacking activities. Investigated her Linux disk image to reconstruct her actions.
OS Identified: Kali Linux

.msf4 folder = Metasploit pre-installed (Kali signature)
binwalk, dradis, inetsim found in system logs = Kali default tools
apt package manager = Debian-based confirmed

What Karen Was Doing

Running Metasploit (msfconsole) with PostgreSQL = actively attacking other systems
Downloaded mimikatz = credential dumping tool to steal Windows passwords
Used binwalk on a jpg file = steganography, hiding data inside an image

Key Findings

Secret file created at /root/Desktop/SuperSecretFile.txt
Discovered via .bash_history which logged exact command used to create it
Apache access.log was empty = logs wiped or never generated
Mimikatz zip found in /root/Downloads

Forensic Artifacts Used

.bash_history = full timeline of Karen's terminal activity
File system structure = OS fingerprinting via tool signatures
Apache logs = evidence of log tampering

Tools Used: FTK Imager
Concepts Learned: Disk forensics, bash history analysis, OS fingerprinting, steganography, credential dumping, Metasploit artifacts
