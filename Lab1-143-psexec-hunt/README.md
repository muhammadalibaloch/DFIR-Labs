# PsExec Hunt

## Objective

Investigate lateral movement using PsExec by analyzing network traffic captured in a PCAP file.

## Scenario

An attacker remotely executed commands using PsExec to move laterally between Windows machines inside the network.

## Attack Summary

- Attacker IP: 10.0.0.130
- SALES-PC: 10.0.0.133
- MARKETING-PC: 10.0.0.131

### Attack Chain

1. Authenticated using compromised account **ssales**
2. Connected to IPC$
3. Accessed ADMIN$
4. Uploaded **PSEXESVC.exe**
5. Started PsExec service
6. Pivoted to MARKETING-PC using **jdoe**

## Evidence

- SMB Authentication
- IPC$ access
- ADMIN$ access
- NTLMSSP authentication
- PsExec service creation

## Tools

- Wireshark

## Skills Learned

- SMB
- Windows Administrative Shares
- NTLM Authentication
- Lateral Movement
- Living off the Land (LOLBins)
- Network Forensics
