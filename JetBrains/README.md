# TeamCity Authentication Bypass Investigation (CVE-2024-27198)

## Overview

This lab walks through a network forensics investigation of an attack against a JetBrains TeamCity server. Using Wireshark to analyze a packet capture, I traced an attacker's activity from initial authentication bypass through webshell deployment, command execution, credential tampering, and a failed attempt to escape the Docker container running the service.

The full investigation was done entirely from PCAP analysis, no host artifacts, no logs, just raw traffic.

## Environment

- Tool: Wireshark
- Capture: Capture.pcap
- Target: TeamCity server at 3.71.79.4:8111
- Attacker IP: 23.158.56.196

## Investigation Steps

### 1. Identifying the Attacker

I started by filtering for POST requests hitting the authentication endpoint:

```
http.request.method == POST && frame contains "authentication"
```

This isolated repeated POST requests to `/authenticationTest.html?csrf` coming from the same source IP hitting two different internal destinations back to back, a strong signal of automated, scripted behavior rather than a normal login.

**Attacker IP: `23.158.56.196`**

<img width="1722" height="295" alt="Q1" src="https://github.com/user-attachments/assets/4ce6e866-07fe-4c80-a6eb-ca54cf44e523" />


### 2. Identifying the Vulnerable Service

Checked the server headers and version info returned in the HTTP responses to confirm the TeamCity build in use.

**Web server version: `2023.11.3`**

<img width="1141" height="1130" alt="Q2" src="https://github.com/user-attachments/assets/a556f15e-27b9-41a0-8f74-11bbac8e52ca" />


### 3. Mapping the CVE

Cross referencing the version against known TeamCity vulnerabilities confirmed the flaw being exploited was the authentication bypass disclosed in early 2024.

**CVE: `CVE-2024-27198`**

<img width="684" height="206" alt="Q3" src="https://github.com/user-attachments/assets/34a176b6-9938-46a7-aa77-bb23b5e7213f" />


### 4. Malicious User Account Creation

Using the confirmed attacker IP, I filtered for POST traffic referencing user account activity:

```
http.request.method == POST && ip.addr == 23.158.56.196 && frame contains "users"
```

The attacker exploited the auth bypass to create a rogue admin account directly through the TeamCity admin panel.

**Created credentials: `c91oyemw:CL5vzdwLuK`**

<img width="1139" height="1011" alt="Q4" src="https://github.com/user-attachments/assets/71788ecd-d412-4ccd-86af-efcc4da538e3" />


### 5. Webshell Upload

Filtered for multipart file upload traffic to confirm how persistence was established:

```
http.request.method == POST && frame contains "filename="
```

The attacker uploaded a JSP webshell packaged as a zip archive to the TeamCity plugins directory.

**Uploaded file: `NSt8bHTg.zip`** (deployed as `/plugins/NSt8bHTg/NSt8bHTg.jsp`)

<img width="1718" height="1176" alt="Q5" src="https://github.com/user-attachments/assets/743ff9c6-0f21-44e4-acb6-2402fb4b674c" />


### 6. First Command Execution

Once the webshell was live, every subsequent command came through as a POST to that same JSP file with a `cmd=` parameter in the form body:

```
http.request.method == POST && frame contains "cmd="
```

Sorting these chronologically and checking the earliest timestamp gave the first executed command.

**First command execution: `2024-06-30 08:03`**

<img width="1723" height="367" alt="Q6" src="https://github.com/user-attachments/assets/8e392923-b318-4617-80d7-910f93f07777" />


### 7. Credential File Tampering

Digging further into the `cmd=` traffic, one request stood out by length compared to simple recon commands like `ls` or `whoami`. Decoding the form body revealed the attacker writing fake credentials to a file on disk to mislead responders or plant a false trail:

```
bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/Creds.txt'
```

**Written credentials: `a1l4m:youarecompromised`**

<img width="1714" height="1121" alt="Q7" src="https://github.com/user-attachments/assets/5c50fcb7-9f10-475b-80a8-e8a7f533678c" />


### 8. MITRE ATT&CK Mapping

Writing arbitrary data to disguise or manipulate a legitimate looking credentials file maps to the Hide Artifacts technique for masquerading/manipulating file content used to mislead investigators.

**MITRE Technique: `T1565.001`** (Data Manipulation, Stored Data Manipulation)

<img width="716" height="356" alt="Q8" src="https://github.com/user-attachments/assets/c57a3e1b-447e-4a26-a432-4ef9f9df2a40" />


### 9. Container Escape Attempt

Continuing to filter on `cmd=` traffic from the attacker, three separate Docker related commands showed up in sequence:

```
docker run --rm -it --privileged ubuntu
docker run --rm -it -v /:/host ubuntu chroot /host
docker run -v /var/run/docker.sock:/var/run/docker.sock -it ubuntu
```

All three attempted to break out of the container the webshell was running in, first by requesting a privileged container, then by mounting the host's root filesystem and chrooting into it, then by mounting the Docker socket to gain control of the host's Docker daemon.

Every one of these requests returned a response with a `Content-Length` of only 4 bytes, effectively empty output, compared to legitimate follow up commands like `ls` and `whoami` which returned full, sensible output. That drop back to basic recon commands right after three failed escape attempts, combined with the empty responses, confirms none of the escape attempts succeeded.

**Escape attempt command: `docker run --rm -it -v /:/host ubuntu chroot /host`**

<img width="658" height="92" alt="SCR-20260805-pftq" src="https://github.com/user-attachments/assets/218df687-a961-4992-ad0d-a15f1f2ed3d2" />


## Summary

| Finding | Detail |
|---|---|
| Attacker IP | 23.158.56.196 |
| Vulnerable service | TeamCity 2023.11.3 |
| CVE | CVE-2024-27198 |
| Malicious account | c91oyemw:CL5vzdwLuK |
| Webshell | NSt8bHTg.zip (NSt8bHTg.jsp) |
| First command execution | 2024-06-30 08:03 |
| Tampered credentials | a1l4m:youarecompromised |
| MITRE Technique | T1565.001 |
| Container escape attempt | docker run --rm -it -v /:/host ubuntu chroot /host (failed) |

## Key Takeaways

This lab was a good reminder that filtering by keyword alone isn't always precise enough since generic strings can pull in unrelated traffic that just happens to contain the same word. Combining method, source IP, and content filters together got much cleaner results. Comparing response `Content-Length` values across similar commands also turned out to be a fast, reliable way to tell working commands apart from failed ones without needing to manually inspect every single HTTP stream.

**Tools used:** Wireshark, HTTP Stream analysis
