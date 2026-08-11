# Volatility Traces — Memory Forensics Analysis

**Lab:** Volatility Traces (CyberDefenders)
**Category:** Endpoint Forensics
**Tactics Covered:** Execution, Persistence, Defense Evasion, Credential Access
**Tool:** Volatility 3
**Analyst:** Muhammad Ali Khan

---

## 1. Executive Summary

**Incident Type:** Malware Infection / Fileless PowerShell Abuse / Process Injection / Infostealer Deployment

On May 2, 2024, a multinational corporation flagged suspicious PowerShell activity on a critical endpoint. Analysis of the provided memory dump (`memory.dmp`) confirmed that the endpoint, used by domain account **Lee**, was compromised via a phishing lure disguised as an invoice (`InvoiceCheckList.exe`). Execution of this lure triggered a short, automated infection chain: Windows Defender was selectively disabled via PowerShell, a scheduled task was created to guarantee persistence, and a legitimate .NET utility (`RegSvcs.exe`) was hollowed and injected with an **Agent Tesla** infostealer payload. The entire spawn sequence completed within roughly one second, indicating a scripted, automated dropper rather than manual attacker interaction at this stage.

### IOC Table

| Type | Indicator | Description |
|---|---|---|
| Malware Family | Agent Tesla | .NET-based infostealer/keylogger, confirmed via hash lookup |
| Initial Lure / Dropper | `InvoiceCheckList.exe` (PID 4596) | Phishing lure, parent of all malicious child processes |
| Dropped Payload 1 | `C:\Users\Lee\AppData\Local\Temp\InvoiceCheckList.exe` | Excluded from Defender scanning |
| Dropped Payload 2 | `C:\Users\Lee\AppData\Roaming\HcdmIYYf.exe` | Excluded from Defender scanning; randomized filename consistent with malware staging |
| Injection Target | `RegSvcs.exe` (PID 6796) | Legitimate .NET binary, process-hollowed to host Agent Tesla payload |
| Persistence Mechanism | `schtasks.exe` | Scheduled task creation, sibling process under same parent (4596) |
| Payload Hash (SHA-256) | `462c6532a427badf458ebcf0c7d79256e8604f81798ee3d47a41cb3464682db` | Extracted from RegSvcs.exe memory region `0x400000–0x441fff`; identified as Agent Tesla |
| Compromised User | Lee | Domain user, SID `S-1-5-21-1649652813-3480061347-1948202237-1001` |
| Infection Timestamp | 2024-05-02 06:57:59 – 06:58:00 UTC | All malicious child processes spawned within ~1 second |

### MITRE ATT&CK Mapping Overview

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing | T1566 |
| Execution | User Execution | T1204 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Defense Evasion / Execution | Process Injection | T1055 |
| Persistence | Scheduled Task/Job | T1053.005 |
| Credential Access / Collection | Input Capture / Data from Local System (Agent Tesla behavior) | T1056 / T1005 |

---

## 2. Phase 1: Initial Triage & Process Identification

**Objective:** Establish a baseline of running processes and isolate the anomalous activity that triggered the investigation.

`windows.pslist` was run first to enumerate active processes. Two PowerShell instances stood out immediately, both sharing the same Parent Process ID: **4596**.

```
PID     PPID    Process
6980    4596    powershell.exe
7656    4596    powershell.exe
```

Notably, PID 4596 itself did not appear in the `pslist` output — a strong early indicator that the parent process had already exited or was being deliberately concealed by the time of capture.

**Analyst Note:** A parent process missing from `pslist` while its children are still present is a common artifact of short-lived dropper behavior — the dropper spawns its payloads and terminates quickly, sometimes intentionally to reduce its footprint in live process enumeration. This is why `psscan`, which reads process structures directly from memory pool allocations rather than relying on the OS's active linked list, was the correct next step.

Running `windows.psscan` filtered to PID 4596 recovered the missing process, partially:

```
4596   3800   InvoiceCheckLi   0xb882f107e080   0   -   1   False   2024-05-02 06:57:42.000000   2024-05-02 06:58:00.000000   Disabled
```

The name was truncated to `InvoiceCheckLi` — a known limitation of the kernel's `EPROCESS` structure, which stores only the first 16 characters of an image name. `windows.cmdline` was used to recover the full path and confirm the complete filename.

**MITRE ATT&CK Reference:** T1204 — User Execution. The presence of a truncated, short-lived dropper process spawning multiple children is consistent with a user having executed a malicious file, most likely via social engineering.

---

## 3. Phase 2: Parent Process & Execution Chain Reconstruction

**Objective:** Confirm the full identity of the parent process and map every process it spawned.

`windows.cmdline` filtered against the truncated name confirmed the full dropper identity and its command-line context:

```
6980   powershell.exe   "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Local\Temp\InvoiceCheckList.exe"
```

This reveals the parent's full name: **`InvoiceCheckList.exe`**. `windows.pstree` was then used to reconstruct the complete process lineage:

```
explorer.exe (3800)
  └── InvoiceCheckList.exe (4596)
        ├── powershell.exe (6980) → conhost.exe (3940)
        ├── powershell.exe (7656) → conhost.exe (7220)
        ├── RegSvcs.exe (6796)
        └── schtasks.exe
```

`InvoiceCheckList.exe` was spawned directly from `explorer.exe`, consistent with a user double-clicking a file, in this case, almost certainly a fake invoice attachment or download, a common phishing lure theme designed to induce urgency in the victim.

**Analyst Note:** The naming convention `InvoiceCheckList.exe` is a deliberate social engineering choice — invoice- and payment-themed lures remain among the most effective phishing pretexts because they exploit routine business workflows and rarely draw suspicion at first glance.

**MITRE ATT&CK Reference:** T1566 — Phishing (inferred initial access vector) and T1204 — User Execution (confirmed via the explorer.exe → InvoiceCheckList.exe spawn relationship).

---

## 4. Phase 3: Defense Evasion — Windows Defender Exclusions

**Objective:** Determine how the malware attempted to avoid detection.

Full command-line arguments for both PowerShell instances were extracted via `windows.cmdline`:

```
6980   powershell.exe   Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Local\Temp\InvoiceCheckList.exe"
7656   powershell.exe   Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Roaming\HcdmIYYf.exe"
```

Both processes invoke the **`Add-MpPreference`** cmdlet, a legitimate PowerShell command normally used by administrators to configure Windows Defender. Here it is abused to add two file paths to Defender's scan exclusion list, meaning Defender would no longer inspect either file for malicious content.

Two distinct files were excluded:
1. `InvoiceCheckList.exe` — the dropper's own working copy in the Temp directory
2. `HcdmIYYf.exe` — a second file staged in the Roaming directory, bearing a randomized, non-descriptive filename typical of malware attempting to blend into legitimate application data folders

**Analyst Note:** Excluding its own dropper *and* a second, differently-named file suggests the malware was staging a secondary payload ahead of execution, ensuring that whatever ran next from the Roaming path would also be invisible to Defender. This is a deliberate two-stage evasion setup, not a single opportunistic exclusion.

**MITRE ATT&CK Reference:** T1562.001 — Impair Defenses: Disable or Modify Tools. The use of Defender's own configuration cmdlet to blind it to specific paths is a textbook example of this sub-technique.

---

## 5. Phase 4: Execution & Process Injection — RegSvcs.exe

**Objective:** Identify further malicious activity beyond the PowerShell processes and determine the actual payload delivery mechanism.

`windows.psscan` filtered to parent PID 4596 revealed a third child process beyond the two PowerShell instances: **`RegSvcs.exe`** (PID 6796). RegSvcs.exe is a legitimate Microsoft .NET Framework utility (`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`), normally used to register .NET assemblies as COM components — its presence as a child of a phishing dropper is highly anomalous.

`windows.dlllist` on PID 6796 showed only expected, benign system modules (`ntdll.dll`, `wow64.dll`, `wow64win.dll`, `wow64cpu.dll`) — nothing unusual was loaded as a DLL. This initially appears clean, but is explained by the injection technique used: the malicious code was not loaded as a DLL at all, it was written directly into the process's memory space, which is why `dlllist` shows nothing abnormal while a different technique was needed to catch it.

`windows.malfind` was run against the full memory image and flagged multiple `PAGE_EXECUTE_READWRITE` regions within RegSvcs.exe, two of which contained a valid **MZ header** — the signature of an embedded, unauthorized executable sitting in memory:

```
6796   RegSvcs.exe   0x400000   0x441fff   VadS   PAGE_EXECUTE_READWRITE   ...  MZ header
6796   RegSvcs.exe   0x54f0000  0x54fffff  VadS   PAGE_EXECUTE_READWRITE   ...  MZ header
```

A legitimate, unmodified process should never contain writable-and-executable memory holding a second PE file. This is the single strongest indicator of compromise in the entire capture.

The flagged region at `0x400000–0x441fff` was extracted using `windows.malfind --dump` and hashed:

```
SHA-256: 462c6532a427badf458ebcf0c7d79256e8604f81798ee3d47a41cb3464682db
```

Hash lookup identified this payload as **Agent Tesla**, a well-documented .NET-based infostealer and keylogger commonly delivered via phishing campaigns, capable of harvesting credentials, keystrokes, and clipboard data, and exfiltrating them via SMTP, FTP, or HTTP-based channels.

**Analyst Note:** Injecting into `RegSvcs.exe` specifically — a signed, trusted Microsoft binary — is a deliberate choice to blend malicious execution into what would appear, on a process list alone, as normal .NET framework activity. This is a textbook example of using a "living-off-the-land" trusted binary as a shell for injected code, rather than running the payload under its own, more conspicuous process name.

**MITRE ATT&CK Reference:** T1055 — Process Injection. The combination of a trusted parent binary, RWX memory permissions, and an embedded MZ header confirms this technique conclusively.

---

## 6. Phase 5: Persistence

**Objective:** Determine how the malware ensured it would survive a reboot or logoff.

Returning to the `windows.psscan` output filtered against parent PID 4596 revealed a fourth sibling process not yet accounted for: **`schtasks.exe`**. This is the native Windows utility used to create, modify, and delete Scheduled Tasks.

**Analyst Note:** My initial hypothesis, based on the Defender-exclusion evidence, was that `HcdmIYYf.exe` (the Roaming-staged file) represented the persistence mechanism, reasoning that its exclusion was preparing it to run undetected on a future trigger. That inference was directionally right in spirit but not the actual mechanism: the memory evidence shows `schtasks.exe` was invoked directly as a child of the dropper, meaning persistence was established via a **Scheduled Task**, not a registry Run key or the Roaming executable acting alone. The Roaming file's exclusion is best understood as preparing the payload that the scheduled task would later re-launch, rather than being the persistence mechanism itself. This distinction matters operationally: remediation must include removing the scheduled task entry, not just deleting the staged file, or the infection would survive a simple file cleanup.

**MITRE ATT&CK Reference:** T1053.005 — Scheduled Task/Job: Scheduled Task. This technique allows malware to re-execute automatically at a defined trigger (logon, system start, or timed interval) without requiring the original dropper to remain resident.

---

## 7. Phase 6: Attribution — Compromised User Account

**Objective:** Confirm which account context the attack executed under, to scope the blast radius.

`windows.getsids` filtered against the malicious PowerShell PIDs returned:

```
6980   powershell.exe   S-1-5-21-1649652813-3480061347-1948202237-1001   Lee
6980   powershell.exe   S-1-5-21-1649652813-3480061347-1948202237-513    Domain Users
```

The malicious activity executed under the domain account **Lee**, a standard Domain Users-level account — not SYSTEM or an administrative service account.

**Analyst Note:** Execution at standard user privilege, rather than SYSTEM, indicates no privilege escalation occurred during this stage of the attack. This is actually consistent with Agent Tesla's typical operating model — it does not require elevated privileges to log keystrokes, harvest browser-stored credentials, or read clipboard data, so the absence of an escalation event here is expected rather than a gap in the investigation.

**MITRE ATT&CK Reference:** No escalation technique observed at this stage; noted for completeness and scoping (account `Lee` should be treated as fully compromised for credential-reset and containment purposes).

---

## 8. Full Attack Timeline

| Time (UTC) | Kill Chain Phase | Activity |
|---|---|---|
| 06:57:42 | Initial Access / Execution | `InvoiceCheckList.exe` (PID 4596) executed by user Lee, spawned from `explorer.exe` |
| 06:57:59 | Defense Evasion | PowerShell (PID 6980) adds Defender exclusion for `InvoiceCheckList.exe` |
| 06:57:59 | Defense Evasion | PowerShell (PID 7656) adds Defender exclusion for `HcdmIYYf.exe` (Roaming) |
| 06:58:00 | Execution / Defense Evasion | `RegSvcs.exe` (PID 6796) launched and process-hollowed with Agent Tesla payload |
| 06:58:00 | Persistence | `schtasks.exe` invoked to establish scheduled-task persistence |
| 06:58:00 | — | `InvoiceCheckList.exe` (parent dropper) exits |

**Analyst Note:** The entire chain, from initial execution to persistence established, completed in under 20 seconds, with the core evasion/injection/persistence sequence occurring within a single second (06:57:59–06:58:00). This speed confirms a fully automated, scripted infection chain rather than manual, hands-on-keyboard attacker activity at this stage — consistent with a commodity phishing-delivered infostealer rather than a targeted, human-operated intrusion.

---

## 9. Remediation & Mitigation Recommendations

**Immediate Actions**
- Isolate the affected host from the network to prevent further credential exfiltration by Agent Tesla
- Force an immediate password reset for the account `Lee`, and for any other credentials that may have been stored in browsers or applications on this host
- Remove the identified scheduled task and both staged files (`InvoiceCheckList.exe`, `HcdmIYYf.exe`)
- Reverse the Windows Defender exclusions added via `Add-MpPreference`

**Short-Term Fixes**
- Audit and restrict which users/processes are permitted to modify Windows Defender exclusions — `Add-MpPreference` should not be freely callable by standard user PowerShell sessions in a hardened environment
- Deploy application allow-listing or attachment sandboxing at the email gateway to prevent invoice-themed executables from reaching end users in the first place
- Enable PowerShell Script Block Logging and Constrained Language Mode to increase visibility into and reduce the capability of PowerShell-based evasion in future incidents

**Long-Term Hardening**
- Implement EDR tooling capable of detecting RWX memory regions containing embedded PE headers in real time — the process injection here would be a strong detection opportunity for any modern EDR, and its absence suggests a coverage gap
- User awareness training focused specifically on invoice/payment-themed phishing lures, given this was the confirmed initial access vector
- Consider disabling or tightly restricting `RegSvcs.exe` and similar living-off-the-land .NET binaries from being spawned by non-standard parent processes via EDR behavioral rules

---

## 10. Conclusion

This investigation traced a complete, automated infection chain from initial phishing execution through to persistence establishment, all reconstructed entirely from a single memory image. Key findings:

- **Initial Access:** A phishing lure (`InvoiceCheckList.exe`) was executed by user Lee, most likely delivered as a fake invoice attachment.
- **Defense Evasion:** The malware abused the legitimate `Add-MpPreference` PowerShell cmdlet to exclude two of its own files from Windows Defender scanning.
- **Execution / Injection:** A legitimate .NET utility, `RegSvcs.exe`, was process-hollowed to host an **Agent Tesla** infostealer payload, confirmed via hash identification.
- **Persistence:** A scheduled task (`schtasks.exe`) was created to ensure the malware would survive reboot or logoff.
- **Scope:** All activity executed under standard user privileges (`Lee`); no privilege escalation was observed at this stage.

**Key Takeaways for the SOC:**
- Parent-child process relationships remain one of the fastest ways to reconstruct an entire attack chain from memory alone — a single anomalous parent PID unlocked every subsequent finding in this case.
- `dlllist` alone is insufficient to detect process injection; `malfind` (RWX memory + embedded headers) is essential and should be a standard step in any memory triage, not an optional deep-dive.
- Persistence mechanisms should always be confirmed via direct process evidence where possible, not inferred from adjacent artifacts like file staging locations — the two can look similar but require different remediation steps.
- Commodity infostealers like Agent Tesla remain effective specifically because they don't require privilege escalation, defenders should not assume "no elevation observed" means "low severity."
