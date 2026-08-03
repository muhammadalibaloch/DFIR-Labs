# XLMRat — Network Forensics & Reflective Payload Analysis

## Scenario
A compromised host was flagged for suspicious outbound traffic. Analysis of the PCAP reveals a multi-stage malware delivery chain: an obfuscated PowerShell script pulls two payloads disguised as an image file, decodes them from embedded hex strings, and uses a reflective PE loader to inject a RAT (AsyncRAT) directly into a legitimate, signed Windows process (`RegSvcs.exe`), avoiding disk-based detection. The script also drops persistence artifacts and registers a disguised Scheduled Task for re-execution every 2 minutes.

Tools used: Wireshark, CyberChef, VirusTotal, macOS Terminal (`sha256sum`).

---

## Q1 — Initial malware download URL

- Filtered Wireshark on `http.request.method == GET` to isolate outbound requests.
- Found two GET requests from the host to `45.126.209.4:222`: one for `/xlm.txt`, one for `/mdm.jpg`.
- Expanded packet 12 and confirmed the full request URI in the HTTP layer.
- **Answer:** `http://45.126.209.4:222/mdm.jpg`

<img width="1512" height="118" alt="Q1 1" src="https://github.com/user-attachments/assets/f4606aa2-b57c-4f15-be76-298f45fdbe44" />

<img width="679" height="224" alt="Q1 2" src="https://github.com/user-attachments/assets/1c9fee50-ee1f-4430-b326-913e53eabf03" />


---

## Q2 — Hosting provider for the malicious IP

- Ran the IP `45.126.209.4` through an IP lookup service.
- Result returned organization/ISP name directly.
- **Answer:** `ReliableSite.Net`

<img width="1196" height="622" alt="Q2" src="https://github.com/user-attachments/assets/61889e49-e921-46dd-9371-ee99bf8b2113" />

---

## Q3 — SHA256 of the malware executable

- Exported the HTTP object `mdm.jpg` via **File → Export Objects → HTTP** in Wireshark.
- Despite the `.jpg` extension, the file was actually a PowerShell script containing two embedded hex-encoded executables (`$hexString_bbb` and `$hexString_pe`).
- Confirmed two payloads exist: a **loader** (`$pe`) and a **secondary executable / actual malware** (`$bbb`).
  - `$pe` is the one passed to `[Reflection.Assembly]::Load()` — it's loaded and run directly, making it the reflective loader.
  - `$bbb` is only ever passed as a byte-array *argument* alongside the target process path — making it the actual injected payload.
- In CyberChef: loaded the exported file, used **Find/Replace** (regex `_` → blank) to strip the underscore delimiters from the hex string, then **From Hex** to convert back to raw binary. Saved the `bbb` output as `gibresh.exe`.
- Hashed the decoded file in terminal with `sha256sum`.
- **Answer:** `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`

<img width="1545" height="996" alt="Q3" src="https://github.com/user-attachments/assets/81e1dfbf-01c5-4eb5-8293-89e96ddef198" />
<img width="1717" height="877" alt="Q3 2" src="https://github.com/user-attachments/assets/03d82974-6e92-4b2d-bee3-86204edb0a1f" />
<img width="1718" height="1294" alt="Q3 3" src="https://github.com/user-attachments/assets/ab196459-f6bf-41db-915c-a1fe51d77e28" />
<img width="1708" height="1304" alt="Q3 4" src="https://github.com/user-attachments/assets/2fd5dc5d-b79a-405e-b7e6-ddc12f080454" />
<img width="593" height="136" alt="Q3 5" src="https://github.com/user-attachments/assets/529cf5f7-2ec5-4fc9-9384-85add3b5a1ed" />


---

## Q4 — Malware family label (per Alibaba)

- Submitted the SHA256 hash to VirusTotal.
- 61/71 vendors flagged the file as malicious.
- Alibaba's detection specifically labeled it as an AsyncRAT variant, consistent with the popular threat label (`trojan.asyncrat/msil`) and family labels shown across the detection results.
- **Answer:** `Asyncrat`

<img width="1661" height="1227" alt="Q4" src="https://github.com/user-attachments/assets/79696ca4-8baf-4288-9e12-d029970c9a6d" />


---

## Q5 — Malware creation timestamp

- On the same VirusTotal report, opened the **Details** tab.
- Under **History**, the Creation Time field shows the PE compile timestamp embedded in the binary.
- **Answer:** `2023-10-30 15:08` (UTC)

<img width="1657" height="1251" alt="Q5" src="https://github.com/user-attachments/assets/9964b2c4-8ca4-407f-b768-69328b3652d1" />

---

## Q6 — LOLBin leveraged for stealthy execution

- Followed the TCP stream in Wireshark for the packet containing the decoded PowerShell script.
- Located the section building the target process path from de-obfuscated string fragments (`-replace '#', ''`), which reassembles to the full path of a legitimate, signed .NET utility.
- This binary is used as the injection target for the reflective loader — a classic Living-Off-the-Land technique (T1218 / T1055) that lets the malware run disguised inside a trusted Microsoft process.
- **Answer:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

<img width="1552" height="967" alt="Q6" src="https://github.com/user-attachments/assets/df4ba082-a1aa-48bd-8e5b-c2fd962dd0dc" />
<img width="1488" height="933" alt="Q6 2" src="https://github.com/user-attachments/assets/69766c74-e584-4414-9425-19c6c63a8071" />

---

## Q7 — Files dropped by the script

- Continued reading through the followed TCP stream past the injection logic.
- Found three `[IO.File]::WriteAllText(...)` calls, each writing a different persistence-chain file to the same public folder:
  - `Conted.ps1` — the actual PowerShell payload (decode → load → inject logic)
  - `Conted.bat` — launches PowerShell silently (`-WindowStyle Hidden -ExecutionPolicy Bypass`) against `Conted.ps1`
  - `Conted.vbs` — uses `WScript.Shell.Run` with visibility `0` to invisibly launch `Conted.bat`
- The script additionally registers a Scheduled Task named **"Update Edge"** to re-trigger `Conted.vbs` every 2 minutes, disguising the persistence mechanism as a routine browser update.
- **Answer:** `Conted.ps1`, `Conted.bat`, `Conted.vbs`

<img width="1498" height="934" alt="Q7" src="https://github.com/user-attachments/assets/d450015f-6b59-4f63-a83c-61be87470966" />

---

## Summary — Attack chain

1. **Initial access:** Victim's system issues an HTTP GET for `mdm.jpg`, a disguised PowerShell script, from `45.126.209.4:222` (ReliableSite.Net).
2. **Deobfuscation:** Script contains two hex-encoded blobs. Decoded and identified as a reflective PE loader (`$pe`) and an AsyncRAT payload (`$bbb`).
3. **Execution / Defense evasion:** Loader is loaded via `Assembly::Load`, locates its `Execute` method, and injects the AsyncRAT payload into `RegSvcs.exe` — a legitimate, signed LOLBin — avoiding on-disk detection (T1055, T1218).
4. **Persistence:** Script drops three chained files (`Conted.ps1` → `Conted.bat` → `Conted.vbs`) and registers a Scheduled Task ("Update Edge") to re-launch every 2 minutes (T1053.005).
5. **Detection:** Payload hash confirmed malicious on VirusTotal (61/71 vendors), identified as AsyncRAT, compiled 2023-10-30.
