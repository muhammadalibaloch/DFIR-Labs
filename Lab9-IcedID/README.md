# IcedID Lab

Category: Threat Intel
Tools: VirusTotal, malpedia, Recorded Future Triage Sandbox, ANY.RUN

## Scenario

A cyber threat group was identified initiating widespread phishing campaigns to distribute further malicious payloads. The most frequently encountered payload was IcedID. Given a hash of an IcedID sample, the goal was to analyze it and monitor the activity of the associated advanced persistent threat (APT) group.

---

## Q1 - What is the name of the file associated with the given hash?

Approach: Paste the sample hash into VirusTotal's search bar, then open the Details tab and check the Names section. VirusTotal aggregates every filename the sample has ever been submitted under, since the same file can be seen in the wild under many different names.

<img width="1508" height="822" alt="Q1" src="https://github.com/user-attachments/assets/59a34100-b928-4680-8837-527394352e01" />


Answer: document-1982481273.xlsm

---

## Q2 - Can you identify the filename of the GIF file that was deployed?

Approach: On Triage Sandbox, open the Behavior tab and check the Files Dropped section. The malicious Excel macro reaches out and drops a GIF-named payload into the IE INetCache folder, disguised as an image to avoid raising suspicion.

<img width="1512" height="867" alt="Q2" src="https://github.com/user-attachments/assets/f9fce59b-ee46-4fe4-b153-99a66447d17e" />

Answer: 3003.gif

---

## Q3 - How many domains does the malware look to download the additional payload file in Q2?

Approach: Still in the Behavior tab, open the HTTP Requests section. Each GET request targeting /ds/3003.gif represents an attempt to fetch the payload from a different domain. Counting the unique domains making that request gives the total.

<img width="1512" height="864" alt="Q3" src="https://github.com/user-attachments/assets/62ca9831-8721-46c3-a2f1-1a0bf906c224" />

Answer: 5

---

## Q4 - From the domains mentioned in Q3, a DNS registrar was predominantly used by the threat actor. Can you specify the Registrar Inc?

Approach: Cross-referencing VirusTotal's Contacted Domains table for each of the five malicious domains from Q3 against their WHOIS records showed that two of them, agenbolatermurah.com and tajushariya.com, were both registered through NameCheap, Inc. Since NameCheap repeated across multiple malicious domains, it was identified as the predominant registrar.

<img width="874" height="465" alt="Q4" src="https://github.com/user-attachments/assets/d3b4e844-b70c-4291-ab5b-94798ad69f42" />

<img width="451" height="217" alt="Q4 (Helpcenter)" src="https://github.com/user-attachments/assets/9fe9a9a1-37b8-4928-92e1-197cfaa7bd10" />


Note - why my own WHOIS lookup didn't initially show NameCheap:
I couldn't find NameCheap in my own WHOIS lookup because the domain had since expired and been re-registered by DropCatch, a domain drop-catching service. Since WHOIS only shows current registration data, the original registrar from the time of the actual malicious activity (2017) was replaced by the new one (2026) in later lookups.

Answer: Namecheap

---

## Q5 - Could you specify the threat actor linked to the sample provided?

Approach: Checked the Community tab on the sample's VirusTotal page. Community-submitted comments and crowdsourced context often carry attribution notes from other analysts who have already researched the sample.

<img width="451" height="150" alt="Q5" src="https://github.com/user-attachments/assets/6ac0f0ce-adc4-4937-ac73-d4121d3d6e49" />

Answer: GOLD CABIN

---

## Q6 - In the Execution phase, what function does the malware employ to fetch extra payloads onto the system?

Approach: Searched the sample hash in Triage Sandbox and opened the Static analysis tab, then checked the Malware Config section. The extracted XLM macro source shows repeated CALL statements invoking a specific Windows API function through URLMon to download the GIF payload from each malicious domain onto disk.

<img width="1512" height="858" alt="Q6" src="https://github.com/user-attachments/assets/678c2e0f-322f-4416-8d17-94696cfbbabb" />

Answer: URLDownloadToFileA

---

## Summary

The sample (document-1982481273.xlsm) is a malicious Excel 4.0 macro (XLM) document that, on execution, calls URLDownloadToFileA via URLMon across five hardcoded domains to fetch a payload disguised as 3003.gif into the IE INetCache directory. Two of the five delivery domains (agenbolatermurah.com and tajushariya.com) were originally registered through NameCheap, Inc., indicating a registrar preference by the threat actor at the time of the campaign, though later WHOIS lookups reflect a different registrar due to domain expiry and drop-catch re-registration. Community attribution on VirusTotal links this IcedID sample to the threat actor group GOLD CABIN.
