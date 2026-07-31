# OpenCTI 101: APT29

Platform: CyberDefenders
Category: Threat Intel
Tools: OpenCTI, VirusTotal, OSINT

Scenario

I'm working as a Threat Intel Analyst at a fictional MDR, and the job here was to track APT29 (Cozy Bear, NOBELIUM, whatever alias you want to use) using OpenCTI. 
This one was different from my usual labs. Most of the labs I've done so far have me digging through pcaps or memory dumps to reconstruct an attack from scratch. 
This one flips that. The intel is already sitting in a platform, structured and connected, and the job is to actually know how to navigate it: pivot through relationships, 
trace an IOC back to the campaign it belongs to, and figure out when the platform gives you enough versus when you need to go pull the original vendor report yourself.

**Q1: Two campaigns tied to APT29**

First question was just about getting oriented. 
APT29's Intrusion Set page in OpenCTI has a Campaigns section under Threats in the sidebar, 
and it listed two: SolarWinds Compromise and Operation Ghost. Nothing complicated here, 
just needed to know the structure of the platform enough to find where campaigns live separate from the intrusion set itself.

<img width="1714" height="1226" alt="Q1" src="https://github.com/user-attachments/assets/a794421c-df97-424f-a61d-c83f9f7f1cb2" />

<img width="1695" height="1154" alt="Q1 1" src="https://github.com/user-attachments/assets/35617cca-1aa1-4f68-a614-11c4b694e61a" />

<img width="506" height="142" alt="Q1 2" src="https://github.com/user-attachments/assets/1528c8af-ff89-436a-8049-3c73cd2d4d2d" />


**Answer: SolarWinds Compromise, Operation Ghost**

**Q2: The Tor plugin APT29 uses**

Under Arsenal > Tools there were 15 tools tied to the group. Scrolled through and found one called meek, and its description spelled it out directly: 
an open source Tor plugin that tunnels Tor traffic through HTTPS. Didn't need to go outside the platform for this one.

<img width="198" height="849" alt="Q2" src="https://github.com/user-attachments/assets/8dd0cf4b-bfdc-4416-8675-17ba3ad43635" />

<img width="1718" height="1114" alt="Q2 1" src="https://github.com/user-attachments/assets/5b494e17-b6bb-490b-ac35-820808a282cf" />

<img width="658" height="287" alt="Q2 2" src="https://github.com/user-attachments/assets/26cb360a-290e-4b0b-ad16-e0611906dc60" />

**Answer: meek**

**Q3: Exfiltration technique IDs**

This one needed the MITRE ATT&CK matrix view, filtered to mitre-attack under the kill chain dropdown. 
Scrolled over to the exfiltration column and found two techniques with a highlighted border around them, T1030 and T1048. 
My first thought was that the highlighting meant "most recently observed," which is actually wrong. 
The highlighting just marks which techniques are directly linked to APT29 in that view. 
Good reminder not to assume what a visual cue is telling you without checking.

<img width="1717" height="1152" alt="Q3" src="https://github.com/user-attachments/assets/1071ec51-e243-44ab-b9d2-32f6524dcd25" />

**Answer: T1030, T1048**

**Q4: Cobalt Strike and EnvyScout tied to crossfity.com**

Searched crossfity[.]com directly in OpenCTI and opened its Knowledge tab. 
The relationships table laid it out clean: this indicator points to Cobalt Strike and EnvyScout, and also directly to the APT29 intrusion set.

<img width="1757" height="793" alt="Q4" src="https://github.com/user-attachments/assets/f543e06f-5f0e-42fb-8ee5-8a17e7088c88" />


**Answer: Cobalt Strike (adversary emulation tool), EnvyScout (malware family)**

**Q5: Finding the second domain in the same campaign**

This one I got wrong on the first try. I opened the source report's Entities tab and it had 29 entities mixed together, indicators, malware, attack patterns, sectors, all in one list. 
I just picked a domain that looked right (techspaceinfo.com) without actually confirming anything. That's a guess, not an answer.

To actually verify it, I went to techspaceinfo.com's own page and checked its relationships the same way I did for crossfity.com. 
Turns out it also indicates Cobalt Strike, EnvyScout, and APT29, the exact same three relationships. That overlap is the real proof they're part of the same infrastructure, 
not just two domains that happened to show up in the same report.

<img width="1700" height="1219" alt="Q5" src="https://github.com/user-attachments/assets/60ebb36a-047c-420d-8b49-78c1dbaf701c" />

<img width="1467" height="1207" alt="Q5 1" src="https://github.com/user-attachments/assets/10c40672-f875-4d24-a8ee-dfe7d5cf8578" />

<img width="1659" height="494" alt="Q5 2" src="https://github.com/user-attachments/assets/be23cc6a-695d-4af4-9af1-4e4a1083e3ce" />

**Answer: techspaceinfo.com**

**Q6: The Old Wine in a New Bottle phishing link**

This question sent me down the wrong path for a bit. 
There's a report tied to APT29 that references a BlackBerry article, and I assumed that was the source for this campaign. 
Turned out that article was actually about a totally different operation (the Poland Ambassador/LegisWrite lure, 
which is a different question entirely).

The actual source for Old Wine in a New Bottle is a Mandiant report called "Backchannel Diplomacy: APT29's Rapidly Evolving Diplomatic Phishing Operations," 
published September 2023. This one report actually covers several APT29 sub-campaigns from the first half of 2023 in one continuous writeup, 
so once I found the right report, the next few questions were all sitting in the same place.

<img width="1756" height="926" alt="q6" src="https://github.com/user-attachments/assets/563786ef-ec85-4f08-bb22-7dd6f8c5769e" />

<img width="1710" height="1096" alt="q6 1" src="https://github.com/user-attachments/assets/d7098b0c-8d1f-4f44-9882-395d5e5e1ba3" />

**Answer: https://sylvio[.]com[.]br/form.php**

**Q7: Hostname in the Earthquake-Themed Türkiye Campaign**

Still in the same Mandiant report, scrolled down to the March 2023 Earthquake-Themed Türkiye Campaign section. 
The first phishing wave used a URL shortener to redirect victims to a compromised site that was actually hosting the ROOTSAW dropper.

<img width="1710" height="1185" alt="Q7" src="https://github.com/user-attachments/assets/bf933354-1db6-4a86-8ea2-38709d71dfee" />

**Answer: www.willyminiatures.com**

**Q8: PDF decoy in the same campaign**

Same section as above. The ROOTSAW variant used here checked the victim's user agent, 
looking for Windows and non-.NET signatures. If that check failed, meaning the victim wasn't a real Windows target, 
the server handed over a decoy PDF instead of the malicious ISO.

<img width="1694" height="1185" alt="q8" src="https://github.com/user-attachments/assets/a607e163-6931-4f7c-bf19-9434b32fdda5" />

**Answer: e-yazi.pdf**

**Q9: MD5 hash of the SVG-based ROOTSAW dropper**

Kept reading through the same report into the June 2023 Split ROOTSAW Campaign section. 
This one used two delivery methods, a PDF linking out to a hosted ROOTSAW variant, and an email with an SVG file attached instead of the usual HTML payload. 
The question wanted the hash of the SVG-specific one, and it was right there in the paragraph.

<img width="1084" height="1188" alt="q9" src="https://github.com/user-attachments/assets/f5f3babb-24ac-42dc-9d56-59a9aeac7687" />

**Answer: 295527e2e38da97167979ade004de880**

**Q10: URL indicators in the Poland Ambassador campaign**

This is actually the report I mistakenly thought was tied to Old Wine in a New Bottle earlier. 
Found it properly this time through APT29's Analyses tab: "NOBELIUM Uses Poland's Ambassador's Visit to the U.S. to Target EU Governments Assisting Ukraine" by AlienVault. 
Its Observables tab had 10 entries, and two of them were URL-type observables pointing to a compromised library website based in El Salvador.

<img width="1715" height="809" alt="Q10" src="https://github.com/user-attachments/assets/84e50f1b-47b9-4d72-bf39-4ece3b066484" />

<img width="1460" height="948" alt="Q10 1" src="https://github.com/user-attachments/assets/336a3081-5a14-4db0-a358-19c542887059" />


**Answer: https://literaturaelsalvador.com/Schedule.html, https://literaturaelsalvador.com/Instructions.html**

**Q11: The command run by the .lnk file**

Blackberry link wasnt working. So, had to the manaully for this one. The 2nd report referenced an AlienVault OTX pulse with the file hashes for this campaign. 
I grabbed the MD5 of the .lnk file and ran it through VirusTotal directly, then checked the Details tab under Lnk Info. 
It showed the target path (rundll32.exe) and the command line arguments together, which is basically the full command that gets executed the moment someone opens that shortcut.

<img width="1707" height="1188" alt="Q11" src="https://github.com/user-attachments/assets/1267cb44-8415-4f9f-9d2d-8f69c56ea828" />

<img width="1713" height="962" alt="Q11 1" src="https://github.com/user-attachments/assets/4c64a389-a602-43d9-acff-64b930c7c477" />

<img width="1714" height="1224" alt="Q11 2" src="https://github.com/user-attachments/assets/4d744ec3-fce9-4f7c-8238-cce19babbe3a" />


**Answer: C:\Windows\system32\rundll32.exe BugSplatRc64.dll,InitiateDs**

**What I took away from this one**

The biggest thing I keep relearning across these labs is that showing up in the same list or the same report doesn't mean two things are actually connected. 
I had to prove the techspaceinfo.com link through actual relationship data, not just because it was sitting in the same entities table as crossfity.com. 
Same thing with the highlighting on the ATT&CK matrix, 
I assumed it meant something it didn't, and the only way to know for sure was to dig deeper instead of trusting the UI at face value.

The other thing worth remembering is that one vendor report can quietly cover multiple named campaigns. 
I lost time on the Old Wine question because I assumed one report equals one campaign, and that assumption was wrong. 
Once I found the real Mandiant writeup, three separate questions basically fell into place from the same source.
