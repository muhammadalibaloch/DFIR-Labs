Lab 11: DanaBot Malicious JS Deobfuscation

Overview
This lab focuses on analyzing a packet capture involving DanaBot, a banking trojan and infostealer that has historically been delivered through malicious JavaScript attachments. The investigation walks through identifying the initial access vector, extracting and examining the malicious files involved, and tracing how the attack executed on the victim machine. The platform used for this lab was CyberDefenders.

Objective
The goal was to analyze network traffic to determine how the attacker gained initial access, identify the malicious files used at each stage of the infection, and confirm which Windows process was responsible for executing the malicious JavaScript payload.

Tools Used
* Wireshark
* CyberChef (for JavaScript deobfuscation)
* sha256sum / md5sum (Linux terminal)
* Text editor for reviewing extracted script content

Analysis

Q1: Which IP address was used by the attacker during the initial access?
I started by filtering the capture with the http display filter to get a quick view of all HTTP activity. The earliest entry showed a GET request to /login.php from the victim host 10.2.14.101 to 62.173.142.148.
Rather than relying on filter order alone, I confirmed this properly by filtering on ip.addr == 62.173.142.148 with the HTTP filter cleared, which showed the full TCP handshake (SYN, SYN-ACK, ACK) immediately preceding the HTTP request, with no DNS or ARP activity for that IP earlier in the capture. This confirmed the connection was made directly to the IP address rather than through a resolved domain.
Answer: 62.173.142.148
<img width="1492" height="885" alt="Q1" src="https://github.com/user-attachments/assets/35dcb794-7344-4b7f-a3b9-a0f2c5b438d5" />


Q2: What is the name of the malicious file used for initial access?
Following the TCP stream on the /login.php request and its corresponding 200 OK response (reassembled across packets 8 through 10 into packet 11) revealed the file being delivered was named allegato_708.js. The Italian filename ("allegato" translates to "attachment") is consistent with DanaBot campaigns that have targeted Italian speaking regions through phishing emails with malicious script attachments.
Answer: allegato_708.js
<img width="1506" height="866" alt="SCR-20260803-srnq" src="https://github.com/user-attachments/assets/6df25bde-8ed5-405e-8950-4cdc160a3cad" />
<img width="1482" height="785" alt="Q2 2" src="https://github.com/user-attachments/assets/bfe80ba2-1107-48d2-89ef-5867ef0a4470" />

Q3: What is the SHA-256 hash of the malicious file used for initial access?
After extracting the file object from the HTTP response using Wireshark's Export Objects feature (File > Export Objects > HTTP), I hashed the extracted file to generate its SHA-256 value for identification and threat intel lookup purposes.
Answer: 847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476...
<img width="1706" height="1216" alt="Q3" src="https://github.com/user-attachments/assets/223744dd-176e-427b-81b3-69d26e164c7c" />

Q4: Which process was used to execute the malicious file?
Since allegato_708.js carries a .js extension, Windows requires an interpreter to run it, as JavaScript files are not natively executable. Windows handles this through Windows Script Host, which provides two possible interpreters: wscript.exe and cscript.exe.
I opened the extracted script and worked through deobfuscating it using CyberChef, applying JavaScript Beautify along with decoding steps for the encoded strings present in the file. The deobfuscated code contained calls to WScript.CreateObject, which only resolves within a Windows Script Host context. This confirmed the script was designed to run under WSH rather than in a browser or another JavaScript engine.
Since wscript.exe is the default handler for .js files on Windows and runs without a visible console window, unlike cscript.exewhich opens a terminal window, it is the far more likely execution method for a payload designed to run silently on a victim's machine.
Answer: wscript.exe
<img width="816" height="217" alt="Q4" src="https://github.com/user-attachments/assets/146c9061-6305-4da5-b80c-cd2df2ce5cbd" />
Q5: What is the file extension of the second malicious file utilized by the attacker?
Continuing through the HTTP traffic after the initial script execution, a second GET request appeared for /resources.dll from the victim host, indicating a second stage payload was pulled down after the initial script ran.
Answer: .dll
<img width="1506" height="336" alt="Q5" src="https://github.com/user-attachments/assets/ae30af41-9e41-47d5-b399-dd88d671abf6" />

Q6: What is the MD5 hash of the second malicious file?
I exported the resources.dll object the same way as the first file, through Wireshark's Export Objects, and generated its MD5 hash for identification.
Answer: e758e07113016aca55d9eda2b0ffeebe
<img width="1717" height="1315" alt="Q6" src="https://github.com/user-attachments/assets/74c6e020-12d1-4870-b1a3-7b9b043f2f03" />



Conclusion
This lab walked through a full DanaBot infection chain, starting from initial access over HTTP, identifying the malicious JavaScript dropper, confirming its execution method through code analysis rather than assumption, and tracking the download of a second stage DLL payload. The key takeaway for me was learning to verify the execution process not just from file extension logic but by actually deobfuscating the script and finding the WScript object references that proved it. It reinforced why pcap analysis alone can only get you so far, the real confirmation came from reading the payload itself.
